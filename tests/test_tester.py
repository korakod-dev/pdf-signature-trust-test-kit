"""Proves that the test page stays local, isolates validators and keeps nothing."""

import http.client
import socket
import subprocess
import sys
import threading
from http.server import HTTPServer
from pathlib import Path
from urllib.parse import urlencode

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding

from trustkit import tester
from trustkit.oracle import cases_for, load_withheld

CONNECT = (
    "import socket,sys\n"
    "s=socket.socket()\n"
    "s.settimeout(3)\n"
    "try:\n"
    "    s.connect(('127.0.0.1',int(sys.argv[1])))\n"
    "except OSError:\n"
    "    sys.exit(7)\n"
)
needs_sandbox = pytest.mark.skipif(not Path(tester.SANDBOX).exists(), reason="macOS only")


def _row(raw: str = "raw") -> dict:
    return {
        "tool": "pdfsig",
        "tool_version": "1",
        "verdict": "VALID",
        "raw_output": raw,
        "fixture_sha256": "abc",
        "signals": {},
    }


@pytest.fixture
def page(tmp_path):
    seen = []

    def fake_check(pdf, anchor, work_dir, profile):
        seen.append(
            {"pdf": pdf, "anchor": anchor, "profile": profile, "bytes": pdf.read_bytes()}
        )
        return [_row("<b>raw</b>")]

    class Handler(tester.TesterHandler):
        samples = {
            "A1": tester.Sample("A1", "title", "VALID", tmp_path / "A1.pdf"),
        }
        default_anchor = tmp_path / "root.pem"
        check = staticmethod(fake_check)

    (tmp_path / "A1.pdf").write_bytes(b"%PDF-1.7 sample")
    server = HTTPServer((tester.HOST, 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server.server_address[1], seen
    server.shutdown()
    server.server_close()


def _request(port, method, path, body=None, headers=None):
    connection = http.client.HTTPConnection(tester.HOST, port, timeout=5)
    connection.request(method, path, body=body, headers=headers or {})
    response = connection.getresponse()
    return response.status, response.read().decode(), dict(response.getheaders())


def _upload(port, pdf: bytes, anchor: bytes = b""):
    boundary = "testboundary"
    body = (
        (
            f'--{boundary}\r\nContent-Disposition: form-data; name="pdf"; filename="a.pdf"\r\n'
            "Content-Type: application/pdf\r\n\r\n"
        ).encode()
        + pdf
        + (
            f'\r\n--{boundary}\r\nContent-Disposition: form-data; name="anchor"; filename="r"\r\n'
            "Content-Type: application/octet-stream\r\n\r\n"
        ).encode()
        + anchor
        + f"\r\n--{boundary}--\r\n".encode()
    )
    return _request(
        port,
        "POST",
        "/check",
        body,
        {"Content-Type": f"multipart/form-data; boundary={boundary}"},
    )


def _certificate() -> x509.Certificate:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "TEST ONLY")])
    import datetime as dt

    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(dt.datetime(2020, 1, 1))
        .not_valid_after(dt.datetime(2030, 1, 1))
        .sign(key, hashes.SHA256())
    )


def test_page_is_served_with_a_strict_policy(page):
    status, body, headers = _request(page[0], "GET", "/")
    assert status == 200
    assert "A1: title" in body
    assert headers["Cache-Control"] == "no-store"
    assert "default-src 'none'" in headers["Content-Security-Policy"]


def test_another_host_header_is_refused(page):
    status, _, _ = _request(page[0], "GET", "/", headers={"Host": "attacker.invalid"})
    assert status == 403


def test_a_post_from_another_site_is_refused(page):
    status, _, _ = _request(
        page[0], "POST", "/sample", "case=A1", {"Origin": "https://attacker.invalid"}
    )
    assert status == 403
    assert page[1] == []


def test_a_sample_gets_loopback_only(page):
    status, body, _ = _request(page[0], "POST", "/sample", urlencode({"case": "A1"}))
    assert status == 200
    assert page[1][0]["profile"] == tester.LOOPBACK_ONLY
    assert "Expected verdict: VALID" in body


def test_an_unknown_sample_is_refused(page):
    assert _request(page[0], "POST", "/sample", "case=../x")[0] == 400


def test_an_upload_gets_no_network_and_is_deleted(page):
    status, body, _ = _upload(page[0], b"%PDF-1.7 mine")
    assert status == 200
    seen = page[1][0]
    assert seen["profile"] == tester.NO_NETWORK
    assert seen["bytes"] == b"%PDF-1.7 mine"
    assert not seen["pdf"].exists()
    assert "Network during the check: none" in body


def test_output_from_a_tool_is_escaped(page):
    _, body, _ = _upload(page[0], b"%PDF-1.7 mine")
    assert "<b>raw</b>" not in body
    assert "&lt;b&gt;raw&lt;/b&gt;" in body


def test_a_file_that_is_not_a_pdf_is_refused(page):
    assert _upload(page[0], b"not one")[0] == 400
    assert page[1] == []


def test_a_bad_root_is_refused(page):
    assert _upload(page[0], b"%PDF-1.7", b"not a certificate")[0] == 400


@pytest.mark.parametrize("encoding", [Encoding.PEM, Encoding.DER])
def test_a_root_can_be_pem_or_der(page, encoding):
    assert _upload(page[0], b"%PDF-1.7", _certificate().public_bytes(encoding))[0] == 200
    assert page[1][0]["anchor"].name == "anchor.pem"


def test_an_oversized_body_is_refused_without_reading_it(page):
    headers = {"Content-Length": str(tester.MAX_BODY_BYTES + 1)}
    connection = http.client.HTTPConnection(tester.HOST, page[0], timeout=5)
    connection.putrequest("POST", "/check")
    for key, value in headers.items():
        connection.putheader(key, value)
    connection.endheaders()
    assert connection.getresponse().status == 413


def test_withheld_cases_are_not_offered_as_samples(tmp_path):
    cases = cases_for("M4")

    class Built:
        path = tmp_path / "x.pdf"

    samples = tester.load_samples({case.id: Built for case in cases}, cases, load_withheld())
    assert load_withheld()
    assert not load_withheld() & set(samples)


def test_missing_sandbox_means_no_check(monkeypatch):
    monkeypatch.setattr(tester, "SANDBOX", "/does/not/exist")
    with pytest.raises(tester.IsolationError):
        tester.isolated_command(tester.NO_NETWORK, ["true"])


@needs_sandbox
@pytest.mark.parametrize("profile, code", [(tester.NO_NETWORK, 7), (tester.LOOPBACK_ONLY, 0)])
def test_sandbox_profiles_on_loopback(profile, code):
    with socket.socket() as listener:
        listener.bind((tester.HOST, 0))
        listener.listen()
        result = subprocess.run(
            tester.isolated_command(
                profile, [sys.executable, "-I", "-c", CONNECT, str(listener.getsockname()[1])]
            ),
            capture_output=True,
            timeout=30,
        )
    assert result.returncode == code
