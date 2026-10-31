"""A local test page: pick a sample or give a PDF, and see what each validator says.

The page listens on loopback only, and keeps nothing after a check. Validators run in a
sandboxed child process, because a PDF and its certificates can name any URL and the
adapters are allowed to fetch. A given file gets no network at all, not even loopback.
A sample gets loopback only, for the local revocation service.
"""

import email.parser
import email.policy
import json
import shutil
import signal
import subprocess
import sys
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from html import escape
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from trustkit import fixtures, pki, services
from trustkit.adapters.dss_adapter import DssAdapter
from trustkit.adapters.pdfsig_adapter import PdfsigAdapter
from trustkit.adapters.pyhanko_adapter import PyHankoAdapter
from trustkit.oracle import cases_for, load_mapping, load_withheld
from trustkit.report import PAGE_STYLE

HOST = "127.0.0.1"
DEFAULT_PORT = 18770
MAX_BODY_BYTES = 25 * 1024 * 1024
MAX_RAW_CHARS = 200_000
WORKER_TIMEOUT_SECONDS = 300
SANDBOX = "/usr/bin/sandbox-exec"

_WRITES = (
    '(deny file-write*)(allow file-write* (subpath "/private/var/folders") '
    '(subpath "/private/tmp") (subpath "/dev"))'
)
NO_NETWORK = f"(version 1)(allow default){_WRITES}(deny network*)"
LOOPBACK_ONLY = (
    f"{NO_NETWORK}"
    '(allow network* (local ip "localhost:*"))(allow network* (remote ip "localhost:*"))'
)

VERDICT_MEANINGS = {
    "VALID": "Signature valid, trusted, no change after signing.",
    "VALID_WITH_ALLOWED_CHANGES": "Valid, with changes the tool classifies as permitted.",
    "VALID_WITH_UNCLASSIFIED_CHANGES": (
        "Signature passes, and the tool reports later changes or partial coverage "
        "without judging them."
    ),
    "INVALID": "Broken signature, disallowed change, or revoked certificate.",
    "INDETERMINATE": "No cryptographic failure, but the evidence is insufficient.",
    "NO_SIGNATURE": "No signature in the file.",
    "UNSUPPORTED": "The tool does not assess this aspect.",
    "TOOL_ERROR": "The tool failed, or gave output that is not in the mapping.",
}
VERDICT_CLASSES = {
    "VALID": "AGREE",
    "VALID_WITH_ALLOWED_CHANGES": "AGREE",
    "VALID_WITH_UNCLASSIFIED_CHANGES": "PARTIAL",
    "INDETERMINATE": "PARTIAL",
    "INVALID": "MISSED",
    "TOOL_ERROR": "MISSED",
}
SHOWN_SIGNALS = (
    "problem",
    "sub_indication",
    "coverage",
    "modification_level",
    "modifications",
    "warnings",
)


class IsolationError(Exception):
    """The child process cannot be isolated, so no validator runs."""


@dataclass
class Sample:
    case_id: str
    title: str
    expected: str
    path: Path


def isolated_command(profile: str, command: list[str]) -> list[str]:
    if not Path(SANDBOX).exists():
        raise IsolationError(f"{SANDBOX} was not found, and this page runs only on macOS for now")
    return [SANDBOX, "-p", profile, *command]


def run_validators(pdf: Path, trust_anchor: Path, work_dir: Path) -> list[dict]:
    """Runs in the sandboxed child."""
    mapping = load_mapping()
    rows = []
    for adapter in (PyHankoAdapter(mapping), PdfsigAdapter(mapping), DssAdapter(mapping)):
        tool_dir = work_dir / adapter.name
        tool_dir.mkdir()
        rows.append(adapter.validate("input", pdf, trust_anchor, tool_dir).to_dict())
    return rows


def check_in_sandbox(pdf: Path, trust_anchor: Path, work_dir: Path, profile: str) -> list[dict]:
    result_path = work_dir / "result.json"
    subprocess.run(
        isolated_command(
            profile,
            [sys.executable, "-m", "trustkit.tester", str(pdf), str(trust_anchor), str(work_dir)],
        ),
        check=True,
        capture_output=True,
        timeout=WORKER_TIMEOUT_SECONDS,
    )
    return json.loads(result_path.read_text(encoding="utf-8"))


def parse_form(content_type: str, body: bytes) -> dict[str, bytes]:
    """The parts of a multipart form, by field name."""
    header = f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n".encode()
    message = email.parser.BytesParser(policy=email.policy.HTTP).parsebytes(header + body)
    if not message.is_multipart():
        return {}
    parts = {}
    for part in message.iter_parts():
        name = part.get_param("name", header="content-disposition")
        if name:
            parts[name] = part.get_payload(decode=True) or b""
    return parts


def certificate_to_pem(data: bytes) -> bytes:
    """Accepts PEM or DER. Raises ValueError on anything else."""
    loader = x509.load_pem_x509_certificate if b"-----BEGIN" in data else x509.load_der_x509_certificate
    return loader(data).public_bytes(Encoding.PEM)


def _page(body: str) -> bytes:
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Signature Trust Tester</title>
<style>{PAGE_STYLE}
.panel {{ border: 1px solid var(--line); background: var(--surface); padding: 16px; margin: 0 0 16px; }}
.panel h2 {{ margin-top: 0; }}
label {{ display: block; font-weight: 600; margin: 12px 0 4px; }}
select, input[type=file] {{ width: 100%; max-width: 100%; font: inherit; padding: 8px; color: var(--text);
  background: var(--bg); border: 1px solid var(--line); }}
button {{ font: inherit; font-weight: 600; margin-top: 14px; padding: 9px 18px; cursor: pointer;
  color: var(--bg); background: var(--text); border: 0; }}
.verdict {{ font-size: 1.05rem; font-weight: 700; overflow-wrap: anywhere; }}
pre {{ overflow-x: auto; font-size: .78rem; max-height: 420px; }}
</style>
</head>
<body><main>
<h1>Signature Trust Tester</h1>
<p class="lead">"The signature verifies" and "this document can be trusted" are different questions.
This page shows what each validator says. It is not a legal or compliance verdict.</p>
{body}
</main></body>
</html>
""".encode()


def form_page(samples: dict[str, Sample]) -> bytes:
    options = "".join(
        f'<option value="{escape(s.case_id)}">{escape(s.case_id)}: {escape(s.title)}</option>'
        for s in samples.values()
    )
    return _page(f"""
<section class="panel"><h2>Try a synthetic sample</h2>
<form method="post" action="/sample">
<label for="case">Case</label><select id="case" name="case">{options}</select>
<button>Check sample</button>
</form></section>
<section class="panel"><h2>Check a PDF</h2>
<p class="muted">Use test files. The file stays on this computer, runs with no network, and is
deleted after the check. Revocation is therefore not reachable for it.</p>
<form method="post" action="/check" enctype="multipart/form-data">
<label for="pdf">PDF file</label><input id="pdf" type="file" name="pdf" accept=".pdf" required>
<label for="anchor">Trusted root certificate, PEM or DER (optional)</label>
<input id="anchor" type="file" name="anchor">
<p class="muted">Without one, only the kit's throw-away test root is trusted, so any other signer
is reported as untrusted.</p>
<button>Check file</button>
</form></section>""")


def result_page(title: str, network: str, rows: list[dict], expected: str | None = None) -> bytes:
    cards = []
    for row in rows:
        verdict = row["verdict"]
        signals = row.get("signals") or {}
        details = "".join(
            f"<li>{escape(key)}: <code>{escape(str(signals[key]))}</code></li>"
            for key in SHOWN_SIGNALS
            if signals.get(key)
        )
        if verdict == "TOOL_ERROR":
            details += f"<li>exit code: <code>{escape(str(row.get('exit_code')))}</code></li>"
        cards.append(f"""
<section class="panel"><h2>{escape(row["tool"])} {escape(str(row.get("tool_version") or ""))}</h2>
<p class="verdict {VERDICT_CLASSES.get(verdict, "INFO")}">{escape(verdict)}</p>
<p>{escape(VERDICT_MEANINGS.get(verdict, ""))}</p>
<ul>{details}</ul>
<details><summary>Raw output</summary><pre>{escape(row["raw_output"][:MAX_RAW_CHARS])}</pre></details>
</section>""")
    sha = rows[0]["fixture_sha256"] if rows else ""
    expected_line = f"<li>Expected verdict: {escape(expected)}</li>" if expected else ""
    return _page(f"""
<p><a href="/">Check another</a></p>
<h2>{escape(title)}</h2>
<ul class="run">{expected_line}<li>Network during the check: {escape(network)}</li>
<li>SHA-256: <code>{escape(sha)}</code></li></ul>
<p class="muted">The mapping is written for the versions pinned in CI. Other versions on this
computer can give other verdicts, so these results are not the kit's published results.</p>
{"".join(cards)}""")


def error_page(message: str) -> bytes:
    return _page(f'<p class="draft">{escape(message)}</p><p><a href="/">Back</a></p>')


class TesterHandler(BaseHTTPRequestHandler):
    samples: dict[str, Sample] = {}
    default_anchor: Path
    check: Callable[[Path, Path, Path, str], list[dict]] = staticmethod(check_in_sandbox)

    def log_message(self, format: str, *args) -> None:  # noqa: A002
        pass

    def _send(self, status: int, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'",
        )
        self.end_headers()
        self.wfile.write(body)

    def _expected_host(self) -> set[str]:
        port = self.server.server_address[1]
        return {f"{HOST}:{port}", f"localhost:{port}"}

    def _allowed(self) -> bool:
        """Blocks other sites from reaching this page through a browser."""
        if self.headers.get("Host") not in self._expected_host():
            return False
        origin = self.headers.get("Origin")
        return origin is None or origin.removeprefix("http://") in self._expected_host()

    def do_GET(self) -> None:  # noqa: N802
        if not self._allowed():
            self._send(403, error_page("This request did not come from this page."))
        elif self.path == "/":
            self._send(200, form_page(self.samples))
        else:
            self._send(404, error_page("Not found."))

    def do_POST(self) -> None:  # noqa: N802
        if not self._allowed():
            self._send(403, error_page("This request did not come from this page."))
            return
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            self._send(411, error_page("The request has no length."))
            return
        if length > MAX_BODY_BYTES:
            self.close_connection = True
            self._send(413, error_page("The limit is 25 MB."))
            return
        body = self.rfile.read(length)
        if self.path == "/sample":
            self._check_sample(body)
        elif self.path == "/check":
            self._check_upload(body)
        else:
            self._send(404, error_page("Not found."))

    def _run(self, pdf: Path, anchor: Path, work_dir: Path, profile: str) -> list[dict] | None:
        try:
            return self.check(pdf, anchor, work_dir, profile)
        except IsolationError as error:
            self._send(503, error_page(f"No check was run. {error}"))
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            self._send(500, error_page(f"The check failed: {type(error).__name__}"))
        return None

    def _check_sample(self, body: bytes) -> None:
        names = parse_qs(body.decode("ascii", "replace")).get("case", [""])
        sample = self.samples.get(names[0])
        if sample is None:
            self._send(400, error_page("Unknown case."))
            return
        with tempfile.TemporaryDirectory(prefix="trustkit-check-") as work:
            rows = self._run(sample.path, self.default_anchor, Path(work), LOOPBACK_ONLY)
        if rows is not None:
            self._send(
                200,
                result_page(
                    f"{sample.case_id}: {sample.title}", "loopback only", rows, sample.expected
                ),
            )

    def _check_upload(self, body: bytes) -> None:
        parts = parse_form(self.headers.get("Content-Type", ""), body)
        pdf = parts.get("pdf", b"")
        if b"%PDF-" not in pdf[:1024]:
            self._send(400, error_page("That file is not a PDF."))
            return
        with tempfile.TemporaryDirectory(prefix="trustkit-check-") as work:
            work_dir = Path(work)
            anchor = self.default_anchor
            if parts.get("anchor"):
                try:
                    pem = certificate_to_pem(parts["anchor"])
                except ValueError:
                    self._send(400, error_page("The root is not a PEM or DER certificate."))
                    return
                anchor = work_dir / "anchor.pem"
                anchor.write_bytes(pem)
            path = work_dir / "input.pdf"
            path.write_bytes(pdf)
            run_dir = work_dir / "run"
            run_dir.mkdir()
            rows = self._run(path, anchor, run_dir, NO_NETWORK)
        if rows is not None:
            self._send(200, result_page("Your file", "none", rows))


def load_samples(built: dict, cases: list, withheld: set[str]) -> dict[str, Sample]:
    return {
        case.id: Sample(case.id, case.title, case.expected, built[case.id].path)
        for case in cases
        if case.id not in withheld
    }


def _stop_on_terminate(signum, frame) -> None:
    raise KeyboardInterrupt


def serve(port: int = DEFAULT_PORT) -> int:
    # A terminated server must still delete its keys and samples.
    signal.signal(signal.SIGTERM, _stop_on_terminate)
    if not Path(SANDBOX).exists():
        print(f"{SANDBOX} was not found, and this page runs only on macOS for now", file=sys.stderr)
        return 2
    for tool in ("pdfsig", "certutil", "java"):
        if shutil.which(tool) is None:
            print(f"{tool} was not found", file=sys.stderr)
            return 2
    # Keys and samples live only here, outside the repository, and vanish with this block.
    with tempfile.TemporaryDirectory(prefix="trustkit-tester-") as root:
        base = Path(root)
        keys = base / "keys"
        keys.mkdir()
        test_pki = pki.generate(base / "certs", keys)
        built = fixtures.BUILDERS["M4"](base / "fixtures", test_pki)
        TesterHandler.samples = load_samples(built, cases_for("M4"), load_withheld())
        TesterHandler.default_anchor = test_pki.root.cert_path
        with services.RevocationService(test_pki), HTTPServer((HOST, port), TesterHandler) as server:
            print(f"http://{HOST}:{port}/  (Ctrl+C stops it and deletes the samples)", flush=True)
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                pass
    return 0


def main() -> None:
    pdf, trust_anchor, work_dir = (Path(value) for value in sys.argv[1:4])
    rows = run_validators(pdf, trust_anchor, work_dir)
    (work_dir / "result.json").write_text(json.dumps(rows), encoding="utf-8")


if __name__ == "__main__":
    main()
