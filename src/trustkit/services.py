"""Local CRL and OCSP service for revocation cases. Listens on loopback only.

The TSA is not here. Fixtures take their timestamps from a timestamper in the same
process, so no timestamp request reaches any network. See docs/decisions.md.
"""

import datetime as dt
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import ocsp

from trustkit import pki
from trustkit.pki import TestPki


def build_crl(test_pki: TestPki, now: dt.datetime) -> bytes:
    """A current CRL from the test root that lists the revoked leaf."""
    key = serialization.load_pem_private_key(test_pki.root.key_path.read_bytes(), password=None)
    revoked = (
        x509.RevokedCertificateBuilder()
        .serial_number(test_pki.revoked_leaf.cert.serial_number)
        .revocation_date(pki.REVOKED_AT)
        .build()
    )
    return (
        x509.CertificateRevocationListBuilder()
        .issuer_name(test_pki.root.cert.subject)
        .last_update(now - dt.timedelta(minutes=5))
        .next_update(now + dt.timedelta(days=1))
        .add_revoked_certificate(revoked)
        .sign(key, hashes.SHA256())
        .public_bytes(serialization.Encoding.DER)
    )


def build_ocsp_response(test_pki: TestPki, request_der: bytes, now: dt.datetime) -> bytes:
    """Answer for the revoked leaf, signed directly by the test root."""
    request = ocsp.load_der_ocsp_request(request_der)
    if request.serial_number != test_pki.revoked_leaf.cert.serial_number:
        return ocsp.OCSPResponseBuilder.build_unsuccessful(
            ocsp.OCSPResponseStatus.UNAUTHORIZED
        ).public_bytes(serialization.Encoding.DER)
    key = serialization.load_pem_private_key(test_pki.root.key_path.read_bytes(), password=None)
    return (
        ocsp.OCSPResponseBuilder()
        .add_response(
            cert=test_pki.revoked_leaf.cert,
            issuer=test_pki.root.cert,
            algorithm=hashes.SHA1(),
            cert_status=ocsp.OCSPCertStatus.REVOKED,
            this_update=now - dt.timedelta(minutes=5),
            next_update=now + dt.timedelta(days=1),
            revocation_time=pki.REVOKED_AT,
            revocation_reason=None,
        )
        .responder_id(ocsp.OCSPResponderEncoding.HASH, test_pki.root.cert)
        .sign(key, hashes.SHA256())
        .public_bytes(serialization.Encoding.DER)
    )


class RevocationService:
    """Serves /crl and /ocsp, and records the path of every request."""

    def __init__(self, test_pki: TestPki):
        self._pki = test_pki
        self._requests: list[str] = []
        address = urlparse(pki.SERVICE_URL)
        self._server = ThreadingHTTPServer((address.hostname, address.port), self._handler())

    def _handler(self):
        service = self

        class Handler(BaseHTTPRequestHandler):
            def _respond(self, body: bytes, content_type: str) -> None:
                self.send_response(200)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self) -> None:
                service._requests.append(f"GET {self.path}")
                if self.path != "/crl":
                    self.send_error(404)
                    return
                now = dt.datetime.now(dt.timezone.utc)
                self._respond(build_crl(service._pki, now), "application/pkix-crl")

            def do_POST(self) -> None:
                service._requests.append(f"POST {self.path}")
                if self.path != "/ocsp":
                    self.send_error(404)
                    return
                body = self.rfile.read(int(self.headers["Content-Length"]))
                now = dt.datetime.now(dt.timezone.utc)
                response = build_ocsp_response(service._pki, body, now)
                self._respond(response, "application/ocsp-response")

            def log_message(self, *args) -> None:
                pass

        return Handler

    def take_requests(self) -> list[str]:
        """Return and clear the requests seen since the last call."""
        taken, self._requests = self._requests, []
        return taken

    def __enter__(self) -> "RevocationService":
        threading.Thread(target=self._server.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *exc_info) -> None:
        self._server.shutdown()
        self._server.server_close()
