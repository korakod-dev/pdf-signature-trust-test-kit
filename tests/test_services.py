"""The local revocation service, checked with `cryptography` and no validator."""

import urllib.request

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import ocsp

from trustkit import pki, services


def _ocsp_request(cert: x509.Certificate, issuer: x509.Certificate) -> bytes:
    builder = ocsp.OCSPRequestBuilder().add_certificate(cert, issuer, hashes.SHA1())
    return builder.build().public_bytes(serialization.Encoding.DER)


def test_service_listens_on_loopback_only(built):
    with services.RevocationService(built[0]) as service:
        assert service._server.server_address[0] == "127.0.0.1"


def test_crl_lists_the_revoked_leaf_with_the_fixed_date_and_no_other(built):
    test_pki = built[0]
    with services.RevocationService(test_pki) as service:
        with urllib.request.urlopen(f"{pki.SERVICE_URL}/crl") as response:
            crl = x509.load_der_x509_crl(response.read())
        assert service.take_requests() == ["GET /crl"]
    assert crl.is_signature_valid(test_pki.root.cert.public_key())
    entry = crl.get_revoked_certificate_by_serial_number(test_pki.revoked_leaf.cert.serial_number)
    assert entry is not None and entry.revocation_date_utc == pki.REVOKED_AT
    assert crl.get_revoked_certificate_by_serial_number(test_pki.leaf.cert.serial_number) is None
    assert crl.get_revoked_certificate_by_serial_number(test_pki.tsa.cert.serial_number) is None


def test_ocsp_reports_the_revoked_leaf_as_revoked(built):
    test_pki = built[0]
    request = urllib.request.Request(
        f"{pki.SERVICE_URL}/ocsp",
        data=_ocsp_request(test_pki.revoked_leaf.cert, test_pki.root.cert),
        method="POST",
    )
    with services.RevocationService(test_pki):
        with urllib.request.urlopen(request) as response:
            answer = ocsp.load_der_ocsp_response(response.read())
    assert answer.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL
    assert answer.certificate_status == ocsp.OCSPCertStatus.REVOKED
    assert answer.revocation_time_utc == pki.REVOKED_AT


def test_take_requests_clears_the_log(built):
    with services.RevocationService(built[0]) as service:
        with urllib.request.urlopen(f"{pki.SERVICE_URL}/crl"):
            pass
        assert service.take_requests() == ["GET /crl"]
        assert service.take_requests() == []
