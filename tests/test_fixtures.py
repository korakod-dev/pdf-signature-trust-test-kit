"""Fixture properties, asserted without calling any validator."""

import re

import pytest
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes

from trustkit import fixtures, pki, scan
from trustkit.adapters.pdfsig_adapter import build_nss_database, list_nss_database
from trustkit.fixtures import inspect
from trustkit.oracle import ROOT


def _read(built, case_id: str) -> bytes:
    return built[1][case_id].path.read_bytes()


def _subjects(certs: list[x509.Certificate]) -> set[str]:
    return {c.subject.rfc4514_string() for c in certs}


def test_page_content_is_uncompressed_inside_a_stream():
    base = fixtures.base_pdf()
    position = base.index(fixtures.AMOUNT_TEXT)
    assert base.count(fixtures.AMOUNT_TEXT) == 1
    assert base.rfind(b"stream", 0, position) > base.rfind(b"endstream", 0, position)


def test_a1_signature_covers_the_whole_file(built):
    data = _read(built, "A1")
    region = inspect.signed_region(data)
    assert region.start1 == 0
    assert region.start2 + region.length2 == len(data)
    assert data[region.start1 + region.length1] == ord("<")
    assert data[region.start2 - 1] == ord(">")


def test_a1_is_cryptographically_valid_by_independent_computation(built):
    test_pki, _, _ = built
    data = _read(built, "A1")
    assert inspect.digest_matches(data)
    inspect.verify_signed_attributes(data, test_pki.leaf.cert)
    test_pki.leaf.cert.verify_directly_issued_by(test_pki.root.cert)


def test_a2_differs_from_a1_by_exactly_one_byte_inside_the_signed_range(built):
    a1, a2 = _read(built, "A1"), _read(built, "A2")
    assert len(a1) == len(a2)
    differing = [i for i in range(len(a1)) if a1[i] != a2[i]]
    assert len(differing) == 1
    assert inspect.signed_region(a2).covers(differing[0])
    assert a2[differing[0] - len(b"Amount: ") : differing[0]] == b"Amount: "


def test_a2_keeps_xref_offsets(built):
    pattern = re.compile(rb"startxref\s+(\d+)")
    assert pattern.findall(_read(built, "A1")) == pattern.findall(_read(built, "A2"))


def test_a2_digest_no_longer_matches_by_independent_computation(built):
    assert not inspect.digest_matches(_read(built, "A2"))


def test_b1_second_root_is_not_the_trust_anchor(built):
    test_pki, built_fixtures, _ = built
    assert built_fixtures["B1"].trust_anchor is test_pki.root
    assert test_pki.other_root.cert.fingerprint(hashes.SHA256()) != test_pki.root.cert.fingerprint(
        hashes.SHA256()
    )
    with pytest.raises((ValueError, InvalidSignature)):
        test_pki.other_leaf.cert.verify_directly_issued_by(test_pki.root.cert)


def test_b1_signature_itself_is_good_under_its_own_root(built):
    test_pki, _, _ = built
    data = _read(built, "B1")
    assert inspect.digest_matches(data)
    inspect.verify_signed_attributes(data, test_pki.other_leaf.cert)
    test_pki.other_leaf.cert.verify_directly_issued_by(test_pki.other_root.cert)


def test_b1_embeds_its_untrusted_root(built):
    test_pki, _, _ = built
    subjects = _subjects(inspect.embedded_certificates(_read(built, "B1")))
    assert test_pki.other_root.cert.subject.rfc4514_string() in subjects


def test_nss_database_holds_only_the_trust_anchor(built, tmp_path):
    test_pki, _, _ = built
    build_nss_database(tmp_path / "nss", test_pki.root.cert_path)
    assert list_nss_database(tmp_path / "nss") == ["trust-anchor"]


def test_names_are_obviously_fake(built):
    test_pki, _, _ = built
    for identity in (test_pki.root, test_pki.leaf, test_pki.other_root, test_pki.other_leaf):
        subject = identity.cert.subject.rfc4514_string()
        assert "TEST ONLY" in subject and "Example Test Org" in subject


def test_certificates_contain_no_urls(built):
    test_pki, _, _ = built
    for identity in (test_pki.root, test_pki.leaf, test_pki.other_root, test_pki.other_leaf):
        for extension in identity.cert.extensions:
            assert not isinstance(
                extension.value,
                (x509.AuthorityInformationAccess, x509.CRLDistributionPoints),
            )


def test_validity_windows_are_the_documented_dates(built):
    test_pki, _, _ = built
    assert test_pki.leaf.cert.not_valid_after_utc.year == 2046
    assert test_pki.leaf.cert.not_valid_before_utc.year == 2020


def test_key_directory_inside_the_repository_is_refused(tmp_path):
    with pytest.raises(ValueError):
        pki.generate(tmp_path / "certs", ROOT / "should-not-exist")
    assert not (ROOT / "should-not-exist").exists()


def test_fixture_and_certificate_output_holds_no_key_material(built):
    _, _, base = built
    assert scan.scan_directory(base / "fixtures") == []
    assert scan.scan_directory(base / "certs") == []

