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


def _identities(test_pki: pki.TestPki) -> tuple[pki.Identity, ...]:
    return (
        test_pki.root,
        test_pki.leaf,
        test_pki.other_root,
        test_pki.other_leaf,
        test_pki.second_leaf,
        test_pki.expired_leaf,
    )


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
    for identity in _identities(test_pki):
        subject = identity.cert.subject.rfc4514_string()
        assert "TEST ONLY" in subject and "Example Test Org" in subject


def test_certificates_contain_no_urls(built):
    test_pki, _, _ = built
    for identity in _identities(test_pki):
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


def _assert_later_update(built, case_id: str) -> tuple[bytes, bytes]:
    """The signed revision is unchanged, and later bytes exist. Returns both parts."""
    fixture = built[1][case_id]
    data = fixture.path.read_bytes()
    revision = fixture.signed_revision
    assert revision is not None and data.startswith(revision) and len(data) > len(revision)
    first = inspect.signed_regions(revision)[0]
    assert first.start2 + first.length2 == len(revision)
    assert inspect.digest_matches(revision)
    return revision, data[len(revision) :]


def test_leaves_declare_no_revocation_data_and_the_root_does_not(built):
    test_pki, _, _ = built
    for identity in (
        test_pki.leaf,
        test_pki.other_leaf,
        test_pki.second_leaf,
        test_pki.expired_leaf,
    ):
        extension = identity.cert.extensions.get_extension_for_oid(pki.NO_REV_AVAIL)
        assert extension.value.value == pki.ASN1_NULL and not extension.critical
    assert pki.NO_REV_AVAIL not in [e.oid for e in test_pki.root.cert.extensions]


def test_n1_has_no_signature(built):
    data = _read(built, "N1")
    assert inspect.signed_regions(data) == []
    assert b"/Sig" not in data


def test_b2_certificate_ended_by_2021_and_chains_to_the_anchor(built):
    test_pki, built_fixtures, _ = built
    cert = test_pki.expired_leaf.cert
    assert cert.not_valid_after_utc.year < 2021
    cert.verify_directly_issued_by(test_pki.root.cert)
    assert built_fixtures["B2"].trust_anchor is test_pki.root
    data = _read(built, "B2")
    assert inspect.digest_matches(data)
    inspect.verify_signed_attributes(data, cert)


def test_b2_has_no_timestamp(built):
    assert b"/DocTimeStamp" not in _read(built, "B2")


def test_c1_appends_a_second_signature_covering_the_whole_file(built):
    revision, later = _assert_later_update(built, "C1")
    data = revision + later
    regions = inspect.signed_regions(data)
    assert len(regions) == 2
    assert regions[1].start2 + regions[1].length2 == len(data)
    assert b"/Signature2" in later or b"(Signature2)" in later


def test_c1_second_signer_chains_to_the_anchor(built):
    test_pki, _, _ = built
    test_pki.second_leaf.cert.verify_directly_issued_by(test_pki.root.cert)
    assert test_pki.second_leaf.cert.subject != test_pki.leaf.cert.subject


def test_c2_certifies_at_level_2_and_only_later_bytes_hold_the_value(built):
    revision, later = _assert_later_update(built, "C2")
    assert re.search(rb"/P\s+2\b", revision)
    assert b"/DocMDP" in revision
    assert fixtures.FORM_FIELD_VALUE.encode() not in revision
    assert fixtures.FORM_FIELD_VALUE.encode() in later


def test_c3_certifies_at_level_1_and_later_bytes_add_an_annotation(built):
    revision, later = _assert_later_update(built, "C3")
    assert re.search(rb"/P\s+1\b", revision)
    assert b"/DocMDP" in revision
    assert b"/Subtype /Text" in later


def test_c4_has_no_docmdp_and_later_bytes_change_the_amount(built):
    revision, later = _assert_later_update(built, "C4")
    assert b"/DocMDP" not in revision + later
    assert fixtures.AMOUNT_TEXT in revision
    assert fixtures.CHANGED_AMOUNT_TEXT not in revision
    assert fixtures.CHANGED_AMOUNT_TEXT in later


def test_c5_changed_amount_is_already_signed_and_later_bytes_add_no_page_content(built):
    revision, later = _assert_later_update(built, "C5")
    assert fixtures.AMOUNT_TEXT in revision
    assert fixtures.CHANGED_AMOUNT_TEXT in revision
    assert revision.index(fixtures.CHANGED_AMOUNT_TEXT) < revision.index(fixtures.AMOUNT_TEXT)
    assert b"1 1 1 rg" in revision
    assert b"/DocMDP" not in revision + later
    assert fixtures.CHANGED_AMOUNT_TEXT not in later
    assert b"BT " not in later


def test_c5_new_page_lists_one_content_stream_and_the_signed_page_lists_two(built):
    revision, later = _assert_later_update(built, "C5")
    assert re.search(rb"/Contents\s*\[\s*\d+ 0 R\s+\d+ 0 R\s*\]", revision)
    assert re.search(rb"/Contents\s+\d+ 0 R", later)


def test_every_active_case_has_a_fixture(built):
    from trustkit.oracle import cases_for

    assert {c.id for c in cases_for("M2")} == set(built[1])


def test_every_active_case_has_rationale_and_basis():
    from trustkit.oracle import cases_for

    for case in cases_for("M2"):
        assert case.rationale.strip() and case.basis in ("crypto", "spec", "policy")
