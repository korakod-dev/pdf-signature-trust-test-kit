"""Fixture properties, asserted without calling any validator."""

import re

import pytest
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes

from trustkit import fixtures, gates, pki, scan
from trustkit.adapters.pdfsig_adapter import build_nss_database, list_nss_database
from trustkit.fixtures import inspect, pdfa
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
        test_pki.past_leaf,
        test_pki.revoked_leaf,
        test_pki.unreachable_leaf,
        test_pki.tsa,
        test_pki.other_tsa,
    )


def _urls(cert: x509.Certificate) -> list[str]:
    found = []
    for extension in cert.extensions:
        if isinstance(extension.value, x509.CRLDistributionPoints):
            found += [n.value for p in extension.value for n in p.full_name]
        if isinstance(extension.value, x509.AuthorityInformationAccess):
            found += [d.access_location.value for d in extension.value]
    return found


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


def test_every_certificate_url_is_on_loopback(built):
    test_pki, _, _ = built
    for identity in _identities(test_pki):
        for url in _urls(identity.cert):
            assert url.startswith("http://127.0.0.1:"), url


def test_only_the_certificates_that_need_a_revocation_url_have_one(built):
    test_pki, _, _ = built
    with_urls = {
        i.cert.subject.rfc4514_string() for i in _identities(test_pki) if _urls(i.cert)
    }
    assert with_urls == {
        i.cert.subject.rfc4514_string()
        for i in (
            test_pki.past_leaf,
            test_pki.revoked_leaf,
            test_pki.unreachable_leaf,
            test_pki.tsa,
            test_pki.other_tsa,
        )
    }


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
    for identity in (
        test_pki.root,
        test_pki.past_leaf,
        test_pki.revoked_leaf,
        test_pki.unreachable_leaf,
    ):
        assert pki.NO_REV_AVAIL not in [e.oid for e in identity.cert.extensions]


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

    assert {c.id for c in cases_for("M4")} == set(built[1])


def test_every_active_case_has_rationale_and_basis():
    from trustkit.oracle import cases_for

    for case in cases_for("M4"):
        assert case.rationale.strip() and case.basis in ("crypto", "spec", "policy")


def test_a3_gap_is_wider_than_contents_and_the_signed_bytes_are_untouched(built):
    a1 = _read(built, "A3")
    region = inspect.signed_region(a1)
    extra = inspect.bytes_after_contents(a1)
    assert fixtures.UNSIGNED_MARKER in extra
    assert not region.covers(a1.index(fixtures.UNSIGNED_MARKER))
    assert region.start1 == 0 and region.start2 + region.length2 == len(a1)
    assert inspect.digest_matches(a1)


def test_a3_signature_still_verifies_by_independent_computation(built):
    test_pki, _, _ = built
    inspect.verify_signed_attributes(_read(built, "A3"), test_pki.leaf.cert)


def test_b3_leaf_is_expired_and_the_timestamp_is_inside_its_window(built):
    test_pki, built_fixtures, _ = built
    cert = test_pki.past_leaf.cert
    assert cert.not_valid_after_utc.year < 2021
    timestamp = inspect.signature_timestamp(built_fixtures["B3"].signed_revision)
    assert timestamp is not None
    assert cert.not_valid_before_utc < timestamp[0] < cert.not_valid_after_utc


def test_b3_later_bytes_embed_revocation_data_for_the_window(built):
    test_pki, built_fixtures, _ = built
    revision, later = _assert_later_update(built, "B3")
    assert b"/DSS" in later and b"/CRLs" in later
    crl = x509.load_der_x509_crl(fixtures.past_crl(test_pki.root))
    cert = test_pki.past_leaf.cert
    assert cert.not_valid_before_utc < crl.last_update_utc < cert.not_valid_after_utc
    assert crl.get_revoked_certificate_by_serial_number(cert.serial_number) is None


def test_b4_is_signed_and_timestamped_after_the_revocation_date(built):
    test_pki, _, _ = built
    data = _read(built, "B4")
    timestamp = inspect.signature_timestamp(data)
    assert timestamp is not None and timestamp[0] > pki.REVOKED_AT
    inspect.verify_signed_attributes(data, test_pki.revoked_leaf.cert)


def test_b5_urls_are_the_closed_port_only(built):
    test_pki, _, _ = built
    urls = _urls(test_pki.unreachable_leaf.cert)
    assert urls and all(u.startswith(pki.CLOSED_URL) for u in urls)
    assert pki.CLOSED_URL != pki.SERVICE_URL


def test_d1_page_names_someone_other_than_the_certificate_subject(built):
    test_pki, _, _ = built
    data = _read(built, "D1")
    assert fixtures.OTHER_NAME_TEXT.encode() in data
    assert "Other Person" not in test_pki.leaf.cert.subject.rfc4514_string()
    assert b"Other Person" not in test_pki.leaf.cert.subject.public_bytes()


def test_e1_timestamp_chains_to_the_trust_anchor(built):
    test_pki, _, _ = built
    timestamp = inspect.signature_timestamp(_read(built, "E1"))
    assert timestamp is not None
    assert test_pki.tsa.cert in timestamp[1]
    test_pki.tsa.cert.verify_directly_issued_by(test_pki.root.cert)


def test_e2_timestamp_does_not_chain_to_the_trust_anchor(built):
    test_pki, built_fixtures, _ = built
    timestamp = inspect.signature_timestamp(_read(built, "E2"))
    assert timestamp is not None
    assert test_pki.other_tsa.cert in timestamp[1]
    assert built_fixtures["E2"].trust_anchor is test_pki.root
    with pytest.raises((ValueError, InvalidSignature)):
        test_pki.other_tsa.cert.verify_directly_issued_by(test_pki.root.cert)


def test_tsa_certificates_are_for_timestamping_only(built):
    test_pki, _, _ = built
    for identity in (test_pki.tsa, test_pki.other_tsa):
        extension = identity.cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        assert extension.critical
        assert list(extension.value) == [x509.oid.ExtendedKeyUsageOID.TIME_STAMPING]


def test_f1_signature_covers_the_attachment_and_the_whole_file(built):
    data = _read(built, "F1")
    region = inspect.signed_region(data)
    position = data.index(pdfa.synthetic_xml(pdfa.PAGE_AMOUNT))
    assert region.covers(position)
    assert region.start1 == 0 and region.start2 + region.length2 == len(data)
    assert inspect.digest_matches(data)


def test_f1_declares_pdfa_3b_with_an_embedded_font_and_an_output_intent(built):
    data = _read(built, "F1")
    assert data.startswith(b"%PDF-1.7")
    assert b"<pdfaid:part>3</pdfaid:part>" in data
    assert b"<pdfaid:conformance>B</pdfaid:conformance>" in data
    assert b"/FontFile2" in data and b"/GTS_PDFA1" in data and b"/AFRelationship /Data" in data


def test_f1_unsigned_file_is_the_start_of_the_signed_file(built):
    _, _, base = built
    unsigned = (base / "fixtures" / "unsigned" / "F1.pdf").read_bytes()
    assert _read(built, "F1").startswith(unsigned)


def test_f2_replaces_only_the_attachment_after_signing(built):
    revision, later = _assert_later_update(built, "F2")
    assert pdfa.synthetic_xml(pdfa.PAGE_AMOUNT) in revision
    assert pdfa.synthetic_xml(pdfa.OTHER_AMOUNT) not in revision
    assert pdfa.synthetic_xml(pdfa.OTHER_AMOUNT) in later
    assert b"/Type /Page" not in later and b"BT " not in later
    assert b"/DocMDP" not in revision + later


def test_f3_xml_disagrees_with_the_page_before_signing_and_nothing_follows(built):
    data = _read(built, "F3")
    region = inspect.signed_region(data)
    assert pdfa.PAGE_AMOUNT != pdfa.OTHER_AMOUNT
    assert region.covers(data.index(pdfa.synthetic_xml(pdfa.OTHER_AMOUNT)))
    assert pdfa.synthetic_xml(pdfa.PAGE_AMOUNT) not in data
    assert region.start2 + region.length2 == len(data)


def test_attachment_data_is_obviously_synthetic():
    xml = pdfa.synthetic_xml(pdfa.PAGE_AMOUNT)
    assert b"TEST ONLY" in xml and b"Example Test Org" in xml and b"example.test" in xml


def test_every_pdfa_check_file_exists(built):
    _, _, base = built
    for relative in fixtures.PDFA_CHECKS.values():
        assert (base / "fixtures" / relative).exists()
    assert tuple(fixtures.PDFA_CHECKS) == gates.PDFA_CHECK_NAMES
