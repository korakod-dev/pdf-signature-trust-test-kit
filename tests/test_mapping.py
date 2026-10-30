"""Mapping tests from captured output of an unrelated throw-away PDF.

Those outputs are in tests/data/raw_outputs. Lines marked synthetic have not been
seen from the installed tool version, so they only test the parser.
"""

import pytest

from trustkit.adapters.dss_adapter import parse_reports
from trustkit.adapters.pdfsig_adapter import parse_report
from trustkit.adapters.pyhanko_adapter import map_signals

from .conftest import RAW_OUTPUTS, load_capture

PDFSIG = RAW_OUTPUTS / "pdfsig"


def _pdfsig(name: str) -> tuple[str, int]:
    stdout = (PDFSIG / f"{name}.stdout").read_text()
    return stdout, int((PDFSIG / f"{name}.exit").read_text())


@pytest.mark.parametrize(
    "name, verdict, unmapped",
    [
        ("valid_trusted_total", "VALID", False),
        ("valid_trusted_not_total", "VALID_WITH_UNCLASSIFIED_CHANGES", False),
        ("digest_mismatch", "INVALID", False),
        ("issuer_not_trusted", "INDETERMINATE", False),
        ("issuer_unknown", "INDETERMINATE", False),
        ("no_signatures", "NO_SIGNATURE", False),
        ("unreadable_file", "TOOL_ERROR", False),
        ("no_ocsp_generic_cert_error", "TOOL_ERROR", True),
        ("certificate_expired", "INDETERMINATE", False),
        ("second_signature", "VALID_WITH_UNCLASSIFIED_CHANGES", False),
    ],
)
def test_pdfsig_captures(mapping, name, verdict, unmapped):
    stdout, exit_code = _pdfsig(name)
    got, got_unmapped, _, _ = parse_report(stdout, exit_code, mapping)
    assert (got, got_unmapped) == (verdict, unmapped)


def test_pdfsig_captures_are_all_exercised():
    parametrized = {
        "valid_trusted_total",
        "valid_trusted_not_total",
        "digest_mismatch",
        "issuer_not_trusted",
        "issuer_unknown",
        "no_signatures",
        "unreadable_file",
        "no_ocsp_generic_cert_error",
        "certificate_expired",
        "second_signature",
    }
    assert {p.stem for p in PDFSIG.glob("*.stdout")} == parametrized


@pytest.mark.parametrize(
    "line, verdict",
    [
        ("Signature Validation: Signature is Invalid.", "INVALID"),
        ("Certificate Validation: Certificate has been Revoked.", "INVALID"),
    ],
)
def test_pdfsig_synthetic_lines_not_yet_observed(mapping, line, verdict):
    stdout, _ = _pdfsig("valid_trusted_total")
    kind = line.split(":")[0]
    rewritten = "\n".join(
        f"  - {line}" if existing.startswith(f"  - {kind}:") else existing
        for existing in stdout.splitlines()
    )
    assert parse_report(rewritten, 0, mapping)[:2] == (verdict, False)


def test_pdfsig_certificate_problem_wins_over_coverage(mapping):
    stdout, _ = _pdfsig("issuer_not_trusted")
    rewritten = stdout.replace("Total document signed", "Not total document signed")
    assert parse_report(rewritten, 0, mapping)[0] == "INDETERMINATE"


@pytest.mark.parametrize(
    "mutation",
    [
        lambda s: s.replace("Signature is Valid.", "Signature is Probably Fine."),
        lambda s: s.replace("Certificate is Trusted.", "Certificate is Great."),
        lambda s: s.replace("Total document signed", "Most of document signed"),
        lambda s: s + "  - A New Line In A Future Version: yes\n",
    ],
)
def test_pdfsig_unknown_strings_never_default_to_a_verdict(mapping, mutation):
    stdout, _ = _pdfsig("valid_trusted_total")
    verdict, unmapped, rule, _ = parse_report(mutation(stdout), 0, mapping)
    assert (verdict, unmapped, rule) == ("TOOL_ERROR", True, None)


def test_pdfsig_unknown_exit_code_is_unmapped(mapping):
    assert parse_report("", 99, mapping)[:2] == ("TOOL_ERROR", True)


def test_pdfsig_exit_zero_with_no_report_is_unmapped(mapping):
    assert parse_report("", 0, mapping)[:2] == ("TOOL_ERROR", True)


def test_pdfsig_judges_the_first_signature(mapping):
    stdout, _ = _pdfsig("valid_trusted_total")
    second, _ = _pdfsig("digest_mismatch")
    combined = stdout + "\n".join(second.splitlines()[1:]).replace("Signature #1", "Signature #2")
    verdict, _, _, signals = parse_report(combined, 0, mapping)
    assert verdict == "VALID"
    assert signals["signature_count"] == 2


def test_pdfsig_signals_record_the_signer_subject(mapping):
    stdout, _ = _pdfsig("valid_trusted_total")
    signals = parse_report(stdout, 0, mapping)[3]
    assert signals["signer_subject_shown"] is True
    assert "SAMPLE Leaf" in signals["signer_subject"]


@pytest.mark.parametrize(
    "name, verdict, rule",
    [
        ("valid_whole_file", "VALID", "valid-whole-file-or-lta"),
        ("one_byte_changed", "INVALID", "invalid-any-failure"),
        ("unknown_root", "INDETERMINATE", "indeterminate-trust"),
    ],
)
def test_pyhanko_captures(mapping, name, verdict, rule):
    assert map_signals(load_capture("pyhanko", name), mapping) == (verdict, rule)


def test_pyhanko_trailing_bytes_stay_unmapped(mapping):
    # EXTENDED_WITH_NONE: the brief does not map it, so it must not become VALID.
    assert map_signals(load_capture("pyhanko", "trailing_bytes"), mapping) == ("TOOL_ERROR", None)


@pytest.mark.parametrize(
    "change, verdict",
    [
        ({"valid": False}, "INVALID"),
        ({"revoked": True}, "INVALID"),
        ({"docmdp_ok": False}, "INVALID"),
        ({"modification_level": "OTHER"}, "INVALID"),
        ({"coverage_summary": "NONSTANDARD_COVERAGE"}, "INVALID"),
        ({"timestamp_trusted": False}, "INDETERMINATE"),
        (
            {
                "coverage": "ENTIRE_REVISION",
                "coverage_summary": "EXTENDED_WITH_LTA_UPDATES",
                "modification_level": "LTA_UPDATES",
            },
            "VALID",
        ),
        (
            {
                "coverage": "ENTIRE_REVISION",
                "coverage_summary": "EXTENDED_WITH_FORM_FILLING",
                "modification_level": "FORM_FILLING",
            },
            "VALID_WITH_ALLOWED_CHANGES",
        ),
        (
            {
                "coverage": "ENTIRE_REVISION",
                "coverage_summary": "EXTENDED_WITH_ANNOTATIONS",
                "modification_level": "ANNOTATIONS",
            },
            "TOOL_ERROR",
        ),
    ],
)
def test_pyhanko_rules_on_modified_captures(mapping, change, verdict):
    signals = {**load_capture("pyhanko", "valid_whole_file"), **change}
    assert map_signals(signals, mapping)[0] == verdict


DSS = RAW_OUTPUTS / "dss"


def _dss(name: str) -> tuple[str, str]:
    return (DSS / name / "simple.xml").read_text(), (DSS / name / "diagnostic.xml").read_text()


DSS_CAPTURES = [
    ("valid_whole_file", "VALID", None, []),
    ("one_byte_changed", "INVALID", "HASH_FAILURE", []),
    ("unknown_root", "INDETERMINATE", "NO_CERTIFICATE_CHAIN_FOUND", []),
    ("expired_no_timestamp", "INDETERMINATE", "OUT_OF_BOUNDS_NOT_REVOKED", []),
    ("second_signature", "VALID_WITH_ALLOWED_CHANGES", None, ["SignatureOrFormFill"]),
    (
        "docmdp2_form_fill",
        "VALID_WITH_UNCLASSIFIED_CHANGES",
        None,
        ["SignatureOrFormFill", "VisualDifference"],
    ),
    ("docmdp1_annotation", "VALID_WITH_UNCLASSIFIED_CHANGES", None, ["AnnotationChange"]),
    ("content_replaced", "VALID_WITH_UNCLASSIFIED_CHANGES", None, ["Undefined", "VisualDifference"]),
    ("overlay_removed", "VALID_WITH_UNCLASSIFIED_CHANGES", None, ["Undefined", "VisualDifference"]),
]


@pytest.mark.parametrize("name, verdict, sub_indication, modifications", DSS_CAPTURES)
def test_dss_captures(mapping, name, verdict, sub_indication, modifications):
    got, unmapped, _, signals = parse_reports(*_dss(name), mapping)
    assert (got, unmapped) == (verdict, False)
    assert signals["sub_indication"] == sub_indication
    assert signals["modifications"] == modifications


def test_dss_captures_are_all_exercised():
    parametrized = {capture[0] for capture in DSS_CAPTURES} | {"no_signatures"}
    assert {p.name for p in DSS.iterdir() if p.is_dir()} == parametrized


def test_dss_no_signatures(mapping):
    assert parse_reports(*_dss("no_signatures"), mapping)[:2] == ("NO_SIGNATURE", False)


def test_dss_judges_the_first_signature(mapping):
    signals = parse_reports(*_dss("second_signature"), mapping)[3]
    assert signals["signature_count"] == 2
    assert signals["signer_subject"] == "TEST ONLY Signer - Not For Production"


def test_dss_a_good_chain_without_no_rev_avail_would_be_indeterminate(mapping):
    # Rewritten from a capture. See "Certificates declare that no revocation data exists".
    simple, diagnostic = _dss("valid_whole_file")
    simple = simple.replace(
        "<Indication>TOTAL_PASSED</Indication>",
        "<Indication>INDETERMINATE</Indication>"
        "<SubIndication>CERTIFICATE_CHAIN_GENERAL_FAILURE</SubIndication>",
    )
    verdict, unmapped, _, signals = parse_reports(simple, diagnostic, mapping)
    assert (verdict, unmapped) == ("INDETERMINATE", False)
    assert signals["sub_indication"] == "CERTIFICATE_CHAIN_GENERAL_FAILURE"


@pytest.mark.parametrize(
    "name, old, new",
    [
        ("valid_whole_file", "<Indication>TOTAL_PASSED<", "<Indication>TOTAL-PASSED<"),
        ("valid_whole_file", "BBB_XCV_AIA_PRES_ANS", "BBB_SOMETHING_NEW"),
        ("second_signature", "<SignatureOrFormFill ", "<SomethingNew "),
    ],
)
def test_dss_unknown_output_never_defaults_to_a_verdict(mapping, name, old, new):
    simple, diagnostic = _dss(name)
    assert old in simple or old in diagnostic
    closing = old.replace("<", "</").strip()
    simple, diagnostic = simple.replace(old, new), diagnostic.replace(old, new)
    if "SomethingNew" in new:
        diagnostic = diagnostic.replace(closing + ">", new.replace("<", "</").strip() + ">")
    verdict, unmapped, rule, _ = parse_reports(simple, diagnostic, mapping)
    assert (verdict, unmapped, rule) == ("TOOL_ERROR", True, None)


def test_dss_annotation_only_is_not_reported_as_allowed(mapping):
    assert parse_reports(*_dss("docmdp1_annotation"), mapping)[2] == "passed-other-modifications"
