"""Proves that the gates actually fail when they should."""

import json
import subprocess

from trustkit import cli, gates, scan
from trustkit.adapters.pdfsig_adapter import parse_report
from trustkit.oracle import load_findings

from .conftest import RAW_OUTPUTS


def _gate(failures: list[str], number: int) -> list[str]:
    return [f for f in failures if f.startswith(f"gate {number}:")]


def test_clean_results_pass_all_gates(clean_results):
    baseline = gates.baseline_from_results(clean_results)
    assert gates.check_all(clean_results, baseline) == []


def test_disagreeing_with_the_oracle_alone_does_not_fail_a_gate(clean_results):
    clean_results["observations"][0].update(verdict="VALID_WITH_ALLOWED_CHANGES", score="PARTIAL")
    baseline = gates.baseline_from_results(clean_results)
    assert gates.check_all(clean_results, baseline) == []


def test_gate4_fails_on_a_tampered_baseline(clean_results):
    baseline = gates.baseline_from_results(clean_results)
    baseline["results"]["A2"]["pdfsig"]["verdict"] = "VALID"
    baseline["results"]["A2"]["pdfsig"]["score"] = "MISSED"
    failures = _gate(gates.check_all(clean_results, baseline), 4)
    assert len(failures) == 1 and "A2/pdfsig" in failures[0]


def test_gate4_fails_when_results_get_better_too(clean_results, tamper):
    worse = tamper(clean_results)
    worse["observations"][2].update(verdict="VALID", score="MISSED")
    baseline = gates.baseline_from_results(worse)
    assert _gate(gates.check_all(clean_results, baseline), 4)


def test_gate4_fails_on_a_score_change_with_the_same_verdict(clean_results):
    baseline = gates.baseline_from_results(clean_results)
    baseline["results"]["A1"]["pyhanko"]["score"] = "PARTIAL"
    assert _gate(gates.check_all(clean_results, baseline), 4)


def test_gate4_fails_when_a_row_exists_on_one_side_only(clean_results):
    baseline = gates.baseline_from_results(clean_results)
    baseline["results"]["Z9"] = {"pdfsig": {"verdict": "VALID", "score": "AGREE"}}
    assert _gate(gates.check_all(clean_results, baseline), 4)


def test_gate4_fails_with_no_baseline(clean_results):
    assert _gate(gates.check_all(clean_results, None), 4)


def test_gate4_fails_on_a_baseline_for_another_milestone(clean_results):
    baseline = gates.baseline_from_results(clean_results)
    baseline["milestone"] = "M2"
    assert _gate(gates.check_all(clean_results, baseline), 4)


def test_gate3_fails_end_to_end_on_an_unknown_output_string(clean_results, mapping):
    stdout = (RAW_OUTPUTS / "pdfsig" / "valid_trusted_total.stdout").read_text()
    verdict, unmapped, _, signals = parse_report(
        stdout.replace("Signature is Valid.", "Signature is Mostly Valid."), 0, mapping
    )
    baseline = gates.baseline_from_results(clean_results)
    row = next(r for r in clean_results["observations"] if r["tool"] == "pdfsig")
    row.update(verdict=verdict, score="ERROR", unmapped=unmapped, signals=signals)
    failures = gates.check_all(clean_results, baseline)
    assert _gate(failures, 3)
    assert verdict == "TOOL_ERROR"


def test_gate3_is_not_excused_by_the_baseline(clean_results):
    row = clean_results["observations"][0]
    row.update(verdict="TOOL_ERROR", score="ERROR", unmapped=True)
    baseline = gates.baseline_from_results(clean_results)
    baseline["results"][row["case_id"]][row["tool"]]["recorded_tool_error"] = True
    assert _gate(gates.check_all(clean_results, baseline), 3)


def test_gate2_fails_when_a_tool_is_missing(clean_results):
    clean_results["tools"]["pdfsig"] = None
    assert _gate(gates.check_all(clean_results, gates.baseline_from_results(clean_results)), 2)


def test_gate2_fails_when_a_case_was_not_run(clean_results):
    baseline = gates.baseline_from_results(clean_results)
    clean_results["observations"].pop()
    assert _gate(gates.check_all(clean_results, baseline), 2)


def test_gate2_fails_on_an_unrecorded_tool_error(clean_results):
    clean_results["observations"][0].update(verdict="TOOL_ERROR", score="ERROR")
    baseline = gates.baseline_from_results(clean_results)
    assert _gate(gates.check_all(clean_results, baseline), 2)


def test_gate2_accepts_an_explicitly_recorded_tool_error(clean_results):
    row = clean_results["observations"][0]
    row.update(verdict="TOOL_ERROR", score="ERROR")
    baseline = gates.baseline_from_results(clean_results)
    baseline["results"][row["case_id"]][row["tool"]]["recorded_tool_error"] = True
    assert gates.check_all(clean_results, baseline) == []


def test_check_command_exits_nonzero_on_a_tampered_baseline(clean_results, tmp_path):
    results = tmp_path / "results.json"
    results.write_text(json.dumps(clean_results))
    baseline = tmp_path / "baseline.json"
    good = gates.baseline_from_results(clean_results)
    baseline.write_text(json.dumps(good))
    assert cli.main(["check", "--results", str(results), "--baseline", str(baseline)]) == 0
    good["results"]["B1"]["pyhanko"]["verdict"] = "VALID"
    baseline.write_text(json.dumps(good))
    assert cli.main(["check", "--results", str(results), "--baseline", str(baseline)]) == 1


def _git_repo(path, files: dict[str, bytes]):
    subprocess.run(["git", "init", "-q"], cwd=path, check=True)
    for name, content in files.items():
        (path / name).write_bytes(content)
    subprocess.run(["git", "add", "-f", "."], cwd=path, check=True)


def test_gate5_catches_key_names_and_marker_text_in_tracked_files(tmp_path):
    _git_repo(
        tmp_path,
        {
            "a.key": b"x",
            "b.P12": b"x",
            "c.pfx": b"x",
            "note.txt": b"-----BEGIN " + scan.TEXT_MARKER + b"-----",
            "fine.txt": b"nothing here",
        },
    )
    findings = scan.scan_tracked(tmp_path)
    assert len(findings) == 4
    assert not any("fine.txt" in f for f in findings)


def test_gate5_ignores_untracked_files(tmp_path):
    _git_repo(tmp_path, {"fine.txt": b"ok"})
    (tmp_path / "untracked.key").write_bytes(b"x")
    assert scan.scan_tracked(tmp_path) == []


def test_gate5_directory_scan_catches_artifacts(tmp_path):
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "leaked.key").write_bytes(b"x")
    assert scan.scan_directory(tmp_path)


def test_this_repository_passes_gate5():
    assert scan.scan_tracked(cli.ROOT) == []


def test_gate2_fails_at_m2_when_dss_is_missing(clean_results):
    clean_results["milestone"] = "M2"
    failures = gates.check_completeness(clean_results)
    assert "gate 2: tool dss is missing or has no version" in failures
    assert any(f.startswith("gate 2: case C5 was not run") for f in failures)


def test_every_finding_in_the_baseline_has_a_review_label():
    baseline = json.loads(cli.DEFAULT_BASELINE.read_text())
    labels = load_findings()
    allowed = {"documented_behavior", "possible_bug", "oracle_disputed"}
    for case_id, tools in baseline["results"].items():
        for tool, entry in tools.items():
            if entry["score"] in ("MISSED", "PARTIAL"):
                assert labels[(case_id, tool)]["label"] in allowed, (case_id, tool)
