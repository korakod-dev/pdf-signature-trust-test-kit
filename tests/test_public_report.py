"""Proves that withheld cases do not reach public results."""

import json

import pytest

from trustkit import cli, report
from trustkit.oracle import load_cases, load_withheld


@pytest.fixture
def results() -> dict:
    """A results document with the fields the report renders. F2 is the withheld case."""
    ids = ("A1", "F2")
    return {
        "milestone": "M4",
        "date": "2026-01-01",
        "commit": "abc",
        "platform": "test",
        "network_isolated": True,
        "tools": {"pdfsig": {"version": "x"}},
        "cases": [
            {"id": i, "title": "t", "expected": "VALID", "basis": "crypto", "informational": False}
            for i in ids
        ],
        "observations": [
            {
                "case_id": i,
                "tool": "pdfsig",
                "verdict": "VALID",
                "score": "MISSED",
                "options": ["none"],
                "signals": {},
            }
            for i in ids
        ],
    }


def test_withheld_cases_are_known_cases():
    assert load_withheld() <= {case.id for case in load_cases()}


def test_public_results_drop_the_withheld_case_everywhere(results):
    public = report.public_results(results, {"F2"})
    assert [case["id"] for case in public["cases"]] == ["A1"]
    assert [row["case_id"] for row in public["observations"]] == ["A1"]
    assert public["withheld_cases"] == 1
    rendered = report.render_markdown(public)
    assert "F2" not in rendered
    assert "Cases withheld from this table: 1" in rendered


def test_public_results_do_not_change_the_input(results):
    before = json.dumps(results, sort_keys=True)
    report.public_results(results, {"F2"})
    assert json.dumps(results, sort_keys=True) == before


def test_full_results_keep_the_case_and_do_not_mention_withholding(results):
    rendered = report.render_markdown(results)
    assert "| F2 |" in rendered
    assert "withheld" not in rendered


def test_public_report_writes_both_files(results, tmp_path):
    source = tmp_path / "results.json"
    source.write_text(json.dumps(results), encoding="utf-8")
    out = tmp_path / "public"

    assert cli.main(["public-report", "--results", str(source), "--out", str(out)]) == 0

    written = json.loads((out / "results.json").read_text(encoding="utf-8"))
    assert written["withheld_cases"] == 1
    assert [row["case_id"] for row in written["observations"]] == ["A1"]
    assert "F2" not in (out / "results.md").read_text(encoding="utf-8")
    page = (out / "index.html").read_text(encoding="utf-8")
    assert "F2" not in page
    assert "Cases withheld from this table: 1" in page


def test_page_escapes_tool_output_and_loads_nothing_external(results):
    results["cases"][0]["title"] = "<script>alert(1)</script>"
    page = report.render_html(results)
    assert "<script>" not in page
    assert "http://" not in page and "https://" not in page


def test_page_marks_itself_as_a_draft_by_default(results):
    assert "Draft. Not published." in report.render_html(results)
    assert "Draft. Not published." not in report.render_html(results, draft=False)
