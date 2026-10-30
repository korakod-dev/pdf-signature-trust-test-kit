import pytest

from trustkit.oracle import Case, cases_for, load_cases
from trustkit.score import score


def _case(expected="VALID", acceptable=(), informational=False) -> Case:
    return Case("X", "t", "M1", expected, acceptable, informational, "crypto", "n/a", "r", "f")


@pytest.mark.parametrize(
    "case, observed, result",
    [
        # Rule 1 comes first, even over a tool error.
        (_case(informational=True), "TOOL_ERROR", "INFO"),
        (_case(informational=True), "INVALID", "INFO"),
        (_case(), "TOOL_ERROR", "ERROR"),
        (_case(), "UNSUPPORTED", "NOT_ASSESSED"),
        (_case(), "VALID", "AGREE"),
        (_case("INVALID", acceptable=("INDETERMINATE",)), "INDETERMINATE", "AGREE"),
        # Rule 5 comes before rule 6, as the brief orders them.
        (_case("INVALID"), "VALID_WITH_UNCLASSIFIED_CHANGES", "PARTIAL"),
        (_case("VALID"), "VALID_WITH_UNCLASSIFIED_CHANGES", "PARTIAL"),
        (_case("INVALID"), "VALID", "MISSED"),
        (_case("INDETERMINATE"), "VALID_WITH_ALLOWED_CHANGES", "MISSED"),
        (_case("VALID"), "INVALID", "OVER_REJECTED"),
        (_case("VALID_WITH_ALLOWED_CHANGES"), "INDETERMINATE", "OVER_REJECTED"),
        (_case("INVALID"), "INDETERMINATE", "REJECTED_DIFFERENTLY"),
        (_case("VALID"), "VALID_WITH_ALLOWED_CHANGES", "PARTIAL"),
        (_case("NO_SIGNATURE"), "VALID", "MISMATCH"),
        (_case("VALID"), "NO_SIGNATURE", "MISMATCH"),
    ],
)
def test_score_rules(case, observed, result):
    assert score(case, observed) == result


def test_oracle_has_the_twenty_cases_and_m1_has_three():
    assert len(load_cases()) == 20
    assert [c.id for c in cases_for("M1")] == ["A1", "A2", "B1"]


def test_every_case_has_rationale_and_a_known_basis():
    for case in load_cases():
        assert case.rationale.strip() and case.fixture_recipe.strip()
        assert case.basis in {"crypto", "spec", "policy"}
        # No clause number may be cited until the text has been read.
        if case.basis == "spec":
            assert case.spec_ref == "TODO"
