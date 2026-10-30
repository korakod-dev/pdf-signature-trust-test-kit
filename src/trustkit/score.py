"""Scoring rules from oracle/verdict-model.md, applied in order."""

from trustkit.oracle import Case

ACCEPT = {"VALID", "VALID_WITH_ALLOWED_CHANGES"}
REJECT = {"INVALID", "INDETERMINATE"}


def score(case: Case, observed: str) -> str:
    if case.informational:
        return "INFO"
    if observed == "TOOL_ERROR":
        return "ERROR"
    if observed == "UNSUPPORTED":
        return "NOT_ASSESSED"
    if observed == case.expected or observed in case.acceptable:
        return "AGREE"
    if observed == "VALID_WITH_UNCLASSIFIED_CHANGES":
        return "PARTIAL"
    if case.expected in REJECT and observed in ACCEPT:
        return "MISSED"
    if case.expected in ACCEPT and observed in REJECT:
        return "OVER_REJECTED"
    if case.expected in REJECT and observed in REJECT:
        return "REJECTED_DIFFERENTLY"
    if case.expected in ACCEPT and observed in ACCEPT:
        return "PARTIAL"
    return "MISMATCH"
