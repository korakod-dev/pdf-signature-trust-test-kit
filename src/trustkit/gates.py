"""CI gates 2, 3 and 4, and the PDF/A part of gate 1. The rest of gate 1 is pytest, and gate 5
is trustkit.scan.

A tool disagreeing with the oracle is a recorded result and fails no gate here. It
fails gate 4 only if it differs from the committed baseline.
"""

from trustkit.oracle import TOOLS_BY_MILESTONE, cases_for

PDFA_CHECK_NAMES = (
    "F1 before signing",
    "F1 after signing",
    "F3 before signing",
    "F3 after signing",
)


def baseline_from_results(results: dict, record_tool_errors: tuple[str, ...] = ()) -> dict:
    """Keep only what must be stable: per-case verdict and score, no run-specific data.

    record_tool_errors lists "case/tool" entries whose TOOL_ERROR is accepted. Gate 2
    fails on any other TOOL_ERROR, so this has to be asked for by name.
    """
    entries: dict = {}
    for row in results["observations"]:
        entry = {"verdict": row["verdict"], "score": row["score"]}
        if row["verdict"] == "TOOL_ERROR" and f"{row['case_id']}/{row['tool']}" in record_tool_errors:
            entry["recorded_tool_error"] = True
        entries.setdefault(row["case_id"], {})[row["tool"]] = entry
    return {"version": 1, "milestone": results["milestone"], "results": entries}


def check_completeness(results: dict) -> list[str]:
    """Gate 2: every tool present, every active case run on every tool."""
    failures = []
    milestone = results["milestone"]
    tools = TOOLS_BY_MILESTONE[milestone]
    for tool in tools:
        details = results["tools"].get(tool)
        if not details or not details.get("version"):
            failures.append(f"gate 2: tool {tool} is missing or has no version")
    seen = {(row["case_id"], row["tool"]) for row in results["observations"]}
    for case in cases_for(milestone):
        for tool in tools:
            if (case.id, tool) not in seen:
                failures.append(f"gate 2: case {case.id} was not run on {tool}")
    return failures


def check_tool_errors(results: dict, baseline: dict | None) -> list[str]:
    """Gate 2: a TOOL_ERROR passes only when the baseline records it explicitly."""
    recorded = (baseline or {}).get("results", {})
    failures = []
    for row in results["observations"]:
        if row["verdict"] != "TOOL_ERROR":
            continue
        entry = recorded.get(row["case_id"], {}).get(row["tool"], {})
        if not entry.get("recorded_tool_error"):
            failures.append(
                f"gate 2: {row['case_id']}/{row['tool']} is TOOL_ERROR "
                "and is not recorded in the baseline"
            )
    return failures


def check_unmapped(results: dict) -> list[str]:
    """Gate 3: any output the mapping does not cover."""
    return [
        f"gate 3: {row['case_id']}/{row['tool']} produced unmapped output: "
        f"{row['signals'].get('problem', 'no rule matched')}"
        for row in results["observations"]
        if row["unmapped"]
    ]


def check_baseline(results: dict, baseline: dict | None) -> list[str]:
    """Gate 4: any difference from the baseline, better or worse."""
    if baseline is None:
        return ["gate 4: no baseline committed yet"]
    if baseline.get("milestone") != results["milestone"]:
        return [
            f"gate 4: baseline is for {baseline.get('milestone')}, "
            f"results are for {results['milestone']}"
        ]
    expected = baseline["results"]
    actual = baseline_from_results(results)["results"]
    failures = []
    for case_id in sorted(set(expected) | set(actual)):
        tools = set(expected.get(case_id, {})) | set(actual.get(case_id, {}))
        for tool in sorted(tools):
            want = expected.get(case_id, {}).get(tool)
            got = actual.get(case_id, {}).get(tool)
            if want is None or got is None:
                failures.append(f"gate 4: {case_id}/{tool} baseline={want} result={got}")
            elif (want["verdict"], want["score"]) != (got["verdict"], got["score"]):
                failures.append(
                    f"gate 4: {case_id}/{tool} baseline={want['verdict']}/{want['score']} "
                    f"result={got['verdict']}/{got['score']}"
                )
    return failures


def check_pdfa(results: dict) -> list[str]:
    """Gate 1: from M4, every file labeled PDF/A-3b must have passed veraPDF."""
    if results["milestone"] != "M4":
        return []
    pdfa = results.get("pdfa")
    if not pdfa or not pdfa.get("version"):
        return ["gate 1: veraPDF is missing"]
    failures = []
    for name in PDFA_CHECK_NAMES:
        check = pdfa["checks"].get(name)
        if check is None:
            failures.append(f"gate 1: {name} was not checked with veraPDF")
        elif not check["compliant"]:
            failures.append(f"gate 1: {name} failed veraPDF: {check}")
    return failures


def check_all(results: dict, baseline: dict | None) -> list[str]:
    return [
        *check_pdfa(results),
        *check_completeness(results),
        *check_tool_errors(results, baseline),
        *check_unmapped(results),
        *check_baseline(results, baseline),
    ]
