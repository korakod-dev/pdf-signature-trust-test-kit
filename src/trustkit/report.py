"""Renders the results table. Reports behavior per case and version, not a ranking."""

from trustkit.oracle import load_findings


def render_markdown(results: dict) -> str:
    tools = sorted({row["tool"] for row in results["observations"]})
    lines = [
        f"# Results: {results['milestone']}",
        "",
        f"- Test date (UTC): {results['date']}",
        f"- Commit: {results['commit']}",
        f"- Platform: {results['platform']}",
        f"- Validators ran with no network route: {results['network_isolated']}",
        "",
        "## Tool versions",
        "",
    ]
    for tool, details in sorted(results["tools"].items()):
        rendered = ", ".join(f"{k}={v}" for k, v in (details or {}).items()) or "missing"
        lines.append(f"- {tool}: {rendered}")

    lines += [
        "",
        "## Observations",
        "",
        "| Case | Expected | Basis | " + " | ".join(tools) + " |",
        "|---|---|---|" + "---|" * len(tools),
    ]
    by_key = {(row["case_id"], row["tool"]): row for row in results["observations"]}
    for case in results["cases"]:
        cells = []
        for tool in tools:
            row = by_key.get((case["id"], tool))
            cells.append(f"{row['verdict']} ({row['score']})" if row else "not run")
        lines.append(
            f"| {case['id']} | {case['expected']} | {case['basis']} | " + " | ".join(cells) + " |"
        )

    lines += ["", "## Options", ""]
    for tool in tools:
        options = next(row["options"] for row in results["observations"] if row["tool"] == tool)
        lines.append(f"- {tool}: {'; '.join(options)}")

    informational = [c["id"] for c in results["cases"] if c["informational"]]
    if informational:
        lines += ["", "## Informational cases", ""]
        for case_id in informational:
            for tool in tools:
                row = by_key.get((case_id, tool))
                if row:
                    shown = row["signals"].get("signer_subject_shown", False)
                    lines.append(f"- {case_id}/{tool}: signer subject shown: {shown}")

    disagreements = [
        row
        for row in results["observations"]
        if row["score"] in ("OVER_REJECTED", "REJECTED_DIFFERENTLY", "ERROR", "MISMATCH")
    ]
    if disagreements:
        lines += ["", "## Other results that differ from the oracle", ""]
        for row in disagreements:
            lines.append(f"- {row['case_id']}/{row['tool']}: {row['score']} ({row['verdict']})")

    requests = sum(len(r["signals"].get("revocation_requests", [])) for r in results["observations"])
    lines += ["", f"Requests to the local revocation service: {requests}"]

    findings = [
        row for row in results["observations"] if row["score"] in ("MISSED", "PARTIAL")
    ]
    if findings:
        labels = load_findings()
        lines += ["", "## Findings", ""]
        for row in findings:
            entry = labels.get((row["case_id"], row["tool"]), {})
            note = f": {entry['note']}" if entry.get("note") else ""
            lines.append(
                f"- {row['case_id']}/{row['tool']}: {row['score']} "
                f"({entry.get('label', 'not_reviewed')}){note}"
            )
    return "\n".join(lines) + "\n"
