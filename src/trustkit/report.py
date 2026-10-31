"""Renders the results table. Reports behavior per case and version, not a ranking."""

from collections import Counter
from html import escape

from trustkit.oracle import load_findings, load_withheld

SCORE_MEANINGS = {
    "AGREE": "Matches the expected verdict.",
    "PARTIAL": "Passes the signature without judging the change, or classifies it differently.",
    "INFO": "Informational case, not scored.",
    "MISSED": "Expected a rejection, and the tool accepted.",
    "OVER_REJECTED": "Expected acceptance, and the tool rejected.",
    "REJECTED_DIFFERENTLY": "Both reject, for different reasons.",
    "ERROR": "Output the mapping treats as a tool error.",
    "NOT_ASSESSED": "The tool does not assess this aspect.",
    "MISMATCH": "Fits no other score.",
}

PAGE_STYLE = """
:root {
  --bg: #fbfaf8; --surface: #ffffff; --text: #1f2328; --muted: #5d646d; --line: #dcdad5;
  --good: #1f6f4a; --warn: #8a5a00; --bad: #a3322a; --info: #2f5f94;
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    --bg: #15171a; --surface: #1d2024; --text: #e8e6e3; --muted: #a3a8ae; --line: #33373c;
    --good: #6cc79c; --warn: #e0b45c; --bad: #ef8f86; --info: #8db8e8;
  }
}
:root[data-theme="dark"] {
  --bg: #15171a; --surface: #1d2024; --text: #e8e6e3; --muted: #a3a8ae; --line: #33373c;
  --good: #6cc79c; --warn: #e0b45c; --bad: #ef8f86; --info: #8db8e8;
}
* { box-sizing: border-box; }
body {
  margin: 0; background: var(--bg); color: var(--text);
  font: 16px/1.55 system-ui, -apple-system, "Segoe UI", sans-serif;
}
main { max-width: 1120px; margin: 0 auto; padding: 40px 16px 64px; }
h1 { font-size: 1.9rem; line-height: 1.2; margin: 0 0 8px; }
h2 { font-size: 1.2rem; margin: 40px 0 12px; }
.lead { font-size: 1.1rem; margin: 0 0 16px; max-width: 46em; }
.muted, .run { color: var(--muted); }
.run { font-size: .9rem; margin: 0; padding: 0; list-style: none; }
.draft { border: 1px solid var(--warn); color: var(--warn); padding: 8px 12px; margin: 0 0 24px; }
.scroll { overflow-x: auto; border: 1px solid var(--line); background: var(--surface); }
table { border-collapse: collapse; width: 100%; font-size: .875rem; }
th, td { padding: 10px 12px; text-align: left; vertical-align: top; border-top: 1px solid var(--line); }
thead th { border-top: 0; font-weight: 600; white-space: nowrap; }
tbody th { font-weight: 400; min-width: 15em; }
td { min-width: 9.5em; }
.case { display: block; font-weight: 600; }
.score { display: block; font-size: .78rem; font-weight: 600; }
.AGREE { color: var(--good); }
.PARTIAL, .REJECTED_DIFFERENTLY { color: var(--warn); }
.MISSED, .OVER_REJECTED, .ERROR, .MISMATCH { color: var(--bad); }
.INFO, .NOT_ASSESSED { color: var(--info); }
.counts td:first-child { min-width: 0; white-space: nowrap; }
.counts td:nth-child(2) { min-width: 0; text-align: right; }
a { color: var(--info); }
ul { padding-left: 20px; }
li { margin: 6px 0; }
code { font-size: .9em; overflow-wrap: anywhere; }
"""


def _breakable(text: str) -> str:
    return escape(text).replace("_", "_<wbr>")


def render_html(results: dict, draft: bool = True) -> str:
    """A standalone results page with no external resources."""
    tools = sorted({row["tool"] for row in results["observations"]})
    by_key = {(row["case_id"], row["tool"]): row for row in results["observations"]}
    labels = load_findings()
    counts = Counter(row["score"] for row in results["observations"])

    rows = []
    for case in results["cases"]:
        cells = []
        for tool in tools:
            row = by_key.get((case["id"], tool))
            cells.append(
                f"<td>{_breakable(row['verdict'])}"
                f'<span class="score {escape(row["score"])}">{escape(row["score"])}</span></td>'
                if row
                else "<td>not run</td>"
            )
        rows.append(
            f'<tr><th scope="row"><span class="case">{escape(case["id"])}</span>'
            f"{escape(case['title'])}</th><td>{_breakable(case['expected'])}</td>"
            f"<td>{escape(case['basis'])}</td>{''.join(cells)}</tr>"
        )

    count_rows = "".join(
        f'<tr><td class="{escape(score)}">{escape(score)}</td><td>{count}</td>'
        f"<td>{escape(SCORE_MEANINGS.get(score, ''))}</td></tr>"
        for score, count in counts.most_common()
    )
    versions = "".join(
        f"<li>{escape(tool)}: "
        f"{escape(', '.join(f'{k}={v}' for k, v in (details or {}).items()) or 'missing')}</li>"
        for tool, details in sorted(results["tools"].items())
    )
    options = "".join(
        f"<li>{escape(tool)}: "
        f"{escape('; '.join(next(r['options'] for r in results['observations'] if r['tool'] == tool)))}</li>"
        for tool in tools
    )
    findings = ""
    for row in results["observations"]:
        if row["score"] in ("MISSED", "PARTIAL"):
            entry = labels.get((row["case_id"], row["tool"]), {})
            note = f": {escape(entry['note'])}" if entry.get("note") else ""
            findings += (
                f"<li><strong>{escape(row['case_id'])}/{escape(row['tool'])}</strong> "
                f'<span class="{escape(row["score"])}">{escape(row["score"])}</span> '
                f"({escape(entry.get('label', 'not_reviewed'))}){note}</li>"
            )
    withheld = results.get("withheld_cases")
    withheld_note = (
        f'<p class="muted">Cases withheld from this table: {withheld}</p>' if withheld else ""
    )
    banner = '<p class="draft">Draft. Not published.</p>' if draft else ""

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Signature Trust Results</title>
<style>{PAGE_STYLE}</style>
</head>
<body>
<main>
{banner}
<h1>PDF Signature Trust Test Kit: results</h1>
<p class="lead">"The signature verifies" and "this document can be trusted" are different
questions. Expected verdicts were committed before the first real run on each fixture.</p>
<ul class="run">
<li>Test date (UTC): {escape(results["date"])}</li>
<li>Commit: <code>{escape(results["commit"][:7])}</code></li>
<li>Validators ran with no network route: {escape(str(results["network_isolated"]))}</li>
</ul>

<h2>Observations</h2>
<p class="muted">Behavior per case, version and configuration. This is not a ranking of tools,
and a disagreement with the expected verdict is not by itself a defect in a tool.</p>
<div class="scroll"><table>
<thead><tr><th scope="col">Case</th><th scope="col">Expected</th><th scope="col">Basis</th>
{"".join(f'<th scope="col">{escape(tool)}</th>' for tool in tools)}</tr></thead>
<tbody>{"".join(rows)}</tbody>
</table></div>
{withheld_note}

<h2>Scores</h2>
<div class="scroll"><table class="counts"><tbody>{count_rows}</tbody></table></div>

<h2>Tool versions</h2>
<ul>{versions}</ul>

<h2>Options</h2>
<ul>{options}</ul>

<h2>Reviewed findings</h2>
<ul>{findings}</ul>
</main>
</body>
</html>
"""


def public_results(results: dict, withheld: set[str] | None = None) -> dict:
    """A copy of the results without the withheld cases. It says how many, and not why."""
    withheld = load_withheld() if withheld is None else withheld
    removed = sum(case["id"] in withheld for case in results["cases"])
    return {
        **results,
        "cases": [case for case in results["cases"] if case["id"] not in withheld],
        "observations": [row for row in results["observations"] if row["case_id"] not in withheld],
        "withheld_cases": removed,
    }


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

    if results.get("withheld_cases"):
        lines += ["", f"Cases withheld from this table: {results['withheld_cases']}"]

    lines += ["", "## Options", ""]
    for tool in tools:
        options = next(row["options"] for row in results["observations"] if row["tool"] == tool)
        lines.append(f"- {tool}: {'; '.join(options)}")

    if results.get("pdfa"):
        lines += ["", f"## PDF/A-3b checks (veraPDF {results['pdfa']['version']})", ""]
        for name, check in results["pdfa"]["checks"].items():
            lines.append(f"- {name}: {'passed' if check['compliant'] else 'failed'}")

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
