"""Command line: run, check, scan, write-baseline."""

import argparse
import datetime as dt
import json
import os
import platform
import subprocess
import sys
import tempfile
from pathlib import Path

from trustkit import fixtures, gates, pki, report, scan, services
from trustkit.adapters.dss_adapter import DssAdapter
from trustkit.adapters.pdfsig_adapter import PdfsigAdapter
from trustkit.adapters.pyhanko_adapter import PyHankoAdapter
from trustkit.oracle import ROOT, TOOLS_BY_MILESTONE, cases_for, load_mapping
from trustkit.score import score

DEFAULT_BASELINE = ROOT / "baselines" / "baseline.json"


def network_isolated() -> bool:
    """True when this process has no route at all. Probes nothing outside the host."""
    try:
        routes = Path("/proc/net/route").read_text().splitlines()[1:]
    except OSError:
        return False
    return not any(line.strip() for line in routes)


def current_commit() -> str:
    if os.environ.get("GITHUB_SHA"):
        return os.environ["GITHUB_SHA"]
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True
    )
    return result.stdout.strip() or "unknown"


def run_cases(milestone: str, out_dir: Path) -> dict:
    mapping = load_mapping()
    available = [PyHankoAdapter(mapping), PdfsigAdapter(mapping), DssAdapter(mapping)]
    adapters = [a for a in available if a.name in TOOLS_BY_MILESTONE[milestone]]
    cases = cases_for(milestone)
    fixtures_dir = out_dir / "fixtures"
    certs_dir = out_dir / "certs"
    raw_dir = out_dir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)

    observations = []
    # Keys live only here, outside the repository, and vanish with this block.
    with tempfile.TemporaryDirectory(prefix="trustkit-keys-") as keys, tempfile.TemporaryDirectory(
        prefix="trustkit-work-"
    ) as work:
        test_pki = pki.generate(certs_dir, Path(keys))
        built = fixtures.BUILDERS[milestone](fixtures_dir, test_pki)
        with services.RevocationService(test_pki) as revocation:
            for case in cases:
                fixture = built[case.id]
                for adapter in adapters:
                    work_dir = Path(work) / case.id / adapter.name
                    work_dir.mkdir(parents=True)
                    observation = adapter.validate(
                        case.id, fixture.path, fixture.trust_anchor.cert_path, work_dir
                    )
                    (raw_dir / f"{case.id}.{adapter.name}.txt").write_text(
                        observation.raw_output, encoding="utf-8"
                    )
                    row = observation.to_dict()
                    row["score"] = score(case, observation.verdict)
                    row["signals"]["revocation_requests"] = revocation.take_requests()
                    observations.append(row)

    return {
        "milestone": milestone,
        "date": dt.datetime.now(dt.timezone.utc).date().isoformat(),
        "commit": current_commit(),
        "platform": platform.platform(),
        "network_isolated": network_isolated(),
        "tools": {adapter.name: adapter.version() for adapter in adapters},
        "cases": [
            {
                "id": c.id,
                "title": c.title,
                "expected": c.expected,
                "basis": c.basis,
                "informational": c.informational,
            }
            for c in cases
        ],
        "observations": observations,
    }


def command_run(args: argparse.Namespace) -> int:
    if args.require_network_isolation and not network_isolated():
        print("refusing to run: this process has a network route", file=sys.stderr)
        return 2
    args.out.mkdir(parents=True, exist_ok=True)
    results = run_cases(args.milestone, args.out)
    (args.out / "results.json").write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    table = report.render_markdown(results)
    (args.out / "results.md").write_text(table, encoding="utf-8")
    print(table)
    return 0


def _read_baseline(path: Path) -> dict | None:
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None


def command_check(args: argparse.Namespace) -> int:
    results = json.loads(args.results.read_text(encoding="utf-8"))
    failures = gates.check_all(results, _read_baseline(args.baseline))
    for failure in failures:
        print(failure, file=sys.stderr)
    print(f"{len(failures)} gate failure(s)")
    return 1 if failures else 0


def command_scan(args: argparse.Namespace) -> int:
    findings = scan.scan_directory(args.directory) if args.directory else scan.scan_tracked(ROOT)
    for finding in findings:
        print(finding, file=sys.stderr)
    print(f"{len(findings)} finding(s)")
    return 1 if findings else 0


def command_write_baseline(args: argparse.Namespace) -> int:
    results = json.loads(args.results.read_text(encoding="utf-8"))
    args.baseline.parent.mkdir(parents=True, exist_ok=True)
    args.baseline.write_text(
        json.dumps(
            gates.baseline_from_results(results, tuple(args.record_tool_error)), indent=2
        )
        + "\n",
        encoding="utf-8",
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="trustkit")
    commands = parser.add_subparsers(dest="command", required=True)

    run = commands.add_parser("run", help="generate fixtures and run the validators")
    run.add_argument("--milestone", default="M3", choices=sorted(TOOLS_BY_MILESTONE))
    run.add_argument("--out", type=Path, default=ROOT / "out")
    run.add_argument("--require-network-isolation", action="store_true")
    run.set_defaults(func=command_run)

    check = commands.add_parser("check", help="apply gates 2, 3 and 4 to a results file")
    check.add_argument("--results", type=Path, default=ROOT / "out" / "results.json")
    check.add_argument("--baseline", type=Path, default=DEFAULT_BASELINE)
    check.set_defaults(func=command_check)

    scan_parser = commands.add_parser("scan", help="gate 5: look for key material")
    scan_parser.add_argument("--directory", type=Path, help="scan this directory, not tracked files")
    scan_parser.set_defaults(func=command_scan)

    write = commands.add_parser("write-baseline", help="write a baseline from a results file")
    write.add_argument("--results", type=Path, required=True)
    write.add_argument("--baseline", type=Path, default=DEFAULT_BASELINE)
    write.add_argument(
        "--record-tool-error",
        action="append",
        default=[],
        metavar="CASE/TOOL",
        help="accept this TOOL_ERROR in the baseline",
    )
    write.set_defaults(func=command_write_baseline)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
