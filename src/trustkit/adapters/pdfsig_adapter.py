"""pdfsig adapter. Trust comes from a temporary NSS database holding one root."""

import os
import re
import shutil
import subprocess
from pathlib import Path

from trustkit.adapters.base import TOOL_ERROR, Observation, sha256_file

TIMEOUT_SECONDS = 120
SIGNATURE_LINE = "  - Signature Validation: "
CERTIFICATE_LINE = "  - Certificate Validation: "
SIGNER_LINE = "  - Signer full Distinguished Name: "
SIGNATURE_HEADER = re.compile(r"^Signature #(\d+):$")


def parse_report(stdout: str, exit_code: int, mapping: dict) -> tuple[str, bool, str | None, dict]:
    """Return (verdict, unmapped, rule, signals) for one pdfsig run.

    Only the first signature is judged. Every stdout line must be known, and an
    unknown line anywhere makes the whole report unmapped.
    """
    table = mapping["pdfsig"]
    action = table["exit_codes"].get(str(exit_code))
    if action is None:
        return TOOL_ERROR, True, None, {"problem": f"unmapped exit code {exit_code}"}
    if action != "parse_stdout":
        return action, False, f"exit-{exit_code}", {}

    signatures: list[dict] = []
    for line in stdout.splitlines():
        if not line.strip():
            continue
        header = SIGNATURE_HEADER.match(line)
        if header:
            signatures.append({})
            continue
        if line.startswith(SIGNATURE_LINE):
            field, value = "signature", line[len(SIGNATURE_LINE) :]
        elif line.startswith(CERTIFICATE_LINE):
            field, value = "certificate", line[len(CERTIFICATE_LINE) :]
        elif line.strip(" -") in table["coverage"]:
            field, value = "coverage", line.strip(" -")
        elif line.startswith(SIGNER_LINE):
            field, value = "signer", line[len(SIGNER_LINE) :]
        elif line.startswith(tuple(table["informational_lines"])):
            continue
        else:
            return TOOL_ERROR, True, None, {"problem": f"unmapped line: {line}"}
        if not signatures:
            return TOOL_ERROR, True, None, {"problem": f"line before any signature: {line}"}
        signatures[-1][field] = value

    if not signatures:
        return TOOL_ERROR, True, None, {"problem": "no signature in a report with exit 0"}
    first = signatures[0]
    signals = {
        "signature_validation": first.get("signature"),
        "certificate_validation": first.get("certificate"),
        "coverage": first.get("coverage"),
        "signer_subject": first.get("signer"),
        "signer_subject_shown": "signer" in first,
        "signature_count": len(signatures),
    }

    outcome = table["signature_validation"].get(first.get("signature"))
    if outcome is None:
        return TOOL_ERROR, True, None, {**signals, "problem": "unmapped signature validation"}
    if outcome != "valid":
        return outcome, False, "signature-failed", signals

    outcome = table["certificate_validation"].get(first.get("certificate"))
    if outcome is None:
        return TOOL_ERROR, True, None, {**signals, "problem": "unmapped certificate validation"}
    if outcome != "trusted":
        return outcome, False, "certificate-not-trusted", signals

    outcome = table["coverage"].get(first.get("coverage"))
    if outcome is None:
        return TOOL_ERROR, True, None, {**signals, "problem": "unmapped coverage"}
    return outcome, False, "valid-and-trusted", signals


def build_nss_database(db_dir: Path, trust_anchor: Path) -> None:
    """Create an NSS database that contains only the trust anchor."""
    db_dir.mkdir(parents=True, exist_ok=True)
    certutil = ["certutil", "-d", f"sql:{db_dir}"]
    subprocess.run([*certutil, "-N", "--empty-password"], check=True, capture_output=True)
    subprocess.run(
        [*certutil, "-A", "-n", "trust-anchor", "-t", "CT,C,C", "-i", str(trust_anchor)],
        check=True,
        capture_output=True,
    )


def list_nss_database(db_dir: Path) -> list[str]:
    """Return every certificate nickname in the database, built-in tokens included."""
    result = subprocess.run(
        ["certutil", "-L", "-d", f"sql:{db_dir}", "-h", "all"],
        check=True,
        capture_output=True,
        text=True,
    )
    return [
        line.rsplit(None, 1)[0].strip()
        for line in result.stdout.splitlines()[4:]
        if line.strip()
    ]


class PdfsigAdapter:
    name = "pdfsig"

    def __init__(self, mapping: dict):
        self.mapping = mapping

    def version(self) -> dict | None:
        if shutil.which("pdfsig") is None or shutil.which("certutil") is None:
            return None
        result = subprocess.run(["pdfsig", "-v"], capture_output=True, text=True)
        match = re.search(r"pdfsig version (\S+)", result.stdout + result.stderr)
        details = {"version": match.group(1) if match else None}
        details.update(_debian_packages())
        return details

    def validate(self, case_id: str, pdf: Path, trust_anchor: Path, work_dir: Path) -> Observation:
        version = (self.version() or {}).get("version")
        observation = Observation(
            case_id=case_id,
            tool=self.name,
            tool_version=version,
            options=["-nssdir <temporary database containing only the case trust anchor>"],
            verdict=TOOL_ERROR,
            unmapped=False,
            rule=None,
            raw_output="",
            exit_code=None,
            fixture_sha256=sha256_file(pdf),
        )
        db_dir = work_dir / "nss"
        home = work_dir / "home"
        home.mkdir(parents=True, exist_ok=True)
        try:
            build_nss_database(db_dir, trust_anchor)
            # HOME points at an empty directory, so no other profile is consulted.
            env = {"PATH": os.environ.get("PATH", ""), "HOME": str(home), "LC_ALL": "C"}
            result = subprocess.run(
                ["pdfsig", "-nssdir", str(db_dir), str(pdf)],
                capture_output=True,
                text=True,
                env=env,
                timeout=TIMEOUT_SECONDS,
            )
        except (OSError, subprocess.SubprocessError) as error:
            observation.raw_output = f"{type(error).__name__}: {error}"
            observation.rule = "exception"
            return observation

        observation.exit_code = result.returncode
        observation.raw_output = f"--- stdout\n{result.stdout}--- stderr\n{result.stderr}"
        (
            observation.verdict,
            observation.unmapped,
            observation.rule,
            observation.signals,
        ) = parse_report(result.stdout, result.returncode, self.mapping)
        return observation


def _debian_packages() -> dict:
    if shutil.which("dpkg-query") is None:
        return {}
    result = subprocess.run(
        ["dpkg-query", "-W", "-f", "${Package}=${Version}\n", "poppler-utils", "libnss3"],
        capture_output=True,
        text=True,
    )
    return dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
