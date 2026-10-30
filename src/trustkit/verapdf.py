"""veraPDF check for files labeled PDF/A-3b. It is a precondition, not a validator under test."""

import json
import re
import shutil
import subprocess
from pathlib import Path

from trustkit.oracle import ROOT

RUNNER_JAR = ROOT / "adapters" / "verapdf-runner" / "target" / "verapdf-runner.jar"
TIMEOUT_SECONDS = 120


def parse_report(stdout: str) -> dict:
    """Reduce a JSON report to whether the file passed, and which rules failed."""
    result = json.loads(stdout)["report"]["jobs"][0]["validationResult"]
    result = result[0] if isinstance(result, list) else result
    return {
        "compliant": result["compliant"] is True,
        "profile": result["profileName"],
        "failed_rules": [
            f"{rule['clause']}-{rule['testNumber']}" for rule in result["details"]["ruleSummaries"]
        ],
    }


def version(jar: Path = RUNNER_JAR) -> str | None:
    if shutil.which("java") is None or not jar.exists():
        return None
    result = subprocess.run(
        ["java", "-jar", str(jar), "--version"],
        capture_output=True,
        text=True,
        timeout=TIMEOUT_SECONDS,
    )
    match = re.search(r"veraPDF (\S+)", result.stdout)
    return match.group(1) if match else None


def check(pdf: Path, jar: Path = RUNNER_JAR) -> dict:
    """Check one file against PDF/A-3b. Anything that is not a clear pass is not compliant."""
    try:
        result = subprocess.run(
            ["java", "-jar", str(jar), "-f", "3b", "--format", "json", str(pdf)],
            capture_output=True,
            text=True,
            timeout=TIMEOUT_SECONDS,
        )
        return parse_report(result.stdout)
    except (OSError, subprocess.SubprocessError, ValueError, KeyError, IndexError) as error:
        return {"compliant": False, "problem": f"{type(error).__name__}: {error}"}
