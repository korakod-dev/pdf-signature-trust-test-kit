"""Gate 5: fail when a tracked file looks like key material."""

import fnmatch
import subprocess
from pathlib import Path

NAME_PATTERNS = ("*.key", "*.p12", "*.pfx")
# Split so that this source file does not match its own scan.
TEXT_MARKER = b"PRIVATE" + b" KEY"


def scan_files(root: Path, relative_paths: list[str]) -> list[str]:
    findings = []
    for relative in relative_paths:
        name = Path(relative).name
        if any(fnmatch.fnmatch(name.lower(), pattern) for pattern in NAME_PATTERNS):
            findings.append(f"{relative}: file name matches a key pattern")
        path = root / relative
        if path.is_file() and TEXT_MARKER in path.read_bytes():
            findings.append(f"{relative}: contains key marker text")
    return findings


def scan_tracked(root: Path) -> list[str]:
    result = subprocess.run(
        ["git", "ls-files", "-z"], cwd=root, check=True, capture_output=True, text=True
    )
    return scan_files(root, [p for p in result.stdout.split("\0") if p])


def scan_directory(directory: Path) -> list[str]:
    """Scan a directory that is about to be uploaded as an artifact."""
    paths = [str(p.relative_to(directory)) for p in directory.rglob("*") if p.is_file()]
    return scan_files(directory, paths)
