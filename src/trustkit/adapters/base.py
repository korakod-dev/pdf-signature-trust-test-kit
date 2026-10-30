"""Common observation record and adapter interface."""

import hashlib
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Protocol

TOOL_ERROR = "TOOL_ERROR"


@dataclass
class Observation:
    case_id: str
    tool: str
    tool_version: str | None
    options: list[str]
    verdict: str
    # True when the tool produced output that the mapping does not cover.
    unmapped: bool
    rule: str | None
    raw_output: str
    exit_code: int | None
    fixture_sha256: str
    signals: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


class Adapter(Protocol):
    name: str

    def version(self) -> dict | None:
        """Version details, or None when the tool is missing."""

    def validate(self, case_id: str, pdf: Path, trust_anchor: Path, work_dir: Path) -> Observation:
        """Validate one fixture, trusting only trust_anchor."""


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()
