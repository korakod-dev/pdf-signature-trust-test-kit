"""Loads the pre-registered oracle files."""

from dataclasses import dataclass
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
ORACLE_DIR = ROOT / "oracle"

MILESTONES = ("M1", "M2", "M3", "M4")
TOOLS_BY_MILESTONE = {
    "M1": ("pyhanko", "pdfsig"),
    "M2": ("pyhanko", "pdfsig", "dss"),
    "M3": ("pyhanko", "pdfsig", "dss"),
    "M4": ("pyhanko", "pdfsig", "dss"),
}


@dataclass(frozen=True)
class Case:
    id: str
    title: str
    milestone: str
    expected: str
    acceptable: tuple[str, ...]
    informational: bool
    basis: str
    spec_ref: str
    rationale: str
    fixture_recipe: str


def load_cases(path: Path = ORACLE_DIR / "cases.yaml") -> list[Case]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    return [
        Case(
            id=c["id"],
            title=c["title"],
            milestone=c["milestone"],
            expected=c["expected"],
            acceptable=tuple(c.get("acceptable", ())),
            informational=c["informational"],
            basis=c["basis"],
            spec_ref=c["spec_ref"],
            rationale=c["rationale"],
            fixture_recipe=c["fixture_recipe"],
        )
        for c in data["cases"]
    ]


def cases_for(milestone: str, cases: list[Case] | None = None) -> list[Case]:
    """Return the cases active at a milestone, which includes earlier milestones."""
    included = MILESTONES[: MILESTONES.index(milestone) + 1]
    return [c for c in (cases or load_cases()) if c.milestone in included]


def load_mapping(path: Path = ORACLE_DIR / "mapping.yaml") -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def load_findings(path: Path = ORACLE_DIR / "findings.yaml") -> dict[tuple[str, str], dict]:
    """Review labels, keyed by (case id, tool)."""
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    return {(f["case"], f["tool"]): f for f in data["findings"]}
