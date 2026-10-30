import copy
import json
from pathlib import Path

import pytest

from trustkit import fixtures, pki
from trustkit.oracle import load_mapping

RAW_OUTPUTS = Path(__file__).parent / "data" / "raw_outputs"


@pytest.fixture(scope="session")
def mapping() -> dict:
    return load_mapping()


@pytest.fixture(scope="session")
def built(tmp_path_factory):
    """All fixtures and the PKI. Keys stay in a pytest temp directory outside the repo."""
    base = tmp_path_factory.mktemp("fixtures")
    test_pki = pki.generate(base / "certs", base / "keys")
    return test_pki, fixtures.build_m2(base / "fixtures", test_pki), base


@pytest.fixture
def clean_results() -> dict:
    """A results document that passes every gate against its own baseline."""
    rows = []
    for case_id, verdict in [("A1", "VALID"), ("A2", "INVALID"), ("B1", "INDETERMINATE")]:
        for tool in ("pyhanko", "pdfsig"):
            rows.append(
                {
                    "case_id": case_id,
                    "tool": tool,
                    "verdict": verdict,
                    "score": "AGREE",
                    "unmapped": False,
                    "signals": {},
                }
            )
    return {
        "milestone": "M1",
        "tools": {"pyhanko": {"version": "x"}, "pdfsig": {"version": "y"}},
        "observations": rows,
    }


@pytest.fixture
def tamper():
    return copy.deepcopy


def load_capture(tool: str, name: str) -> dict:
    return json.loads((RAW_OUTPUTS / tool / f"{name}.json").read_text())
