"""pyHanko adapter. Uses the API and trusts only the case's trust anchor."""

import json
import traceback
from importlib import metadata
from pathlib import Path

from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.general import load_cert_from_pemder
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko_certvalidator import ValidationContext

from trustkit.adapters.base import TOOL_ERROR, Observation, sha256_file

# Fetching is off by default. It is on so that revocation cases can reach the loopback
# service. Only certificates with URLs fetch, and those URLs are on loopback.
OPTIONS = ["ValidationContext(trust_roots=[case trust anchor], allow_fetching=True)"]
COVERAGE_TOKENS = ("UNTOUCHED", "EXTENDED", "NONSTANDARD_COVERAGE")


def _name(value) -> str | None:
    return None if value is None else value.name


def extract_signals(status) -> dict:
    """Flatten a PdfSignatureStatus into JSON-safe signals, which the mapping reads."""
    timestamp = status.timestamp_validity
    summary_fields = list(status.summary_fields())
    return {
        "intact": status.intact,
        "valid": status.valid,
        "trusted": status.trusted,
        "revoked": status.revoked,
        "docmdp_ok": status.docmdp_ok,
        "bottom_line": status.bottom_line,
        "coverage": _name(status.coverage),
        "coverage_summary": next(
            (f for f in summary_fields if f.startswith(COVERAGE_TOKENS)), None
        ),
        "modification_level": _name(status.modification_level),
        "timestamp_present": timestamp is not None,
        "timestamp_trusted": (
            None
            if timestamp is None
            else bool(timestamp.valid and timestamp.intact and timestamp.trusted)
        ),
        "trust_problem_indic": (
            None if status.trust_problem_indic is None else str(status.trust_problem_indic)
        ),
        "summary": status.summary(),
        "signer_subject": status.signing_cert.subject.human_friendly,
        "signer_subject_shown": True,
    }


def _matches(condition: dict, signals: dict) -> bool:
    value = signals.get(condition["field"])
    if "equals" in condition:
        return value == condition["equals"]
    return value in condition["in"]


def _rule_applies(rule: dict, signals: dict) -> bool:
    if "all" in rule and not all(_matches(c, signals) for c in rule["all"]):
        return False
    if "any" in rule and not any(_matches(c, signals) for c in rule["any"]):
        return False
    return True


def map_signals(signals: dict, mapping: dict) -> tuple[str, str | None]:
    """Return (verdict, rule id). A state that no rule covers is (TOOL_ERROR, None)."""
    for rule in mapping["pyhanko"]["rules"]:
        if _rule_applies(rule, signals):
            return rule["verdict"], rule["id"]
    return TOOL_ERROR, None


class PyHankoAdapter:
    name = "pyhanko"

    def __init__(self, mapping: dict):
        self.mapping = mapping

    def version(self) -> dict | None:
        try:
            return {
                "version": metadata.version("pyHanko"),
                "pyhanko-certvalidator": metadata.version("pyhanko-certvalidator"),
            }
        except metadata.PackageNotFoundError:
            return None

    def validate(self, case_id: str, pdf: Path, trust_anchor: Path, work_dir: Path) -> Observation:
        details = self.version() or {}
        observation = Observation(
            case_id=case_id,
            tool=self.name,
            tool_version=details.get("version"),
            options=list(OPTIONS),
            verdict=TOOL_ERROR,
            unmapped=False,
            rule=None,
            raw_output="",
            exit_code=None,
            fixture_sha256=sha256_file(pdf),
        )
        try:
            context = ValidationContext(
                trust_roots=[load_cert_from_pemder(str(trust_anchor))], allow_fetching=True
            )
            with pdf.open("rb") as stream:
                embedded = PdfFileReader(stream).embedded_signatures
                if not embedded:
                    observation.verdict = self.mapping["pyhanko"]["no_embedded_signatures"]
                    observation.rule = "no-embedded-signatures"
                    observation.raw_output = "no embedded signatures"
                    return observation
                status = validate_pdf_signature(embedded[0], context)
                signals = extract_signals(status)
                details_text = status.pretty_print_details()
        except Exception:
            observation.raw_output = traceback.format_exc()
            observation.rule = "exception"
            return observation

        observation.signals = signals
        observation.raw_output = json.dumps(signals, indent=2) + "\n\n" + details_text
        observation.verdict, observation.rule = map_signals(signals, self.mapping)
        observation.unmapped = observation.rule is None
        return observation
