"""EU DSS adapter. Runs adapters/dss-runner, which uses the unmodified default policy."""

import shutil
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

from trustkit.adapters.base import TOOL_ERROR, Observation, sha256_file
from trustkit.oracle import ROOT

RUNNER_JAR = ROOT / "adapters" / "dss-runner" / "target" / "dss-runner.jar"
TIMEOUT_SECONDS = 120
SIMPLE = "{http://dss.esig.europa.eu/validation/simple-report}"
DIAGNOSTIC = "{http://dss.esig.europa.eu/validation/diagnostic}"
OPTIONS = [
    "default validation policy",
    "CommonTrustedCertificateSource(case trust anchor)",
    "OnlineCRLSource, OnlineOCSPSource and DefaultAIASource, for certificates with URLs",
]


def _modifications(signature: ET.Element) -> list[str]:
    """Category names in ModificationDetection, from the diagnostic data."""
    detection = signature.find(f"{DIAGNOSTIC}PDFRevision/{DIAGNOSTIC}ModificationDetection")
    found = []
    for child in [] if detection is None else detection:
        name = child.tag.removeprefix(DIAGNOSTIC)
        if name == "ObjectModifications":
            found += [item.tag.removeprefix(DIAGNOSTIC) for item in child]
        else:
            found.append(name)
    return sorted(set(found))


def _first_signature(diagnostic: ET.Element) -> ET.Element:
    """The signature whose ByteRange ends earliest, which is the first one applied."""

    def range_end(signature: ET.Element) -> int:
        byte_range = signature.findtext(
            f"{DIAGNOSTIC}PDFRevision/{DIAGNOSTIC}PDFSignatureDictionary"
            f"/{DIAGNOSTIC}SignatureByteRange"
        )
        numbers = [int(n) for n in byte_range.split()]
        return numbers[2] + numbers[3]

    return min(diagnostic.findall(f"{DIAGNOSTIC}Signatures/{DIAGNOSTIC}Signature"), key=range_end)


def parse_reports(
    simple_xml: str, diagnostic_xml: str, mapping: dict
) -> tuple[str, bool, str | None, dict]:
    """Return (verdict, unmapped, rule, signals) for one DSS run."""
    table = mapping["dss"]
    simple = ET.fromstring(simple_xml)
    diagnostic = ET.fromstring(diagnostic_xml)
    reported = simple.findall(f"{SIMPLE}Signature")
    if not reported:
        return table["no_signatures"], False, "no-signatures", {"signature_count": 0}

    first = _first_signature(diagnostic)
    by_id = {signature.get("Id"): signature for signature in reported}
    signature = by_id.get(first.get("Id"))
    if signature is None:
        return TOOL_ERROR, True, None, {"problem": "first signature missing from simple report"}

    details = signature.find(f"{SIMPLE}AdESValidationDetails")
    messages = [] if details is None else list(details)
    errors = [m.get("Key") for m in messages if m.tag == f"{SIMPLE}Error"]
    others = [m.get("Key") for m in messages if m.tag != f"{SIMPLE}Error"]
    indication = signature.findtext(f"{SIMPLE}Indication")
    modifications = _modifications(first)
    signals = {
        "indication": indication,
        "sub_indication": signature.findtext(f"{SIMPLE}SubIndication"),
        "modifications": modifications,
        "timestamps": [
            {
                "indication": t.findtext(f"{SIMPLE}Indication"),
                "sub_indication": t.findtext(f"{SIMPLE}SubIndication"),
            }
            for t in signature.findall(f"{SIMPLE}Timestamps/{SIMPLE}Timestamp")
        ],
        "errors": errors,
        "warnings": others,
        "signer_subject": signature.findtext(f"{SIMPLE}SignedBy"),
        "signer_subject_shown": signature.findtext(f"{SIMPLE}SignedBy") is not None,
        "signature_count": len(reported),
    }

    outcome = table["indications"].get(indication)
    if outcome is None:
        return TOOL_ERROR, True, None, {**signals, "problem": f"unmapped indication {indication}"}
    if outcome != "inspect_modifications":
        return outcome, False, f"indication-{indication}", signals

    allowed = set(table["allowed_modifications"])
    extensions = set(table["extension_modifications"])
    known = allowed | extensions | set(table["other_modifications"])
    unknown = sorted(set(modifications) - known)
    if unknown:
        return TOOL_ERROR, True, None, {**signals, "problem": f"unmapped modification {unknown}"}
    warnings = set(table["modification_warnings"])
    unknown = sorted(set(others) - warnings - set(table["informational_messages"]))
    if unknown or errors:
        return TOOL_ERROR, True, None, {**signals, "problem": f"unmapped message {unknown + errors}"}

    significant = set(modifications) - extensions
    if not significant and not warnings & set(others):
        return "VALID", False, "passed-no-modifications", signals
    if significant <= allowed and not warnings & set(others):
        return "VALID_WITH_ALLOWED_CHANGES", False, "passed-allowed-modifications", signals
    return "VALID_WITH_UNCLASSIFIED_CHANGES", False, "passed-other-modifications", signals


class DssAdapter:
    name = "dss"

    def __init__(self, mapping: dict, jar: Path = RUNNER_JAR):
        self.mapping = mapping
        self.jar = jar

    def version(self) -> dict | None:
        if shutil.which("java") is None or not self.jar.exists():
            return None
        result = subprocess.run(
            ["java", "-jar", str(self.jar), "--version"],
            capture_output=True,
            text=True,
            timeout=TIMEOUT_SECONDS,
        )
        if result.returncode != 0:
            return None
        details = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
        return {"version": details.get("dss"), "java": details.get("java")}

    def validate(self, case_id: str, pdf: Path, trust_anchor: Path, work_dir: Path) -> Observation:
        observation = Observation(
            case_id=case_id,
            tool=self.name,
            tool_version=(self.version() or {}).get("version"),
            options=list(OPTIONS),
            verdict=TOOL_ERROR,
            unmapped=False,
            rule=None,
            raw_output="",
            exit_code=None,
            fixture_sha256=sha256_file(pdf),
        )
        try:
            result = subprocess.run(
                ["java", "-jar", str(self.jar), str(pdf), str(trust_anchor), str(work_dir)],
                capture_output=True,
                text=True,
                timeout=TIMEOUT_SECONDS,
            )
        except (OSError, subprocess.SubprocessError) as error:
            observation.raw_output = f"{type(error).__name__}: {error}"
            observation.rule = "exception"
            return observation

        observation.exit_code = result.returncode
        if result.returncode != 0:
            observation.raw_output = f"--- stdout\n{result.stdout}--- stderr\n{result.stderr}"
            observation.rule = "exception"
            return observation

        simple_xml = (work_dir / "simple.xml").read_text(encoding="utf-8")
        diagnostic_xml = (work_dir / "diagnostic.xml").read_text(encoding="utf-8")
        observation.raw_output = f"{simple_xml}\n<!-- diagnostic data -->\n{diagnostic_xml}"
        (
            observation.verdict,
            observation.unmapped,
            observation.rule,
            observation.signals,
        ) = parse_reports(simple_xml, diagnostic_xml, self.mapping)
        return observation
