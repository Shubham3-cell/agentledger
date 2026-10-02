"""Load and validate detection-as-code rules.

Each rule is a YAML file in this folder describing a Microsoft Sentinel / KQL
detection plus its metadata (severity, MITRE ATT&CK mapping, data source). This
module checks that every rule is well-formed and mapped.

IMPLEMENTED HERE: structural + metadata validation of the rules, gated by CI.
NOT RUN HERE (external): the KQL itself executes inside Microsoft Sentinel against
real log tables (SigninLogs, AuditLogs, ...). We do not need Azure or any live
data to validate the rules — a malformed or unmapped rule simply can't ship.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import yaml

RULES_DIR = Path(__file__).resolve().parent
ALLOWED_SEVERITY = {"low", "medium", "high", "critical"}
ALLOWED_SOURCES = {"SigninLogs", "AuditLogs", "SecurityAlert", "SecurityIncident", "DeviceEvents"}
TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
REQUIRED = ("id", "title", "description", "severity", "mitre", "data_source", "query")


class RuleError(Exception):
    """Raised when a detection rule is malformed."""


@dataclass(frozen=True)
class Detection:
    id: str
    title: str
    severity: str
    tactic: str
    technique: str
    data_source: str
    query: str
    path: Path


def load_rules(rules_dir: Path = RULES_DIR) -> list[Detection]:
    """Load and validate every *.yml rule in the directory."""
    rules: list[Detection] = []
    for path in sorted(rules_dir.glob("*.yml")):
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        rules.append(validate_rule(raw, path))
    return rules


def validate_rule(raw: object, path: Path) -> Detection:
    if not isinstance(raw, dict):
        raise RuleError(f"{path.name}: file is not a YAML mapping")
    for field in REQUIRED:
        if field not in raw or raw[field] in (None, ""):
            raise RuleError(f"{path.name}: missing required field '{field}'")

    severity = str(raw["severity"]).lower()
    if severity not in ALLOWED_SEVERITY:
        raise RuleError(f"{path.name}: severity '{severity}' not in {sorted(ALLOWED_SEVERITY)}")

    mitre = raw["mitre"]
    if not isinstance(mitre, dict) or "technique" not in mitre or "tactic" not in mitre:
        raise RuleError(f"{path.name}: 'mitre' must contain 'tactic' and 'technique'")
    technique = str(mitre["technique"])
    if not TECHNIQUE_RE.match(technique):
        raise RuleError(
            f"{path.name}: MITRE technique '{technique}' is not a valid ATT&CK id (e.g. T1110.003)"
        )

    source = str(raw["data_source"])
    if source not in ALLOWED_SOURCES:
        raise RuleError(f"{path.name}: data_source '{source}' not in {sorted(ALLOWED_SOURCES)}")

    query = str(raw["query"]).strip()
    if source not in query:
        raise RuleError(f"{path.name}: query does not reference its data_source table '{source}'")
    if len(query) < 20:
        raise RuleError(f"{path.name}: query looks too short to be a real detection")

    return Detection(
        id=str(raw["id"]),
        title=str(raw["title"]),
        severity=severity,
        tactic=str(mitre["tactic"]),
        technique=technique,
        data_source=source,
        query=query,
        path=path,
    )


if __name__ == "__main__":
    loaded = load_rules()
    for d in loaded:
        print(f"OK  {d.id:<22} {d.severity:<8} {d.technique:<10} {d.data_source}")
    print(f"\n{len(loaded)} detection(s) valid.")
