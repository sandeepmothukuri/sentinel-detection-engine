#!/usr/bin/env python3
"""
CI validation for sentinel-detection-engine rules.

Checks every YAML under Detections/ and Hunting Queries/:

  Schema
    1. Required fields present (id, name, description, query, tactics, relevantTechniques).
    2. id is a valid UUID; ids and names are globally unique.
    3. severity (detections) in {Informational, Low, Medium, High}.

  ATT&CK (against the vendored scripts/attack_data.json built from MITRE CTI)
    4. Every relevantTechniques id exists in the current enterprise ATT&CK
       matrix (revoked/deprecated techniques are excluded from the dataset,
       so referencing one fails).
    5. Rule tactics overlap the tactics of at least one referenced technique.

  Telemetry
    6. Every table used by the query is in the curated catalog, and the rule
       declares the connector + data types that produce it.

  Metadata (production quality bar)
    7. Detections require entityMappings, queryFrequency, queryPeriod, version,
       incidentConfiguration, eventGroupingSettings, and a metadata block with
       validationStatus, falsePositives, tuningGuidance, suppression.
    8. Hunts require a metadata block with hypothesis, requiredTelemetry,
       expectedFindings, investigationSteps, escalation, limitations.

  KQL
    9. kql_lint checks (brackets, quotes, invalid set operators, regex sanity,
       now() usage, truncation).

Stdlib + pyyaml.
"""
from __future__ import annotations

import json
import re
import sys
import uuid
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
import kql_lint  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
RULE_DIRS = [
    (REPO / "Detections", True),
    (REPO / "Hunting Queries", False),
]
ATTACK_DATA = Path(__file__).resolve().parent / "attack_data.json"

VALID_TACTICS = {
    "Reconnaissance", "ResourceDevelopment", "InitialAccess", "Execution",
    "Persistence", "PrivilegeEscalation", "DefenseEvasion", "CredentialAccess",
    "Discovery", "LateralMovement", "Collection", "CommandAndControl",
    "Exfiltration", "Impact",
}
VALID_SEVERITY = {"Informational", "Low", "Medium", "High"}
VALID_TECH_RE = re.compile(r"^T\d{4}(\.\d{3})?$")

# table -> (connector ids, data types)
TABLE_CATALOG: dict[str, tuple[list[str], list[str]]] = {
    "SigninLogs": (["AzureActiveDirectory"], ["SigninLogs"]),
    "AuditLogs": (["AzureActiveDirectory"], ["AuditLogs"]),
    "OfficeActivity": (["Office365"], ["OfficeActivity"]),
    "AzureActivity": (["AzureActivity"], ["AzureActivity"]),
    "AzureDiagnostics": (["AzureKeyVault", "AzureFirewall", "MicrosoftWebSites"], ["AzureDiagnostics"]),
    "DeviceProcessEvents": (["MicrosoftThreatProtection"], ["DeviceProcessEvents"]),
    "DeviceNetworkEvents": (["MicrosoftThreatProtection"], ["DeviceNetworkEvents"]),
    "DeviceInfo": (["MicrosoftThreatProtection"], ["DeviceInfo"]),
    "DeviceFileEvents": (["MicrosoftThreatProtection"], ["DeviceFileEvents"]),
    "DeviceRegistryEvents": (["MicrosoftThreatProtection"], ["DeviceRegistryEvents"]),
    "DeviceImageLoadEvents": (["MicrosoftThreatProtection"], ["DeviceImageLoadEvents"]),
    "DeviceLogonEvents": (["MicrosoftThreatProtection"], ["DeviceLogonEvents"]),
    "SecurityIncident": (["Sentinel"], ["SecurityIncident"]),
    "SecurityAlert": (["Sentinel"], ["SecurityAlert"]),
    "EmailEvents": (["Office365"], ["EmailEvents"]),
}

REQUIRED_DETECTION_FIELDS = {
    "entityMappings", "queryFrequency", "queryPeriod", "version",
    "incidentConfiguration", "eventGroupingSettings",
}
REQUIRED_DETECTION_METADATA = {"validationStatus", "falsePositives", "tuningGuidance", "suppression"}
REQUIRED_HUNT_METADATA = {
    "hypothesis", "requiredTelemetry", "expectedFindings",
    "investigationSteps", "escalation", "limitations",
}


def load_attack_dataset() -> dict:
    with open(ATTACK_DATA, encoding="utf-8") as fh:
        return json.load(fh)


def used_tables(query: str) -> set[str]:
    """Table names referenced as tabular expression starts in the query."""
    tables = set()
    cleaned, _ = kql_lint.strip_comments_and_strings(query)
    for line in cleaned.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("|"):
            continue
        first = stripped.split()[0].strip("|;")
        if first in TABLE_CATALOG:
            tables.add(first)
        else:
            m = re.search(r"\b(union|join)\s+(?:kind=\w+\s+)?(?:\w+\s*,\s*)?([A-Z][A-Za-z0-9_]*)\b", stripped)
            if m and m.group(2) in TABLE_CATALOG:
                tables.add(m.group(2))
    return tables


def normalize_attack_tactic(t: str) -> str:
    """Map ATT&CK CTI phase names (kebab-case, incl. the v18 renames) to the
    classic tactic vocabulary Microsoft Sentinel still uses in rule YAML.
    defense-impairment and stealth both fold into DefenseEvasion."""
    name = t.replace("-", "").lower()
    return {"defenseimpairment": "defenseevasion", "stealth": "defenseevasion"}.get(name, name)


def validate_attack(data: dict, attack_db: dict, errs: list[str]) -> None:
    tactics = {normalize_attack_tactic(t) for t in (data.get("tactics") or [])}
    for t in data.get("relevantTechniques") or []:
        tid = str(t)
        if not VALID_TECH_RE.match(tid):
            errs.append(f"bad ATT&CK technique id: {tid!r}")
            continue
        if tid not in attack_db:
            errs.append(f"technique {tid} not found in current ATT&CK matrix "
                        f"(revoked, deprecated, or invalid)")
            continue
        tech_tactics = {normalize_attack_tactic(t) for t in attack_db[tid]["tactics"]}
        if not tactics & tech_tactics:
            errs.append(f"tactic mismatch: {tid} ({attack_db[tid]['name']}) covers "
                        f"{sorted(tech_tactics)} but rule declares {sorted(tactics)}")


def validate_telemetry(data: dict, query: str, errs: list[str]) -> None:
    tables = used_tables(query)
    if not tables:
        errs.append("no known table found in query — confirm the source table "
                    "and add it to the TABLE_CATALOG")
        return
    declared_connectors = {c.get("connectorId") for c in data.get("requiredDataConnectors") or []}
    declared_types = set()
    for c in data.get("requiredDataConnectors") or []:
        declared_types.update(c.get("dataTypes") or [])
    for table in sorted(tables):
        connectors, datatypes = TABLE_CATALOG[table]
        if not declared_connectors & set(connectors):
            errs.append(f"table {table} requires connector {connectors} but rule declares "
                        f"{sorted(declared_connectors)}")
        if not declared_types & set(datatypes):
            errs.append(f"table {table} is produced by data types {datatypes} which are "
                        f"not declared in requiredDataConnectors")


def validate_file(path: Path, is_detection: bool, attack_db: dict) -> list[str]:
    errs: list[str] = []
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        return [f"YAML parse error: {exc}"]
    if not isinstance(data, dict):
        return ["top-level YAML is not a mapping"]

    required = {"id", "name", "description", "query", "tactics", "relevantTechniques"}
    missing = required - data.keys()
    if missing:
        errs.append(f"missing required fields: {sorted(missing)}")

    rid = str(data.get("id", ""))
    try:
        uuid.UUID(rid)
    except ValueError:
        errs.append(f"id is not a valid UUID: {rid!r}")

    if is_detection:
        sev = data.get("severity")
        if sev not in VALID_SEVERITY:
            errs.append(f"severity {sev!r} not in {sorted(VALID_SEVERITY)}")

    for tac in data.get("tactics") or []:
        if tac not in VALID_TACTICS:
            errs.append(f"unknown tactic: {tac!r}")

    techs = data.get("relevantTechniques") or []
    if not techs:
        errs.append("relevantTechniques is empty")

    validate_attack(data, attack_db, errs)

    query = data.get("query") or ""
    if not query.strip():
        errs.append("query is empty")
    else:
        errs.extend(kql_lint.lint(query, is_detection=is_detection))
        validate_telemetry(data, query, errs)

    metadata = data.get("metadata") or {}
    if is_detection:
        missing_meta = REQUIRED_DETECTION_FIELDS - data.keys()
        if missing_meta:
            errs.append(f"detection missing production fields: {sorted(missing_meta)}")
        miss = REQUIRED_DETECTION_METADATA - metadata.keys()
        if miss:
            errs.append(f"detection metadata missing: {sorted(miss)}")
        if not data.get("entityMappings"):
            errs.append("detection has no entityMappings")
    else:
        # Hunts carry hunt-specific fields at the top level.
        miss = REQUIRED_HUNT_METADATA - data.keys()
        if miss:
            errs.append(f"hunt metadata missing: {sorted(miss)}")

    return errs


def main() -> int:
    attack_db = load_attack_dataset()
    failed = 0
    total = 0
    seen_ids: dict[str, str] = {}
    seen_names: dict[str, str] = {}
    for d, is_det in RULE_DIRS:
        if not d.is_dir():
            continue
        for path in sorted(d.glob("*.yaml")):
            total += 1
            errs = validate_file(path, is_det, attack_db)
            try:
                data = yaml.safe_load(path.read_text(encoding="utf-8"))
            except yaml.YAMLError:
                data = {}
            rid = str(data.get("id", ""))
            name = str(data.get("name", ""))
            rel = path.relative_to(REPO).as_posix()
            if rid in seen_ids:
                errs.append(f"duplicate id {rid} (also in {seen_ids[rid]})")
            if name in seen_names:
                errs.append(f"duplicate name {name!r} (also in {seen_names[name]})")
            seen_ids[rid] = rel
            seen_names[name] = rel
            if errs:
                failed += 1
                for e in errs:
                    print(f"::error file={rel}::{e}")
            else:
                print(f"ok  {rel}")
    print(f"\n{total - failed}/{total} files passed validation "
          f"(ATT&CK dataset: {len(attack_db)} techniques).")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
