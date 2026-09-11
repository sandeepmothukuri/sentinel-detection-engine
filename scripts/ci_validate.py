#!/usr/bin/env python3
"""
CI validation for sentinel-detection-engine rules and the validation ledger.

Every failure is reported as a GitHub annotation in the form

    ::error file=<path>::<rule name> | <field> | <problem> | expected: <expectation>

so the message says which file, which rule, which field, what is wrong, and what
would be right.

Checks
------
Schema
  1. Required fields present (id, name, description, query, tactics,
     relevantTechniques, kind for detections).
  2. id is a valid UUID; ids and names are globally unique.
  3. severity in {Informational, Low, Medium, High}; status in {Available}.
  4. version is semantic (a.b.c); name and description are substantive.
  5. kind is Scheduled or NRT (mandatory for analytics rules).

Scheduling
  6. queryFrequency / queryPeriod parse as KQL timespans, sit inside the platform
     range (5 minutes to 14 days), and satisfy frequency <= period. A period of
     2 days or more requires a frequency of at least 1 hour.

ATT&CK (against the vendored scripts/attack_data.json built from MITRE CTI)
  7. Every relevantTechniques id exists in the current enterprise matrix
     (revoked/deprecated techniques are excluded from the dataset, so referencing
     one fails).
  8. Rule tactics overlap the tactics of at least one referenced technique.

Telemetry
  9. Every table used by the query is in the curated catalog, and the rule
     declares the connector + data type that produces it.

Entity mapping
 10. Entity identifiers are real for their entity type, and every mapped column
     is produced by the query. Sentinel cannot entity-map an array, so a mapped
     column must not be a make_set/make_list/make_bag output.

Alert details
 11. alertDetailsOverride placeholders reference columns the query produces.

Metadata (production quality bar)
 12. Detections require entityMappings, queryFrequency, queryPeriod, version,
     incidentConfiguration, eventGroupingSettings, and a metadata block with
     validationStatus, falsePositives, tuningGuidance, suppression.
 13. Hunts require hypothesis, requiredTelemetry, expectedFindings,
     investigationSteps, escalation and limitations.

KQL
 14. kql_lint checks (brackets, quotes, invalid set operators, regex sanity,
     now() usage, truncation) plus an explicit time bound.

Validation ledger (tests/validation/atomics.yaml)
 15. Every rule has exactly one ledger entry and vice versa.
 16. status is from the closed vocabulary; an entry may not claim SIMULATED or
     VALIDATED IN LIVE TENANT without dated, non-placeholder evidence.
 17. Every cited Atomic Test Index exists upstream for that technique
     (scripts/atomic_data.json), and the technique is one the rule declares.
 18. Every rule has a trigger-role atomic or a manual procedure.

Stdlib + pyyaml.
"""
from __future__ import annotations

import argparse
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
ATOMIC_DATA = Path(__file__).resolve().parent / "atomic_data.json"
LEDGER = REPO / "tests" / "validation" / "atomics.yaml"
SCHEMA_VERSION = "1.0"

VALID_TACTICS = {
    "Reconnaissance", "ResourceDevelopment", "InitialAccess", "Execution",
    "Persistence", "PrivilegeEscalation", "DefenseEvasion", "CredentialAccess",
    "Discovery", "LateralMovement", "Collection", "CommandAndControl",
    "Exfiltration", "Impact",
}
VALID_SEVERITY = {"Informational", "Low", "Medium", "High"}
VALID_STATUS = {"Available", "InDevelopment"}
VALID_KIND = {"Scheduled", "NRT"}
VALID_TRIGGER_OPERATOR = {"gt", "lt", "eq"}
VALID_TECH_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
VALID_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")
TIMESPAN_RE = re.compile(r"^(\d+)(d|h|m|s)$")

# Platform limits for scheduled analytics rules (Microsoft Sentinel).
MIN_FREQUENCY_S = 5 * 60
MAX_PERIOD_S = 14 * 24 * 60 * 60
LONG_PERIOD_S = 2 * 24 * 60 * 60
LONG_PERIOD_MIN_FREQUENCY_S = 60 * 60

# Whole-word markers, so that a legitimate KQL function such as todouble() is not
# mistaken for a TODO comment.
PLACEHOLDER_PATTERNS = (
    r"\btodo\b", r"\bfixme\b", r"\bxxx+\b", r"\bhack\b", r"\bchangeme\b",
    r"\breplace[-_ ]?me\b", r"\byour[-_ ]tenant\b", r"\byour[-_ ]workspace\b",
    r"\bplaceholder\b", r"\bnot implemented\b", r"\bcoming soon\b",
    r"\blorem ipsum\b", r"<tbd>", r"\bdummy\b", r"\bfake\b",
)

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

# Documented Sentinel entity identifiers (identifier column in the entity-mapping
# table). An identifier outside this map is rejected rather than silently
# deploying a mapping Sentinel will drop.
ENTITY_IDENTIFIERS: dict[str, set[str]] = {
    "Account": {
        "AadUserId", "PUID", "Sid", "ObjectGuid", "FullName", "Name", "NTDomain",
        "UPN", "UPNSuffix", "DisplayName", "AadTenantId", "CloudAppAccountId",
    },
    "Host": {
        "HostName", "FullName", "DnsDomain", "NTDomain", "AzureID", "OMSAgentID",
        "OsFamily", "NetBiosName", "AadDeviceId",
    },
    "IP": {"Address"},
    "URL": {"Url"},
    "File": {"Name", "Directory", "FullPath"},
    "FileHash": {"Algorithm", "Value"},
    "Process": {"ProcessId", "CommandLine", "ElevationToken", "CreationTimeUtc", "ImageFile", "Name"},
    "CloudApplication": {"AppId", "Name", "InstanceName"},
    "AzureResource": {"ResourceId"},
    "Mailbox": {"MailboxPrimaryAddress", "DisplayName", "Upn", "ExternalDirectoryObjectId"},
    "MailMessage": {
        "NetworkMessageId", "Recipient", "Sender", "Subject", "DeliveryAction",
        "ThreatDetectionMethods", "InternetMessageId", "P1Sender",
        "P1SenderDomain", "P1SenderDisplayName", "P2Sender", "P2SenderDomain",
        "P2SenderDisplayName", "SenderIP", "Urls", "Severity", "RecipientDomain",
    },
    "DNS": {"DomainName"},
    "RegistryKey": {"Hive", "Key"},
    "RegistryValue": {"Name", "Value", "Key"},
    "SecurityGroup": {"DistinguishedName", "SID", "ObjectGuid"},
    "OAuthApplication": {"AppId", "Name", "ObjectId"},
    "Malware": {"Name", "Category"},
    "SubmissionMail": {
        "NetworkMessageId", "SubmissionId", "Submitter", "Recipient", "Sender",
        "SenderIp", "Subject",
    },
}

REQUIRED_DETECTION_FIELDS = {
    "entityMappings", "queryFrequency", "queryPeriod", "version",
    "incidentConfiguration", "eventGroupingSettings", "kind",
}
REQUIRED_DETECTION_METADATA = {"validationStatus", "falsePositives", "tuningGuidance", "suppression"}
REQUIRED_HUNT_METADATA = {
    "hypothesis", "requiredTelemetry", "expectedFindings",
    "investigationSteps", "escalation", "limitations",
}

ARRAY_PRODUCERS = ("make_set", "make_list", "make_bag", "make_set_if", "make_list_if", "make_bag_if")


class Report:
    """Collects findings so every problem in a file is reported, not just the first."""

    def __init__(self, path: Path, rule_name: str = "") -> None:
        try:
            self.path = path.relative_to(REPO).as_posix()
        except ValueError:
            # Temp fixtures used by the negative test suite live outside the repo.
            self.path = path.name
        self.rule_name = rule_name
        self.errors: list[str] = []

    def add(self, field: str, problem: str, expected: str) -> None:
        self.errors.append(
            f"{self.rule_name or '(unnamed)'} | {field} | {problem} | expected: {expected}"
        )

    @property
    def failed(self) -> bool:
        return bool(self.errors)


def load_attack_dataset() -> dict:
    with open(ATTACK_DATA, encoding="utf-8") as fh:
        return json.load(fh)


def load_atomic_dataset() -> dict:
    with open(ATOMIC_DATA, encoding="utf-8") as fh:
        return json.load(fh)


def timespan_to_seconds(value: str) -> int | None:
    m = TIMESPAN_RE.match(str(value).strip())
    if not m:
        return None
    n, unit = int(m.group(1)), m.group(2)
    return n * {"d": 86400, "h": 3600, "m": 60, "s": 1}[unit]


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


def projected_columns(query: str) -> set[str]:
    """Column-ish tokens the query mentions. Used for mapping/override checks."""
    cleaned, strings = kql_lint.strip_comments_and_strings(query)
    cols = set(re.findall(r"\b([A-Z][A-Za-z0-9_]{2,})\b", cleaned))
    cols.update(strings)
    return cols


def array_valued_columns(query: str) -> set[str]:
    """Columns bound to an array-producing aggregate: `X = make_set(...)`."""
    cleaned, _ = kql_lint.strip_comments_and_strings(query)
    out = set()
    for producer in ARRAY_PRODUCERS:
        for m in re.finditer(rf"\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*{producer}\s*\(", cleaned):
            out.add(m.group(1))
    return out


def normalize_attack_tactic(t: str) -> str:
    """Map ATT&CK CTI phase names (kebab-case, including the v19 split) to the
    classic tactic vocabulary Microsoft Sentinel still uses in rule YAML.
    defense-impairment and stealth both fold into DefenseEvasion."""
    name = t.replace("-", "").lower()
    return {"defenseimpairment": "defenseevasion", "stealth": "defenseevasion"}.get(name, name)


def validate_attack(data: dict, attack_db: dict, rep: Report) -> None:
    tactics = {normalize_attack_tactic(t) for t in (data.get("tactics") or [])}
    for t in data.get("relevantTechniques") or []:
        tid = str(t)
        if not VALID_TECH_RE.match(tid):
            rep.add("relevantTechniques", f"{tid!r} is not a well-formed ATT&CK id",
                    "T#### or T####.### (for example T1059.001)")
            continue
        if tid not in attack_db:
            rep.add("relevantTechniques",
                    f"{tid} does not exist in the current ATT&CK matrix "
                    f"(revoked, deprecated, or invalid)",
                    "a non-deprecated technique id from the current enterprise matrix")
            continue
        tech_tactics = {normalize_attack_tactic(t) for t in attack_db[tid]["tactics"]}
        if not tactics & tech_tactics:
            rep.add("tactics",
                    f"{tid} ({attack_db[tid]['name']}) covers {sorted(tech_tactics)} "
                    f"but the rule declares {sorted(tactics)}",
                    f"one of {sorted(tech_tactics)} added to tactics, or a technique that "
                    f"covers {sorted(tactics)}")


def validate_schedule(data: dict, rep: Report) -> None:
    if data.get("kind") == "NRT":
        ban = timespan_to_seconds("1m")
        if ban:  # NRT rules have no queryFrequency/queryPeriod requirement
            return
    freq_raw, period_raw = data.get("queryFrequency"), data.get("queryPeriod")
    freq = timespan_to_seconds(freq_raw) if freq_raw is not None else None
    period = timespan_to_seconds(period_raw) if period_raw is not None else None

    if freq is None:
        rep.add("queryFrequency", f"{freq_raw!r} is not a KQL timespan",
                "a KQL timespan such as 5m, 15m, 1h, 1d")
    elif not MIN_FREQUENCY_S <= freq <= MAX_PERIOD_S:
        rep.add("queryFrequency", f"{freq_raw} is outside the platform range",
                "between 5m and 14d")

    if period is None:
        rep.add("queryPeriod", f"{period_raw!r} is not a KQL timespan",
                "a KQL timespan such as 1h, 1d, 14d")
        return
    if period > MAX_PERIOD_S:
        rep.add("queryPeriod", f"{period_raw} exceeds the platform maximum lookback",
                "14d or less (Sentinel rejects a longer queryPeriod on a scheduled rule)")
    if freq is not None and freq > period:
        rep.add("queryFrequency",
                f"{freq_raw} is longer than queryPeriod {period_raw}, which leaves gaps",
                "a queryFrequency less than or equal to the queryPeriod")
    if period >= LONG_PERIOD_S and freq is not None and freq < LONG_PERIOD_MIN_FREQUENCY_S:
        rep.add("queryFrequency",
                f"{freq_raw} is too frequent for a queryPeriod of {period_raw}",
                "at least 1h when the queryPeriod is 2d or more")

    op = data.get("triggerOperator")
    if op is not None and op not in VALID_TRIGGER_OPERATOR:
        rep.add("triggerOperator", f"{op!r} is not a supported operator",
                "one of gt, lt, eq")
    thr = data.get("triggerThreshold")
    if thr is not None and (not isinstance(thr, int) or isinstance(thr, bool) or not 0 <= thr <= 10000):
        rep.add("triggerThreshold", f"{thr!r} is not a usable threshold",
                "an integer between 0 and 10000")


def validate_telemetry(data: dict, query: str, rep: Report) -> None:
    tables = used_tables(query)
    if not tables:
        rep.add("query", "no known table is read by the query",
                "a source table from the connector catalog, or add the new table to TABLE_CATALOG")
        return
    declared_connectors = {c.get("connectorId") for c in data.get("requiredDataConnectors") or []}
    declared_types = set()
    for c in data.get("requiredDataConnectors") or []:
        declared_types.update(c.get("dataTypes") or [])
    for table in sorted(tables):
        connectors, datatypes = TABLE_CATALOG[table]
        if not declared_connectors & set(connectors):
            rep.add("requiredDataConnectors",
                    f"query reads {table} but no connector that produces it is declared "
                    f"(declared: {sorted(declared_connectors)})",
                    f"one of {connectors}")
        if not declared_types & set(datatypes):
            rep.add("requiredDataConnectors.dataTypes",
                    f"query reads {table} but its data types {datatypes} are not declared",
                    f"one of {datatypes}")


def validate_entity_mappings(data: dict, query: str, rep: Report) -> None:
    if not data.get("entityMappings"):
        rep.add("entityMappings", "no entity mappings are declared",
                "at least one entity mapping so incidents carry investigable entities")
        return
    columns = projected_columns(query)
    arrays = array_valued_columns(query)
    for mapping in data.get("entityMappings") or []:
        etype = mapping.get("entityType")
        if etype not in ENTITY_IDENTIFIERS:
            rep.add("entityMappings.entityType", f"{etype!r} is not a Sentinel entity type",
                    f"one of {sorted(ENTITY_IDENTIFIERS)}")
            continue
        for fm in mapping.get("fieldMappings") or []:
            ident = fm.get("identifier")
            col = fm.get("columnName")
            if ident not in ENTITY_IDENTIFIERS[etype]:
                rep.add(f"entityMappings[{etype}].identifier",
                        f"{ident!r} is not a valid identifier for entity type {etype}",
                        f"one of {sorted(ENTITY_IDENTIFIERS[etype])}")
            if not col:
                rep.add(f"entityMappings[{etype}].columnName", "missing columnName",
                        "the name of a column the query produces")
                continue
            if col not in columns:
                rep.add(f"entityMappings[{etype}].columnName",
                        f"{col!r} is not produced by the query",
                        "a column present in the query output")
            elif col in arrays:
                rep.add(f"entityMappings[{etype}].columnName",
                        f"{col!r} is an array (make_set/make_list output); Sentinel "
                        f"cannot entity-map arrays and drops the mapping silently",
                        "a scalar column, for example tostring(array[0]) or any(column)")


def final_projection(query: str) -> str | None:
    """Column list of the last `project` clause, or None if the query has none."""
    cleaned, _ = kql_lint.strip_comments_and_strings(query)
    matches = list(re.finditer(r"\|\s*project\s+(.+)", cleaned))
    if not matches:
        return None
    return matches[-1].group(1)


def validate_alert_details(data: dict, query: str, rep: Report) -> None:
    override = data.get("alertDetailsOverride")
    if not override:
        return
    columns = projected_columns(query)
    for field in ("alertDisplayNameFormat", "alertDescriptionFormat"):
        text = override.get(field)
        if not text:
            continue
        for placeholder in re.findall(r"\{\{\s*([A-Za-z0-9_]+)\s*\}\}", text):
            if placeholder not in columns:
                rep.add(f"alertDetailsOverride.{field}",
                        f"placeholder {{{{{placeholder}}}}} is not a column the query produces",
                        "a column present in the query output")


def validate_metadata(data: dict, is_detection: bool, rep: Report) -> None:
    metadata = data.get("metadata") or {}
    if is_detection:
        missing_meta = REQUIRED_DETECTION_METADATA - metadata.keys()
        if missing_meta:
            rep.add("metadata", f"missing keys {sorted(missing_meta)}",
                    f"all of {sorted(REQUIRED_DETECTION_METADATA)}")
        if not metadata.get("falsePositives") or len(str(metadata.get("falsePositives"))) < 20:
            rep.add("metadata.falsePositives",
                    "false-positive analysis is absent or too thin to be useful",
                    "the concrete benign behaviours that will generate this alert")
        if not metadata.get("tuningGuidance") or len(str(metadata.get("tuningGuidance"))) < 20:
            rep.add("metadata.tuningGuidance",
                    "tuning guidance is absent or too thin to be usable",
                    "the named thresholds or allow-lists an analyst should change")
        author = str(metadata.get("author", "")).strip()
        if not author:
            rep.add("metadata.author", "no author recorded", "the rule owner's name")
        elif re.search(r"@|claude|gpt|copilot|openai|anthropic|\bai\b", author, re.I):
            rep.add("metadata.author", f"author {author!r} is not an individual owner",
                    "the human maintainer responsible for the rule")
    else:
        miss = REQUIRED_HUNT_METADATA - data.keys()
        if miss:
            rep.add("(hunt)", f"missing keys {sorted(miss)}",
                    f"all of {sorted(REQUIRED_HUNT_METADATA)}")
        author = str(metadata.get("author", "")).strip()
        if not author:
            rep.add("metadata.author", "no author recorded",
                    "the rule owner's name, so the hunt has a maintainer")
        elif re.search(r"@|claude|gpt|copilot|openai|anthropic|\bai\b", author, re.I):
            rep.add("metadata.author", f"author {author!r} is not an individual owner",
                    "the human maintainer responsible for the hunt")
        if not metadata.get("validationStatus"):
            rep.add("metadata.validationStatus", "hunt has no validation status",
                    "one of static-validation / simulated / validated-live-tenant / not-yet-validated")


def validate_content_hygiene(data: dict, path: Path, rep: Report) -> None:
    name = str(data.get("name", ""))
    if len(name) > 100:
        rep.add("name", f"name is {len(name)} characters",
                "100 characters or fewer, so it stays readable in the incident queue")
    description = str(data.get("description", ""))
    if len(description.strip()) < 40:
        rep.add("description", "description is too short to explain the detection",
                "what fires, why it matters, and what the attacker is doing")

    # Only the prose fields are scanned: KQL legitimately contains tokens such as
    # `todouble`, and the query is already covered by kql_lint plus the explicit
    # placeholder rules below.
    blob = "\n".join(str(data.get(f, "")) for f in ("name", "description")).lower()
    for pattern in PLACEHOLDER_PATTERNS:
        m = re.search(pattern, blob)
        if m:
            rep.add("(content)", f"contains placeholder text {m.group(0)!r}",
                    "final content with no scaffolding left behind")


def validate_file(path: Path, is_detection: bool, attack_db: dict) -> tuple[list[str], str]:
    """Validate one rule file. Returns (errors, rule name)."""
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        rep = Report(path)
        rep.add("(yaml)", f"YAML parse error: {exc}", "well-formed YAML")
        return rep.errors, ""
    if not isinstance(data, dict):
        rep = Report(path)
        rep.add("(yaml)", "top-level YAML is not a mapping", "a mapping of rule fields")
        return rep.errors, ""

    rep = Report(path, str(data.get("name", "")))

    required = {"id", "name", "description", "query", "tactics", "relevantTechniques"}
    missing = required - data.keys()
    if missing:
        rep.add("(schema)", f"missing required fields {sorted(missing)}",
                f"all of {sorted(required)}")

    rid = str(data.get("id", ""))
    try:
        uuid.UUID(rid)
    except ValueError:
        rep.add("id", f"{rid!r} is not a valid UUID",
                "a UUID4 (for example 8a9d3f0c-1b2e-4d6a-9c11-7f4e0c2b8a01)")

    if is_detection:
        sev = data.get("severity")
        if sev not in VALID_SEVERITY:
            rep.add("severity", f"{sev!r} is not a Sentinel severity",
                    f"one of {sorted(VALID_SEVERITY)}")
        status = data.get("status")
        if status not in VALID_STATUS:
            rep.add("status", f"{status!r} is not a valid rule status",
                    f"one of {sorted(VALID_STATUS)}")
        kind = data.get("kind")
        if kind not in VALID_KIND:
            rep.add("kind", f"{kind!r} is missing or invalid — Sentinel requires this field "
                            f"on an analytics rule",
                    "kind: Scheduled (or NRT)")
        version = data.get("version")
        if version is None:
            rep.add("version", "missing version",
                    "a semantic version such as 1.0.0")
        elif not VALID_VERSION_RE.match(str(version)):
            rep.add("version", f"{version!r} is not a semantic version",
                    "a version of the form major.minor.patch, for example 1.1.0")
        missing_fields = REQUIRED_DETECTION_FIELDS - data.keys()
        if missing_fields:
            rep.add("(schema)", f"detection missing production fields {sorted(missing_fields)}",
                    "all of " + ", ".join(sorted(REQUIRED_DETECTION_FIELDS)))
        validate_schedule(data, rep)
        incident = data.get("incidentConfiguration") or {}
        if incident.get("createIncident") is not True:
            rep.add("incidentConfiguration.createIncident", f"{incident.get('createIncident')!r}",
                    "true for an alerting detection")
        grouping = incident.get("groupingConfiguration") or {}
        if grouping.get("enabled") and grouping.get("matchingMethod") == "Selected":
            groups = grouping.get("groupByEntities") or []
            if not groups:
                rep.add("incidentConfiguration.groupingConfiguration.groupByEntities",
                        "matchingMethod is Selected but no groupByEntities are listed",
                        "at least one entity type, or matchingMethod: AllEntities")
    else:
        version = data.get("version")
        if version is not None and not VALID_VERSION_RE.match(str(version)):
            rep.add("version", f"{version!r} is not a semantic version",
                    "a version of the form major.minor.patch")

    for tac in data.get("tactics") or []:
        if tac not in VALID_TACTICS:
            rep.add("tactics", f"{tac!r} is not a Sentinel tactic name",
                    f"one of {sorted(VALID_TACTICS)}")

    techniques = data.get("relevantTechniques") or []
    if not techniques:
        rep.add("relevantTechniques", "no techniques declared",
                "at least one ATT&CK technique id")

    validate_attack(data, attack_db, rep)

    query = data.get("query") or ""
    if not query.strip():
        rep.add("query", "query is empty", "the KQL the rule evaluates")
    else:
        for issue in kql_lint.lint(query, is_detection=is_detection):
            rep.add("query", issue, "valid KQL following the house style")
        validate_telemetry(data, query, rep)
        if is_detection and "TimeGenerated" not in query:
            rep.add("query", "scheduled rules must return TimeGenerated, which the "
                             "platform uses as the lookback reference",
                    "a projection or filter that carries TimeGenerated into the results")
        if is_detection:
            final = final_projection(query)
            if final is not None and not re.search(r"(^|,\s*)TimeGenerated\b", final):
                rep.add("query", "the final project clause drops TimeGenerated, so the "
                                 "alert has no event-time column for the platform to anchor on",
                        "TimeGenerated (or a column aliased to it, e.g. "
                        "`TimeGenerated = max(TimeGenerated)`) in the final projection")
        if not re.search(r"\bago\s*\(", query):
            rep.add("query", "no explicit time bound (ago(...)) in the query",
                    "an explicit ago() bound so the evaluated window is unambiguous")

    validate_entity_mappings(data, query, rep) if is_detection else None
    validate_alert_details(data, query, rep)
    validate_metadata(data, is_detection, rep)
    validate_content_hygiene(data, path, rep)
    return rep.errors, str(data.get("name", ""))


# --------------------------------------------------------------------- ledger
def load_ledger() -> dict:
    """Read the validation ledger. Separated so tests can substitute a ledger."""
    if not LEDGER.exists():
        return {}
    return yaml.safe_load(LEDGER.read_text(encoding="utf-8")) or {}


def validate_ledger(attack_db: dict, atomic_db: dict, rules: dict[str, dict]) -> list[tuple[str, list[str]]]:
    """rules: file stem -> {'name', 'techniques', 'is_detection'}. Returns per-file errors."""
    if not LEDGER.exists():
        return [(str(LEDGER.relative_to(REPO)), ["(ledger) | file is missing | expected: a validation ledger"])]

    rel = LEDGER.relative_to(REPO).as_posix()
    errors: list[str] = []
    try:
        ledger = load_ledger()
    except yaml.YAMLError as exc:
        return [(rel, [f"(ledger) | YAML parse error: {exc} | expected: well-formed YAML"])]

    for key in ("schema_version", "last_reviewed", "source"):
        if not ledger.get(key):
            errors.append(f"(ledger) | {key} | document level key is missing | "
                          f"expected: {key} in tests/validation/atomics.yaml")
    if ledger.get("schema_version") and ledger["schema_version"] != SCHEMA_VERSION:
        errors.append(f"(ledger) | schema_version | {ledger['schema_version']!r} does not match the "
                      f"schema in tests/validation/validation-schema.yaml | "
                      f"expected: {SCHEMA_VERSION}")
    if ledger.get("last_reviewed") and not re.match(r"^20\d{2}-\d{2}-\d{2}$", str(ledger["last_reviewed"])):
        errors.append(f"(ledger) | last_reviewed | {ledger['last_reviewed']!r} is not an ISO date | "
                      f"expected: YYYY-MM-DD")

    entries = ledger.get("rules") or []
    seen: set[str] = set()
    ast = sorted(attack_db)
    for entry in entries:
        stem = str(entry.get("rule", ""))
        prefix = f"{stem}"
        if not stem:
            errors.append("(ledger) | entry without a rule name | expected: a rule file stem")
            continue
        if stem not in rules:
            errors.append(f"{prefix} | rule | no such rule file under Detections/ or Hunting Queries/ "
                          f"| expected: one of the {len(rules)} rule file stems")
            continue
        if stem in seen:
            errors.append(f"{prefix} | rule | duplicate ledger entry | expected: exactly one entry per rule")
        seen.add(stem)

        status = entry.get("status")
        if status not in {"STATIC VALIDATION", "SIMULATED", "VALIDATED IN LIVE TENANT", "NOT YET VALIDATED"}:
            errors.append(f"{prefix} | status | {status!r} is outside the closed vocabulary | "
                          f"expected: STATIC VALIDATION, SIMULATED, VALIDATED IN LIVE TENANT or NOT YET VALIDATED")

        evidence = " ".join(str(entry.get("evidence", "")).split())
        if len(evidence) < 8:
            errors.append(f"{prefix} | evidence | evidence is missing or trivial | "
                          f"expected: what actually backs the recorded status")
        if status in {"SIMULATED", "VALIDATED IN LIVE TENANT"}:
            if not re.search(r"\b20\d{2}-\d{2}-\d{2}\b", evidence):
                errors.append(f"{prefix} | evidence | status {status} without a dated evidence reference | "
                              f"expected: an ISO date plus an incident number or workspace reference")
            if status == "VALIDATED IN LIVE TENANT" and not re.search(r"INC-?\d+|incident\s*\d+|incident number", evidence, re.I):
                errors.append(f"{prefix} | evidence | status VALIDATED IN LIVE TENANT without an incident reference | "
                              f"expected: the incident number the rule produced")
        elif re.search(r"INC-?\d+", evidence):
            errors.append(f"{prefix} | evidence | status {status} but the evidence cites an incident number | "
                          f"expected: no incident reference unless the status is SIMULATED or "
                          f"VALIDATED IN LIVE TENANT")

        checks = entry.get("checks")
        if checks is None:
            errors.append(f"{prefix} | checks | key is missing | "
                          f"expected: a list (may be empty only with a manual_procedure)")
            checks = []

        declared = set(rules[stem]["techniques"])
        has_trigger = any(c.get("role") == "trigger" for c in checks)
        for c in checks:
            tech = str(c.get("technique", ""))
            if not VALID_TECH_RE.match(tech) or tech not in ast:
                errors.append(f"{prefix} | checks.technique | {tech!r} is not a valid current ATT&CK id | "
                              f"expected: a non-deprecated technique id")
                continue
            if tech not in declared:
                errors.append(f"{prefix} | checks.technique | {tech} is not declared by this rule | "
                              f"expected: one of {sorted(declared)}")
            role = c.get("role")
            if role not in {"trigger", "precondition", "partial"}:
                errors.append(f"{prefix} | checks.role | {role!r} is not a valid role | "
                              f"expected: trigger, precondition or partial")
            if role == "partial" and not c.get("note"):
                errors.append(f"{prefix} | checks.note | a partial mapping must state what it does not cover | "
                              f"expected: a note explaining the gap")
            index = c.get("atomic")
            if index is None:
                continue
            available = atomic_db.get("techniques", {}).get(tech)
            if not available:
                errors.append(f"{prefix} | checks.atomic | {tech}-{index} is cited but Atomic Red Team has "
                              f"no atomics for {tech} | expected: remove the atomic and document a manual "
                              f"procedure instead")
                continue
            if not isinstance(index, int) or not any(a["index"] == index for a in available):
                valid = [a["index"] for a in available]
                errors.append(f"{prefix} | checks.atomic | {tech}-{index} does not exist upstream | "
                              f"expected: one of {valid} for {tech}")

        if not has_trigger and not entry.get("manual_procedure"):
            errors.append(f"{prefix} | checks | no trigger-role atomic and no manual procedure | "
                          f"expected: at least one of the two, so the rule can actually be validated")

    for stem in rules:
        if stem not in seen:
            errors.append(f"{stem} | rule | no ledger entry | "
                          f"expected: an entry in tests/validation/atomics.yaml")
    return [(rel, errors)] if errors else []


def collect_rule_index(attack_db: dict) -> tuple[dict[str, dict], int, int, list[tuple[str, str, list[str]]]]:
    """Validate every rule file. Returns the index, counts and per-file failures."""
    failed = 0
    total = 0
    rule_index: dict[str, dict] = {}
    seen_ids: dict[str, str] = {}
    seen_names: dict[str, str] = {}
    failures: list[tuple[str, str, list[str]]] = []

    for d, is_det in RULE_DIRS:
        if not d.is_dir():
            continue
        for path in sorted(d.glob("*.yaml")):
            total += 1
            errs, name = validate_file(path, is_det, attack_db)
            try:
                data = yaml.safe_load(path.read_text(encoding="utf-8"))
            except yaml.YAMLError:
                data = {}
            if not isinstance(data, dict):
                data = {}
            rid = str(data.get("id", ""))
            rel = path.relative_to(REPO).as_posix()
            if rid in seen_ids:
                errs.append(f"{name or path.stem} | id | duplicate id {rid} "
                            f"| expected: a unique UUID (also used in {seen_ids[rid]})")
            if name in seen_names and name:
                errs.append(f"{name} | name | duplicate rule name "
                            f"| expected: a unique display name (also used in {seen_names[name]})")
            seen_ids[rid] = rel
            if name:
                seen_names[name] = rel
            rule_index[path.stem] = {
                "name": name,
                "techniques": [str(t) for t in (data.get("relevantTechniques") or [])],
                "is_detection": is_det,
            }
            if errs:
                failed += 1
                failures.append((rel, name, errs))
            else:
                print(f"ok  {rel}")
    return rule_index, total, failed, failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate detection content, KQL, metadata and the validation ledger."
    )
    parser.add_argument("--ledger-only", action="store_true",
                        help="check only the validation ledger and its atomic citations")
    args = parser.parse_args(argv)

    attack_db = load_attack_dataset()
    atomic_db = load_atomic_dataset()

    if args.ledger_only:
        # The ledger is the record of what has and has not been validated, so it can be
        # gated on its own in a separate CI step with a clearer failure message.
        rule_index = {
            path.stem: {
                "name": str((yaml.safe_load(path.read_text(encoding="utf-8")) or {}).get("name", "")),
                "techniques": [
                    str(t) for t in
                    ((yaml.safe_load(path.read_text(encoding="utf-8")) or {}).get("relevantTechniques") or [])
                ],
                "is_detection": is_det,
            }
            for d, is_det in RULE_DIRS if d.is_dir()
            for path in sorted(d.glob("*.yaml"))
        }
        ledger_failures = validate_ledger(attack_db, atomic_db, rule_index)
        for rel, errs in ledger_failures:
            for e in errs:
                print(f"::error file={rel}::{e}")
        print(f"ledger: {len(rule_index)} rules, "
              f"{'OK' if not ledger_failures else f'{len(ledger_failures)} failing file(s)'}")
        return 1 if ledger_failures else 0

    rule_index, total, failed, failures = collect_rule_index(attack_db)
    for rel, _, errs in failures:
        for e in errs:
            print(f"::error file={rel}::{e}")

    ledger_failures = validate_ledger(attack_db, atomic_db, rule_index)
    for rel, errs in ledger_failures:
        failed += 1
        for e in errs:
            print(f"::error file={rel}::{e}")

    print(f"\n{total - failed}/{total} rule files passed validation "
          f"(ATT&CK dataset: {len(attack_db)} techniques; "
          f"atomic dataset: {len(atomic_db.get('techniques', {}))} techniques with atomics; "
          f"ledger entries: {len(rule_index)}).")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
