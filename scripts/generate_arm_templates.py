#!/usr/bin/env python3
"""Generate ARM deployment templates from the rule YAML.

Why this exists
---------------
Microsoft Sentinel Repositories (the CI/CD connection between a Git repository
and a workspace) deploys **Bicep or ARM templates**, not the analytics-rule YAML
that is used for authoring. Pointing a repository connection at `Detections/`
and expecting it to sync does not work — the files have to be converted first.
Microsoft's own sample content ships a PowerShell converter
(`ConvertAnalyticsRuleFromYamlToArm.ps1`) for exactly this reason; this script is
the reviewable, tested equivalent, and it runs in CI so the output cannot drift
from the rules.

What it emits
-------------
    deploy/analytic-rules/<rule>.json     Microsoft.OperationalInsights/workspaces/providers/alertRules
    deploy/hunting-queries/<hunt>.json    Microsoft.OperationalInsights/workspaces/savedSearches

The resource shape follows the reference converter: one resource per file, a
`workspace` string parameter, the resource name built from the workspace plus the
Microsoft.SecurityInsights provider, ISO-8601 durations, and PascalCase trigger
operators.

Deliberate differences from the reference converter
---------------------------------------------------
* The alert-rule resource name uses the rule's **committed `id`** rather than a
  freshly generated GUID. Re-running the conversion produces the same deployment
  name, so a repository connection updates a rule instead of creating a second
  copy of it.
* The `metadata:` block is **not** copied. It is authoring documentation
  (false-positive notes, tuning guidance, validation status) and is not a valid
  property of an alert rule; a template that carried it would be rejected.

What this does not do: prove the deployment works. No template here has been
deployed to a tenant. That is a deployment-time action, and the templates are
validated structurally — not by Azure — before they leave this repository.

Usage
-----
    python scripts/generate_arm_templates.py            # write deploy/
    python scripts/generate_arm_templates.py --check     # fail if deploy/ is stale
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent.parent
DETECTIONS = REPO / "Detections"
HUNTS = REPO / "Hunting Queries"
OUT = REPO / "deploy"

SCHEMA = "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#"
CONTENT_VERSION = "1.0.0.0"

# https://learn.microsoft.com/azure/templates/microsoft.operationalinsights/workspaces/providers/alertrules
ALERT_RULE_API = "2020-01-01"
# https://learn.microsoft.com/azure/templates/microsoft.operationalinsights/workspaces/savedsearches
SAVED_SEARCH_API = "2020-08-01"

TRIGGER_OPERATORS = {"gt": "GreaterThan", "lt": "LessThan", "eq": "Equal", "ne": "NotEqual"}

# Every property the generator is allowed to emit for an alert rule. Anything a
# rule file carries beyond this list is authoring metadata and must not leak into
# the template; tests/test_arm_templates.py enforces this.
ALERT_RULE_PROPERTY_KEYS = {
    "displayName", "description", "severity", "enabled", "query",
    "queryFrequency", "queryPeriod", "triggerOperator", "triggerThreshold",
    "suppressionDuration", "suppressionEnabled", "tactics", "techniques",
    "entityMappings", "incidentConfiguration", "eventGroupingSettings",
    "alertDetailsOverride", "customDetails",
}

TIMESPAN_RE = re.compile(r"^(\d+)\s*([smhdw])$")
UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}


class ConversionError(RuntimeError):
    pass


def to_iso8601(timespan: str) -> str:
    """KQL timespan ('5m', '1h', '14d') -> ISO-8601 duration ('PT5M', 'PT1H', 'P14D')."""
    match = TIMESPAN_RE.match(str(timespan).strip())
    if not match:
        raise ConversionError(
            f"{timespan!r} is not a KQL timespan the converter understands "
            "(expected forms like 5m, 1h, 14d)")
    value, unit = int(match.group(1)), match.group(2)
    if unit == "s":
        return f"PT{value}S"
    if unit == "m":
        return f"PT{value}M"
    if unit == "h":
        return f"PT{value}H"
    if unit == "d":
        return f"P{value}D"
    return f"P{value}W"


def slug(text: str) -> str:
    return re.sub(r"[^a-z0-9-]", "", text.lower().replace(" ", "-"))


def arm_shell(workspace_parameter: bool = True) -> dict:
    """The deployment skeleton shared by both content types."""
    return {
        "$schema": SCHEMA,
        "contentVersion": CONTENT_VERSION,
        "parameters": {
            "workspace": {
                "type": "string",
                "metadata": {"description": "Log Analytics workspace name that Microsoft Sentinel is enabled on"},
            }
        },
        "variables": {},
        "resources": [],
    }


def analytic_rule_template(path: Path) -> dict:
    rule = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(rule, dict):
        raise ConversionError(f"{path.name} is not a YAML mapping")
    for field in ("id", "name", "query", "severity", "queryFrequency", "queryPeriod"):
        if not rule.get(field):
            raise ConversionError(f"{path.name} has no {field}")

    operator = TRIGGER_OPERATORS.get(str(rule.get("triggerOperator", "gt")))
    if operator is None:
        raise ConversionError(
            f"{path.name}: triggerOperator {rule.get('triggerOperator')!r} has no ARM equivalent "
            f"({sorted(TRIGGER_OPERATORS)})")

    properties: dict = {
        "displayName": rule["name"],
        "description": rule["description"],
        "severity": rule["severity"],
        "enabled": True,
        "query": rule["query"],
        "queryFrequency": to_iso8601(rule["queryFrequency"]),
        "queryPeriod": to_iso8601(rule["queryPeriod"]),
        "triggerOperator": operator,
        "triggerThreshold": rule.get("triggerThreshold", 0),
        "suppressionEnabled": False,
        "suppressionDuration": "PT1H",
    }
    if rule.get("tactics"):
        properties["tactics"] = rule["tactics"]
    if rule.get("relevantTechniques"):
        properties["techniques"] = rule["relevantTechniques"]
    for key in ("entityMappings", "incidentConfiguration", "eventGroupingSettings",
                "alertDetailsOverride", "customDetails"):
        if rule.get(key):
            properties[key] = rule[key]

    unexpected = set(properties) - ALERT_RULE_PROPERTY_KEYS
    if unexpected:
        raise ConversionError(f"{path.name}: refusing to emit non-schema properties {sorted(unexpected)}")

    parameter_name = f"analytic-{slug(path.stem)}-id"
    template = arm_shell()
    template["parameters"][parameter_name] = {
        "type": "string",
        "defaultValue": rule["id"],
        "minLength": 1,
        "metadata": {"description": f"Resource name of the analytics rule '{rule['name']}'"},
    }
    template["resources"].append({
        "type": "Microsoft.OperationalInsights/workspaces/providers/alertRules",
        "apiVersion": ALERT_RULE_API,
        "name": f"[concat(parameters('workspace'), '/Microsoft.SecurityInsights/', parameters('{parameter_name}'))]",
        "kind": rule.get("kind", "Scheduled"),
        "location": "[resourceGroup().location]",
        "properties": properties,
    })
    return template


def hunting_query_template(path: Path) -> dict:
    hunt = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(hunt, dict):
        raise ConversionError(f"{path.name} is not a YAML mapping")
    for field in ("name", "query"):
        if not hunt.get(field):
            raise ConversionError(f"{path.name} has no {field}")

    tags = []
    if hunt.get("description"):
        tags.append({"name": "description", "value": " ".join(str(hunt["description"]).split())[:240]})
    if hunt.get("tactics"):
        tags.append({"name": "tactics", "value": ",".join(hunt["tactics"])})
    if hunt.get("relevantTechniques"):
        tags.append({"name": "relevantTechniques", "value": ",".join(hunt["relevantTechniques"])})

    parameter_name = f"hunt-{slug(path.stem)}-name"
    template = arm_shell()
    template["parameters"][parameter_name] = {
        "type": "string",
        "defaultValue": slug(path.stem),
        "minLength": 1,
        "metadata": {"description": f"Resource name of the hunting query '{hunt['name']}'"},
    }
    template["resources"].append({
        "type": "Microsoft.OperationalInsights/workspaces/savedSearches",
        "apiVersion": SAVED_SEARCH_API,
        "name": f"[concat(parameters('workspace'), '/', parameters('{parameter_name}'))]",
        "location": "[resourceGroup().location]",
        "properties": {
            "eTag": "*",
            "displayName": hunt["name"],
            "category": "Hunting Queries",
            "query": hunt["query"],
            "version": 1,
            "tags": tags,
        },
    })
    return template


def render(template: dict) -> str:
    return json.dumps(template, indent=2, ensure_ascii=False) + "\n"


def build() -> dict[Path, str]:
    """Every output file and its intended contents."""
    outputs: dict[Path, str] = {}
    for path in sorted(DETECTIONS.glob("*.yaml")):
        outputs[OUT / "analytic-rules" / f"{path.stem}.json"] = render(analytic_rule_template(path))
    for path in sorted(HUNTS.glob("*.yaml")):
        outputs[OUT / "hunting-queries" / f"{path.stem}.json"] = render(hunting_query_template(path))
    return outputs


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true",
                        help="do not write; fail if the committed templates differ from the rules")
    args = parser.parse_args(argv)

    try:
        outputs = build()
    except ConversionError as exc:
        print(f"::error::ARM conversion failed: {exc}", file=sys.stderr)
        return 2

    if args.check:
        stale = []
        for path, content in outputs.items():
            if not path.exists():
                stale.append(f"{path.relative_to(REPO)} is missing")
            elif path.read_text(encoding="utf-8") != content:
                stale.append(f"{path.relative_to(REPO)} is out of date")
        expected = {p for p in outputs}
        for path in sorted(OUT.rglob("*.json")):
            if path not in expected:
                stale.append(f"{path.relative_to(REPO)} has no corresponding rule")
        if stale:
            for line in stale:
                print(f"::error::{line}")
            print("Run 'python scripts/generate_arm_templates.py' and commit the result.")
            return 1
        print(f"deploy/: {len(outputs)} ARM templates match the rule files")
        return 0

    written = 0
    for path, content in outputs.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists() or path.read_text(encoding="utf-8") != content:
            path.write_text(content, encoding="utf-8")
            written += 1
    for path in sorted(OUT.rglob("*.json")):
        if path not in outputs:
            path.unlink()
    rules = sum(1 for p in outputs if "analytic-rules" in p.parts)
    print(f"deploy/: {rules} analytics-rule templates and {len(outputs) - rules} hunting-query "
          f"templates ({written} file(s) written)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
