#!/usr/bin/env python3
"""The generated ARM templates must match the rules and stay inside the schema.

Sentinel Repositories deploy ARM templates, so `deploy/` is the deployable form of
this repository. These tests hold three lines:

1. the templates are current with the rule files (a stale template is a rule that
   would not deploy, which is worse than no template);
2. every property emitted is a real alert-rule property, so authoring metadata can
   never leak into a deployment;
3. the resource identity is derived from the committed rule id, so a redeploy
   updates the rule rather than duplicating it.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys

import pytest
import yaml
from conftest import REPO

GENERATOR = REPO / "scripts" / "generate_arm_templates.py"
DEPLOY = REPO / "deploy"
DETECTIONS = REPO / "Detections"
HUNTS = REPO / "Hunting Queries"

ISO8601 = re.compile(r"^P(?:\d+[YMWD])*(?:T(?:\d+[HMS])*)?$")
ALERT_PROPERTY_KEYS = {
    "displayName", "description", "severity", "enabled", "query",
    "queryFrequency", "queryPeriod", "triggerOperator", "triggerThreshold",
    "suppressionDuration", "suppressionEnabled", "tactics", "techniques",
    "entityMappings", "incidentConfiguration", "eventGroupingSettings",
    "alertDetailsOverride", "customDetails",
}


def generated() -> list[tuple]:
    paths = sorted((DEPLOY / "analytic-rules").glob("*.json"))
    return [(p, json.loads(p.read_text(encoding="utf-8"))) for p in paths]


def generated_hunts() -> list[tuple]:
    paths = sorted((DEPLOY / "hunting-queries").glob("*.json"))
    return [(p, json.loads(p.read_text(encoding="utf-8"))) for p in paths]


def test_generator_check_mode_is_green():
    """CI's drift gate: deploy/ must be exactly what the rules produce today."""
    proc = subprocess.run([sys.executable, str(GENERATOR), "--check"],
                          capture_output=True, text=True, cwd=REPO, check=False)
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_every_rule_and_hunt_has_a_template():
    assert len(generated()) == len(list(DETECTIONS.glob("*.yaml")))
    assert len(generated_hunts()) == len(list(HUNTS.glob("*.yaml")))


def test_alert_rule_resources_are_well_formed():
    for path, template in generated():
        assert template["$schema"].endswith("deploymentTemplate.json#"), path
        assert "workspace" in template["parameters"], path
        assert len(template["resources"]) == 1, f"{path.name} should deploy exactly one rule"
        resource = template["resources"][0]
        assert resource["type"] == "Microsoft.OperationalInsights/workspaces/providers/alertRules", path
        assert resource["kind"] == "Scheduled", path
        assert resource["location"] == "[resourceGroup().location]", path
        assert "/Microsoft.SecurityInsights/" in resource["name"], path


def test_alert_rule_properties_stay_inside_the_schema():
    for path, template in generated():
        properties = template["resources"][0]["properties"]
        unexpected = set(properties) - ALERT_PROPERTY_KEYS
        assert not unexpected, f"{path.name} emits non-schema properties: {sorted(unexpected)}"
        assert "metadata" not in properties, (
            f"{path.name} leaked the authoring metadata block into a deployable template")
        assert properties["enabled"] is True, path
        assert ISO8601.match(properties["queryFrequency"]), (path, properties["queryFrequency"])
        assert ISO8601.match(properties["queryPeriod"]), (path, properties["queryPeriod"])
        assert "ago(" in properties["query"], f"{path.name} lost its time bound in conversion"
        assert properties["triggerOperator"] in {"GreaterThan", "LessThan", "Equal", "NotEqual"}, path


def test_resource_name_uses_the_committed_rule_id():
    """A template that invented a new id would deploy a duplicate rule on every sync."""
    for path, template in generated():
        rule = yaml.safe_load((DETECTIONS / f"{path.stem}.yaml").read_text(encoding="utf-8"))
        id_parameters = [name for name in template["parameters"] if name.startswith("analytic-")]
        assert len(id_parameters) == 1, path
        assert template["parameters"][id_parameters[0]]["defaultValue"] == rule["id"], path
        assert f"parameters('{id_parameters[0]}')" in template["resources"][0]["name"], path


def test_hunting_query_templates_are_well_formed():
    for path, template in generated_hunts():
        resource = template["resources"][0]
        assert resource["type"] == "Microsoft.OperationalInsights/workspaces/savedSearches", path
        assert len(template["resources"]) == 1, path
        properties = resource["properties"]
        assert properties["category"] == "Hunting Queries", path
        assert properties["version"] == 1, path
        assert "ago(" in properties["query"], f"{path.name} lost its time bound in conversion"
        assert properties["eTag"] == "*", path
        names = {tag["name"] for tag in properties["tags"]}
        assert "description" in names, f"{path.name} has no description tag"
        hunt = yaml.safe_load((HUNTS / f"{path.stem}.yaml").read_text(encoding="utf-8"))
        assert properties["displayName"] == hunt["name"], path


def test_hunting_query_tags_mirror_the_rule_metadata():
    for path, template in generated_hunts():
        hunt = yaml.safe_load((HUNTS / f"{path.stem}.yaml").read_text(encoding="utf-8"))
        tags = {tag["name"]: tag["value"] for tag in template["resources"][0]["properties"]["tags"]}
        if hunt.get("tactics"):
            assert tags["tactics"] == ",".join(hunt["tactics"]), path
        if hunt.get("relevantTechniques"):
            assert tags["relevantTechniques"] == ",".join(hunt["relevantTechniques"]), path


def test_no_attribution_or_placement_leaks_into_templates():
    """Same content-hygiene bar as the rule files: the author is the only name that
    appears, and no template carries a generated-by style marker."""
    banned = ["generated by ai", "chatgpt", "claude", "copilot", "co-authored-by"]
    for directory in ("analytic-rules", "hunting-queries"):
        for path in sorted((DEPLOY / directory).glob("*.json")):
            text = path.read_text(encoding="utf-8").lower()
            hits = [b for b in banned if b in text]
            assert not hits, f"{path.name} contains {hits}"


@pytest.mark.parametrize("timespan,expected", [
    ("5m", "PT5M"), ("1h", "PT1H"), ("2h", "PT2H"), ("14d", "P14D"), ("30m", "PT30M"), ("7d", "P7D"),
])
def test_timespan_conversion(timespan, expected):
    sys.path.insert(0, str(REPO / "scripts"))
    import generate_arm_templates

    assert generate_arm_templates.to_iso8601(timespan) == expected


def test_converter_refuses_an_unknown_timespan():
    sys.path.insert(0, str(REPO / "scripts"))
    import generate_arm_templates

    with pytest.raises(generate_arm_templates.ConversionError):
        generate_arm_templates.to_iso8601("fortnightly")


def test_converter_refuses_an_unknown_trigger_operator(tmp_path):
    bad = REPO / "Detections" / "_tmp_bad_operator.yaml"
    source = yaml.safe_load((DETECTIONS / "MDE_ShadowCopyDeletion.yaml").read_text(encoding="utf-8"))
    source["triggerOperator"] = "gte"
    bad.write_text(yaml.safe_dump(source, sort_keys=False), encoding="utf-8")
    try:
        sys.path.insert(0, str(REPO / "scripts"))
        import generate_arm_templates

        with pytest.raises(generate_arm_templates.ConversionError):
            generate_arm_templates.analytic_rule_template(bad)
    finally:
        bad.unlink()
