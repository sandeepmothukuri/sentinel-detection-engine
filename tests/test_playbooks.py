#!/usr/bin/env python3
"""The SOAR playbooks must implement the safety gates the documentation promises.

`docs/workflows/soar-decision-flow.md` states the contract: no playbook acts on an
alert alone. Detection, then confidence, then validation, then a safety gate, then
the action, then verification, then an audit entry, then a rollback path. This module
is the machine-checkable half of that contract, because the gaps found in the sixth
audit pass were all cases of JSON drifting away from the documented behaviour:

P1  a parameter called `MinimumSeverity` compared with `equals`, which skips every
    severity above it — the opposite of a floor;
P2  device isolation with no exclusion list, so a domain controller was eligible;
P3  a firewall block with no severity gate at all;
P4  an IPv6 entity silently gaining a `/32` suffix, and reserved ranges missing from
    the filter;
P5  a VirusTotal call whose response was never read;
P7  an exclusion list consulted for one account and ignored for the rest;
P8  privileged accounts unprotected despite the decision-flow promise.

Every assertion below is a regression guard for one of those, written against the
deployed JSON rather than the README, so the two cannot drift apart again.
"""
from __future__ import annotations

import json
import re

import pytest
from conftest import REPO

PLAYBOOKS = REPO / "Playbooks"
NAMES = ["AutoEnrichDisableUser", "IsolateDeviceMDE", "BlockIPAzureFirewall",
         "CreateServiceNowTicket"]
DESTRUCTIVE = {"AutoEnrichDisableUser", "IsolateDeviceMDE", "BlockIPAzureFirewall"}


# --------------------------------------------------------------------- helpers
def load(name: str) -> dict:
    return json.loads((PLAYBOOKS / name / "azuredeploy.json").read_text(encoding="utf-8"))


def workflow(definition: dict) -> dict:
    workflows = [r for r in definition["resources"]
                 if r.get("type") == "Microsoft.Logic/workflows"]
    assert len(workflows) == 1, "a playbook deploys exactly one Logic App"
    return workflows[0]["properties"]["definition"]


def actions(definition: dict, path: str = "") -> list[tuple[str, dict, dict]]:
    """Walk the action tree, yielding (qualified name, action, parent action map)."""
    outer = workflow(definition)["actions"]
    found: list[tuple[str, dict, dict]] = []

    def walk(siblings: dict, prefix: str) -> None:
        for name, spec in siblings.items():
            found.append((prefix + name, spec, siblings))
            for branch in ("actions", "else"):
                sub = spec.get(branch) or {}
                inner = sub.get("actions") if branch == "else" else sub
                if isinstance(inner, dict) and inner:
                    walk(inner, f"{prefix}{name}.")

    walk(outer, path)
    return found


def strings(node) -> list[str]:
    if isinstance(node, dict):
        return [s for v in node.values() for s in strings(v)]
    if isinstance(node, list):
        return [s for v in node for s in strings(v)]
    return [node] if isinstance(node, str) else []


def condition_of(spec: dict) -> str:
    """An If action's expression as JSON text.

    The keys matter as much as the values here: `greaterOrEquals` is a key, and a
    helper that joined only the operand strings would not see it.
    """
    return json.dumps(spec.get("expression") or {})


def equals_pairs(node) -> list[list[str]]:
    """Every operand pair of an `equals` clause anywhere in a subtree."""
    found: list[list[str]] = []
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "equals" and isinstance(value, list):
                found.append([json.dumps(operand) for operand in value])
            else:
                found.extend(equals_pairs(value))
    elif isinstance(node, list):
        for value in node:
            found.extend(equals_pairs(value))
    return found


@pytest.fixture(params=NAMES)
def playbook(request) -> tuple[str, dict]:
    return request.param, load(request.param)


# ------------------------------------------------------------- universal rules
def test_every_playbook_is_well_formed(playbook) -> None:
    name, definition = playbook
    wf = workflow(definition)
    declared = set(wf.get("parameters") or {}) | {"$connections"}
    for action_name, spec, siblings in actions(definition):
        for target in spec.get("runAfter") or {}:
            assert target in siblings, f"{name}: {action_name} runAfter unknown {target}"
        if spec.get("type") == "Foreach":
            assert spec.get("foreach"), f"{name}: {action_name} has an empty Foreach"
        for value in strings(spec):
            if "@" not in value:
                continue
            for expr in re.findall(r"@[a-zA-Z]+\([^\"]*", value):
                assert expr.count("(") == expr.count(")"), f"{name}: {action_name} {expr}"
            for param in re.findall(r"parameters\('([^']+)'\)", value):
                assert param in declared, f"{name}: {action_name} uses undeclared {param}"


def test_action_names_are_unique_per_playbook(playbook) -> None:
    name, definition = playbook
    names = [n for n, _, _ in actions(definition)]
    assert len(names) == len(set(names)), f"{name}: duplicate action names"


def test_no_playbook_compares_severity_with_equals(playbook) -> None:
    """P1: a severity floor must compare ranks, never string equality."""
    name, definition = playbook
    for action_name, spec, _ in actions(definition):
        blob = condition_of(spec)
        if "severity" not in blob:
            continue
        assert "greaterOrEquals" in blob, f"{name}: {action_name} gates severity without a floor"
        assert not re.search(r"\"equals\": \[\"@triggerBody\(\)\?\['object'\].*severity", blob), (
            f"{name}: {action_name} still uses equals() on incident severity")


def test_destructive_actions_sit_behind_a_conditional() -> None:
    """The decision flow: Detection -> Confidence -> Validation -> Safety Gate -> Action."""
    for name in DESTRUCTIVE:
        definition = load(name)
        for action_name, spec, _ in actions(definition):
            if not action_name.endswith(("AAD_-_Disable_User", "MDE_-_Isolate_Machine",
                                         "Update_IP_Group")):
                continue
            assert "." in action_name, (
                f"{name}: {action_name} is a top-level action, so nothing gates it")
            outer = action_name.split(".")[0]
            gate = next(s for n, s, _ in actions(definition) if n == outer)
            assert gate.get("type") == "If", f"{name}: {action_name} is not inside an If"
            assert gate.get("expression"), f"{name}: {action_name} sits behind an empty gate"


def test_every_playbook_leaves_an_audit_trail(playbook) -> None:
    name, definition = playbook
    comments = [n for n, s, _ in actions(definition)
                if "Comment" in n or "Comment" in json.dumps(s)]
    assert comments, f"{name}: no Sentinel incident comment, so no audit trail"
    for action_name, spec, _ in actions(definition):
        if "Comment" not in action_name:
            continue
        body = json.dumps(spec)
        assert "incidentArmId" in body, f"{name}: {action_name} does not target the incident"


def test_parameters_are_surfaced_to_the_deployment(playbook) -> None:
    """A parameter the workflow declares but the ARM resource never binds is a
    setting the operator cannot change."""
    name, definition = playbook
    wf = workflow(definition)
    declared = {k for k in (wf.get("parameters") or {}) if k != "$connections"}
    resource_text = json.dumps(definition)
    for param in declared:
        assert f"[parameters('{param}')]" in resource_text, f"{name}: {param} is not bound"


# ------------------------------------------------------------------ P1 severity
@pytest.mark.parametrize("name", sorted(DESTRUCTIVE))
def test_severity_floor_is_monotonic(name: str) -> None:
    """Every acting playbook has MinimumSeverity, and the rank mapping is 3/2/1/0."""
    definition = load(name)
    wf = workflow(definition)
    assert "MinimumSeverity" in (wf.get("parameters") or {}), f"{name}: no severity floor"
    blob = json.dumps(definition)
    assert "'High'),3," in blob and "'Medium'),2," in blob and "'Low'),1,0" in blob, (
        f"{name}: severity rank mapping is not High=3, Medium=2, Low=1, other=0")


# ------------------------------------------------------- AutoEnrichDisableUser
def test_accounts_are_gated_individually() -> None:
    """P7/P8: the exclusion checks must apply to every account, not to the first."""
    definition = load("AutoEnrichDisableUser")
    gate = next(s for n, s, _ in actions(definition)
                if n.endswith("Check_Account_Is_Disableable"))
    blob = condition_of(gate)
    assert "ExcludedUserPrincipals" in blob, "P7: exclusion list not in the per-account gate"
    assert "PrivilegedUserPrincipals" in blob, "P8: privileged accounts are auto-disabled"
    assert "items('For_each_Account')?['UserPrincipalName']" in blob, (
        "the gate must read the current item, not first(Accounts)")
    assert "first(" not in blob, "P7: the gate still tests only the first account"
    assert gate["actions"], "the disable action disappeared from inside the gate"
    assert gate.get("else", {}).get("actions"), "a skipped account must be commented"
    wf = workflow(definition)
    assert "PrivilegedUserPrincipals" in wf["parameters"], "P8: parameter not declared"


def test_privileged_accounts_never_reach_the_disable_call() -> None:
    definition = load("AutoEnrichDisableUser")
    for action_name, spec, _ in actions(definition):
        if not action_name.endswith("AAD_-_Disable_User"):
            continue
        parents = action_name.split(".")[:-1]
        assert "Check_Account_Is_Disableable" in parents, (
            "P8: the Graph disable call is not behind the privileged-account gate")


def test_virustotal_response_is_used() -> None:
    """P5: a per-IP API call whose answer is thrown away is cost without evidence."""
    definition = load("AutoEnrichDisableUser")
    blob = json.dumps(definition)
    assert "VT_-_IP_Report" in blob, "the VirusTotal call vanished"
    assert "last_analysis_stats" in blob, "P5: the VirusTotal response is still unread"
    assert "EnrichmentSummary" in blob, "P5: enrichment is not surfaced in the comments"


# ------------------------------------------------------------- IsolateDeviceMDE
def test_device_isolation_has_an_exclusion_list() -> None:
    """P2: critical infrastructure must route to an analyst, not to isolation."""
    definition = load("IsolateDeviceMDE")
    wf = workflow(definition)
    assert "ExcludedDeviceNames" in wf["parameters"], "P2: no device exclusion parameter"
    gate = next(s for n, s, _ in actions(definition) if n.endswith("Check_Has_MDE_ID"))
    blob = condition_of(gate)
    assert "ExcludedDeviceNames" in blob, "P2: the exclusion list is never consulted"
    assert "HostName" in blob and "ComputerDnsName" in blob, (
        "an alias-only host must still match the exclusion list")
    for action_name, spec, _ in actions(definition):
        if action_name.endswith("MDE_-_Isolate_Machine"):
            assert "Check_Has_MDE_ID" in action_name.split(".")[:-1], (
                "P2: isolation is not behind the device gate")


def test_isolation_comment_distinguishes_the_two_skip_reasons() -> None:
    definition = load("IsolateDeviceMDE")
    comment = next(s for n, s, _ in actions(definition)
                   if n.endswith("Sentinel_Comment_No_MDE_ID"))
    message = json.dumps(comment)
    assert "ExcludedDeviceNames" in message, (
        "an excluded host deserves a review instruction, not a 'no entity id' note")


# --------------------------------------------------------- BlockIPAzureFirewall
def test_firewall_block_requires_severity_and_a_ceiling() -> None:
    """P3: pushing a deny into a firewall rule is destructive and was ungated."""
    definition = load("BlockIPAzureFirewall")
    wf = workflow(definition)
    gate = next(s for n, s, _ in actions(definition) if n.endswith("Condition_-_Guard_Rails"))
    blob = condition_of(gate)
    assert "severity" in blob, "P3: no severity gate on the firewall block"
    assert "MaxIPGroupEntries" in blob, "the IP Group ceiling disappeared"
    assert "MinimumSeverity" in wf["parameters"], "P3: parameter not declared"
    for action_name, spec, _ in actions(definition):
        if action_name.endswith("Update_IP_Group"):
            assert "Condition_-_Guard_Rails" in action_name.split(".")[:-1]


def test_ip_group_updates_only_accept_public_ipv4() -> None:
    """P4: an IPv6 entity must never become 'x:y::z/32', and RFC1918 or special-use
    ranges must never be pushed to a firewall deny list.

    The shape guard matters as much as the range list: expression `and()` does not
    short-circuit, so the octet arithmetic has to sit behind a filter that has already
    removed anything that is not a dotted quad. Otherwise an IPv6 entity reaches
    `int()` and the whole compose fails instead of commenting.
    """
    definition = load("BlockIPAzureFirewall")
    compose = next(s for n, s, _ in actions(definition)
                   if n.endswith("Compose_Candidate_IPs"))
    blob = compose["inputs"]

    inner = blob[blob.index("filter(body("):blob.index("(x) => and(")]
    assert "not(contains(a?['Address'], ':'))" in inner, "P4: IPv6 entities are not filtered"
    assert "equals(length(split(a?['Address'], '.')), 4)" in inner, (
        "P4: nothing guarantees a dotted quad before the octets are parsed")
    assert "int(" not in inner, (
        "P4: octet arithmetic runs before the shape guard, so a malformed or IPv6 "
        "entity would fault the expression instead of being dropped")

    for required in ["greater(int(first(split(x?['Address'], '.'))), 0)",
                     "less(int(first(split(x?['Address'], '.'))), 224)",
                     "100", "10.", "127.", "169.254.", "172.16.", "172.19.",
                     "172.2", "172.30.", "172.31.", "192.168.", "AllowlistedIPs"]:
        assert required in blob, f"P4: address filter no longer excludes {required!r}"
    assert "/32" in blob, "public IPv4 candidates still need a /32 suffix"


def test_ip_group_suffix_follows_the_ipv4_filter() -> None:
    """The /32 must be applied by the select() that reads the filtered IPv4 list, so
    the suffix can never land on an IPv6 address."""
    definition = load("BlockIPAzureFirewall")
    compose = next(s for n, s, _ in actions(definition)
                   if n.endswith("Compose_Candidate_IPs"))
    text = compose["inputs"]
    select_at = text.index("@select(")
    filter_at = text.index("filter(")
    suffix_at = text.index("'/32'")
    assert filter_at > select_at and suffix_at > filter_at, (
        "the /32 suffix is applied outside the IPv4 filter")


# ------------------------------------------------------- CreateServiceNowTicket
def test_servicenow_ticket_creation_is_not_a_destructive_action() -> None:
    """The ticketing playbook is the one that may run on every severity, but it still
    has to report the severity it mapped rather than acting on it."""
    definition = load("CreateServiceNowTicket")
    assert "MinimumSeverity" not in workflow(definition).get("parameters", {}), (
        "ticket creation is a notification path; leave it ungated but documented")
    for action_name, spec, _ in actions(definition):
        assert spec.get("type") != "ApiConnection" or "firewall" not in json.dumps(spec).lower()
