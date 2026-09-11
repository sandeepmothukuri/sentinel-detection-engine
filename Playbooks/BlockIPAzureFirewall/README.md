# Playbook: BlockIPAzureFirewall

Pulls all public IP entities from the incident, unions them into an Azure Firewall **IP Group** consumed by a deny network rule, and posts an audit comment back to Sentinel.

Uses the Logic App's **system-assigned managed identity** to call the ARM REST API directly — no API connection needed for the IP Group update.

## Prerequisites

1. An Azure Firewall + an existing **IP Group** (e.g. `secops-blocklist`) referenced by a deny network rule in the firewall policy.
2. After deploy, grant the Logic App's managed identity **Network Contributor** on the IP Group:

```bash
PRINCIPAL_ID=$(az resource show \
  --ids "/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.Logic/workflows/BlockIPAzureFirewall" \
  --query identity.principalId -o tsv)

az role assignment create \
  --assignee $PRINCIPAL_ID \
  --role "Network Contributor" \
  --scope "/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.Network/ipGroups/secops-blocklist"
```

## Deploy

```bash
az deployment group create \
  --resource-group <rg> \
  --template-file azuredeploy.json \
  --parameters PlaybookName=BlockIPAzureFirewall \
               IpGroupResourceId="/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.Network/ipGroups/secops-blocklist" \
               MinimumSeverity=High
```

## Safeguards (v1.1)

- **Severity floor** — `MinimumSeverity` (default `High`). Adding an address to a firewall deny list is a destructive action like the other two playbooks, so it is gated the same way: incidents *at or above* the floor may push a block, anything below gets a comment. Comparison is by severity rank, so a floor of `Medium` still acts on `High`.
- **Public IPv4 only** — the playbook drops IPv6 entities rather than guessing: an IP Group entry is a prefix, and `concat(address, '/32')` is meaningless for an IPv6 address, so an IPv6 indicator is reported in the comment as *not blocked*. Addresses are shape-checked (four dot-separated parts, no colon) in a filter that runs **before** any octet arithmetic, because expression `and()` does not short-circuit in Logic Apps: without that guard an IPv6 entity would reach `int()` and fault the run instead of producing a comment. It also drops RFC1918 (10/8, 172.16/12, 192.168/16), loopback (127/8), link-local (169.254/16), carrier-grade NAT (100.64/10), "this network" (0.0.0.0/8) and multicast/reserved (224/4 and above), so an internal or special-use address can never reach the deny list.
- **Guarded write** — the block only runs when the incident clears the severity floor *and* at least one candidate survives the filter *and* the merged group stays inside the ceiling. Every other path comments instead.
- **Allowlist** — `AllowlistedIPs` parameter: corporate egress, partner endpoints, and backup destinations are filtered out per-IP before any firewall change.
- **Ceiling guard** — `MaxIPGroupEntries` (default 1000): if the merged group would exceed the ceiling, nothing is written and the incident gets a comment instead. This protects firewall rule capacity from a runaway incident.
- Idempotent: re-running with the same IP is a no-op (set-union).
- Trigger concurrency pinned to 1 run at a time.
- Every block comment embeds the rollback instruction.

## Reversal

`az network ip-group update --name secops-blocklist --remove ipAddresses=<ip/32>`

Track block-list growth via a workbook tile (count of entries over time) — uncontrolled growth is the canonical operational risk for this playbook.
