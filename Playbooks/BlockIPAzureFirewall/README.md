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
               IpGroupResourceId="/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.Network/ipGroups/secops-blocklist"
```

## Safeguards (v1.1)

- The playbook drops RFC1918 addresses **plus** loopback (127/8) and link-local (169.254/16) before merging, so internal IPs can never accidentally hit the blocklist.
- **Allowlist** — `AllowlistedIPs` parameter: corporate egress, partner endpoints, and backup destinations are filtered out per-IP before any firewall change.
- **Ceiling guard** — `MaxIPGroupEntries` (default 1000): if the merged group would exceed the ceiling, nothing is written and the incident gets a comment instead. This protects firewall rule capacity from a runaway incident.
- Idempotent: re-running with the same IP is a no-op (set-union).
- Trigger concurrency pinned to 1 run at a time.
- Every block comment embeds the rollback instruction.

## Reversal

`az network ip-group update --name secops-blocklist --remove ipAddresses=<ip/32>`

Track block-list growth via a workbook tile (count of entries over time) — uncontrolled growth is the canonical operational risk for this playbook.
