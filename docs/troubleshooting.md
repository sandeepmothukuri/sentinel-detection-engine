# Troubleshooting

## Rules deploy but never fire

1. **Data connector** — Sentinel → Data connectors: is the connector connected and are the data types ingesting? (CI verifies declared connectors match query tables, but only the workspace can confirm ingestion.)
2. **Rule status** — Analytics rule → "Last run" column. `no results` is healthy if the behaviour hasn't occurred; errors need the run detail.
3. **Query manually** — run the rule's KQL over `queryPeriod` in Logs. Zero rows with data present means the event simply hasn't happened; rows appearing but no incident means grouping/threshold configuration.
4. **Time windows** — a `queryFrequency` of 1h means worst-case 1h latency; do not expect instant incidents.

## Key Vault rule returns nothing

- Diagnostic settings must be enabled **per vault** with audit events (SecretGet/KeyGet/CertificateGet). Without them `AzureDiagnostics` has no Key Vault rows.
- The identity columns (`identity_claim_upn_s`, `identity_claim_appid_g_s`) only exist in diagnostic mode; classic log-alert mode of the connector will not populate them.

## Inbox rule / Exchange detections miss events

- Exchange **admin** audit logging must be enabled (it is by default in most tenants; verify via `Get-AdminAuditLogConfig`).
- The `Parameters` dynamic array format is the single most fragile part — if Microsoft changes the serialisation, re-check the `mv-expand p = Parameters` block. A regression test pins the pattern (`test_inbox_rule_uses_mv_expand_parameters`).

## MDE hunts return nothing

- Confirm devices are onboarded: Sentinel → Data connectors → Microsoft Defender for Endpoint → check connected devices count.
- Command lines empty on `DeviceProcessEvents` means command-line capture is off on those endpoints.
- `AdditionalFields.IsSigned` may be empty for some events — the unsigned-binary hunt treats empty as unsigned; verify noise on one device before judging the rule.

## AzureActivity rule misses NSG changes

- The activity log must be connected at the **subscription** scope that contains the NSGs.
- `Properties.requestbody` can be truncated for large rule bodies — if a rule with many port ranges doesn't fire, check the raw event.

## Playbook doesn't run on incident creation

- Automation rule must be enabled and scoped to include the analytics rule that created the incident.
- The playbook's Sentinel API connection needs to be authorised once after deployment.
- Playbook identity needs **Microsoft Sentinel Responder** on the workspace (comments/updates) — check the run history for 403s.

## CI failures

| Failure | Fix |
|---|---|
| `coverage.md or layer.json is stale` | Run `python scripts/generate_coverage.py`, commit results |
| `technique Txxxx not found in current ATT&CK matrix` | Technique revoked/deprecated in MITRE CTI — replace with successor (see [ATTACK.md](ATTACK.md)) |
| `tactic mismatch` | Rule tactics contradict the referenced techniques' phases |
| `table X requires connector Y` | Add the connector + data type to `requiredDataConnectors`, or add the table to `TABLE_CATALOG` if it's a legitimate new source |
| `invalid KQL set operator` | `endswith any` etc. don't exist — use `has_any`, `in`, or per-element predicates |
| `odd number of double quotes` / `unclosed brackets` | KQL lint caught a syntax break; the scanner is string-aware, so this is usually a real defect |

## Still stuck

Check the CI run output first (`validate.yml` prints the failing check per file), then [troubleshoot the connector](https://learn.microsoft.com/azure/sentinel/connect-data-sources) before changing detection logic.
