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
- The `Parameters` dynamic array format is the single most fragile part — if Microsoft changes the serialisation, re-check the `mv-expand p = Parameters` block. A regression test pins the pattern, including that the keys are read capitalised as the payload actually serialises them (`tests/test_rules.py::test_inbox_rule_reads_capitalised_parameters`).

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

### Generated-artefact drift

These four gates all mean the same thing: a file that is derived from other files no longer matches
them. The fix is always to run the generator and commit what it writes — never to hand-edit the
generated file, and never to regenerate the *source* from the artefact.

| Failure | Fix |
|---|---|
| `coverage.md or attack-navigator/layer.json is stale` | `python scripts/generate_coverage.py`, commit the result |
| `tests/atomics.md is stale` | `python scripts/generate_atomics_ledger.py`, commit the result. The YAML ledger is the source of truth; the markdown is rendered from it |
| `deploy/ is stale`, `… is missing`, `… has no corresponding rule` | `python scripts/generate_arm_templates.py`, commit the result |
| `docs/metrics-matrix.md is stale` | `python scripts/generate_metrics_matrix.py`, commit the result |
| `design preview digest mismatch` | The workbook changed and the preview PNG did not: `python scripts/render_design_preview.py`, commit the image and its `.sha256` |

### Validation failures

| Failure | Fix |
|---|---|
| `technique Txxxx not found in current ATT&CK matrix` | Technique revoked/deprecated in MITRE CTI — replace with successor (see [ATTACK.md](ATTACK.md)) |
| `tactic mismatch` | Rule tactics contradict the referenced techniques' phases |
| `table X requires connector Y` | Add the connector + data type to `requiredDataConnectors`, or add the table to `TABLE_CATALOG` if it's a legitimate new source |
| `queryPeriod exceeds` / `frequency > period` | Sentinel's ceiling is 14 days; a longer period is accepted by the linter and rejected by the platform |
| `mapped column is an array` | Sentinel cannot entity-map `make_set`/`make_list` output. Project a scalar first |
| `TimeGenerated dropped by the final projection` | Keep it: incident timelines and the workbook's latency tile read it |
| `invalid KQL set operator` | `endswith any` etc. don't exist — use `has_any`, `in`, or per-element predicates |
| `odd number of double quotes` / `unclosed brackets` | KQL lint caught a syntax break; the scanner is string-aware, so this is usually a real defect |
| `stale counts still documented` / `does not state the real test total` | A number in the README or `docs/testing.md` no longer matches the repository. Update the prose — the test measures the repository, so the repository is right |
| `broken relative link` | `python scripts/check_links.py` names the file and the target |

## Still stuck

Check the CI run output first (`validate.yml` prints the failing check per file), then [troubleshoot the connector](https://learn.microsoft.com/azure/sentinel/connect-data-sources) before changing detection logic.
