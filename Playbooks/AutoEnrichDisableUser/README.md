# Playbook: AutoEnrichDisableUser

Triggers on a new Microsoft Sentinel incident. For every IP entity, queries VirusTotal and AbuseIPDB and tracks the maximum reputation confidence across the incident. If confidence is at or above the configurable threshold (default 80), the playbook disables every Entra ID user entity on the incident and posts an audit comment back to Sentinel. Below threshold, it still posts the enrichment results as a comment for the analyst — no auto-action.

## Required API connections

Deploy and authorise these once in the resource group before deploying the playbook:

- `azuresentinel` — Microsoft Sentinel
- `azuread` — Microsoft Entra ID (account that has User Administrator at minimum)
- `virustotal` — VirusTotal v3
- `abuseipdb` — AbuseIPDB v2

## Deploy

```bash
az deployment group create \
  --resource-group <rg> \
  --template-file azuredeploy.json \
  --parameters PlaybookName=AutoEnrichDisableUser \
               DisableUserConfidenceThreshold=80
```

Then bind it to incidents via an **automation rule** in Sentinel (Sentinel → Automation → Create automation rule → "Run playbook").

## Why a confidence threshold and not full-auto disable

False positives on user disablement are very expensive (loss of legitimate access, support burden). Forcing a reputation-confidence floor and posting an audit comment lets the playbook double as both an action *and* an enrichment, so the analyst gets value either way.

## Safeguards (v1.1)

Three gates must all pass before any account is disabled:

1. **Severity gate** — `MinimumSeverity` (default `High`). Incidents below the gate get enrichment + comment only. Sentinel severities are High / Medium / Low / Informational, so the default `High` means only the top severity can act.
2. **Confidence threshold** — `DisableUserConfidenceThreshold` (default 80) on the max AbuseIPDB abuse score across the incident's IPs.
3. **Exclusion list** — `ExcludedUserPrincipals`. UPNs on this list (break-glass accounts, documented service accounts, manual-only VIPs) are never auto-disabled.

Additional operational controls:

- Trigger concurrency is pinned to 1 run at a time (no parallel races on the same incident).
- Failed or unconfirmed disables raise a loud `WARNING` incident comment so an analyst always closes the loop manually.
- Every action and no-action path posts a full audit trail (what ran, confidence, thresholds, exclusion-list size) into the incident.

## Rollback

```powershell
Set-AzureADUser -ObjectId <upn> -AccountEnabled $true
```

Or Entra ID portal → Users → the account → Enable sign-in. Rollback is also embedded in the audit comment the playbook posts at action time. The playbook performs no other destructive change.

## Least privilege

Prefer a managed identity or an app registration with **Microsoft Graph `User.EnableDisableUser`** only, scoped via administrative unit where possible — not the full `User.ReadWrite.All` and never Global Admin. The Sentinel connection needs the **Microsoft Sentinel Responder** role on the workspace.
