# Playbook: AutoEnrichDisableUser

Triggers on a new Microsoft Sentinel incident. For every IP entity, queries VirusTotal and AbuseIPDB and tracks the maximum reputation confidence across the incident. If confidence is at or above the configurable threshold (default 80) and the incident clears the severity floor, the playbook disables each Entra ID user entity that passes a per-account safety gate, and posts an audit comment back to Sentinel. Accounts that are excluded, privileged, or missing a UPN are reported in their own comment instead of being touched. Below threshold, it posts the same enrichment evidence with no auto-action. The evidence travels with the verdict: each comment carries the VirusTotal malicious-engine count and the AbuseIPDB score for every IP that was looked up, so an analyst can see why the threshold was or was not met.

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
               DisableUserConfidenceThreshold=80 \
               MinimumSeverity=High \
               ExcludedUserPrincipals='["breakglass@contoso.com"]' \
               PrivilegedUserPrincipals='["admin1@contoso.com","admin2@contoso.com"]'
```

The template also takes connection-name parameters, every one of them defaulting to the connection
listed above: `SentinelConnectionName` (`azuresentinel`), `AADConnectionName` (`azuread`),
`VTConnectionName` (`virustotal`) and `AbuseIPDBConnectionName` (`abuseipdb`). Change one only if you
created that API connection under a different name — a mismatch fails at the connector call, not at
deployment, so it is worth reading the names back after a deploy.

Then bind it to incidents via an **automation rule** in Sentinel (Sentinel → Automation → Create automation rule → "Run playbook").

## Why a confidence threshold and not full-auto disable

False positives on user disablement are very expensive (loss of legitimate access, support burden). Forcing a reputation-confidence floor and posting an audit comment lets the playbook double as both an action *and* an enrichment, so the analyst gets value either way.

## Safeguards (v1.1)

Four gates must all pass before any account is disabled:

1. **Severity floor** — `MinimumSeverity` (default `High`). Incidents *at or above* the floor may act; anything below gets enrichment + comment only. The comparison is by severity rank (High 3, Medium 2, Low 1, Informational 0), so setting the floor to `Medium` still acts on High — a floor is a floor. Sentinel has no `Critical`, so the default `High` means the top severity.
2. **Confidence threshold** — `DisableUserConfidenceThreshold` (default 80) on the max AbuseIPDB abuse score across the incident's IPs.
3. **Exclusion list** — `ExcludedUserPrincipals`. UPNs on this list (break-glass accounts, documented service accounts, manual-only VIPs) are never auto-disabled.
4. **Privileged list** — `PrivilegedUserPrincipals`. Directory-role holders are never auto-disabled: disabling a Global Administrator can lock an organisation out of its own tenant, so the account is named in a skip comment for analyst authorisation instead. The list is maintained by an operator, not read from the directory — see [`docs/limitations.md`](../../docs/limitations.md) L10.

Additional operational controls:

- The exclusion and privileged checks run **per account**, inside the loop, against the account being processed — not against the first account on the incident.
- Every action and no-action path posts a full audit trail: what ran, the per-IP evidence, the max confidence against the threshold, the severity floor, and the size of both lists.
- Skipped accounts get their own comment naming the UPN and the reason, so a deliberate skip is never mistaken for a playbook failure.
- Trigger concurrency is pinned to 1 run at a time (no parallel races on the same incident).
- Failed or unconfirmed disables raise a loud `WARNING` incident comment so an analyst always closes the loop manually.

## Rollback

```powershell
Set-AzureADUser -ObjectId <upn> -AccountEnabled $true
```

Or Entra ID portal → Users → the account → Enable sign-in. Rollback is also embedded in the audit comment the playbook posts at action time. The playbook performs no other destructive change.

## Least privilege

Prefer a managed identity or an app registration with **Microsoft Graph `User.EnableDisableUser`** only, scoped via administrative unit where possible — not the full `User.ReadWrite.All` and never Global Admin. The Sentinel connection needs the **Microsoft Sentinel Responder** role on the workspace.
