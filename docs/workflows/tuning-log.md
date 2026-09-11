# Detection Tuning Log

> Every `FP-NOISE` closure adds an entry here. Reviewed weekly by detection-engineering on-call. Closed entries are kept (not deleted) so we can correlate tuning history against rule churn over time.

## Entry template

```
### YYYY-MM-DD — <rule-name>
- **Incident:** INC-<id>
- **FP pattern:** what benign behaviour caused this to fire
- **Proposed fix:** query change / watchlist / dynamic threshold / suppression rule
- **Owner:** @handle
- **Due:** YYYY-MM-DD
- **Status:** Open / In-PR / Merged / Won't-fix
- **PR:** #<num>
```

---

## Open entries

### 2026-05-13 — MDE - PowerShell EncodedCommand With Long Payload
- **Incident:** INC-1037
- **FP pattern:** SCCM client-side scripting deploys legitimate `-EncodedCommand` payloads from `C:\Windows\CCM\` during patch cycles (~Tuesday 02:00 local). Encoded body decodes to MS-signed deployment scripts.
- **Proposed fix:** Add exclusion `where InitiatingProcessFolderPath !startswith @"C:\Windows\CCM"` AND `InitiatingProcessFileName != "CcmExec.exe"`. Confirm with patching team that script signer is `O=Microsoft Corporation`.
- **Owner:** @sandeepmothukuri
- **Due:** 2026-05-20
- **Status:** In-PR
- **PR:** #14

### 2026-05-09 — Entra ID - Successful Legacy Auth Sign-In
- **Incident:** INC-1019
- **FP pattern:** Finance team's monthly ERP export tool authenticates via SMTP AUTH from a service account `svc-finance-export@`. Cannot be moved to modern auth until ERP vendor releases v9 (Q3).
- **Proposed fix:** Add the service-account UPN to watchlist `LegacyAuthExemptions`, then `| where UserPrincipalName !in (_GetWatchlist('LegacyAuthExemptions') | project SearchKey)`.
- **Owner:** @sandeepmothukuri
- **Due:** 2026-05-21
- **Status:** Open

## Closed entries

### 2026-04-22 — HUN - Sign-In From Hosting / Datacenter ASN
- **Incident:** INC-947
- **FP pattern:** Engineering team uses GitHub Codespaces (Azure-hosted) which appears in the datacenter-ASN list (8075).
- **Fix:** Added `AppDisplayName !in ("GitHub","GitHub.com","GitHub Codespaces")` to the hunt.
- **Status:** Merged
- **PR:** #6

### 2026-04-11 — M365 - Mass SharePoint / OneDrive Download
- **Incident:** INC-902
- **FP pattern:** OneDrive sync client on a new laptop bulk-downloads a user's existing files on first login.
- **Fix:** Excluded `UserAgent has "OneDriveMpc"` AND `Operation == "FileSyncDownloadedFull"`, kept manual downloads (`FileDownloaded`) in scope.
- **Status:** Merged
- **PR:** #3

---

## Weekly review checklist (detection-engineering on-call)

```
□ All entries with Open status > 14 days → escalate to L3 lead
□ Any rule with > 5 tuning entries in the last quarter → consider rewrite
□ Merged entries from last 7 d → confirm FP rate dropped via Sentinel workbook
□ New `BP-AUTHORISED` patterns repeating → propose watchlist instead of per-incident closure
```

## Metric: FP rate per rule (last 14 days)

Refresh via this KQL in the L3 Triage workbook:

```kusto
SecurityIncident
| where TimeGenerated > ago(14d)
| where Classification == "FalsePositive"
| summarize FPs = count() by AlertRuleName = tostring(AdditionalData.alertProductNames[0])
| join kind=leftouter (
    SecurityIncident
    | where TimeGenerated > ago(14d)
    | summarize Total = count() by AlertRuleName = tostring(AdditionalData.alertProductNames[0])
) on AlertRuleName
| extend FPRate = round(100.0 * FPs / Total, 1)
| order by FPRate desc
```
