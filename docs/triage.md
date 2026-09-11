# Triage

![L3 triage dashboard design preview](images/workbooks/01-triage-dashboard-design-preview.png)

*Design preview generated from `Workbooks/L3-Triage-Dashboard.json` by
`scripts/render_design_preview.py`. It requires deployment to display live telemetry and contains
no data: every panel shows `—` where a value would appear.*


The L1 → L3 workflow documents live in [`docs/workflows/`](workflows/). This page connects them to the specific artifacts in this repository.

![L3 triage dashboard, illustrative sample data](images/workbooks/02-triage-dashboard-sample-data.png)

*Same workbook, drawn with illustrative values **so the layout can be reviewed before deployment**.
The numbers on it are inventions, listed as such in [`evidence.md`](evidence.md): they are not
measurements and must never be cited as evidence of a detection. The data-free wireframe above is the
version to quote from.*

## Triage flow

```
Alert → Incident created (grouping per rule)
  → L1: enrich via workbook (KPIs, top entities, open incidents view)
       disposition: benign / needs L2
  → L2: investigate via incident graph + hunts
       disposition: FP (log in tuning log) / TP → escalate
  → L3: containment via SOAR playbooks + IR runbook
```

## Where to look first

- **[L3 Triage workbook](../Workbooks/L3-Triage-Dashboard.json)** — open incidents, MTTA/MTTR, top firing rules, top entities, tactic distribution, tuning indicators (rules with the highest benign-positive closure rate).
- **[Incident response runbook](workflows/ir-runbook.md)** — SANS/NIST phases applied to this rule pack.
- **[Triage SOP](workflows/triage-sop.md)** — L1/L2/L3 hand-off and disposition labels.
- **[Escalation matrix](workflows/escalation-matrix.md)** — paging thresholds per rule family.

## Rule-specific triage notes

| Rule family | First triage question | Follow-up artifact |
|---|---|---|
| Entra ID sign-ins | Did the user complete MFA, and from where? | `HUN_FirstSeenASN_PerUser`, `HUN_SignInFromDatacenterASN` |
| OAuth / SP credentials | Is the actor a human or `ActorApp` automation? | `EntraID_ServicePrincipalCredAdd` metadata |
| Inbox / forwarding | Out-of-band verify the owner before touching the mailbox | `HUN_AnomalousMailboxForwarding` |
| MDE LOLBins | What is the parent process chain? | `HUN_OfficeChildProcess`, `HUN_RareProcessPerDevice` |
| Azure exposure | Who is `Caller` — pipeline or human? | `Azure_NSG_OpenToInternet` metadata |
| Key Vault spike | Rotation tooling or harvesting? Check `Identity` UPN vs appid | `Azure_KeyVault_SecretAccessSpike` metadata |

## Disposition discipline

- Every closed incident gets a `CloseReason` — the workbook's tuning indicators are only as good as this discipline.
- Benign-positive incidents feed the [tuning loop](tuning.md); true positives feed the validation ledger in [`tests/atomics.md`](../tests/atomics.md).
