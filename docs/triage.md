# Triage

The L1 → L3 workflow documents live in [`docs/workflows/`](workflows/). This page connects them to the specific artifacts in this repository.

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
