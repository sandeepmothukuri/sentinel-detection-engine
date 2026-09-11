# Triage SOP — Sentinel Incidents

> Reference document for the L1 → L2 → L3 hand-off. Goal: under 7 min average triage time per incident, ≥ 90% true-positive routing to L2+.

## 0  Triage tiers

| Tier | Skill | Owns | SLA to next action |
|---|---|---|---|
| **L1** | Alert dispositioning | Acknowledge, dedup, run enrichment playbooks, apply SOP labels | 10 min |
| **L2** | Investigation | Pivot across SecurityAlert + raw tables, propose containment | 30 min (High), 2 h (Medium) |
| **L3** | Detection engineering + IR lead | Containment authority, tune detections, postmortems | Same shift |

## 1  L1 — Disposition checklist

For each new Sentinel incident, in order:

1. **Read the incident description** — title, severity, primary entity. Do NOT click around first.
2. **Run enrichment playbook** (`AutoEnrichDisableUser` triggers automatically; if not, run manually).
3. **Apply one disposition label** within 10 min:

| Label | When to apply | Next step |
|---|---|---|
| `TP-CONFIRMED` | The behaviour described actually happened AND is not authorised. | Escalate to L2. |
| `BP-AUTHORISED` | The behaviour happened but is authorised (change window, sanctioned tool). | Close as Benign Positive, comment with change ticket #. |
| `FP-NOISE` | The rule fired on a benign pattern (known scanner, dev workflow). | Close as False Positive, add a tuning entry. |
| `NEEDS-L2` | Cannot decide within 10 min. | Escalate. |

4. **Add 1-line comment** with the disposition rationale.

## 2  L2 — Investigation checklist

For every `TP-CONFIRMED` or `NEEDS-L2` incident:

```
□ Build a 5-line timeline (first sign, escalation, current state)
□ Identify all entities (user, host, IP, file hash, app)
□ Pivot to the raw table behind the alert — does the broader context support the alert?
□ Search 7d for the same entity in OTHER detections — is this part of a chain?
□ Decide containment level: monitor / soft (revoke session) / hard (disable+isolate)
□ Hand to L3 if: containment is "hard", chain spans > 2 detections, or exec-level account
```

L2 must not close `TP-CONFIRMED` without L3 sign-off if the entity is in the **executive watchlist** or the **service-account watchlist**.

## 3  L3 — Containment + closure

L3 owns:
- Authorisation to disable a user, isolate a device, or block at the perimeter.
- The decision to invoke the on-call engineer (see `escalation-matrix.md`).
- The decision to declare an **Incident** (uppercase) vs. continue handling as an alert.

After containment, L3 runs **Eradicate / Recover / Lessons Learned** per `ir-runbook.md`.

## 4  Dispositions to detection-tuning

Every `FP-NOISE` closure MUST add an entry to `tuning-log.md` describing:
- The benign pattern that triggered the rule
- The proposed query change (or watchlist addition)
- Owner + due date

The detection-engineering on-call reviews the tuning log weekly and lands changes via PR.

## 5  Triage metrics worth tracking

| Metric | Target | Source |
|---|---|---|
| MTTA (mean time to acknowledge) | < 5 min, High | Sentinel `SecurityIncident.CreatedTime` → first ownership change |
| MTTD (mean dwell time) | < 1 h, High | `FirstActivityTime` → `CreatedTime` |
| MTTR (mean time to remediate) | < 4 h, High | `CreatedTime` → `ClosedTime` |
| FP rate per rule | < 30% | `SecurityIncident.Classification` |
| Escalations rejected by L2 | < 10% | Manual sample |

These are wired into the **L3 Triage Dashboard** workbook (see `Workbooks/`).
