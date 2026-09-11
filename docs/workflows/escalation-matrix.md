# Escalation Matrix

> Replace the placeholder names/contacts with your real org's roster before publishing internally. This template documents the structure, not specific people.

## 1  Decision tree

```
                          ┌──────────────────────────┐
                          │   New Sentinel incident   │
                          └──────────────┬───────────┘
                                         │
                       ┌─────────────────┴─────────────────┐
                       │                                   │
              Severity = Low/Med                 Severity = High / Critical
                       │                                   │
                       ▼                                   ▼
              L1 dispositions                  L1 acks + escalate to L2 IMMEDIATELY
              within 10 min                            (≤ 5 min SLA)
                       │                                   │
            ┌──────────┴──────────┐              ┌─────────┴──────────┐
            │                     │              │                    │
       FP / BP / TP        Needs L2 review    Single-entity      Multi-entity OR
       → close              → escalate         contained          exec / privileged
                                              → L2 owns           account
                                                                   │
                                                                   ▼
                                                       L3 takes lead, evaluates
                                                       declaring an Incident,
                                                       pages on-call eng if needed
```

## 2  Severity → who gets paged

| Severity | L1 | L2 | L3 | SecOps Mgr | On-call Eng | CISO |
|---|---|---|---|---|---|---|
| Informational | — | — | — | — | — | — |
| Low | own | review weekly | — | — | — | — |
| Medium | own | own | review daily | — | — | — |
| **High** | ack | own | **own** | notify | summon if scope > 1 host | — |
| **Critical** | ack | hand-off | **own** | **notify immediately** | **page** | brief within 1 h |

## 3  Critical-incident criteria (any one)

- Confirmed data exfiltration > 100 MB OR any PII / PCI / PHI
- Confirmed ransomware encryption activity on ≥ 1 host
- Compromise of a privileged account (Global Admin, Domain Admin, root, prod break-glass)
- Active C2 from ≥ 5 hosts
- Public-facing service compromise (web app, RDP gateway, VPN appliance)
- Detected nation-state TTP overlap (MS Threat Intel match for Storm-*, Midnight Blizzard, APT29/41, etc.)

## 4  Paging channels

| Channel | Use |
|---|---|
| `#sec-ops` (Slack/Teams) | All-hands real-time chat per incident |
| PagerDuty `secops-primary` | L3 on-call rotation |
| PagerDuty `secops-eng` | Detection engineering on-call (P1 only) |
| PagerDuty `secops-mgr` | Severity-High escalation, executive-account compromise |
| `secops-leadership@<org>` | Critical incident summary email within 30 min |

## 5  Hand-off template

When escalating, post in `#sec-ops` and DM the next tier:

```
INC-<id> hand-off
- Severity: <S>
- Rule: <name>
- Entities: <list>
- Timeline (max 5 lines):
- What I've done:
- What I need from you:
- Containment level proposed: monitor / soft / hard
```

## 6  Out-of-hours coverage

L3 follows-the-sun across 3 regions; PagerDuty rotation handles the hand-off. If a region's on-call cannot acknowledge within 10 min the alert escalates to that region's manager, then the global SecOps director.

| Region | Hours (local) | Primary | Backup |
|---|---|---|---|
| AMER | 08:00 – 18:00 | L3 rotation | SecOps Mgr |
| EMEA | 08:00 – 18:00 | L3 rotation | SecOps Mgr |
| APAC | 08:00 – 18:00 | L3 rotation | SecOps Mgr |
