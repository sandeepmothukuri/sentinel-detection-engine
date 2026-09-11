# Incident Response Runbook (generic)

> Apply this runbook to any incident raised by a rule in this pack. It mirrors the SANS / NIST SP 800-61r2 phases (Identify → Contain → Eradicate → Recover → Lessons Learned) and is sized for an L3 analyst working with L1/L2 hand-offs and on-call escalation.

## 0  Acknowledge (target: ≤ 5 min from page)

- Open the incident in Sentinel → set status **Active**, assign yourself as owner.
- Post in `#sec-ops` channel: `INC-<id> ACK by <you>, severity <S>, primary entity <X>`.
- Start the **incident-clock** timer (Phase 5 ends it).

## 1  Identify (target: ≤ 15 min)

Verify it is not a benign cause before touching anything.

| Check | KQL hint | Action if true |
|---|---|---|
| Is the affected identity in the **change-window exemption** list? | `_GetWatchlist('ChangeWindowExemptions')` | Lower severity, monitor. |
| Did the alert fire on a **known scanner / pen-test box**? | `DeviceInfo \| where DeviceName has_any (scanners)` | Suppress via incident comment, link to scanner-schedule doc. |
| Is the rule **still tuning**? See `tuning-log.md`. | n/a | Apply incident-comment template `TUNING-NOISE`. |
| Has the same **entity + rule** combo fired in the last 24h? | `SecurityAlert \| where AlertName == "<rule>"` | Merge into the original incident, don't duplicate work. |

If none apply → proceed.

## 2  Contain (target: ≤ 30 min for S=High)

Pick the lightest-touch containment that stops the bleeding. Document every action as an incident comment.

### Identity compromise indicators
- Sentinel → Incident → **Actions → Confirm user as compromised** (sets Entra ID risk = High).
- If high-confidence: run playbook **AutoEnrichDisableUser** (or disable manually: `Update-MgUser -UserId X -AccountEnabled $false`).
- Revoke sessions: `Revoke-MgUserSignInSession -UserId X`.

### Endpoint compromise indicators
- Run playbook **IsolateDeviceMDE** (network-isolates the device, keeps Defender comms).
- Pull live forensics: MDE → device → **Initiate Live Response** → `getfile`, `processes`, `connections`.

### Network indicator
- Run playbook **BlockIPAzureFirewall** (adds IP to deny rule on perimeter firewall).
- If IP is in a high-volume range, block ASN at the WAF instead.

## 3  Eradicate (target: same day for S=High)

- For inbox-rule incidents: `Remove-InboxRule` for the malicious rule; review last 30 d of rule changes for that mailbox.
- For OAuth consent: revoke the application's permissions in Entra ID → Enterprise Apps → app → Permissions → Remove.
- For endpoint malware: MDE → **Run antivirus scan** + **Collect investigation package** before re-imaging.
- Rotate any secrets the compromised identity could see (Key Vault, app credentials, service principals).

## 4  Recover

- Re-enable user only after: password reset, MFA re-enrollment, sign-in risk = Low.
- Un-isolate device only after: AV scan clean, EDR shows no malicious processes for 24 h.
- Drop firewall block only after the campaign has stopped or threat-intel feed expires the IOC.

## 5  Lessons Learned (within 5 business days)

Stop the incident clock. Write a postmortem in `docs/postmortems/INC-<id>.md` using `docs/workflows/postmortem-template.md`. Required sections:

- Timeline (with timestamps)
- Root cause (5-whys)
- What detected it (rule name + dwell time)
- What we missed (detection gap)
- Action items (each must have an owner + due date)
- Detection-tuning entries → add to `tuning-log.md`

If the rule fired too late or with too much dwell time, file a detection improvement ticket and link it from the postmortem.

## Per-rule overrides

A handful of detections need rule-specific containment steps. Each detection YAML file's `description:` block names the dominant adversary technique; if that points to a known campaign (e.g. Storm-0558, Midnight Blizzard), prefer the campaign-specific MS Threat Intel guidance over generic eradication.
