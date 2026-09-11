# SOAR

![SOAR decision flow and safety gates](images/soar/01-soar-safety-gate-flow.png)

*Source: `docs/diagrams/soar/01-soar-safety-gate-flow.mmd`. The gate parameters shown are the
defaults declared in the playbook ARM templates.*


Four Logic App playbooks automate enrichment and containment. The decision pipeline and per-rule automation matrix are in [`docs/workflows/soar-decision-flow.md`](workflows/soar-decision-flow.md); each playbook's operational details are in its own `README.md`.

## Playbooks

| Playbook | Trigger binding | Action | Destructive? |
|---|---|---|---|
| [AutoEnrichDisableUser](../Playbooks/AutoEnrichDisableUser/README.md) | Any incident (recommend: Entra ID rules) | VT + AbuseIPDB enrichment; disables Entra ID user above confidence + severity + exclusion gates | Yes |
| [IsolateDeviceMDE](../Playbooks/IsolateDeviceMDE/README.md) | Incidents from `MDE_*` rules | Network-isolates device via MDE `machineActions` | Yes |
| [BlockIPAzureFirewall](../Playbooks/BlockIPAzureFirewall/README.md) | Incidents with IP entities | Adds public IPs to an Azure Firewall deny IP Group | Yes |
| [CreateServiceNowTicket](../Playbooks/CreateServiceNowTicket/README.md) | Severity High | Opens a mapped INC record + cross-links | No |

## Safety model (v1.1)

No playbook in this pack takes a destructive action without all of:

1. **Severity gate** — a `MinimumSeverity` parameter (default `High`, the top Sentinel severity). Lower-severity incidents get an explanatory comment instead of an action.
2. **Confidence/quality gate** — reputation threshold (disable user) or entity-quality checks (MDE ID present, public IP only).
3. **Allowlists** — `ExcludedUserPrincipals` (break-glass/VIPs) and `AllowlistedIPs` (corporate egress) are never actioned on.
4. **Ceilings** — the firewall blocklist refuses to exceed `MaxIPGroupEntries` rather than half-update.
5. **Audit trail** — every action *and* no-action path posts a comment to the incident stating what ran, the thresholds, and the rollback command.
6. **Failure visibility** — failed or unconfirmed actions raise a loud `WARNING` comment so an analyst closes the loop manually.
7. **Single-flight concurrency** — triggers run one at a time to prevent racing automations on the same incident.

## Enabling auto-action safely

The gates above are the reason a destructive step can run unattended, and they are also the reason
it should not run on day one. The onboarding path that matches how these parameters behave:

1. **Comment-only first.** Set `DisableUserConfidenceThreshold` above 100 (and leave the firewall
   allowlist empty of nothing — instead scope its automation rule to nothing) so every path
   enriches and comments but never acts. No code change is needed: a threshold above the scale is
   the off switch.
2. **Read the comments.** They state the observed confidence, the severity gate and the exclusion
   list for every incident. That is the data a threshold decision needs.
3. **Lower the threshold with a tuning-log entry** naming the incident numbers that justified it,
   then leave the allowlists in place. Relaxing a gate without a recorded reason is how an
   automation earns a bad reputation.
4. **Scope the automation rule, not just the playbook.** Bind each playbook to the smallest set of
   rules and severities that still makes it useful; the gates are a second line, not the first.

## What is deliberately NOT automated

- **Approval gates**: none of these playbooks pause for human approval mid-flow — they are bound to narrow conditions instead. If your organisation prefers approve-then-act, add an approval connector step *before* the destructive action; the gate conditions already make that insertion point obvious.
- **Session revocation, credential reset, mailbox purge, VM shutdown**: out of scope; too broad for unattended automation without tenant-specific context.

## Rollback summary

| Action | Rollback |
|---|---|
| Disable user | `Set-AzureADUser -ObjectId <upn> -AccountEnabled $true` (embedded in comment) |
| Device isolation | MDE portal → Release from isolation |
| Blocked IP | Remove the `/32` from the IP Group |
| ServiceNow ticket | Close INC via normal process |

## Binding playbooks

Sentinel → Automation → New rule → trigger `Incident created` → conditions (rule name / severity) → action `Run playbook`. Scope automation rules as narrowly as the playbook's gates allow; defence-in-depth here is cheap.

## Testing playbooks safely

Use the [validation procedure](testing.md#live-validation-procedure-self-service) with test users/devices before binding to production severities. Keep `MinimumSeverity` at its strictest during onboarding and relax only with tuning-log evidence.
