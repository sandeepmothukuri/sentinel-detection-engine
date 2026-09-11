# Capturing the real screenshots

This repository ships **no invented screenshots**. Where a real capture is missing it says so and
leaves the gap visible, because a plausible-looking picture of a tenant nobody has is the single most
expensive kind of fake evidence: it is read as proof.

What it ships instead is this page. It names the pictures worth taking, says what each one proves,
lists what must be redacted, and files a capture with one command that strips metadata and writes the
register entry. [`capture-manifest.yaml`](capture-manifest.yaml) is the machine-readable version of
the list, and [`../evidence.md`](../evidence.md) is where a filed capture lands.

**Current state: 1 of 10 shots is filed.** The ATT&CK Navigator export at
[`attack/03-attack-navigator-export.png`](attack/03-attack-navigator-export.png) is a real capture of a
real tool. The other nine are pending, and they are the reason every validation status in this
repository reads `STATIC VALIDATION` rather than anything stronger. A repository cannot capture a
tenant it does not have. It can, however, make the ten minutes that capture takes as small as possible
— that is what this page is for.

---

## The minimum viable evidence set

If you capture nothing else, capture these three. They cover detection, response and investigation,
and between them they turn the repository from *described* to *demonstrated*:

| # | Shot | Retires |
|---|---|---|
| 1 | An incident raised by one of these rules, with its entities and custom alert details | "the rules exist" → "a rule fired on real telemetry and produced the entities the playbooks consume" |
| 2 | The playbook's comment on that incident | "the playbook has a safety gate" → "the gate ran and left an audit trail on the incident" |
| 3 | The triage workbook rendered against that incident history | "the workbook queries are valid" → "the workbook binds to the declared tables and returns rows" |

Everything else on the list is supporting evidence.

---

## Ground rules

These are the rules the register enforces. Following them at capture time is cheaper than discovering
them at review time.

1. **Redact in the pixels, before saving.** The intake script removes file metadata; it cannot remove
   what is *on the screen*. Paint over or blur: tenant id, subscription id, resource group id,
   workspace id, user principal names, e-mail addresses, organisation names, hostnames and FQDNs, IP
   addresses, licence and commitment information, connection ids, tokens, and anything in the browser
   chrome (bookmarks bar, other tabs, profile name).
2. **Keep the product chrome.** The header that identifies the portal is what makes the shot
   attributable. Crop the tenant switcher, not the page title.
3. **One claim per image.** If two things need proving, that is two captures. A shot that proves
   nothing in particular is a shot a reviewer will discount entirely.
4. **Never stage a shot.** No hand-typed incidents, no sample workspace, no reproduction of a screen
   in an editor. An empty panel captured honestly is evidence; a filled one that never happened is a
   defect, and the register treats it as one.
5. **Where a number is missing, show the absence.** If a panel is empty, capture it empty. `—` and a
   zero row are real results; a placeholder rendered as a value is not.
6. **Annotate to obscure, never to add.** No arrows, circles or captions drawn onto a capture: they
   assert something the pixels do not.
7. **Settings.** Window at least 1400 px wide, browser zoom 100 %, one theme per shot, saved as PNG.
8. **Finish the register entry.** The intake script deliberately leaves the `Demonstrates` line empty.
   `tests/test_evidence.py` fails the build until the person who took the screenshot writes it in one
   sentence.

---

## The shot list

| Pri | id | Area | What it proves |
|:-:|---|---|---|
| — | `attack-navigator-export` | `attack` | *Filed.* The ATT&CK layer this repository generates is rendered by the official MITRE Navigator |
| 1 | `sentinel-incident-with-entities` | `sentinel` | A rule fired on real telemetry, produced the mapped entities, and rendered its custom alert details |
| 2 | `soar-incident-comment-audit-trail` | `soar` | The playbook ran the safety gate and left the audit trail the SOAR model promises |
| 3 | `workbooks-triage-dashboard-live` | `workbooks` | The workbook binds to the declared tables and renders against real incident history |
| 4 | `sentinel-analytics-rule-deployed` | `sentinel` | The generated ARM templates deploy: the rules exist in the workspace, enabled, with their mappings |
| 5 | `soar-playbook-run-history` | `soar` | The gate logic is observable per run: which accounts were actioned and which were skipped |
| 6 | `hunting-query-results` | `hunting` | A hunt query executes against its declared table and returns the shape the README describes |
| 7 | `ci-actions-run-green` | `ci-cd` | The validation workflow runs on GitHub — the one claim a local reproduction cannot make |
| 8 | `sentinel-repository-connection` | `sentinel` | The GitOps path is the real deployment path, consuming the generated templates |
| 9 | `detections-local-validation-run` | `detections` | *Optional.* The validator and suite run end to end on a real machine — superseded by shot 7 once CI is green |

---

## Per-shot instructions

### 1 · `sentinel-incident-with-entities` — priority 1

**Where:** Microsoft Defender portal → **Incidents & alerts → Incidents** → open an incident raised by
one of the rules in `Detections/`.
**What must be visible:** the incident title (which carries the rule name), severity, the *Evidence
and response* or *Entities* panel showing the account, host and IP entities, and — on the alert
details — the custom details produced by the `alertDetailsOverride` block (`AccountName`, `HostName`,
`OriginalIP`, depending on the rule).
**Redacts:** UPNs, e-mail addresses, hostnames, IP addresses, tenant id, incident id if you consider it
sensitive.
**Why it matters:** this is the shot that proves the entity mapping works. The playbooks act on those
entity types; if the mapping is wrong, the automation silently receives nothing.

```bash
python scripts/register_screenshot.py ~/captures/incident.png \
  --area sentinel --slug incident-with-entities \
  --purpose "Incident raised by EntraID_ImpossibleTravel with account, host and IP entities and the custom alert details rendered" \
  --environment "Single-author lab: one Sentinel workspace with the connectors connected, test accounts only" \
  --redactions "UPNs and e-mail addresses painted over; tenant id and workspace id painted over; hostnames partially masked" \
  --manifest-id sentinel-incident-with-entities
```

### 2 · `soar-incident-comment-audit-trail` — priority 2

**Where:** the same incident → the comment the playbook posted.
**What must be visible:** the comment text as the playbook wrote it — the per-IP evidence, the maximum
confidence against the threshold, the severity floor, the size of the exclusion lists, and the
rollback instruction. A `WARNING` comment is equally valuable: it proves the failure path works.
**Redacts:** UPNs, account ids, addresses.

```bash
python scripts/register_screenshot.py ~/captures/comment.png \
  --area soar --slug incident-comment-audit-trail \
  --purpose "The audit comment posted by AutoEnrichDisableUser on the incident, showing confidence, the severity floor and the rollback line" \
  --environment "Single-author lab: one Sentinel workspace, playbook bound by an automation rule scoped to test accounts" \
  --redactions "Account identifiers and e-mail addresses painted over" \
  --manifest-id soar-incident-comment-audit-trail
```

### 3 · `workbooks-triage-dashboard-live` — priority 3

**Where:** Microsoft Sentinel → **Workbooks** → the triage workbook built from
[`../../Workbooks/`](../../Workbooks/), time range *Last 7 days*.
**What must be visible:** the workbooks deployed and at least one panel returning rows. Panels with no
data yet are captured as they are; an empty panel beside a populated one is honest and readable.
**Redacts:** as above, plus any incident titles if they contain user names.

### 4 · `sentinel-analytics-rule-deployed` — priority 4

**Where:** Sentinel → **Configuration → Analytics** → *Active rules*, filtered to the rule names in
`Detections/`.
**What must be visible:** several rule names with status *Enabled*, severity, tactics and the last
modified time; open one rule and capture the technique mapping if it fits in the same frame.
**Why it matters:** it shows the ARM in `deploy/` was consumed by something, not just generated.

### 5 · `soar-playbook-run-history` — priority 5

**Where:** Azure portal → **Logic apps** → the playbook → **Runs history** → one run → the action
list.
**What must be visible:** the gate actions by name (`Condition_-_Sev_Confidence_and_NotExcluded`,
`Check_Account_Is_Disableable`, `Condition_-_Guard_Rails`) with their outcomes, and the comment or
action steps that followed. A run where the gate *skipped* an account is better evidence than one
where everything ran: it shows the gate doing work.
**Redacts:** the Logic App's resource id, subscription id, and any account identifiers in the inputs.

### 6 · `hunting-query-results` — priority 6

**Where:** Defender portal → **Hunting → Advanced hunting** (or Sentinel → **Logs**) → run one of the
queries from [`../../Hunting Queries/`](../../Hunting Queries/) over the last 7 days.
**What must be visible:** the query text (at least the table and the time bound), the time range, and
the result grid with its columns and row count.

### 7 · `ci-actions-run-green` — priority 7

**Where:** `github.com/sandeepmothukuri/sentinel-detection-engine` → **Actions** → the *validate*
workflow → the newest run on `main`.
**What must be visible:** the green check, the step list including the validator, the test step, the
drift gates and the packaging step, and the run's commit.
**Why it matters:** every other claim about CI in this repository is a claim about a file. This is the
only evidence that GitHub itself ran it.

### 8 · `sentinel-repository-connection` — priority 8

**Where:** Azure portal → Microsoft Sentinel → **Content management → Repositories** → the connected
repository.
**What must be visible:** the connection name, the branch, the deployable content type, and the last
deployment status.

### 9 · `detections-local-validation-run` — priority 9, optional

**Where:** a terminal, after `python -m pytest tests -q` and
`python scripts/ci_validate.py` have run in the repository root on a real machine.
**What must be visible:** the command and its summary line. Take this only until shot 7 exists — a
green CI run supersedes a local one, and a terminal capture is the easiest screenshot to fake, which
is exactly why it is last on the list.

---

## Filing a capture

```bash
# 1. file it: strips metadata, names it NN-lab-<slug>.png, writes the register entry
python scripts/register_screenshot.py <capture.png> \
  --area <area> --slug <slug> \
  --purpose "..." --environment "..." --redactions "..." \
  --manifest-id <id from the shot list>

# 2. complete the Demonstrates line it left for you — only you saw the screen
$EDITOR docs/evidence.md

# 3. the gates that check your work
python -m pytest tests/test_evidence.py -q
```

`--manifest-id` flips the shot's status to `captured` in
[`capture-manifest.yaml`](capture-manifest.yaml) and records the file it created. Without it the
manifest and the register disagree, and `tests/test_evidence.py` fails on that disagreement — the
manifest is not a wish list that rots, it is a checklist the build checks.

`--force` overwrites an existing image and register entry; without it the script refuses, so a
capture cannot silently replace the evidence it supersedes.

---

## What a capture does and does not change

**It does.** It gives the register a dated, checksummed record of an environment in a state you can
describe. It supports a ledger entry: `tests/validation/atomics.yaml` takes an evidence path, and a
filed capture is a legitimate one.

**It does not, by itself.** Move a rule's status. A screenshot of an incident proves the rule fired
once, in one environment, on one day. The status vocabulary in
[`validation-schema.yaml`](../../tests/validation/validation-schema.yaml) requires the
method, the date and the evidence, and `STATIC VALIDATION` becomes something stronger only when a
ledger entry says so — never because an image looks convincing. That distinction is the reason this
repository is trusted at all, and it survives contact with a camera.
