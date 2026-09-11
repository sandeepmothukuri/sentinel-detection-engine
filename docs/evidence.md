# Evidence Register

This file records where every image in `docs/images/` came from, what it demonstrates, and what
was redacted. It exists because a detection-engineering repository should be able to answer
"how do you know?" for its own pictures as readily as for its queries.

## How to read this register

| Field | Meaning |
|---|---|
| **Provenance class** | *Diagram* (original Mermaid source in this repository), *Generated chart* (drawn by a script from repository data), or *Screenshot* (captured from the author's own environment) |
| **Source** | The file that generates it, or the system that was captured |
| **Environment** | What had to exist for the image to be produced |
| **Date** | When the artefact was produced or last regenerated |
| **Demonstrates** | The specific claim a reader is entitled to take from the image |
| **Redactions** | What was removed or, where nothing was removed, why nothing needed removing |

**None of these images shows a live Microsoft Sentinel tenant.** There is no production
deployment behind this repository, so every image is a diagram, a chart generated from committed
files, or a screenshot of a client-side tool rendering committed files. The one screenshot in
the register (the ATT&CK Navigator export) renders the layer that is committed in this
repository; it is not a Sentinel screenshot. Nothing on this page is evidence that a detection
has fired, and no metric, incident number, or alert count appears in any image.

Where the repository does not have evidence, the corresponding documentation says
`Not yet measured`, `Requires live tenant validation`, or `Awaiting live telemetry` rather than
supplying a picture that implies otherwise.

## Filing a real capture

When a live tenant exists and you have a screenshot worth committing, it enters through
[`scripts/register_screenshot.py`](../scripts/register_screenshot.py) rather than by copying a file
into place:

```bash
python scripts/register_screenshot.py capture.png \
    --area sentinel --slug workspace-overview \
    --purpose "The lab workspace with Sentinel enabled and the connectors connected" \
    --environment "Single-author lab: Azure free tier, one Log Analytics workspace, E5 dev tenant" \
    --redactions "Subscription and workspace ids painted over; tenant domain cropped"
```

The script strips the file's EXIF and PNG text metadata by re-encoding it losslessly, names and
files it as `NN-lab-<slug>.png` in the right area, records its SHA-256, and writes the register
entry below with an **empty `Demonstrates` line**. That line is the only part it will not write,
because only the person who took the screenshot can say what it shows.

`tests/test_evidence.py` enforces the rest: no committed image may carry metadata, every
`Screenshot` entry must record an environment, a date and a redaction statement, a lab capture must
follow the naming convention, and **an entry whose `Demonstrates` line is still the intake
placeholder fails the build.** A screenshot that nobody has described is not evidence.

Redaction is yours to do in the pixels, before filing: subscription and tenant ids, workspace ids,
user principal names, e-mail addresses, IP addresses, organisation names, hostnames, tokens and
secrets. The script removes what is attached to the file, not what is on the screen.

---

## architecture

### `architecture/01-logical-architecture.png`
- **Provenance class:** Diagram
- **Source:** `docs/diagrams/architecture/01-logical-architecture.mmd`, rendered by `scripts/render_diagrams.py`
- **Environment:** None. Rendered from source; requires no tenant, no connector, no deployment.
- **Date:** 2026-09-11
- **Demonstrates:** The intended architecture of the repository: four telemetry sources, the
  connectors that ingest them, the Log Analytics tables the rules query, the 18 scheduled
  analytics rules and 10 hunting queries, incident generation, the four response playbooks, and
  the engineering control plane (Git repository, CI, generated ATT&CK artefacts).
- **Redactions:** None required. The diagram contains no environment-specific values by design:
  no workspace name, no subscription id, no hostnames, no addresses.

### `architecture/02-telemetry-to-detection-flow.png`
- **Provenance class:** Diagram
- **Source:** `docs/diagrams/architecture/02-telemetry-to-detection-flow.mmd`
- **Environment:** None.
- **Date:** 2026-09-11
- **Demonstrates:** How a single event becomes an analyst decision: source event → connector →
  table → analytics rule (with `queryFrequency` and `queryPeriod` in the loop) → threshold
  decision → entity-mapped alert → incident grouping → triage → SOAR behind a confidence gate →
  containment → verification and audit → tuning loop back into the rule.
- **Redactions:** None required.

## sentinel

### `sentinel/01-connector-table-coverage.png`
- **Provenance class:** Diagram
- **Source:** `docs/diagrams/sentinel/01-connector-table-coverage.mmd`
- **Environment:** None. The per-table rule counts were derived from the
  `requiredDataConnectors` blocks of the 28 rule files when the diagram was authored.
- **Date:** 2026-09-11
- **Demonstrates:** Which connector is needed for which table, and how many rules depend on each
  table: SigninLogs 5, AuditLogs 4, OfficeActivity 3, DeviceProcessEvents 10, DeviceNetworkEvents 3,
  DeviceFileEvents 1, DeviceInfo 1, AzureActivity 2, AzureDiagnostics 1.
- **Redactions:** None required. This is the deployment shape, not a tenant's state.

## detections

### `detections/01-rule-development-lifecycle.png`
- **Provenance class:** Diagram
- **Source:** `docs/diagrams/detections/01-rule-development-lifecycle.mmd`
- **Environment:** None.
- **Date:** 2026-09-11
- **Demonstrates:** The nine-step lifecycle this repository actually enforces: hypothesis,
  telemetry check, query, static validation, validation-ledger entry, pull request with CI gates,
  deployment, measurement, and the tune-or-diagnose branch that returns to the query.
- **Redactions:** None required.

### `detections/02-analytics-rule-anatomy.png`
- **Provenance class:** Diagram
- **Source:** `docs/diagrams/detections/02-analytics-rule-anatomy.mmd`
- **Environment:** None. The gate names correspond to check families implemented in
  `scripts/ci_validate.py`.
- **Date:** 2026-09-11
- **Demonstrates:** Which validation gate inspects which section of a rule file — schema and
  scheduling bounds, ATT&CK coherence, telemetry-to-connector parity, KQL lint and time bounds,
  entity validity, alert-detail placeholders, metadata quality, and the validation ledger.
- **Redactions:** None required.

## hunting

### `hunting/01-hunt-to-detection-workflow.png`
- **Provenance class:** Diagram
- **Source:** `docs/diagrams/hunting/01-hunt-to-detection-workflow.mmd`
- **Environment:** None.
- **Date:** 2026-09-11
- **Demonstrates:** How a hunt hypothesis is run, triaged and either closed with a documented
  negative result, escalated, recorded as a telemetry gap, or promoted into a detection with its
  own validation-ledger entry and CI gates.
- **Redactions:** None required.

## soar

### `soar/01-soar-safety-gate-flow.png`
- **Provenance class:** Diagram
- **Source:** `docs/diagrams/soar/01-soar-safety-gate-flow.mmd`
- **Environment:** None. The confidence and safety-gate parameters shown are the defaults
  declared in the playbooks' ARM templates (`MinimumSeverity`, `DisableUserConfidenceThreshold`
  and the allowlist parameters).
- **Date:** 2026-09-11
- **Demonstrates:** The control that matters most in this repository: a destructive action
  (disable account, isolate device, block IP) is never taken because a query returned rows. The
  flow requires a confidence threshold, independent corroboration, and a safety gate that routes
  privileged or break-glass accounts, allowlisted entities and unclear blast radii back to
  analyst review. Every automated action still ends in verification, audit and a rollback path.
- **Redactions:** None required.

## workbooks

### `workbooks/01-triage-dashboard-design-preview.png`
- **Provenance class:** Diagram (design preview)
- **Source:** `scripts/render_design_preview.py`, which reads the panel list out of
  `Workbooks/L3-Triage-Dashboard.json`. A `.sha256` sidecar next to the image records the
  digest so CI can detect a workbook change that was not re-rendered.
- **Environment:** None. This is not a screenshot and could not be one: there is no deployed
  workspace to capture.
- **Date:** 2026-09-11
- **Demonstrates:** The panel layout of the workbook that is actually committed — 13 panels
  covering queue health, detection behaviour, analyst performance, and tuning/telemetry health —
  and which table each panel reads.
- **Identity of the image:** It carries the banner **"DESIGN PREVIEW — REQUIRES DEPLOYMENT TO
  DISPLAY LIVE TELEMETRY"** inside the image itself, plus the note "Panel layout only. Contains
  no tenant data, no incident numbers and no metrics." Every panel shows `—` where a value would
  appear after deployment. It is deliberately not styled to look like a Sentinel screenshot:
  there is no Sentinel chrome, no tenant name, and no fabricated numbers.
- **Redactions:** Not applicable; nothing real is depicted.
- **Note on the superseded image:** an earlier revision of this repository contained
  `docs/images/00-dashboard-mockup.png`, which showed invented incident numbers (INC-1042 and
  similar), invented analyst names, invented MTTA/MTTR values, and a technique count that
  disagreed with `coverage.md`. It was deleted, not edited: a picture of numbers that do not
  exist has no place in an evidence register. The replacement above is generated from the
  workbook definition and contains no numbers at all.

## attack

*Numbering note: there is no `attack/02`. The Navigator export was renumbered to `03` when it moved
into this directory, and the number was left as a gap rather than reused, so that a link to the old
path fails loudly instead of silently resolving to a different image.*

### `attack/01-attack-coverage-by-tactic.png`
- **Provenance class:** Generated chart
- **Source:** `scripts/render_coverage_chart.py`, reading `attack-navigator/layer.json`,
  `scripts/attack_data.json` and the 28 rule files.
- **Environment:** None. Every bar is a count of distinct techniques in committed files.
- **Date:** 2026-09-11
- **Demonstrates:** Coverage per ATT&CK tactic split by source — scheduled analytics rules versus
  hunting queries only — with tactics that have no coverage called out explicitly. The headline
  number (techniques, tactics covered) is the same number stated in `coverage.md`.
- **Redactions:** None required.

### `attack/03-attack-navigator-export.png`
- **Provenance class:** Screenshot
- **Source:** MITRE ATT&CK® Navigator (v5.3.2), rendering the layer committed at
  `attack-navigator/layer.json` from the author's own workstation.
- **Environment:** Client-side web tool. No Sentinel workspace, connector or tenant is involved:
  the Navigator is a static renderer for the JSON layer file in this repository.
- **Date:** 2026-09-11
- **Demonstrates:** That the committed layer loads in a real Navigator session — the tab reads
  `sentinel-detection-engine coverage`, not a mock start screen — and that the techniques
  `coverage.md` reports are the ones highlighted on the matrix, including the Impact and
  Lateral Movement entries the six added rules contributed.
- **Redactions:** None required — the Navigator view contains no tenant identifiers, hostnames,
  user names or addresses. The banner announcing a newer ATT&CK release is part of the tool's own
  interface and is left visible rather than cropped.
- **Version note — this capture predates the v19 declaration.** The layer was captured while
  `attack-navigator/layer.json` declared `versions.attack = 18`; the file now declares `19`. The
  visible difference is in the domain data, not in this layer's contents: under v19 the domain
  retires Defense Evasion (TA0005) into Stealth and Defense Impairment (TA0112), splits T1562 into
  T1685 and moves T1562.007 to T1686.001. The screenshot therefore shows the pre-split
  **Defense Evasion** column, and its unhighlighted technique set reflects the v18 domain.
  **Pending action:** re-capture from a Navigator whose domain data is v19 so the register shows
  the same domain the layer declares. Until then the image is evidence that the layer loads and
  highlights as reported — not evidence about the v19 tactic split, which `coverage.md`,
  `docs/ATTACK.md` and the vendored dataset carry instead.
- **Not included:** there is deliberately no screenshot of the analytics-rule blade, the incident
  queue, or the deployed workbook. Those would require a live workspace with real telemetry, and
  no such screenshot can be produced honestly from this repository.

## ci-cd

### `ci-cd/01-validation-pipeline.png`
- **Provenance class:** Diagram
- **Source:** `docs/diagrams/ci-cd/01-validation-pipeline.mmd`
- **Environment:** None. Every gate named in the flow exists as a step in
  `.github/workflows/validate.yml`; the diagram is a rendering of that file, not a screenshot of a
  run.
- **Date:** 2026-09-11
- **Demonstrates:** The order of the checks a change must survive on the way to `main`, including
  the five drift gates (coverage and layer, validation ledger, `deploy/`, quality matrix, workbook preview digest)
  that fail the build when a generated artefact stops matching the files it is derived from. The
  sequence is the argument: nothing reaches the packaging step until the generated artefacts have
  been proven reproducible.
- **Redactions:** None required.

### `ci-cd/02-release-and-pr-automation.png`
- **Provenance class:** Diagram
- **Source:** `docs/diagrams/ci-cd/02-release-and-pr-automation.mmd`
- **Environment:** None. Both workflows are committed at `.github/workflows/release.yml` and
  `.github/workflows/pr-detection-report.yml`.
- **Date:** 2026-09-11
- **Demonstrates:** That a release re-runs the entire validation pipeline rather than trusting the
  tagged tree, and that the pull-request path splits the job that runs contributor code
  (read-only) from the job that holds the comment permission (runs no contributor code, consumes
  only the uploaded artefact). The diagram lists what the release archive actually contains,
  including the generated `deploy/` templates.
- **Redactions:** None required.

---

## What is deliberately absent from this register

| Missing evidence | Why it is missing | Where the gap is recorded |
|---|---|---|
| Sentinel analytics-rule deployment screenshots | No live workspace exists; importing the rules is an environment action the reader performs | `docs/production-readiness.md`, `docs/limitations.md` |
| Incident-queue screenshots | Would require real incidents, real user names and real tenant identifiers | `docs/metrics.md` (`Not yet measured`) |
| Atomic Red Team execution results | Requires a lab with an onboarded endpoint and a connected workspace | `tests/validation/live-validation-guide.md` |
| Workbook rendered with data | Requires deployment and incident history | `tests/validation/performance-metrics.md` |
| Playbook run history | Requires an incident to trigger the playbook | `docs/SOAR.md` |
| CI run screenshots | The pipeline is committed as code; its result is reproducible by running the same commands | `docs/testing.md` |

## Reproducing the generated artefacts

```bash
# Diagrams (network: rendered through mermaid.ink; the .mmd sources are canonical)
python scripts/render_diagrams.py

# Design preview (offline, deterministic)
python scripts/render_design_preview.py
python scripts/render_design_preview.py --check    # CI gate

# Coverage chart (offline, deterministic)
python scripts/render_coverage_chart.py

# The numbers behind the layer and the chart
python scripts/generate_coverage.py
python scripts/generate_atomics_ledger.py

# The ARM deployment set a Sentinel Repositories connection consumes
python scripts/generate_arm_templates.py
python scripts/generate_arm_templates.py --check    # CI gate

# The per-rule quality matrix
python scripts/generate_metrics_matrix.py
python scripts/generate_metrics_matrix.py --check   # CI gate
```

All six generators are deterministic and are invoked by CI, which fails on any diff they produce.
If an artefact in this repository and the command that generates it ever disagree, the command is
right and the file is stale.

Screenshot provenance cannot be re-derived from the repository. That is exactly why it is
recorded here in prose, with its environment and date, instead of being left for the reader to
guess at.
