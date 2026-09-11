# Limitations

The honest register. Each entry states the limitation, what it costs a reader, what already
mitigates it, and what would close it. Entries are not aspirational: if something would be closed by
work already planned, it is in the [roadmap](../README.md#16-roadmap) instead. This file is for the
limits that are structural.

Scores that follow from these limits are in [production-readiness.md](production-readiness.md).

---

## L1 — Nothing in this repository has executed

**The limitation.** No rule, hunt, playbook or workbook has run against a real Sentinel workspace.
No alert, incident or automation run has been produced outside CI. Every detection is
`STATIC VALIDATION`.

**What it costs the reader.** The repository proves that the detections are well-formed, mapped to
telemetry that a declared connector produces, and syntactically valid KQL. It does not prove that
any of them fires. A query that is valid KQL can still be wrong about the data.

**Mitigation in place.** CI validates schema, metadata, ATT&CK mapping against a vendored MITRE
dataset, table-to-connector dependencies and KQL structure. The validation ledger
([`tests/atomics.yaml`](../tests/validation/atomics.yaml)) records the status of all 28 entries and
refuses to let a status improve without evidence. The backtesting interface
([`scripts/backtest_rule.py`](../scripts/backtest_rule.py)) makes the first honest observation
possible.

**What closes it.** One lab workspace, a handful of atomic tests, and the evidence template. This
needs a tenant, not more code.

## L2 — Thresholds are estimates, not baselines

**The limitation.** Every threshold in the pack — counts, rates, distinct-user limits, exclusion
lists — was chosen by reasoning about the behaviour it describes. Not one was derived from observed
telemetry volume.

**What it costs the reader.** Expect noise on day one, and expect the tuning to be real work rather
than a formality. Baseline-dependent rules (impossible travel, mass download, Key Vault access
spike) cannot be meaningful until the workspace has history.

**Mitigation in place.** Each rule carries tuning metadata naming the parameters, their defaults,
their safe range and what happens at the extremes. [`tuning.md`](tuning.md) and
[`workflows/tuning-log.md`](workflows/tuning-log.md) define the change process.
[`tests/validation/performance-metrics.md`](../tests/validation/performance-metrics.md) defines the
field set that turns a tuned threshold into a measured one.

**What closes it.** Thirty days of workspace data and a first tuning pass, recorded in the tuning log.

## L3 — Single author, no independent review

**The limitation.** Every file was written by one person. No second engineer has reviewed the
contents, and no change has been approved by anyone other than its author. `CODEOWNERS` names the
author as the reviewer of everything.

**What it costs the reader.** Review-error classes that a second pair of eyes catches — an
unreachable branch, a wrong field name, a mapping that is plausible but wrong — are the reader's to
find. One such defect (a parameter reference with the wrong casing) was found by this repository's
own validator rather than by a reviewer.

**Mitigation in place.** The compensating control is mechanical rather than social: 15 validation
families, 124 tests including negative tests that prove the validator rejects bad input, four drift
gates, and documentation numbers that fail the build when they stop matching the repository. A
validator that fails loudly is a partial substitute for a reviewer, and the repository says which
it has.

**What closes it.** A second engineer. Until then, treat CI green as "no known mechanical defect",
not "reviewed".

## L4 — ATT&CK coverage measures the presence of a rule, not its effect

**The limitation.** `coverage.md` counts techniques for which a rule or hunt exists. It says nothing
about whether the rule would detect that technique's real-world variants, and it is not a
measurement of detection efficacy.

**What it costs the reader.** The headline coverage number is an inventory, not a capability claim.
Two enterprise tactics (Reconnaissance, Resource Development) have no coverage at all, and two
behaviour families — host firewall manipulation and the T1685 command-blocking family — are covered
only partially, because covering them properly needs telemetry this pack does not assume.

**Mitigation in place.** The generated coverage document separates rules from hunts, names the
uncovered tactics explicitly, and is drift-gated so it cannot quietly diverge from the rule files.
[`ATTACK.md`](ATTACK.md) explains the mapping discipline and the v19 domain changes that affect it.

**What closes it.** Nothing fully. Coverage is intent; efficacy is measured per rule by
[`metrics.md`](metrics.md), one live incident at a time.

## L5 — Threat intelligence is designed, not implemented

**The limitation.** There is no MISP, TAXII or TI-platform connector in this repository. No watchlist
enrichment, no IOC matching in the rules, no indicator-age handling.

**What it costs the reader.** The enrichment playbook consumes its feeds live at run time, and the
detections do not depend on any external indicator — so nothing is broken by the absence. But a
reader looking for a TI-driven detection architecture will not find one here; they will find a
described future design in [`data-sources.md`](data-sources.md), which is labelled as such.

**Mitigation in place.** The absence is documented in the data-sources model rather than implied by
a diagram of something that does not exist.

**What closes it.** A deliberate decision about which TI platform to standardise on, plus an
ingestion path and an indicator-matching rule family. Out of scope for a Sentinel-only pack.

## L6 — Environment-dependent components cannot be validated here

**The limitation.** Four playbooks depend on things that exist only in a real tenant: an Azure
Firewall IP group resource id, a ServiceNow instance and its API credentials, MDE onboarding, and
`Sentinel`-scoped managed identity permissions. All four are unexecuted, and the workbook needs
incident history before any panel has a number to show.

**What it costs the reader.** "It deploys" is unproven for the automation layer. The ARM templates
are structurally reviewed and parameterised with no defaulted secrets, but no deployment has been
attempted.

**Mitigation in place.** Each playbook's README states its prerequisites, its parameters and its
rollback. [`SOAR.md`](SOAR.md) and
[`workflows/soar-decision-flow.md`](workflows/soar-decision-flow.md) document the safety gate that
stands between a query result and a destructive action. The design preview is labelled as a preview
in the image itself, so no one can mistake a wireframe for a screenshot.

**What closes it.** A tenant with the connectors and an incident to trigger on. This is an
environment action, listed in the roadmap under that heading.

## L7 — Backtesting has an interface, not a result

**The limitation.** `scripts/backtest_rule.py` can run a rule's query over a historical window, but
no backtest has been run, because no workspace exists to query it against. The report it produces
widens the rule's `ago()` bound, which means the query executed is not byte-identical to the
deployed rule.

**What it costs the reader.** There is no retrospective alert count, no false-positive estimate, and
no way to answer "how noisy would this have been last month?" from this repository.

**Mitigation in place.** The interface is honest by construction: it prints a plan before running,
refuses to execute without a workspace, reports every rewrite it makes, labels its own output as an
observation rather than validation, and cannot write a result file if the query failed. The contract
is pinned by tests.

**What closes it.** A workspace with retained history, and the time to interpret what comes back.

## L8 — Cost and ingestion assumptions are unmeasured

**The limitation.** The rules assume the tables in [`data-sources.md`](data-sources.md) are
populated, and the two baseline rules pay a longer lookback for their anomaly baselines. No
ingestion volume, query cost or Log Analytics spend has been measured, because measuring it requires
a billable workspace.

**What it costs the reader.** A deploying team should expect to review the query cost of the two
14-day-period rules first, and to size their workspace retention deliberately rather than by default.

**Mitigation in place.** The cost trade-off is documented where the rules are described, and
[`data-sources.md`](data-sources.md) states which connector supplies each table so that partial
deployments can be planned.

**What closes it.** Query-cost observation in a real workspace, and a retention decision.

## L9 — Sigma translation is intentionally partial

**The limitation.** `scripts/sigma_to_kql.py` translates the rule *shape* — selection, filters,
field modifiers — into a KQL scaffold. It is not a Sigma implementation: it does not resolve
condition logic beyond the common cases, does not map every modifier, and does not emit a
production-ready rule.

**What it costs the reader.** A translated rule needs hand work before it is worth deploying, and
the translator's own tests describe the boundary rather than hiding it. A prefix match is never
silently widened into a substring match — the translator refuses instead of guessing.

**Mitigation in place.** The converter's limits are pinned by tests, so the boundary is visible
rather than discovered in production.

**What closes it.** Scope. A full Sigma backend is a different project; this one's value is the
translation of a familiar authoring format into the detection style this pack uses.

---

## How to use this file

- **Evaluating the repository?** Read L1 and L3 first. They are the two limits that affect every
  other claim here.
- **Deploying it?** Read L2, L6 and L8 before you import anything.
- **Extending it?** L4 and L5 explain where the deliberate scope walls are, so you know what the
  absence means.
