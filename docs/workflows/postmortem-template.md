# Postmortem — INC-`<number>`

> Copy to `docs/postmortems/INC-<number>.md` and fill in within five business days of the incident
> closing. Blameless: contributing factors are described as properties of systems, processes and
> detection coverage, never as individual failings. If a person was the only barrier between an
> event and a worse outcome, that is a structural finding, and it is written down as one.

## Summary

| Field | Value |
|---|---|
| Incident | INC-`<number>` |
| Severity | |
| Detected by | rule name, or `missed — found by <other means>` |
| Dwell time | first malicious activity → detection |
| Contained | date and time |
| Closed | date and time |
| Author / reviewers | |

## Impact

What was affected, for how long, and what the business consequence was. Keep it factual: accounts
touched, data reachable, systems isolated, customers affected. `Unknown` is an acceptable entry;
a guess is not.

## Timeline

Every line needs a source — an alert id, a query result, a ticket, a change record.

| Time (UTC) | Event | Source |
|---|---|---|
| | first malicious activity | |
| | first telemetry that should have detected it | |
| | detection fired (or not) | |
| | analyst acknowledged | |
| | containment | |
| | recovery | |

## Root cause

The 5-whys, written out. Stop when the answer is a control, a process or a coverage gap — not a
person's attention.

## Detection assessment

| Question | Answer |
|---|---|
| Which rule fired, and how long after the activity started? | |
| If no rule fired: which rule *should* have, and why did it not? | query logic / telemetry absent / threshold / no coverage |
| Did the alert have the entities an analyst needed? | |
| Was the noise level consistent with the rule's `expectedVolume`? | |

## What we missed

The detection gap, stated plainly. Every gap becomes either a roadmap item, a tuning change or an
accepted risk with a named owner — never a paragraph that closes the discussion.

## Action items

| # | Action | Owner | Due | Tracking |
|---|---|---|---|---|
| 1 | | | | issue / PR |
| 2 | | | | |

An action item without an owner and a date is not an action item.

## Detection and tuning follow-ups

- [ ] Tuning entries added to [`tuning-log.md`](tuning-log.md), one per rule that changed.
- [ ] Rule versions bumped where logic changed.
- [ ] Validation ledger updated if the incident constitutes live-tenant evidence for a rule —
      with an evidence file in `tests/validation/evidence/`.
- [ ] `tests/validation/performance-metrics.md` row updated with the incident as data.

## Quarterly review

Action items from every postmortem are re-read each quarter and scored for completion. The
completion rate, not the writing, is the measure of this process.
