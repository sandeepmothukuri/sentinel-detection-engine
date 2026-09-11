# Validation evidence records

One file per validation, named `<RULE-STEM>-<YYYY-MM-DD>.md`, created from
[`../evidence-template.md`](../evidence-template.md).

**This directory is intentionally empty.** An evidence file is written while a validation is being
performed, by the person performing it, recording output they observed. Nothing has been executed
against a live tenant here, so there is no record to file — and a hand-written example would be
worse than an empty directory, because it would read like proof.

CI enforces the consequence: a ledger entry whose status is `SIMULATED` or `VALIDATED IN LIVE
TENANT` must have a matching dated file in this directory, with an incident reference for a live
claim. See [`../validation-schema.yaml`](../validation-schema.yaml) and
[`../live-validation-guide.md`](../live-validation-guide.md).
