# Backtest observations

Output of `scripts/backtest_rule.py --execute`, one `.md` and one `.json` per rule per run.

A file in this directory records what a rule's query returned against **one workspace over one
historical window**. It is an observation, not a validation:

- It does not change a rule's status in `tests/validation/atomics.yaml`.
- It does not prove the rule detects the behaviour it describes. Rows returned may be the
  behaviour, an artefact of the widened lookback, or false positives; deciding which is the
  analyst's job.
- An empty result is not evidence that a rule works or that it is broken. Check telemetry
  freshness first.

Nothing is in this directory today. A backtest cannot be produced without a workspace to query,
and this repository does not have one — so there is nothing here to look at, rather than a
hand-written example that would read like a result.

The interface contract (plan first, refuse to run without a workspace, report every query rewrite)
is enforced by `tests/test_backtest.py`.
