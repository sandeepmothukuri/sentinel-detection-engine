# Tuning

Tuning is a controlled loop, not a reaction to a noisy week. This page defines the process; the per-rule knobs live in each rule's `metadata.tuningGuidance` block, and history lives in [`docs/workflows/tuning-log.md`](workflows/tuning-log.md).

## The tuning loop

1. **Observe** — the workbook's *Tuning indicators* tile ranks rules by benign-positive closure rate (closed incidents marked False Positive, for rules with ≥ 5 closed incidents).
2. **Classify** the false positives:
   - *Legitimate actor/traffic missing from telemetry expectations* → allow-list (below).
   - *Threshold mismatch* → adjust the named threshold `let` in the query.
   - *Wrong behaviour entirely* → fix the logic; bump minor version.
   - *Rule duplicates another* → consolidate or delete; never keep two rules chasing the same event.
3. **Change one variable** — a tuning PR changes either the allow-list, the threshold, or the logic; never all three.
4. **Record** — add an entry to the tuning log (rule, version before/after, FP examples, expected volume delta).
5. **Verify** — after `queryFrequency × 5` runs, compare volume in the workbook against the log entry; revert if the delta missed expectations.

## Allow-list patterns (in preference order)

1. **Entity-specific filter in the query** — `let excluded_users = dynamic(["svc-backup@..."]);`. Preferred: visible in review, versioned, testable.
2. **IP/URL indicator suppression in Sentinel** — for known-benign destinations (e.g. proxy vendors). Avoid for users: identities change behaviour, indicators do not age out on their own.
3. **Automation rule condition** — e.g. skip a rule for a specific device group. Last resort: it is invisible in the rule's YAML and drifts easily.

**Never** disable a rule globally for tuning purposes during a scheduled exercise unless you record it in the tuning log with a restore date.

## Threshold conventions in this pack

- All thresholds are named `let` values with a `_threshold` suffix (`velocity_kmh_threshold`, `failed_mfa_threshold`, `abs_threshold`...).
- Baseline (z-score) rules: tune the absolute floor (`abs_threshold`) for volume, the multiplier (`> 3.0`) for sensitivity — the 30-day baseline self-adjusts to most seasonal patterns.
- Time windows (`queryFrequency` / `queryPeriod`) are production SLAs, not tuning knobs; changing them changes detection latency and should be a standalone PR.

## Metrics feedback

Every tuning entry should update the rule's `expectedVolume` in its metadata block. Measured precision/recall (once live data exists) belong in [metrics.md](metrics.md), not in the tuning log.
