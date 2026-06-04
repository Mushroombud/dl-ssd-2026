# Score-First Execution Plan

Updated: 2026-05-31 KST

## Goal

Raise the private/dashboard score with the least wasted work.

The loop should prefer changes that can plausibly affect hidden tests:

1. discover a score-relevant edge case,
2. prove it with synthetic or sourced evidence,
3. repair only generalized solver behavior,
4. run the full local gate,
5. record the decision and continue.

Server update/submission is manual-only unless explicitly requested.

## Current Baseline

- Latest submitted score: 88.00
- Sourced cases: 3994 / 0 mismatches
- Synthetic cases: 376 / 0 mismatches
- Unit tests: 1049 OK
- Official parsed-doc coverage: 811 / 1376
- Untriaged A/B coverage gaps: 0

## Score Hypotheses

### P0: AccessControl / GetACL False Negatives

Why:
- A previous score drop was temporally associated with AccessControl/GetACL tightening.
- Hidden tests can encode the same association with slightly different result/status shape.
- We already found one plausible production repair: direct AccessControl.Get mixed metadata+ACL may reject the whole request while still forbidding ACL leakage.

Execution:
- Add focused cases around direct AccessControl.Get status shape, partial metadata, ACL omission, and metadata validation.
- Add GetACL exact ACL cases only when the official association universe is clear.
- Do not loosen special MethodIDObj/SPTemplatesObj ordinary Get associations; sourced evidence says ordinary Get association does not exist in Locking SP.

Exit condition:
- No more plausible false-negative status/result-shape gaps remain without contradicting sourced cases.

### P1: Locking State Machine And Wrapper Long Trajectories

Why:
- Largest known score jump after 85 was likely Locking Get/state tracking.
- Private traces may use wrapper APIs, multiple ranges, reset aliases, disabled-side latent locks, and later raw/wrapper observations.

Execution:
- Multi-range Range1/Range2/Range8 independence.
- LockOnReset with reset type boundaries and per-range isolation.
- Disabled locked cells vs enabled host I/O effects.
- getRange/getMEK/hasLockedRange consistency after wrapper mutations.
- GenKey/media-key invalidation per range.

Exit condition:
- Range1/Range2/Range8, reset, host I/O, getRange, getMEK, hasLockedRange, and GenKey all have positive and negative long cases.

### P2: DataStore Authority, Offset, And Raw/Wrapper Mixing

Why:
- DataStore payload and access control were likely secondary score candidates.
- Hidden traces can mix `readAccess/writeAccess`, wrapper `readData/writeData`, raw `DataStore.Get/Set`, offsets, empty unauthorized results, and failed-call nonmutation.

Execution:
- ACE churn across Admin/User sessions.
- Raw/wrapper cross-observation for payload and authorization.
- Offset/length windows after overwrite and failed overwrite.
- Empty unauthorized reads must not be confused with data loss.

Exit condition:
- Long cases cover read grant, write grant, grant replacement, failed grant, failed write, raw/wrapper observation, offsets, and stale payload rejection.

### P3: C_PIN / Authority Wrapper State

Why:
- Hidden API traces may expose authentication through `checkPIN/changePIN/setMinPINLength` rather than raw `StartSession/Authenticate`.

Execution:
- TryLimit, Tries, Persistence, Uses, Limit.
- Raw table observations after wrapper auth.
- changePIN after lockout and min PIN policy.

Exit condition:
- Wrapper and raw auth state transitions are cross-checked by later raw `Get` and wrapper return values.

### P4: Representation Robustness

Why:
- Hidden logs often vary field names and envelopes.

Execution:
- Add cases for `function`, `functionName`, `operationName`, `name`, `args`, `params`, `parameters`, `kwargs`, top-level `auth_as`, and nested return values.
- Only repair parser normalization when the semantic target is unambiguous.

Exit condition:
- All score-relevant wrappers have at least two envelope variants in synthetic coverage.

### P5: Remaining Coverage

Why:
- A/B are done; D-priority broad coverage is lower expected score return.

Execution:
- After P0-P4 saturate, inspect remaining D docs for any hidden-score-relevant operational semantics.
- Otherwise triage with explicit reason rather than generating low-value cases.

## Execution Loop

For each batch:

1. Pick the highest unfinished P-level.
2. Add 2-8 edge cases with both PASS and FAIL controls.
3. Run targeted synthetic tag.
4. If mismatch appears, inspect whether the case or solver is wrong.
5. For solver bugs, patch generalized code and add/adjust unit tests if production changed.
6. Run:
   - `python3 sm/tools/run_synthetic_edges.py`
   - `python3 sm/tools/run_sourced_edges.py`
   - `cd sm && python3 -m unittest tests.test_solver_rules -q`
   - `python3 sm/tools/doc_coverage.py`
7. Update:
   - `sm/analysis/continuous_loop_state.md`
   - `sm/analysis/solver_update_log.md`
   - `sm/analysis/presentation_audit_trail.md` for story-worthy changes

## Immediate Next Batches

1. P0 AccessControl direct Get: DONE for current batch
   - direct full-row AccessControl.Get with ACL omitted vs leaked,
   - direct full-row rejection accepted,
   - metadata/log columns still validated on success.
2. P1 Locking Range8: DONE for current batch
   - extend Range2 multi-range work to Range8,
   - Range8 LockOnReset and getMEK/GenKey identity.
3. P2 DataStore: PARTIAL DONE, continue with raw-wrapper envelope variants
   - grant replacement User1 -> User2 with raw/wrapper observations in both directions,
   - failed User2 write after grant replacement must not mutate.
4. P4 Wrapper envelope:
   - operationName/name/params variants for P1 and P2 cases.

## Execution Snapshot - 2026-05-31 KST

- Completed:
  - P0 AccessControl direct full-row `Get` guardrails.
  - P1 Range8 independent wrapper state, host I/O, `getRange`, and `LockOnReset` checks.
  - P2 DataStore User1 -> User2 grant replacement and offset mutation checks.
  - P4 wrapper envelope variants for P1/P2 cases.
  - P1 Range8 `getMEK/GenKey` identity and invalidation.
  - P3 User2 auth/policy long trajectories.
- Verified:
  - sourced `3994 / 0`.
  - synthetic `408 / 0`.
  - unit `1049 OK`.
  - doc coverage `811 / 1376`, A/B untriaged `0`.
- Next:
  - P2 DataStore sparse-window/envelope variants with raw `DataStore.Get` cross-checks.
  - P0 AccessControl/GetACL representation variants only where sourced association evidence is clear.
  - P5 remaining D-priority coverage after the score-first queue is saturated.

## Stop Conditions

Stop only when:

- user asks to pause,
- full gate fails and needs attention,
- server update/submission is explicitly requested,
- all P0-P4 immediate batches are saturated and only D-priority coverage remains.
