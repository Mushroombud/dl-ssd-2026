# Score Improvement And Remaining Coverage Plan

Updated: 2026-05-31 KST

## Current Baseline

- Latest server submission:
  - Job ID: `1027`
  - Score: `88.00`
  - Public server eval before submit: `100.00`
- Current local verification:
  - sourced edge cases: `3994`, `0` mismatches
  - synthetic edge cases: `280`, `0` mismatches
  - unit tests: `1048` passed
  - doc coverage: `811 / 1376`
  - untriaged A/B/C docs: `0`
  - untriaged D docs: `349`

## Guiding Principle

The next score gain is more likely to come from model-visible hidden-log forms than from broad document coverage alone.
Do not make solver changes just to satisfy one invented case. Every repair must generalize across:

- official TCG/Opal rule text
- observed parser/log representation variants
- at least one positive control and one impossible/wrong control
- full sourced, synthetic, and unit regression checks

## Phase 1 - AccessControl / GetACL Representation Calibration

Goal: recover hidden score if private traces use alternate but document-equivalent object/method references.

Status: first repair completed. `getacl-representation-equivalence-doc` now covers 14 sourced cases and the solver normalizes `invoking_uid`, `object_uid`, `target_uid`, `table_uid`, `method_uid`, `method_id`, typed dictionaries, and singleton wrappers before applying the existing AccessControl association rules. No broad association existence rule was relaxed.

Work order:

1. Inventory current AccessControl normalization paths:
   - `src/solver_components/parsing.py`
   - `src/solver_components/semantics.py`
   - `src/solver_components/expectations.py`
2. Generate focused fuzz cases for equivalent forms:
   - `InvokingID` as UID, symbolic name, table alias, object alias.
   - `MethodID` as method name, method UID, MethodID row UID, object-style row name.
   - `GetACL` return values as ACE uidrefs, names, list wrappers, and mixed scalar/list mistakes.
3. Keep strict boundaries:
   - Do not resurrect broad false positives for nonexistent optional rows.
   - Keep exact ACL identities for known Opal rows.
   - Allow representation normalization only when the underlying association is the same documented row.
4. Verification:
   - targeted `GetACL`/AccessControl tags
   - full sourced/synthetic/unit
5. Submit only after an actual solver repair or high-confidence regression expansion.

Expected score relevance: high.

## Phase 2 - TCGstorageAPI Wrapper-Layer Hardening

Goal: catch hidden traces expressed through high-level wrapper functions rather than raw method records.

Status: in progress. Completed first wrapper alias repair: `readLock/writeLock/readUnlock/writeUnlock` now decode into Locking row lock-cell Sets, and range/auth aliases such as `range_id`, `band_no`, `lockingRange`, and `auth_as` are accepted for wrapper calls. Completed wrapper envelope normalization for `name`, `function_name`, `functionName`, `operation_name`, and `operationName`; parser and expectation helpers now share the same function-name recognizer. Completed DataStore wrapper offset/window repair for keyword and positional `writeData`/`readData`. Completed wrapper auth alias consistency pass for `auth_as`. Completed wrapper authAs credential guard for implicit high-level operations.

Work order:

1. Inventory wrapper parsing in `src/solver_components/parsing.py`.
2. Build long wrapper trajectories for:
   - `setRange` / `getRange`
   - `readLock` / `writeLock`
   - `readData` / `writeData`
   - `getMEK`
   - `changePIN`, `setMinPINLength`, `getAuthority`, `lockingInfo`
3. Fuzz likely private-log representation variants:
   - camelCase vs snake_case names
   - positional vs keyword args
   - integer/string/boolean representations
   - UID wrapper names with and without underscores
   - partial wrapper return dictionaries
4. Repair only parser/expectation gaps that map cleanly to existing official semantics.

Expected score relevance: high.

## Phase 3 - Locking State Machine Long Trajectories

Goal: expose hidden state bugs that short official cases do not trigger.

Work order:

1. Generate 20-40 step trajectories combining:
   - Global Range fallback
   - non-global range override
   - zero-length ranges
   - adjacent ranges
   - `RangeCrossingBehavior`
   - `LockOnReset` values `{0}`, `{0,3}`, `2`, invalid aliases
   - disabled lock side with stored locked cells
   - reset-aborted sessions
2. Include host I/O observations and later `Get` observations in the same trajectory.
3. Prefer impossible-success checks for data-protection behavior where exact status is not exposed.

Expected score relevance: medium/high.

## Phase 4 - DataStore / MBR Byte-Window And Authority Churn

Goal: catch payload-window and access-control state bugs.

Work order:

1. Compose long byte-table trajectories with:
   - omitted `Where`
   - omitted `endRow`
   - nonzero offset writes
   - overlapping writes
   - no-Values `Set`
   - failed Set nonmutation
   - mandatory granularity
   - Get/Set ACE replacement
   - wrapper and raw byte-table state sharing
2. Use exact byte provenance only after the trajectory writes exact bytes.
3. Keep unauthorized byte-table `Get` behavior as `SUCCESS` with empty result where applicable.

Expected score relevance: medium/high.

## Phase 5 - Score Submission Gate

Submit after a batch only if one of these is true:

- production solver changed in a score-relevant area
- a previously risky interpretation was made safer
- wrapper parser coverage expanded for likely hidden-log forms

Pre-submit checks:

```bash
python3 tools/run_sourced_edges.py
python3 tools/run_synthetic_edges.py
python3 -m unittest tests.test_solver_rules -q
python3 tools/doc_coverage.py
```

Server pre-submit check:

```bash
python3 evaluate.py
```

Record:

- `analysis/solver_update_log.md`
- `analysis/edge_case_backlog.md`
- `analysis/presentation_audit_trail.md`
- latest server job ID and score after submission

## Phase 6 - Remaining D-Priority Coverage Closure

Goal: finish official-document cartography after score-sensitive work.

Current remainder:

- A/B/C untriaged: `0`
- D untriaged: `349`

Work order:

1. Split D docs into four buckets:
   - raw token / packet / secure-message framing
   - leaf UID/name/CommonName/type shards
   - informative or document-format prose
   - model-visible method/table leaf behavior
2. For raw token/packet docs:
   - mark deferred unless a packet-level fixture is added.
3. For leaf metadata docs:
   - link to existing exact table/method tags when behavior is already tested.
4. For informative prose:
   - mark informative or duplicate.
5. For model-visible D behavior:
   - create small sourced cases and run targeted/full verification.

Coverage completion target:

- `0` untriaged docs across A/B/C/D.
- Any non-covered docs must have explicit `informative`, `duplicate`, `covered_indirectly`, or `deferred` reason in `doc_coverage_triage.json`.

## Next Immediate Step

Continue Phase 3:

1. Generate Locking wrapper trajectories that mix `setRange`, lock/unlock wrappers, host reads/writes, and later `getRange`.
2. Cross-check that wrapper lock cells and host I/O protection agree.
3. Repair only if a failure exposes a generalized wrapper-to-Locking state gap.
4. Re-run full regression before any server update or submit.
