# SSD Spec Audit Loop Report

Date: 2026-06-08

## Scope

This pass followed `skills/ssd-spec-auditor/SKILL.md`: full probe sweep first, then obligation packet review, with evaluator or testset edits only when retrieved spec evidence supports the new label.

The RAG pipeline used the local Qwen dense embedder and Qwen reranker:

- Embedding model: `artifacts/models/Qwen3-Embedding-0.6B`
- Reranker model: `artifacts/models/Qwen3-Reranker-0.6B`
- Dense index: `artifacts/rag_index/dense_embeddings.npy`
- Runtime caps: `RAG_EMBEDDING_BATCH_SIZE=4`, `RAG_RERANKER_BATCH_SIZE=4`, `RAG_EMBEDDING_MAX_SEQ_LENGTH=1024`, `RAG_RERANKER_MAX_LENGTH=512`

## Probe Sweep

Full sweep command:

```bash
RAG_EMBEDDING_BATCH_SIZE=4 RAG_RERANKER_BATCH_SIZE=4 RAG_EMBEDDING_MAX_SEQ_LENGTH=1024 RAG_RERANKER_MAX_LENGTH=512 PYTORCH_CUDA_ALLOC_CONF=expandable_segments:True .venv/bin/python tools/spec_audit_rag.py probe-sweep --candidate-top-k 32 --final-top-k 5 --hit-text-chars 700
```

Outputs:

- `analysis/spec_audit/probe_sweep_packets.jsonl`
- `analysis/spec_audit/probe_sweep_summary.json`
- `analysis/spec_audit/probe_sweep_triage.json`

Results:

- Probes audited: 7379 / 7379
- Dense retrieval: enabled
- Reranker: enabled
- Candidate top-k: 32
- Final top-k: 5
- Runtime: 3574.829 seconds
- Current solver/probe label mismatches: 0
- Packets without hits: 0
- Packets without authoritative hits: 0
- Author labels: 3487 PASS, 3892 FAIL

The review-flag queue contains mechanical triage flags, not oracle verdicts. The largest class is `impossible_success_fail`, which is expected for FAIL probes whose target status token is `SUCCESS` or `PASS`; those probes are intentionally checking whether an apparent success would be invalid under the preceding state.

Manual inspection of PASS probes with non-success status found expected failure-normalization cases, including locked host I/O, unauthorized wrapper behavior, read-only sessions, and access-control denials. Retrieved evidence pointed at official or enriched locking/access-control sections, so no probe relabel was justified.

## RAG Tooling Change

`src/rag_retrieval.py` now exposes `HybridRetriever`, which loads the chunk set, BM25 index, dense model/vectors, and reranker once and reuses them across many queries.

`tools/spec_audit_rag.py` uses the reusable retriever in probe and obligation packet generation. This preserves the previous `retrieve()` API while making full GPU reranked sweeps feasible; the old per-query model/index construction was not viable for 7379 probes.

## Obligation Review

Generated packets:

- `analysis/spec_audit/obligation_packets.jsonl`: first 50 obligations
- `analysis/spec_audit/obligation_opal_435_packets.jsonl`: Opal `4.3.5` targeted obligations
- `analysis/spec_audit/obligation_core_57_packets.jsonl`: Core `5.7` targeted obligations
- `analysis/spec_audit/obligation_core_323_packets.jsonl`: Core `3.2.3` packet/framing targeted obligations
- `analysis/spec_audit/obligation_opal_4354_packets.jsonl`: Opal `4.3.5.4` MBR targeted obligation
- `analysis/spec_audit/obligation_opal_4355_packets.jsonl`: Opal `4.3.5.5` K_AES targeted obligation
- `analysis/spec_audit/obligation_opal_51_packets.jsonl`: Opal `5.1` Activate/Revert/RevertSP targeted obligations
- `analysis/spec_audit/obligation_opal_52_packets.jsonl`: Opal `5.2` life-cycle targeted obligations
- `analysis/spec_audit/obligation_opal_53_packets.jsonl`: Opal `5.3` byte-table granularity targeted obligations
- `analysis/spec_audit/obligation_opal_41_packets.jsonl`: Opal `4.1` Properties/StartSession/SyncSession targeted obligations
- `analysis/spec_audit/obligation_opal_42_packets.jsonl`: Opal `4.2` AdminSP table/method targeted obligations
- `analysis/spec_audit/obligation_opal_431_packets.jsonl`: Opal `4.3.1` LockingSP base table targeted obligations
- `analysis/spec_audit/obligation_opal_31_packets.jsonl`: Opal `3.1` Level 0 Discovery targeted obligations
- `analysis/spec_audit/obligation_opal_32_packets.jsonl`: Opal `3.2` reset command targeted obligations
- `analysis/spec_audit/obligation_opal_33_packets.jsonl`: Opal `3.3` host interface and synchronous protocol targeted obligations
- `analysis/spec_audit/obligation_opal_2_packets.jsonl`: Opal `2.x` overview, capabilities, and mandatory feature-set targeted obligations

Findings:

- Early core token, packet, stream, and ComPacket obligations are mostly interface/framing-level. The current evaluator and probe loop operate on method trajectories and host I/O events, so these should remain deferred unless a packet-level fixture is added.
- Opal `2.x` Admin SP, Locking SP, synchronous protocol, authentication, personalization, and lifecycle overview obligations are covered through existing method/session/authority rules. Opal `2.10` raised one additional testcase-backed gap: SPF-17 requires a Locking SP `Activate` with `DataStoreTableSize=X` to be followed by a DataStore Table descriptor `Rows=X` result. The evaluator now tracks that Activate parameter for the modeled `Table_DataStore` descriptor.
- Opal `3.1.1.2` TPer Feature descriptor raised one confirmed evaluator gap: Level 0 discovery coverage handled Locking, Geometry, Opal SSC V2, and Data Removal descriptors, but did not validate mandatory TPer Feature descriptor fields. The evaluator now validates `FeatureCode=0x0001`, `Length=0x0C`, compatible `Version>=1`, and mandatory `StreamingSupported=1` plus `SyncSupported=1`.
- Opal `3.1` Level 0 Locking, Geometry, Opal SSC V2, RangeCrossing, and Supported Data Removal Mechanism obligations are represented in expectations, transitions, and sourced edges. Header byte layout and full descriptor enumeration remain raw discovery response concerns unless a full Level 0 response fixture is added.
- Opal `3.2` Stack Protocol Reset and TPER_RESET behavior is covered for method-level state: programmatic reset enablement, session abort, ComID/session reset behavior, LockOnReset/DoneOnReset effects, and fresh sessions after reset. The raw IF-SEND command table for TPER_RESET remains interface-level.
- Opal `3.3` communication properties are now covered for Opal TPer Properties floors and host property negotiation. Protocol Stack Reset session effects and reset_types are covered. Security Protocol command values, supported token atoms, payload error response packet contents, and one-packet/one-subpacket limits remain raw interface/framing-level.
- Opal `4.1.1.1` Properties raised one confirmed evaluator gap: TPer Properties size floors were validated against Core's generic `MaxComPacketSize`/`MaxPacketSize` lower bounds rather than Opal's SSC-specific lower bounds. The evaluator now requires Opal reported TPer floors for `MaxComPacketSize`, `MaxPacketSize`, and `MaxIndTokenSize`, while still allowing zero as "no limit".
- Opal `4.1.1.2` StartSession SessionTimeout behavior is already covered: bounds are checked against TPer `MaxSessionTimeout`/`MinSessionTimeout` and nonzero SPInfo `SPSessionTimeout`; zero or absent SPInfo timeout is ignored as a cap.
- Opal `4.1.1.3` SyncSession is already covered at the method-trajectory level, including Session Manager targeting, session-id validation, and returned timeout/credit constraints.
- Opal `4.2` AdminSP obligations for SPInfo, AccessControl, ACE, Authority, C_PIN, TPerInfo.ProgrammaticResetEnable, DataRemovalMechanism, and Random are represented in expectations or sourced edges. The C_PIN_SID initial PIN rule remains alternative-dependent because the same section allows either MSID-based automated take ownership or vendor-unique SID PIN.
- Opal `4.3.1` LockingSP base obligations for K_AES/SecretProtect one-of support, Table descriptors, AccessControl/GetACL behavior, ACE `Admins OR UserMMMM`, Authority User1-User8/Admin1-Admin4 coverage, and C_PIN Admin1 initialization are covered or bounded by existing tests and sourced edges. The Type table itself is not required by Opal; the boolean OR and 23-entry AC_element capacity requirement is covered through ACE BooleanExpr behavior rather than raw Type table reads.
- Opal/Core locking obligations for LockingInfo geometry, RangeStart/RangeLength alignment, read/write lock columns, LockOnReset, ActiveKey/NextKey/ReEncrypt behavior, MBRControl, MBR shadowing, and K_AES/GenKey behavior are already represented in the sourced edges, score probes, or solver expectations.
- MBR minimum row size is covered. The spec statement that initial MBR contents are vendor unique is handled by allowing arbitrary MBR table bytes until a trajectory writes known payload; after a write, subsequent reads must match the tracked bytes.
- The requirement that at least one of `K_AES_128` or `K_AES_256` be supported is not a basis for requiring both table descriptors. Table table preconfiguration marks the two K_AES table descriptor rows with `*TT1`, and the retrieved source says only one of the two K_AES tables is required. This pass did not identify a failing trajectory that proves a missing evaluator rule.
- Core `3.2.3` packet, packet header, subpacket, secure messaging, ACK, sequence, padding, and reserved-field obligations remain packet/framing-level. `parse_event()` maps current inputs to high-level `tcg_method` or `host_io` events and does not evaluate raw packet byte layouts, so these are out of the current evaluator contract.
- Opal `5.1` Activate/Revert/RevertSP obligations are covered by sourced lifecycle and RevertSP cases, including SID PIN copy to Admin1 on Activate, Manufactured-Inactive session rejection, Locking Feature descriptor changes, KeepGlobalRangeKey preservation, and KeepGlobalRangeKey failure when Global Range is both read-locked and write-locked.
- Opal `5.3` byte-table granularity obligations are covered for DataStore and descriptor metadata. This pass additionally verified and fixed regression coverage for MBR byte-table `Set` alignment after observing `MandatoryWriteGranularity`.

## Fix Decisions

Evidence-supported evaluator fixes made after obligation review found confirmed gaps:

- `src/solver_components/expectations.py` now validates the mandatory Opal Level 0 TPer Feature descriptor.
- `src/solver_components/engine.py` now validates TPer Properties response size floors with Opal `4.1.1.1` values: `MaxComPacketSize >= 2048`, `MaxPacketSize >= 2028`, and `MaxIndTokenSize >= 1992`, with zero still treated as "no limit".
- `src/solver_components/models.py`, `src/solver_components/parsing.py`, `src/solver_components/transitions.py`, and `src/solver_components/expectations.py` now connect `Activate(LockingSP, DataStoreTableSize=X)` to the subsequent `Table_DataStore.Rows` expectation for the currently modeled DataStore table, based on SPF-17.
- `tests/test_solver_rules.py` adds a regression proving the Opal floors accept exact minimums and reject Core-only lower values.
- `tools/run_sourced_edges.py` now states the same Opal TPer Feature and Properties floor rules for future sourced-edge generation.

Audit-infrastructure and non-bug regression changes:

- Reuse RAG model/index state for long sweeps.
- Add a probe sweep triage summarizer that reports review flags without assigning oracle labels.
- Add regression tests that lock in two audited non-bugs: arbitrary initial MBR vendor bytes before a write, and K_AES table descriptor handling that does not require both AES table families.
- Add a regression test that MBR byte-table `Set` obeys observed Opal `MandatoryWriteGranularity`, matching the already-covered DataStore behavior.

## Remaining Candidates

These are not confirmed bugs and should not drive evaluator edits without narrower sourced probes:

- Packet/framing invalid-token obligations need packet-level fixtures.
- Full Level 0 Discovery Header and descriptor-list byte layout need a raw Level 0 discovery response fixture.
- Security Protocol command values, supported stream tokens, payload error packet formatting, and one-packet/one-subpacket limits need raw IF-SEND/IF-RECV or packet fixtures.
- Missing-both AES table support needs a feature-discovery fixture if the evaluator is expected to model a device-level discovery transcript rather than individual table/method events.
- Additional DataStore Tables beyond the modeled primary `Table_DataStore`, the DataStore Table Feature Descriptor fields, and Block SID feature-set details need raw Level 0 discovery or feature-set fixtures before broader evaluator rules are justified.
- Raw Type table discovery for `boolean_ACE` and `AC_element` remains a candidate only if future fixtures query Type table rows directly; current coverage exercises the same requirements through ACE BooleanExpr behavior and 23-entry OR expressions.
- C_PIN_SID initial PIN equality to MSID should not be enforced globally because Opal `4.2.1.8` also permits a vendor-unique SID PIN for alternative take-ownership models.

## Verification

- `py_compile`: passed for edited Python modules and audit tools.
- `tests.test_solver_rules`: 1304 tests passed.
- `tools/run_sourced_edges.py --tag datastore-activate-size-doc`: 2 sourced edge cases, 0 mismatches.
- `evaluate.py`: `score=100.00`.
- `score_probe_loop.py --iterations 1`: 7379 probes, 0 mismatches, status written to `analysis/spec_audit/score_probe_status_final3.json`.
