# Edge Case Backlog

이 문서는 공식 문서 기반 edge case를 subagent로 반복 생성/검증하기 위한 작업 목차다.

핵심 단위는 "개념" 자체가 아니라, 공식 문서의 normative rule/table row를 최소 trajectory로 바꿀 수 있는 작은 rule slice다.

## Workflow

1. Inventory builder가 `artifacts/documents/core`와 `artifacts/documents/opal`의 모든 txt shard를 `analysis/doc_inventory.jsonl`에 기록한다.
2. Cartography queue가 아직 안 훑은 A/B priority shard를 작은 batch로 나눈다.
3. Cartographer agent가 batch 하나를 읽고 rule slice 후보를 만든다.
4. Rule Normalizer agent가 exact status가 문서에 있는지, 아니면 "non-success only"인지 판별한다.
5. Generator agent는 normalized rule slice 하나만 맡아 PASS/FAIL 후보 pair를 만든다.
6. Integrator는 후보를 `tools/run_sourced_edges.py`에 추가한다.
7. Reviewer agents 3명은 blind packet을 보고 독립 라벨을 작성한다.
8. `tools/label_consensus.py report`로 accepted/quarantine을 나눈다.
9. Quarantine Rewriter가 근거 부족 case를 더 강한 evidence 또는 더 약한 assertion으로 재생성할 수 있는지 본다.
10. Solver는 accepted case에서 mismatch가 날 때만 좁게 수정한다.
11. Solver 수정마다 `analysis/solver_update_log.md`에 요약과 검증 결과를 남긴다.

## Continuous Loop Mode

사용자가 멈추라고 하기 전까지 아래 순서로 반복한다.

1. `python3 tools/build_doc_inventory.py`를 돌려 모든 공식 txt shard의 상태표를 갱신한다.
2. `analysis/doc_cartography_queue.md`의 맨 위 batch를 고른다.
3. batch 안의 각 shard를 `covered_by_case`, `normative_testable`, `supporting_definition`, `needs_cross_doc`, `non_testable`, `duplicate_or_index` 중 하나로 triage한다.
4. 문서가 정확한 status code를 지정하지 않고 "error"처럼 말하면, exact error PASS 케이스를 만들지 않고 `SUCCESS`가 불가능하다는 FAIL 케이스만 만든다.
5. 단독 shard만으로 부족하면 Cross-doc Linker가 column 정의, method rule, Opal SSC 제약을 묶는다.
6. 새 tag나 concept가 생기면 `TAG_METADATA`에 repair path와 repair hint를 먼저 추가한다.
7. 새 batch를 tag 단위로 실행해서 mismatch를 기록한다.
8. 3개 independent reviewer packet을 만들고, concerns가 있는 케이스는 신뢰 corpus에 넣지 않도록 케이스를 좁히거나 제거한다.
9. 케이스 내용을 고쳤는데 tag/name이 같으면 기존 review JSONL이 계속 같은 `case_id`에 붙는다. stale review는 `analysis/label_reviews/superseded/<date>-<reason>/`으로 옮기거나, 재생성 case의 name/tag를 바꾼 뒤 consensus를 다시 계산한다.
10. quarantine에 들어간 case는 `analysis/quarantine_rework_backlog.md`에서 재생성 전략을 기록한다.
11. consensus accepted가 된 뒤에만 solver를 수정한다.
12. sourced, consensus gate, unit, synthetic, public eval, coverage, inventory를 돌리고 로그를 남긴 뒤 다음 slice로 간다.
13. 기계적 검증 루프는 `python3 tools/continuous_edge_loop.py --iterations 0 --sleep 600 --include-slow`로 계속 돌릴 수 있다. 최신 상태는 `analysis/continuous_edge_loop_status.md`, 전체 히스토리는 `analysis/continuous_edge_loop.jsonl`에 남긴다.

## 2026-05-30 Loop Reinforcement

과거 루프의 실제 흔적을 다시 맞춰본 결과, 현재 루프는 아래 순서로 고정한다.

1. 먼저 기계 상태를 새로 만든다: `python3 tools/label_consensus.py report`, `python3 tools/doc_coverage.py`, `python3 tools/build_doc_inventory.py`.
2. 다음 대상은 `analysis/doc_coverage_report.md`의 Highest Priority와 `analysis/doc_cartography_queue.md`의 첫 batch가 같은 후보군을 보도록 고른다.
3. `build_doc_inventory.py`는 이제 A/B priority shard를 `normative_score == 0`이어도 cartography queue에 남긴다. 예전 상태에서는 coverage report의 untriaged A/B 229개 중 39개가 queue 밖으로 빠질 수 있었다.
4. Cartographer는 batch마다 직접 testable rule을 뽑거나, 그렇지 않으면 `analysis/doc_coverage_triage.json`에 명시 triage를 남긴다. “아무것도 안 함”은 완료 상태가 아니다.
5. Rule card에는 sources, source-local rule summary, assertion kind, exact-status 근거 여부, cross-doc dependencies, representation choices를 먼저 적는다.
6. 문서가 concrete status를 주지 않으면 exact-status PASS를 만들지 않는다. `SUCCESS`가 불가능한 FAIL case나 postcondition/nonmutation case로 낮춘다.
7. Payload/state exactness는 provenance가 있어야 한다. 예를 들어 exact bytes를 검사하려면 trajectory 안에서 먼저 그 bytes를 썼거나 공식 default가 있어야 한다.
8. Reviewer packet은 tag 단위로 3개를 만든다. reviewer는 author label과 case name 없이 evidence와 trajectory만 보고 PASS/FAIL을 적는다.
9. 케이스 내용을 바꾸면 기존 review가 같은 `case_id`에 붙을 수 있다. `case_id`는 tag와 name 기반이므로 stale review는 `analysis/label_reviews/superseded/<date>-<reason>/`로 옮기거나 tag/name을 바꿔 새 consensus를 만든다.
10. Quarantine은 실패가 아니라 rework backlog다. `analysis/quarantine_rework_backlog.md`의 패턴처럼 stronger evidence, narrower assertion, cross-doc support 중 하나로만 재생성한다.
11. Solver 수정은 accepted consensus mismatch 뒤에만 한다. 수정 후 `analysis/solver_update_log.md`에 rule, repair path, 검증 command 결과를 남긴다.
12. 한 loop의 종료 조건은 `--consensus-gate`, 전체 sourced, synthetic, unit/public eval, coverage, inventory가 모두 통과하고, 다음 남은 A/B gap 수가 기록되는 것이다.

## Latest Recorded Additions

- C_PIN password max-bytes repair: added `changePIN` regressions for 32-byte success, 33-byte failure, and failed-overlong nonmutation. This is backed by `core/5.1.3.63.txt` (`password = max_bytes(32)`) and should be promoted to sourced consensus when the next official-doc packet is built.
- TCGstorageAPI `changePIN` boolean-payload repair: added regressions proving native `True`/`False` cannot be accepted as C_PIN PIN credential payloads, and failed boolean PIN updates must not poison later authentication state.
- TCGstorageAPI `lockingInfo` repeated-observation repair: added regressions proving repeated high-level LockingInfo observations may be partial, but any returned field already known from prior LockingInfo state must remain stable. This fixed stale `AlignmentGranularity` and `MaxRanges` false positives.
- TCGstorageAPI `getAuthority` enabled-state repair: added high-level regressions proving `getAuthority(UserN)` must return the tracked `Authority.Enabled` boolean after successful `enableAuthority`, and failed `enableAuthority` calls must not poison the later observed value. This fixed a wrapper-level false positive where stale enabled/disabled values both passed.
- TCGstorageAPI `setMinPINLength` boolean-uinteger repair: added high-level regressions proving boolean `True`/`False` cannot be accepted as `_MinPINLength` values, and failed boolean calls must not lower a previously tracked minimum PIN length. This fixed a wrapper-level false positive caused by Python bool-to-int coercion.
- TCGstorageAPI `getMEK` UID-wrapper repair: added high-level `getMEK` regressions proving wrapper-style `K_AES_256_RangeN_Key_UID` byte returns must match the tracked Locking `ActiveKey`. This fixed a false negative where a correct wrapper UID response failed because the solver expected a raw Locking column cell.
- TCGstorageAPI `getRange` stale-state repair: added high-level `setRange` -> `getRange` regressions proving wrapper responses must reflect tracked Locking geometry and lock cells after a successful range mutation. Partial `getRange` returns are allowed, but returned fields are checked; failed `setRange` nonmutation is also covered. This fixed a real false-positive where stale `RangeStart`/`RangeLength` values could still pass.
- TCGstorageAPI wrapper repair: added long high-level `writeAccess`/`readAccess`/`writeData`/`readData` regressions for multi-byte DataStore payloads, ACE replacement, failed `writeData` nonmutation, and blocked Admin `readData` leakage. This found and fixed a real solver bug where wrapper `readData()` expected only the first byte of a multi-byte stored payload.
- `locking-crossing-failed-genkey-nonmutation-doc`: 14 accepted long-trajectory cases proving failed range-key `GenKey` during non-IDLE `ReEncryptState` does not behave like a successful crypto erase. The cases combine RangeCrossingBehavior, adjacent/global crossing writes, blocked `GenKey`, and later host reads; no solver repair was needed.
- `locking-reset-types-alias-reject-tight-doc`: expanded to 24 accepted cases. In addition to ProtocolStackReset alias rejection, reset-list cells now reject boolean tokens for `LockOnReset`, `MBRDoneOnReset`, and `ContOnReset`; valid empty/supported reset sets remain accepted.
- AccessControl/GetACL score-risk tolerance: Locking SP `SPTemplatesObj` / `MethodIDObj` strict sourced cases remain intact, but numeric Get MethodID UID aliases are now treated as a representation-normalization case. `SUCCESS` is accepted only with exact `ACE_Anybody`; textual ordinary `Get` remains rejected.
- `data-removal-mechanism-bool-type-tight-doc`: 4 accepted cases for `DataRemovalMechanism.ActiveDataRemovalMechanism` enum type validation. This repaired a boolean-to-integer coercion path so native `True`/`False` are no longer accepted as data-removal enum values `1`/`0`.
- `authority-secure-spinfo-timeout-type-tight-doc`: 8 accepted cases for scalar type boundaries on `Authority.Secure` and `SPInfo.SPSessionTimeout`. This triggered a solver repair: booleans are no longer accepted through integer parsing for `messaging_type` / `uinteger_4` columns, while real boolean columns such as `SPInfo.Enabled` stay separate.
- `cpin-trylimit-tries-uinteger-tight-doc`: 8 accepted cases proving `C_PIN.TryLimit` and `C_PIN.Tries` use uinteger counters, not booleans. This repaired the same boolean-as-integer coercion class for C_PIN retry counters.
- `authority-limit-uses-uinteger-tight-doc`: 8 accepted cases proving Authority `Limit` and `Uses` are uinteger counters, not booleans. The solver now rejects boolean values before integer parsing for these columns.
- `ecmqv-startup-return-shape-tight-doc`: 6 accepted cases for EC-MQV `StartSession` / `SyncSession` field mapping. A broader exchange-startup packet was archived as superseded after reviewers recorded ambiguity concerns; the accepted tight packet now proves successful EC-MQV exchange startup must return both `SPChallenge` and `SPExchangeCert`.
- `syncsession-signedhash-return-doc`: 6 accepted cases for `SyncSession.SignedHash` return-shape under Admin SP `ResponseSign = Null`. This triggered a solver repair: Authority `ResponseSign` is now tracked and successful Admin SP `Anybody` / `SID` SyncSession responses cannot include `SignedHash` when no SP signing authority exists.
- `syncsession-trans-credit-doc`: 15 accepted cases for optional SyncSession `TransTimeout`/`InitialCredit` values. Equality-boundary draft reviews were archived as stale before final consensus; final cases use less ambiguous in-range/out-of-range values.
- `datastore-byte-table-method-universe-doc`: 20 accepted cases proving DataStore byte-table `CreateRow`/`DeleteRow` direct success is invalid and no AccessControl associations exist for `DataStore.CreateRow` or `DataStore.DeleteRow`.
- `mbr-byte-table-method-universe-doc`: 20 accepted cases proving the same byte-table method-universe boundary for MBR.
- `mbr-byte-payload-doc`: 8 accepted cases for direct MBR byte-table Set/Get payload postconditions. This triggered a solver repair: MBR payload state is now tracked by byte offset and direct MBR Get windows compare returned Bytes.
- `syncsession-return-shape-doc`: 10 accepted cases for StartSession/SyncSession return names and conditional `SPChallenge`/`SPResponse`. Stronger cryptographic freshness or nonce equality checks were deliberately left out because the current packet abstraction does not expose enough evidence.
- `accesscontrol-meta-self-association-doc`: 12 accepted cases proving AccessControl meta-ACL columns do not create callable AccessControl rows for the meta-methods themselves. `SetACL` was deliberately excluded because the cited Core meta-method column set only covers `AddACE`, `RemoveACE`, `GetACL`, and `DeleteMethod`.
- `host-properties-response-reset-long-doc` was reconciled with Opal Table 17: mandatory Opal HostProperties remain required, while optional Core HostProperties are checked only when returned or previously observed as supported.

## Exhaustive Document Loop

현재 1차 문서 조각은 이미 생성된 parsed txt 파일을 그대로 사용한다.

- Core specification: `artifacts/documents/core/*.txt`
- Opal SSC specification: `artifacts/documents/opal/*.txt`
- `.ipynb_checkpoints` 아래 txt는 중복 checkpoint라 제외한다.

`tools/build_doc_inventory.py`는 모든 shard마다 아래 정보를 기록한다.

- stable id: `core:5.7.2.2.13` 같은 `doc_id`
- source path와 parent path
- title, section, sha256, size
- category, priority, normative score, high-risk terms
- sourced case count
- pipeline state
- subshard 필요 여부

기본적으로 기존 shard를 그대로 쓰되, 너무 큰 shard는 deterministic subshard로 다시 나눈다.

- 큰 table 섹션: table row 단위
- 긴 normative prose: paragraph 단위
- 여러 method/status가 섞인 섹션: method/status heading 단위

subshard는 새 원본을 만들지 않고, 원래 txt path와 row/paragraph selector를 함께 기록한다. 즉 evidence source는 계속 공식 txt path를 유지하고, rule slice 안에서 locator만 더 좁힌다.

목표는 모든 shard가 아래 중 하나의 상태를 갖는 것이다.

- `covered_by_sourced_case`
- `normative_testable`
- `supporting_definition`
- `needs_cross_doc`
- `non_testable`
- `duplicate_or_index`
- `quarantined_needs_evidence`

이 상태표가 비어 있지 않게 유지되어야 "문서를 다 훑었다"고 말할 수 있다.

## Metadata Contract

새 sourced case는 아래 정보가 mismatch report와 consensus matrix에 남아야 한다.

- `tag`: 큰 분류. 예: `mbr-doc`, `locking-doc`, `trylimit-doc`.
- `rule_id`: 같은 evidence rule에서 파생된 case를 묶는 id.
- `concepts`: 출제 개념 축. 예: `host-io`, `mbr-shadowing`, `range-boundary`.
- `evidence.sources`: 공식 문서 경로.
- `evidence.rule`: 문서에서 온 rule 요약.
- `repair_paths`: mismatch가 나면 먼저 볼 코드 위치.
- `repair_hint`: 어떤 상태/분기/comparator를 확인할지.

## Priority Slices

### A1. Host I/O, Locking, MBR

Primary docs:

- `core/5.7.3.2.txt`: Table 230 and Table 231.
- `core/5.7.2.5.2.txt`: MBRControl Enable.
- `core/5.7.2.5.3.txt`: MBRControl Done.
- `core/5.7.2.2.6.txt`: ReadLockEnabled.
- `core/5.7.2.2.7.txt`: WriteLockEnabled.
- `core/5.7.2.2.8.txt`: ReadLocked.
- `core/5.7.2.2.9.txt`: WriteLocked.

Interaction axes:

- MBRControl Enable: `True`, `False`.
- MBRControl Done: `True`, `False`, `N/A`.
- LBA relation: inside MBR, partial MBR boundary, outside MBR.
- Read lock: disabled, enabled/unlocked, enabled/locked, mixed.
- Write lock: disabled, enabled/unlocked, enabled/locked, mixed.
- Final command: host `Read`, host `Write`.
- Expected result shape: user data, MBR table data, zero read result, data protection status.

Current status:

- 35 `mbr-doc` cases exist.
- 34 `mbr-doc` cases passed independent consensus.
- 1 MBR table provenance case is quarantined because the packet does not prove actual MBR table bytes.
- 6 `mbr-table-doc` rework cases now explicitly write known bytes into the MBR byte table before the host read assertion.
- 4 `mbr-table-doc` cases passed independent consensus and triggered a solver fix: successful authenticated MBR byte-table `Set` is now tracked as a known table payload, and active MBR shadow reads expect that payload rather than prior user-media data.
- 2 `mbr-table-doc` cases remain quarantined because reviewers recorded concerns about exact post-`Done=true` read source and exact unauthenticated `Set` error-code mapping.
- 1 `mbrcontrol-readonly-doc` case for host non-modifiability of the MBRControl `UID` column has been added and accepted.
- 8 `mbrcontrol-defaults-doc` cases passed independent consensus.
  - They cover the Opal preconfigured MBRControl values `Enable=false`, `Done=false`, and `DoneOnReset=PowerCycle`.
  - They also cover successful Admins `Set` being reflected by a later `Get`.
  - This batch triggered a solver fix: MBRControl `Get` return cells are now validated against known preconfiguration and tracked Set state.
- 10 `locking-feature-descriptor-doc` cases passed independent consensus.
  - They cover Level 0 Locking Feature descriptor `LockingEnabled`, `Locked`, `MBREnabled`, and `MBRDone` bits after fresh Manufactured-Inactive state, Locking SP activation, enabled locked ranges, disabled locked cells, and MBRControl Enable/Done changes.
  - This batch triggered solver fixes: `hasLockedRange()` is now tied to the official Locked predicate, raw Locking Feature descriptor returns are checked against reconstructed Locking/MBR state, and host-style success return validators now run for `None`/`PASS` success-like status forms.
- 6 `locking-feature-lifecycle-doc` cases passed independent consensus.
  - They extend Level 0 Locking Feature state through successful RevertSP and failed KeepGlobalRangeKey RevertSP trajectories.
  - No new solver repair was needed because the descriptor-state repair and existing Locking SP lifecycle transition already generalized.
- 8 mixed-boundary cases for MBR inactive and MBR Done=True rows have been added and accepted by independent consensus.
- 5 `locking-doc` cases passed independent consensus.
- 5 `locking-doc` cases are quarantined because reviewers wanted stronger evidence that `INVALID_PARAMETER` represents the document's Data Protection Error or that MBRControl state is irrelevant.
- 12 `range-geometry-doc` cases for `CreateRow`, zero-length ranges, and `RangeStart`/`RangeLength` overlap mutation have been added and accepted.
- 16 `range-alignment-doc` cases for Opal `RangeStart`/`RangeLength` alignment formulas have been added and accepted.
- 20 `reencrypt-doc` cases for `ReEncryptRequest` state legality and direct `ReEncryptState` write rejection have been added and accepted.
- One accepted `reencrypt-doc` case triggered a solver fix: host `Set` on `ReEncryptState` column 12 is now rejected.
- 18 `reencrypt-lifecycle-doc` cases for `core/5.7.3.7` lifecycle blockers have been added and accepted.
- One accepted `reencrypt-lifecycle-doc` case triggered a solver fix: Global Range non-IDLE now blocks `Delete` of any Locking object.
- 5 `auth-authority-doc` cases for disabled authority StartSession vs Authenticate behavior have been added and accepted.
- One accepted `auth-authority-doc` case triggered a solver fix: disabled-authority `Authenticate` no longer allows `NOT_AUTHORIZED`; it requires `SUCCESS` with result `False`.

Next generator tasks:

- Additional byte-table provenance variants only when the trajectory explicitly writes known bytes into the table first.
  - For MBR, exact active-shadow payload assertions are now trusted when `Enable=true` and `Done=false`.
  - Avoid exact post-`Done=true` payload assertions unless a source or a stronger trajectory proves the underlying media state.
  - Avoid exact unauthenticated error-code PASS assertions unless a source maps the document's authorization failure to that concrete status.
  - DataStore has accepted Admin1 and personalized User1 payload-provenance coverage. For DataStore byte-table `Get`, do not model missing read authorization as `NOT_AUTHORIZED`; `core/5.3.4.2.2` says the successful method returns an empty results list.
  - TCGstorageAPI wrapper regressions now cover `writeAccess`/`readAccess`/`writeData`/`readData`; future sourced cases should stay protocol-level unless the packet explicitly explains the wrapper-to-method mapping.

- TPER reset / MBR reset interactions.
  - `opal/3.2.3.txt`: TPER_RESET side effects.
  - `core/5.7.2.5.4.txt`: MBRDoneOnReset behavior.

- More exact byte-table provenance cases.
  - Only add payload-specific MBR/DataStore read cases when the trajectory explicitly writes the exact bytes into the relevant table first.

### A2. C_PIN Authentication and TryLimit

Primary docs:

- `core/5.3.4.1.1.2.txt`
- `core/5.3.4.1.14.1.txt`
- `core/5.3.4.1.14.txt`
- `core/5.3.2.12.txt`
- `opal/4.2.1.8.txt`
- `opal/4.3.2.txt`

Interaction axes:

- Correct vs incorrect HostChallenge.
- TryLimit: zero, one, two or more.
- Tries count before final authentication.
- Persistence: true/false.
- Reset type: power cycle, hardware reset, programmatic reset.
- Authority enabled/disabled.
- StartSession vs Authenticate method.

Current status:

- 10 `trylimit-doc` cases exist.
- All 10 `trylimit-doc` cases passed independent consensus. The expanded batch covers `TryLimit=2` at `Tries=1`, successful authentication resetting `Tries`, host `Set Tries=0` unlocking a TryLimit-blocked C_PIN, and Opal Locking SP C_PIN `TryLimit`/`Tries` provenance.
- 14 `trylimit-tries-get-doc` cases exist.
- All 14 `trylimit-tries-get-doc` cases passed independent consensus.
  - They deliberately use longer stateful trajectories: failed explicit `Authenticate`, `TryLimit=0`, successful explicit `Authenticate`, PIN `Set`, `PowerCycle`, `HardwareReset`, and `TryLimit` `Set` are followed by `C_PIN_User1.Get` of `Tries` or `TryLimit`.
  - This batch triggered a solver repair: C_PIN non-PIN `Get` now validates returned `TryLimit`, `Tries`, and `Persistence` cells against tracked state, so wrong state-observation payloads no longer pass merely because the status is `SUCCESS`.
- 15 `cpin-issued-readonly-doc` cases exist.
- All 15 `cpin-issued-readonly-doc` cases passed independent consensus. They cover issued C_PIN `UID`, `Name`, and `CommonName` host non-modifiability across Admin SP `C_PIN_SID`, `C_PIN_MSID`, `C_PIN_Admin1`, and Locking SP `C_PIN_Admin1`/`C_PIN_User1`. No solver repair was needed because the existing C_PIN identity-column read-only rule already generalized to those concrete Opal rows.
- 5 `auth-authority-doc` cases exist.
- All 5 `auth-authority-doc` cases passed independent consensus.
- 21 `authority-issued-readonly-doc` cases exist.
- All 21 `authority-issued-readonly-doc` cases passed independent consensus. They cover issued Authority `UID`, `Name`, and `CommonName` host non-modifiability across Admin SP `Anybody`/`Admins`/`SID`/`Admin1` and Locking SP `Admin1`/`Users`/`User1`. This batch triggered a solver repair: issued Authority `CommonName` is now rejected as a host `Set` target instead of being treated as generally mutable.
- 30 `ace-issued-readonly-doc` cases exist.
- All 30 `ace-issued-readonly-doc` cases passed independent consensus. They cover issued ACE `UID`, `Name`, and `CommonName` host non-modifiability across representative Admin SP and Locking SP preconfigured ACE rows. This batch triggered a solver repair: issued ACE `CommonName` is now rejected as a host `Set` target, and the issued ACE range helper includes the preconfigured Opal ACE rows used in the cases.
- 3 `auth-class-doc` cases for class authority `Authenticate` behavior exist.
- All 3 `auth-class-doc` cases passed independent consensus.
- 2 `auth-missing-doc` cases for missing Authenticate authority exist.
- Both `auth-missing-doc` cases passed independent consensus after a rework that made the Awaiting Challenge state explicit with a preceding `Authenticate(Anybody)` success. They triggered a solver fix: missing authority is `INVALID_PARAMETER`, while explicit `Anybody` still succeeds.
- 2 `auth-operation-doc` cases for `TPerSign` explicit `Authenticate` behavior exist.
- Both `auth-operation-doc` cases passed independent consensus and triggered a solver fix: `TPerSign` explicit `Authenticate` may return `SUCCESS False`, but must not return `SUCCESS True`.
- 7 `authenticate-result-doc` cases exist.
- All 7 `authenticate-result-doc` cases passed independent consensus after two rework rounds.
  - The first round found a packet-level `Challenge` vs `Proof` wording concern; the second found missing packet evidence for prior C_PIN `Set` semantics and Anybody's concrete UID.
  - The accepted round uses `Proof`, adds Set/PIN sources proving the prior SID PIN mutation, and uses Anybody UID `0000000900000001`.
  - This batch triggered solver fixes: explicit `Authenticate` now accepts `Proof` as credential input, correct Password authentication requires `SUCCESS True`, incorrect Password authentication requires `SUCCESS False` when the status is `SUCCESS`, and Anybody `Authenticate` requires a true result.
- 5 `auth-operation-startup-doc` cases for wrong session-startup authority parameter roles exist.
- All 5 `auth-operation-startup-doc` cases passed independent consensus and triggered a solver fix: `TPerSign`, `TPerExch`, and `AdminExch` must not be accepted as `HostSigningAuthority`; `SID` and `TPerSign` must not be accepted as `HostExchangeAuthority`.
- 6 `session-class-authority-doc` cases for `StartSession` with class `HostSigningAuthority` values (`Admins`, `Makers`, `Users`) exist.
- All 6 `session-class-authority-doc` cases passed independent consensus. No solver change was needed because `_expected_start_session` already rejects class HostSigningAuthority with `INVALID_PARAMETER`.
- 3 `starttrusted-doc` cases for `StartTrustedSession` ordering/SMUID targeting exist.
- All 3 `starttrusted-doc` cases passed independent consensus. No solver change was needed because `_expected_start_trusted_session` already rejects pre-startup, post-close, and non-SMUID successful invocations.
- 3 `session-key-exchange-doc` cases for secure-messaging session key exchange failure exist.
- All 3 `session-key-exchange-doc` cases passed independent consensus after a re-review that moved explanatory text from `concerns` to `rationale`. They triggered a solver fix: observed Authority `Secure`, `Credential`, and `ResponseExch` columns are now tracked, and `StartSession` success is rejected when secure messaging is required but neither SP nor Host exchange authority has an appropriate credential.
- 6 `startup-hash-sign-doc` cases for Authority `HashAndSign` and `StartSession.SignedHash` exist.
- All 6 `startup-hash-sign-doc` cases passed independent consensus. They triggered a solver fix: observed Authority `HashAndSign` is now tracked, `StartSession` with a host control authority requiring hashing/signing rejects omitted `SignedHash`, `HashAndSign=None` does not require `SignedHash`, and `HashAndSign` is ignored for explicit `Authenticate`.
- 12 `session-timeout-doc` cases for `StartSession(SessionTimeout)` bounds exist.
- All 12 `session-timeout-doc` cases passed independent consensus. They triggered a solver fix: `Properties` return values now track observed `DefSessionTimeout`, `MaxSessionTimeout`, and `MinSessionTimeout`; `SPInfo.SPSessionTimeout` is tracked per SP; and future `StartSession` calls reject SessionTimeout values outside observed TPer/SP bounds, including the special zero-timeout rule.
- 10 `spinfo-readonly-doc` cases exist.
- All 10 `spinfo-readonly-doc` cases passed independent consensus. They cover SPInfo `UID`, `SPID`, `Name`, `Size`, and `SizeInUse` host non-modifiability in both Admin SP and Locking SP preconfigured rows. No solver repair was needed because existing SPInfo `Set` validation already rejects these columns.
- 16 `sptemplates-readonly-doc` cases exist.
- All 16 `sptemplates-readonly-doc` cases passed independent consensus. They cover Admin SP Base/Admin and Locking SP Base/Locking SPTemplates `UID`, `TemplateID`, `Name`, and `Version` host non-modifiability. No solver repair was needed because existing SPTemplates `Set` validation already rejects these read-only columns.
- 6 `trans-timeout-doc` cases for `StartSession(TransTimeout)` bounds exist.
- All 6 `trans-timeout-doc` cases passed independent consensus. They triggered a solver fix: `Properties` return values now track observed `DefTransTimeout`, `MaxTransTimeout`, and `MinTransTimeout`; future `StartSession` calls reject TransTimeout values outside observed TPer bounds; `MaxTransTimeout=0` is handled as no upper limit.
- 18 `host-properties-response-reset-long-doc` cases exist.
- All 18 `host-properties-response-reset-long-doc` cases passed independent consensus. They cover `Properties(HostProperties)` response completeness, cumulative HostProperties state, omitted-value preservation, Table 168 minimum coercion, the AckNak/SequenceNumbers dependency, and reset interactions for PowerCycle, HardwareReset, ProtocolStackReset, and programmatic TPerReset.
- This HostProperties slice triggered a solver repair: `State.host_properties` now records the TPer's current knowledge of host communication capabilities; `Properties` expectations validate returned HostProperties; parsing canonicalizes known host-property names; and reset transitions reset or preserve the state according to the official reset-event rules.
- 16 `tper-properties-response-constraints-doc` cases exist.
- All 16 `tper-properties-response-constraints-doc` cases passed independent consensus. They cover TPer `Properties` returned payload constraints: minimum-or-zero sizes for `MaxPacketSize` and `MaxComPacketSize`, nonnegative uinteger values, boolean property typing, `AckNak`/`SequenceNumbers` dependency, and `Asynchronous=True` requiring `MaxMethods=0`.
- This TPer Properties slice triggered a solver repair: returned TPer `Properties` are parsed separately from `HostProperties`, and `compare_expected_actual` now rejects impossible known-property payloads while allowing omitted unsupported properties and vendor extension fields.
- 7 `authority-limit-doc` cases for Authority `Limit`/`Uses` authentication caps exist.
- All 7 `authority-limit-doc` cases passed independent consensus after one reviewer recheck on the final-use-consumption case. They triggered a solver fix: Authority `Limit` and `Uses` are now tracked from official Authority columns, successful `StartSession`/`Authenticate` calls consume a use for individual authorities, nonzero exhausted limits block future authentication, and `Limit=0` remains unlimited.
- 2 `get-access-doc` cases for non-byte table C_PIN PIN-cell omission exist.
- Both `get-access-doc` cases passed independent consensus and triggered a narrow solver fix: explicit C_PIN PIN `CellBlock` reads are allowed to return `SUCCESS` with omitted cells, while full-row C_PIN reads remain conservative.
- Initial review packets for this slice were discarded and regenerated because failed `StartSession` helper output included session IDs on non-success status. `tools/run_synthetic_edges.py::start_session` now emits empty return values for non-success status.

Suggested generator tasks:

- Remaining secure messaging startup parameters: `StartTrustedSession` key fields, HMAC integrity key size, certificate presentation, and plaintext prohibition when the control authority `Secure` column is 0.
- Session timeout expiration side effects, but only if the trajectory format can express elapsed time or timeout-triggered session termination.
- Remaining PIN modification reset paths via `GenKey` and `SetPackage` on C_PIN, with explicit C_PIN object provenance and later `Get Tries` observation.
- Additional Persistence behavior by reset type only where the trajectory can keep C_PIN provenance and open an authorized post-reset session.
- Authority-adjacent timing/validity fields such as `ClockStart`/`ClockEnd`, once the trajectory format can express clock time or validity-window checks.

Repair paths:

- `src/solver_components/expectations.py::_expected_start_session`
- `src/solver_components/expectations.py::_startup_signed_hash_error`
- `src/solver_components/expectations.py::_startup_session_timeout_error`
- `src/solver_components/expectations.py::_startup_trans_timeout_error`
- `src/solver_components/expectations.py::_expected_host_properties_after_submission`
- `src/solver_components/transitions.py::_apply_host_property_submission`
- `src/solver_components/parsing.py::_submitted_host_properties`
- `src/solver_components/parsing.py::_returned_host_properties`
- `src/solver_components/parsing.py::_returned_tper_properties`
- `src/solver_components/engine.py::_tper_properties_valid`
- `src/solver_components/expectations.py::_authority_limit_reached`
- `src/solver_components/expectations.py::_expected_authenticate`
- `src/solver_components/expectations.py::_expected_get`
- `src/solver_components/transitions.py::_apply_properties_success`
- `src/solver_components/transitions.py::_apply_start_session_success`
- `src/solver_components/transitions.py::_increment_authority_use`
- `src/solver_components/transitions.py::_update_authority_from_columns`
- `src/solver_components/transitions.py::_apply_auth_failure`
- `src/solver_components/transitions.py::_apply_get_success`
- `src/solver_components/transitions.py::_apply_set_success`
- `src/solver_components/transitions.py::_apply_reset`

### A3. GenKey, Media Key, Re-encryption

Primary docs:

- `core/5.3.3.16.2.txt`
- `core/5.3.3.16.4.txt`
- `core/5.7.2.2.12.txt`
- `core/5.7.2.2.17.txt`
- `core/5.7.2.2.18.txt`
- `core/5.7.2.2.19.txt`
- `core/5.1.3.34.txt`
- `core/5.7.3.7.txt`
- `core/5.7.3.7.4.txt`
- `opal/3.1.1.6.3.txt`
- `opal/4.2.5.1.txt`
- `opal/4.2.6.1.txt`
- `opal/4.2.6.1.2.txt`
- `opal/4.2.7.1.txt`
- `opal/4.2.1.5.txt`
- `opal/4.2.1.6.txt`
- `opal/4.3.5.5.txt`

Interaction axes:

- GenKey target object: C_PIN, K_AES range key, non-GenKey-capable object.
- Optional PinLength: absent, valid, greater than 32, present on non-C_PIN.
- ReEncryptState: IDLE vs non-IDLE.
- ReEncryptRequest transitions.
- Re-encryption progress/status columns: LastReEncryptLBA, LastReEncStat, ContOnReset, GeneralStatus.
- DataRemovalMechanism ActiveDataRemovalMechanism enum and ACL.
- Media generation effects on previous host writes.

Current status:

- 6 `genkey-doc` cases exist.
- 4 `genkey-doc` cases passed independent consensus.
- 2 `genkey-doc` ReEncryptState cases are quarantined because the packet does not explicitly decode Locking column 12 or state value `2`.
- 8 `genkey-cpin-doc` cases exist.
- All 8 `genkey-cpin-doc` cases passed independent consensus. They cover omitted PinLength default success, empty GenKey success result, rejection of non-empty successful result, and the fact that successful C_PIN GenKey stores a new generated PIN so the previous SID PIN must no longer authenticate via either `StartSession` or explicit `Authenticate`.
- This batch triggered a solver fix: successful C_PIN `GenKey` now records the previous PIN as invalidated instead of merely forgetting it as unknown.
- 1 `cpin-charset-doc` case passed independent consensus.
  - Accepted case covers C_PIN `CharSet` column `0x04` rejecting a C_PIN object UID because `CharSet` is a `byte_table_ref` and type checking must validate that the uidref points to a byte table.
  - A symbolic `CharSet` column variant was discarded to `analysis/label_reviews/discarded/cpin_charset_symbolic_column_concern/` after one reviewer flagged the name-to-column inference, even though the numeric-column case was unambiguous.
- 2 `genkey-public-exponent-doc` cases passed independent consensus.
  - Accepted cases cover `PublicExponent` on non-C_RSA GenKey targets: C_PIN and K_AES_256 both must not succeed.
  - No new solver repair was needed; existing `_expected_genkey` already rejected `PublicExponent` for non-C_RSA targets.
- 20 `reencrypt-doc` cases exist.
- All 20 `reencrypt-doc` cases passed independent consensus.
- Exact-error-code cases for invalid re-encryption requests were intentionally removed when the document only guaranteed an error/non-success result.
- 18 `reencrypt-lifecycle-doc` cases exist.
- All 18 `reencrypt-lifecycle-doc` cases passed independent consensus.
- Initial review packets for this slice were discarded and regenerated because the default source snippet truncated the Global Range rule. `tools/label_consensus.py` now exports longer source snippets.
- 2 `reencrypt-progress-doc` cases passed independent consensus and triggered a solver fix: LastReEncryptLBA and LastReEncStat are not host-modifiable Locking columns.
- 4 `reencrypt-reset-doc` cases passed independent consensus and triggered a solver/engine extension:
  - empty `ContOnReset` pauses ACTIVE re-encryption after reset with `GeneralStatus=34` (`active_reset_stop_detect`).
  - empty `ContOnReset` must not leave ACTIVE re-encryption active after reset.
  - empty `ContOnReset` pauses PENDING re-encryption after reset with `GeneralStatus=5` (`pend_reset_stop_detect`).
  - empty `ContOnReset` must not leave PENDING re-encryption pending after reset.
- 2 `reencrypt-column-types-doc` cases passed independent consensus.
  - Accepted cases cover Locking `ActiveKey` rejecting a C_PIN credential reference because `ActiveKey` is a `mediakey_object_uidref`, and `ReEncryptRequest` successful `Get` returning no value.
  - Three broader review rounds were discarded before acceptance:
    - `analysis/label_reviews/discarded/reencrypt_column_types_initial_uid_ambiguity/`
    - `analysis/label_reviews/discarded/reencrypt_column_types_recheck_reserved_state_get_concern/`
    - `analysis/label_reviews/discarded/reencrypt_column_types_final_reserved_and_nextkey_concerns/`
  - Deferred cases include valid-media-key UID positives, `NextKey` invalid reference without explicit state context, reserved `ReEncryptRequest`/`AdvKeyMode` Set values, and reserved `ReEncryptState` Get values. Those need stronger source spans or more explicit trajectory setup before becoming trusted.
- 6 `data-removal-doc` cases passed independent consensus.
  - SID can set ActiveDataRemovalMechanism to mandatory Cryptographic Erase.
  - Setting a supported value must not fail with `INVALID_PARAMETER`.
  - reserved ActiveDataRemovalMechanism values fail with `INVALID_PARAMETER`.
  - reserved values must not succeed.
  - Anybody cannot set ActiveDataRemovalMechanism because the ACL is Admins OR SID.
  - Anybody success is invalid for that Set.
- 6 `data-removal-reserved-doc` cases passed independent consensus.
  - They extend the reserved enum coverage to `ActiveDataRemovalMechanism` values `3`, `6`, and `7` using `opal/3.1.1.6.4` plus the `data_removal_mechanism` enum and unsupported-value failure rule.
  - No solver repair was needed; existing enum validation already generalized from the earlier value `4` case.
- 8 `kaes-get-doc` cases passed independent consensus after the initial review packet was discarded for two concerns: symbolic `Mode` return keys and no-Cellblock full-row inference.
  - Accepted cases now use numeric RowValues column identifiers and direct column-targeted trajectories only.
  - They cover K_AES_256 and K_AES_128 Mode reads through `ACE_K_AES_Mode`, valid `symmetric_mode_media` values, missing readable Mode cell rejection, reserved Mode value rejection, protected Key leakage rejection, direct K_AES Key-column rejection, and unknown-column rejection.
  - This slice triggered a solver fix: K_AES successful Mode `Get` now requires a returned Mode cell with a valid `symmetric_mode_media` value and rejects protected Key cells in successful K_AES `Get` RowValues.
- Deeper progress/status and enum-reserved cases remain open, especially listed non-empty `ContOnReset` entries where continuation is permissive rather than mandatory.
  Data-removal interrupted/processing bits remain open because they likely require Level 0 feature descriptor state or long-running operation traces.

Repair paths:

- `src/solver_components/expectations.py::_expected_genkey`
- `src/solver_components/expectations.py::_expected_start_session`
- `src/solver_components/expectations.py::_expected_authenticate`
- `src/solver_components/expectations.py::_expected_set`
- `src/solver_components/expectations.py::_expected_get`
- `src/solver_components/transitions.py::apply_transition`
- `src/solver_components/semantics.py::_pin_owner_by_object`
- `src/solver_components/semantics.py::_credential_was_invalidated`
- `src/solver_components/semantics.py::_range_id_from_key`
- `src/solver_components/semantics.py::_invalid_set_values`
- `src/solver_components/transitions.py::_apply_reset_event`
- `src/solver_components/engine.py::compare_expected_actual`
- `src/solver_components/parsing.py::_flatten_return_values`

### A4. Reset Semantics

Primary docs:

- `core/5.7.2.2.10.txt`
- `core/5.7.2.5.3.txt`
- `core/5.7.2.5.4.txt`
- `opal/3.2.3.txt`
- `opal/4.2.3.1.txt`

Interaction axes:

- LockOnReset values.
- MBRDoneOnReset values.
- Programmatic reset enablement.
- Session close side effects.
- Tries persistence across reset types.

Current status:

- 3 `reset-doc` cases exist.
- 1 `reset-doc` case passed independent consensus.
- 2 `reset-doc` cases are quarantined because the packet does not prove reset type value `0` maps to `PowerCycle` or the exact locked-write failure status.
- 3 `tper-reset-doc` cases passed independent consensus.
  - `TPER_RESET` rejected when `ProgrammaticResetEnable` is false/default.
  - `TPER_RESET` accepted after SID enables `TPerInfo.ProgrammaticResetEnable`.
  - accepted `TPER_RESET` aborts an open session before the next method.
- 8 `tperinfo-readonly-doc` cases passed independent consensus. They cover TPerInfo Core columns `UID`, `Bytes`, `GUDID`, `Generation`, `FirmwareVersion`, `ProtocolVersion`, `SpaceForIssuance`, and `SSC` as host read-only. `ProgrammaticResetEnable` is deliberately excluded because Opal makes it SID-modifiable and existing reset cases depend on that mutability.
- 3 `mbr-done-reset-doc` cases passed independent consensus.
  - `MBRDoneOnReset=PowerCycle` changes Done from true to false across a PowerCycle, so old user-media reads inside the MBR region are invalid.
  - empty `MBRDoneOnReset` preserves Done=true across PowerCycle.
  - empty `MBRDoneOnReset` also preserves an existing Done=false shadowing state across PowerCycle.

Repair paths:

- `src/solver_components/transitions.py::_apply_reset`
- `src/solver_components/semantics.py::_reset_types`
- `src/solver_components/expectations.py::_expected_host_io`

### B1. ACL, ACE, and Method Authorization

Primary docs:

- `core/3.4.2.1.txt`
- `core/3.4.2.2.txt`
- `core/3.4.2.3.txt`
- `core/5.3.3.14.5.txt`
- `core/5.3.4.2.2.txt`
- `opal/4.3.1.7.txt`

Interaction axes:

- Missing ACE.
- Deleted ACL association.
- Class vs individual authority.
- Anybody/Admins/Users expressions.
- Get vs Set vs table method authorization.

Current status:

- 2 `get-access-doc` cases cover one ACL/ACE interaction: `C_PIN_User1.Get` is controlled by `ACE_C_PIN_Admins_Get_All_NOPIN`, whose columns exclude `PIN`, and the general Get rule omits inaccessible non-byte table cells rather than returning a method error.
- 6 `meta-acl-doc` cases cover row-specific meta-ACL behavior for `AddACE`, `RemoveACE`, `GetACL`, and `DeleteMethod`. They lock down empty meta-ACL columns as `NOT_AUTHORIZED`, `AddACE` empty-result shape, and the Locking SP `C_PIN_User1/Set` `GetACLACL=ACE_Anybody` path.
- 6 `meta-acl-empty-doc` cases extend this to the Admin SP `SPInfo/Get` AccessControl row. The base ACL is `ACE_Anybody`, but empty `RemoveACEACL`, `GetACLACL`, and `DeleteMethodACL` still make those meta-methods fail with `NOT_AUTHORIZED`.
- 18 `acl-method-params-doc` cases cover AccessControl meta-method signatures for `GetACL`, `AddACE`, `RemoveACE`, and `DeleteMethod`.
  - They assert impossible-success outcomes for missing `InvokingID`, missing `MethodID`, missing `ACE` where applicable, and invocation on a non-AccessControl target.
  - They also cover success-result shape: `AddACE`, `RemoveACE`, and `DeleteMethod` must return an empty result list, while `GetACL` must return a list of ACE uidrefs rather than a scalar ACE reference.
  - This batch triggered a solver fix: successful `GetACL` responses now enforce UID-list return shape.
- Broader ACL/ACE behavior still needs coverage for ACE BooleanExpr combinations, missing ACE rows, full ACLs, duplicate ACE insertion, and status-specific failure cases where the source names an exact status.

Repair paths:

- `src/solver_components/expectations.py::_expected_get_acl`
- `src/solver_components/expectations.py::_expected_acl_mutation`
- `src/solver_components/expectations.py::_expected_delete_method`
- `src/solver_components/engine.py::_return_is_uid_list`
- `src/solver_components/semantics.py::_method_combo_deleted`
- `src/solver_components/transitions.py::apply_transition`

### B2. Table Methods and Object Table Access

Primary docs:

- `core/5.3.3.2.txt` through `core/5.3.3.10.txt`
- `core/5.3.4.2.2.txt` through `core/5.3.4.2.6.txt`
- `core/5.1.5.11.txt`

Interaction axes:

- Object method vs table method.
- `Where` filtering.
- `CellBlock` start/end column.
- Byte table vs object table behavior.
- Invalid column or malformed required arguments.
- Setup method status vs later side-effect target.

Current status:

- 2 `get-access-doc` cases cover one table-method access rule: inaccessible cells requested by non-byte table `Get` are omitted from the result, and requesting them is not an error.
- 6 `set-rowvalues-doc` cases cover one `Set` parameter rule: RowValues may be sent in any order, but a single `Set` invocation that includes the same column more than once fails with `INVALID_PARAMETER`.
- All 6 `set-rowvalues-doc` cases passed independent consensus. They triggered a solver fix: duplicate RowValues columns are detected before parsed values collapse into a single dictionary entry.
- 8 `set-where-values-doc` cases cover `Set` method shape across object, object-table, and byte-table invocations. They lock down `Object.Set` omitting `Where`, object-table `Where=UID` plus RowValues, byte-table `Where=Row` plus Bytes, omitted `Values` as success/no-op, and empty-list success results.
- All 8 `set-where-values-doc` cases passed independent consensus. They triggered solver fixes: byte-table `Where={Row}` is recognized as row addressing, byte-table omitted `Values` is allowed as no-op success, and successful `Set` responses must have an empty return list.
- 7 `table-lifecycle-doc` cases cover CreateTable duplicate Name/CommonName rejection, object-table CreateRow/DeleteRow, DeleteRow empty-result shape, byte-table CreateRow/DeleteRow rejection, AccessControl system-table DeleteRow rejection, and Delete empty-result shape on Locking objects.
- 8 `table-kind-doc` cases cover `table_kind` values `1=Object` and `2=Byte`, reserved/out-of-range kind rejection, and the two-field `CreateTable` success result (`UID`, `Rows`). They triggered a solver fix: successful `CreateTable` responses now require exactly two result fields.
- 44 `table-descriptor-readonly-doc` cases cover issued Table descriptor `UID`, `Name`, `CommonName`, `TemplateID`, `Kind`, `Column`, `NumColumns`, `Rows`, `RowsFree`, `RowBytes`, and `LastID` host non-modifiability across representative Admin SP and Locking SP table descriptors. `MinSize` and `MaxSize` are deliberately excluded because the Core column definitions describe them as user-settable.
- 15 `template-readonly-doc` cases cover Admin SP Template `UID`, `Name`, `RevisionNumber`, `Instances`, and `MaxInstances` host non-modifiability across Base/Admin/Locking preconfigured template rows.
- 14 `sp-table-readonly-doc` cases cover Admin SP SP-table `UID`, `Name`, `ORG`, `EffectiveAuth`, `DateOfIssue`, `Bytes`, and `LifeCycleState` host non-modifiability across Admin and Locking SP rows. `Frozen` is deliberately excluded because it is a separate owner-control column and the solver already models its session-start side effect.
- 8 `get-cellblock-doc` cases cover `Get` `Cellblock` context rules for byte-table, object-table, and object invocations. They triggered a solver fix: the parser now extracts Cellblock components without mistaking high-level API positional arguments for Cellblocks, and `_expected_get` rejects context-invalid `Table`/row/column components.
- 6 `next-doc` cases cover `Next` object-table iteration result shape, byte-table rejection, and `Count` unsignedness. They triggered a solver fix: successful `Next` responses now must be a list of UID-like values, not a scalar UID or RowValues map.
- 16 `methodid-locking-preconfig-doc` cases cover Locking SP MethodID preconfiguration.
  - Accepted cases verify successful `Get` of MethodID `Name` cells for `Next`, `GenKey`, `RevertSP`, `Get`, `Set`, `Authenticate`, and `Random`, plus impossible-success host `Set` of issued MethodID `UID` and `Name`.
  - This batch triggered a solver fix: MethodID `Get` return cells are now checked against the method UID/name mapping instead of only checking that `Get` succeeded.
- 14 `methodid-locking-extra-readonly-doc` cases cover issued MethodID `CommonName` and `TemplateID` host non-modifiability for the same Locking SP rows.
  - No solver repair was needed; the existing MethodID host-write rejection already handled columns 2 and 3.
- 48 `methodid-admin-preconfig-doc` cases cover Admin SP MethodID preconfiguration.
  - Accepted cases verify successful `Get` of MethodID `Name` cells for `Next`, `GetACL`, `Get`, `Set`, `Authenticate`, `Revert`, `Activate`, and `Random`, wrong-Name rejection for the same rows, and issued MethodID `UID`/`Name`/`CommonName`/`TemplateID` host non-modifiability.
  - No solver repair was needed; earlier MethodID `Get` return-cell checking and MethodID host-write rejection generalized to the Admin SP rows.
- Broader `Get` return payload exactness, `Next` invalid-`Where` cases with stronger fail evidence, CreateTable space/row-limit failure branches, and exact byte-table payload semantics still need coverage.

Suggested generator tasks:

- One subagent for `Get` required/optional parameter shape and malformed `CellBlock`/column selectors.
- One subagent for `CreateRow`/`DeleteRow` row side effects.
- One subagent for byte-table access such as MBR/DataStore, with exact byte provenance called out as an ambiguity risk.

Repair paths:

- `src/solver_components/parsing.py::parse_event`
- `src/solver_components/expectations.py::expected_status`
- `src/solver_components/expectations.py::_expected_set`
- `src/solver_components/semantics.py::_set_has_duplicate_value_columns`
- `src/solver_components/semantics.py::_set_values_omitted`
- `src/solver_components/parsing.py::_byte_table_where_invalid`
- `src/solver_components/parsing.py::_byte_table_set_invalid`
- `src/solver_components/transitions.py::apply_transition`

### B3. Lifecycle, Revert, and DeleteSP

Primary docs:

- `core/5.3.3.1.txt`
- `core/5.3.4.4.txt`
- `core/5.3.5.txt`
- `core/5.4.5.txt`
- `core/5.7.4.txt`
- `opal/3.1.1.6.1.txt`
- `opal/3.1.1.6.4.txt`

Interaction axes:

- LockingSP activation.
- Frozen/Enabled state.
- DeleteSP pending until `EndSession`.
- AdminSP `Revert` vs LockingSP `RevertSP`.
- PSID revert.
- Credential, range, media-key reset postconditions.

Current status:

- 11 `revertsp-lifecycle-doc` cases exist.
- All 11 `revertsp-lifecycle-doc` cases passed independent consensus after the trajectories were lengthened to include explicit `Manufactured-Inactive` observation, `Activate`, host data writes, Global Range lock-state setup, `RevertSP`, and postcondition targets.
- The accepted batch covers `KeepGlobalRangeKey=True` success when the Global Range is read-unlocked or write-unlocked, failure with status `FAIL` when it is both read-locked and write-locked, Global Range data preservation with KeepGlobalRangeKey, data invalidation without KeepGlobalRangeKey, immediate session abort after successful RevertSP, and unchanged lifecycle after failed RevertSP.
- No solver code change was needed in this batch; the existing RevertSP, KeepGlobalRangeKey, session-abort, and Locking SP reset modeling already handled these official-doc-sourced cases.
- 5 `deletesp-lifecycle-doc` cases exist and all 5 passed independent consensus.
  - The accepted batch covers successful `DeleteSP` returning an empty list, non-empty success payload rejection, inability to open the deleted Locking SP after successful session close, disabled-SP deletion consequences, and Admin SP non-deletability.
  - This batch triggered a solver fix: successful `DeleteSP` now requires an empty result list.
- 7 `admin-revert-sid-doc` cases exist and all 7 passed independent consensus.
  - The accepted batch covers AdminSP `Revert` read-write requirement, empty-result shape, immediate session abort, SID reset to MSID when the Opal SSC V2 revert behavior field is `0x00`, pre-revert SID PIN invalidation, and active-LockingSP user-data removal.
  - This batch triggered solver fixes: `Revert`/`RevertSP` now require read-write sessions and empty success results, and factory reset now tracks whether SID was successfully authenticated before applying the C_PIN_SID reset rule.

Suggested generator tasks:

- Continue with one subagent per remaining lifecycle operation.
- Each case should include a postcondition target after the lifecycle method, not only the lifecycle method status.
- Next high-value lifecycle targets: PSID Revert variants, issued-SP deletion via Admin SP `Delete`, and exact SP table lifecycle state observations after revert/delete when evidence proves the target assertion.

Repair paths:

- `src/solver_components/expectations.py::expected_status`
- `src/solver_components/transitions.py::apply_transition`
- `src/solver_components/transitions.py::_reset_factory_state`
- `src/solver_components/transitions.py::_reset_locking_sp`

### C1. Logs, Package, and Crypto Methods

Primary docs:

- `core/5.8.2.1.txt`
- `core/5.8.3.1.txt`
- `core/5.8.4.1.txt` through `core/5.8.4.5.txt`
- `core/5.3.3.17.txt`
- `core/5.3.3.18.txt`
- `core/5.3.4.5.txt`
- `core/5.6.*.txt`

Interaction axes:

- Circular log rows.
- `AddLog`.
- Inaccessible log cells.
- `GetPackage`/`SetPackage` required parameters.
- `Random` length.
- `Sign`/`Verify` parameter validity.

Current status:

- 4 `log-addlog-doc` cases exist.
- All 4 `log-addlog-doc` cases passed independent consensus. They cover `AddLog` success with an empty result in a read-only session, non-empty successful result rejection, non-Log table target rejection, and Data payload longer than 64 bytes. This slice triggered a solver fix: `AddLog` is now modeled as a Log table method with empty success result and 64-byte Data limit.
- 6 `log-clear-flush-doc` cases exist.
- All 6 `log-clear-flush-doc` cases passed independent consensus after evidence was expanded to prove both the Log table target and the C_PIN non-Log target. They cover `ClearLog`/`FlushLog` empty success result, Log table target success, and non-Log target rejection. This slice triggered a solver fix: `ClearLog` and `FlushLog` are now modeled as supported Log table maintenance methods with empty success results.
- 7 `log-createlog-doc` cases exist.
- All 7 `log-createlog-doc` cases passed independent consensus after a reviewer re-pass on the duplicate-name trajectory. They cover `CreateLog` LogList target success, result fields `LogListUID`/`LogTableUID`/`Rows`, missing/negative `MinSize`, duplicate log-table name rejection, and non-LogList target rejection. This slice triggered solver fixes: `CreateLog` is now modeled as a supported LogList table method, duplicate log names are tracked from successful `CreateLog`, and return payload length checks count structured result-field arity.
- 4 `log-createlog-params-doc` cases exist.
- All 4 `log-createlog-params-doc` cases passed independent consensus. They cover `CreateLog` `HighSecurity=True` as a valid boolean, `HighSecurity=2` rejection, missing required `HighSecurity`, and negative optional `HintSize` rejection. No new solver repair was needed; existing `CreateLog` parameter typing already matched the sourced cases.
- 2 `loglist-readonly-doc` cases exist.
- All 2 `loglist-readonly-doc` cases passed independent consensus after two discarded review rounds on an initially ambiguous Log table delete case.
  - Accepted cases cover host non-modifiability of LogList `Log` and `Serial`.
  - This slice triggered a narrow solver fix: LogList `Log`/`Serial` names are now mapped to columns 3/4 and `_invalid_set_values` rejects host `Set` attempts against those columns.
  - The direct Log table delete case remains deferred until the trajectory can express the exact "via the Table table" deletion path or reviewers are given a stronger source span.
- 6 `random-doc` cases exist.
- All 6 `random-doc` cases passed independent consensus after the first packet was discarded for two implicit/borderline points. The accepted cases cover `Random` Count byte-length matching, negative Count rejection via `uinteger`, `BufferOut` empty-result behavior, and unsupported Random parameter rejection with `INVALID_PARAMETER`. This slice triggered solver fixes: `Random` now treats `BufferOut` as an output-buffer path requiring an empty successful Result and rejects unsupported named Random parameters.
- 7 `package-doc` cases exist.
- All 7 `package-doc` cases passed independent consensus. They cover `GetPackage` missing `Purpose`, invalid non-credential `WrappingKey`/`SigningKey`, `SetPackage` missing `Value`, invalid non-credential `SigningKey`, non-credential target rejection, and empty success-result shape. This slice triggered a solver fix: successful `SetPackage` now requires an empty result list.
- 7 `table-query-doc` cases exist.
- All 7 `table-query-doc` cases passed independent consensus. They cover `GetFreeSpace` result arity (`FreeSpace`, `TableRows`), `GetFreeSpace` SP-method target rejection on table objects, and `GetFreeRows` result arity (`FreeRows`). This slice triggered solver fixes: `GetFreeSpace`/`GetFreeRows` successful responses now enforce their result shapes, and single scalar/dict payloads are counted as one result field.
- 3 `secretprotect-doc` cases exist.
- All 3 `secretprotect-doc` cases passed independent consensus. They cover the host non-modifiability of SecretProtect `Table`, `ColumnNumber`, and `ProtectMechanisms` cells on the Opal Locking SP SecretProtect rows. No new solver repair was needed; existing SecretProtect row `Set` rejection was promoted into sourced coverage.
- 2 `cpin-column-types-doc` cases exist.
- All 2 `cpin-column-types-doc` cases passed independent consensus after an initial review round was discarded for exact-status wording concerns. The accepted cases cover impossible-success C_PIN `Set` responses for a negative `TryLimit` (`uinteger_4`) and `Persistence=2` (`boolean`). No new solver repair was needed; existing type validation already rejected both.
- 1 `loglist-highsecurity-doc` case exists.
- The `loglist-highsecurity-doc` case passed independent consensus after an initial round was discarded for exact-status caveats in `concerns`. It covers impossible-success `Set` of LogList `HighSecurity` column `0x05` to boolean value `2`. No new solver repair was needed; existing LogList Set validation already rejected it.
- 2 `log-row-readonly-doc` cases exist.
- All 2 `log-row-readonly-doc` cases passed independent consensus. They cover impossible-success host `Set` of Log entry row `MonotonicTime` and `Data` cells. This slice triggered a solver repair: Log table rows are now treated as direct host-read-only Set targets, and Log column names are parsed for row-level read-only checks.
- 6 `lockinginfo-readonly-doc` cases exist.
- All 6 `lockinginfo-readonly-doc` cases passed independent consensus. They cover host non-modifiability of LockingInfo `UID`, `Name`, `Version`, `EncryptSupport`, `MaxRanges`, and `MaxReEncryptions`. No new solver repair was needed.
- 12 `log-entry-readonly-expanded-doc` cases exist.
- All 12 `log-entry-readonly-expanded-doc` cases passed independent consensus. They expand Log entry row host-read-only coverage to all remaining Log row columns beyond the earlier `MonotonicTime`/`Data` pair. No new solver repair was needed beyond the earlier Log row Set rejection.
- 4 `loglist-initial-row-doc` cases exist.
- All 4 `loglist-initial-row-doc` cases passed independent consensus. They cover the initial LogList row UID `0000000A02000001`, `Name=Log`, and fresh `HighSecurity=false`. This slice triggered a solver repair: known LogList row `Get` return cells are now validated, and successful `HighSecurity` updates are tracked for later `Get` expectations.
- 1 `advkeymode-doc` case exists.
- The `advkeymode-doc` case passed independent consensus. It covers impossible-success `Set` of Locking `AdvKeyMode` to reserved enum value `2`. This slice triggered a solver repair: Locking Set validation now rejects `AdvKeyMode` values outside `{0, 1}`.
- 2 `reencrypt-state-values-doc` cases exist.
- All 2 `reencrypt-state-values-doc` cases passed independent consensus. They cover impossible successful `Get` payloads for reserved `ReEncryptState=6` and stale `COMPLETED` after successful `ADVKEY_req` from `COMPLETED`. No new solver repair was needed; existing postcondition tracking already rejected both.
- 2 `meta-acl-locking-status-doc` cases exist.
- All 2 `meta-acl-locking-status-doc` cases passed independent consensus. They cover exact `NOT_AUTHORIZED` outcomes for Locking SP `C_PIN_User1/Set` `RemoveACE` and `DeleteMethod` when row-specific `RemoveACEACL`/`DeleteMethodACL` are empty. No new solver repair was needed.
- 12 `authority-uses-get-doc` cases exist.
- All 12 `authority-uses-get-doc` cases passed independent consensus. They cover successful/failed explicit `Authenticate`, successful/failed `StartSession`, `Limit=0`, and successful `Limit Set` trajectories observed through later Authority `Get` cells. This slice triggered a solver repair: Authority `Get` now validates tracked `Limit` and `Uses` cells instead of accepting arbitrary successful payloads.
- 8 `lockonreset-get-doc` cases exist.
- All 8 `lockonreset-get-doc` cases passed independent consensus. They cover `PowerCycle` effects on observable `ReadLocked`/`WriteLocked`, empty `LockOnReset`, and nonmatching reset types. This slice triggered a solver repair: Locking `Get` now validates tracked lock-state cells.
- 12 `locking-range-get-doc` cases exist.
- All 12 `locking-range-get-doc` cases passed independent consensus. They cover default and post-`Set` `RangeStart`, `RangeLength`, `ReadLockEnabled`, and `WriteLockEnabled` observations. This slice triggered a solver repair: Locking `Get` now validates tracked geometry and lock-enable cells.
- 8 `locking-lockonreset-get-doc` cases exist.
- All 8 `locking-lockonreset-get-doc` cases passed independent consensus. They cover default `LockOnReset=Power Cycle`, successful `{0,3}`, empty, and `{0,1}` `LockOnReset` observations. This slice triggered solver repairs: default RangeState now reflects Opal `LockOnReset={0}`, and Locking column 9 return comparison now uses `reset_types` set equality.
- 8 `locking-composite-get-doc` cases exist.
- All 8 `locking-composite-get-doc` cases passed independent consensus. They cover longer multi-column Locking Cellblock `Get` trajectories that combine geometry, lock-enable, lock-state, and `LockOnReset` postconditions in one response.
- 6 `datastore-payload-doc` cases exist.
- All 6 `datastore-payload-doc` cases passed independent consensus after a notation rework from Python bytes literals to hex payload strings. They cover DataStore byte-table payload provenance and overwrite behavior.
- 8 `datastore-user-payload-doc` cases exist.
- All 8 `datastore-user-payload-doc` cases passed independent consensus. They cover personalized User1 DataStore Get/Set ACEs, payload provenance, and the official empty-results behavior for unauthorized byte-table `Get`.
- This DataStore slice triggered solver repairs: successful DataStore byte-table `Set` now records the payload, authorized `Get` validates the tracked payload, and unauthorized byte-table `Get` expects `SUCCESS` with an empty result list rather than `NOT_AUTHORIZED`.
- Added high-level TCGstorageAPI wrapper regressions for `writeAccess`, `readAccess`, `writeData`, and `readData` so the same DataStore semantics are exercised in likely dashboard trace formats.
- 12 `byte-table-descriptor-rows-doc` cases exist.
- All 12 `byte-table-descriptor-rows-doc` cases passed independent consensus. They cover Opal Locking SP `Table_MBR` and `Table_DataStore` descriptor `Get` responses for `Kind=Byte`, minimum `Rows`, and composite named/numeric return-cell payloads.
- This descriptor slice triggered solver repairs: `ExpectedResponse` can now require lower-bound return cells, `Table_MBR`/`Table_DataStore` `Get` validates documented minimum Rows values, and Table descriptor named return keys such as `Kind`/`Rows` are parsed into column numbers.
- 16 `byte-table-granularity-doc` cases exist.
- All 16 `byte-table-granularity-doc` cases passed independent consensus. They cover Opal-added Table descriptor granularity columns, object-table zero granularity, byte-table mandatory/recommended bounds, read-only descriptor granularity cells, and DataStore `Set` alignment after observed mandatory granularity.
- This granularity slice triggered solver repairs: observed byte-table mandatory/recommended granularity is tracked from `Table_MBR`/`Table_DataStore` descriptor `Get`, and later byte-table `Set` checks the row offset and byte payload length against the mandatory alignment requirement.
- 14 `create-table-row-allocation-doc` cases exist.
- All 14 retained `create-table-row-allocation-doc` cases passed independent consensus. They cover named and positional `CreateTable` `Rows` results, lower-bound enforcement from `MinSize`, upper-bound enforcement from `MaxSize`, byte-table `Columns` emptiness, and byte-table `MaxSize`/`HintSize` `INVALID_PARAMETER` failures.
- This CreateTable slice triggered solver repairs: successful method results can now be checked by named/positional selectors, `CreateTable` validates `Rows` against `MinSize`/`MaxSize`, and object-table `HintSize < MinSize` is not treated as a proven failure without an explicit sourced status rule.
- 10 `create-row-unique-columns-doc` cases exist.
- All 10 `create-row-unique-columns-doc` cases passed independent consensus. They cover host-created object table schema tracking, unique-column and multi-column unique conflict behavior, missing/undeclared row-data columns, simple no-unique table duplicate allowance, and exact UID-list result length for one-row `CreateRow`.
- This CreateRow slice triggered solver repairs: created table schemas and row values are now tracked in state, and later `CreateRow` invocations validate declared columns, unique combinations, and UID-list result shape.
- 13 `table-descriptor-size-set-doc` cases exist.
- All 13 `table-descriptor-size-set-doc` cases passed independent consensus. They cover `Table.Set` against a created table descriptor row selected by `Where`, valid `MaxSize`/`MinSize` changes, `MaxSize=0`, `MinSize` lowering rejection, `MaxSize` below `MinSize`, `MaxSize` below current `Rows`, same-Set `MinSize`/`MaxSize` interactions, and later `MaxSize` validation after a successful `MinSize` raise.
- This descriptor-size slice triggered solver repairs: created table descriptor UIDs and size metadata are now tracked, successful descriptor size `Set` updates later state, and `CreateRow` increases the row count used by later `MaxSize` checks.
- 5 `delete-row-created-table-doc` cases exist.
- All 5 retained `delete-row-created-table-doc` cases passed independent consensus. They cover unique-value reuse after deleting the matching row, preserving unique conflict when a different row is deleted, multi-row deletion, empty `DeleteRow` success result shape, and omitted `Rows` as an impossible-success condition.
- This DeleteRow lifecycle slice triggered solver repairs: created row values are now indexed by returned row UID, and successful `DeleteRow` removes deleted row values from unique-conflict state. A draft exact-status case for omitted `Rows` was removed because the source evidence did not prove the exact status code.
- 13 `locking-reset-state-machine-doc` cases exist.
- All 13 `locking-reset-state-machine-doc` cases passed independent consensus after an evidence refresh. They cover long `Set -> reset -> StartSession -> Get` trajectories for HardwareReset matching `{0,1}`, HardwareReset not matching `{0,3}`, enabled TPER_RESET/Programmatic matching `{0,3}`, empty LockOnReset preserving both locked and unlocked prior states, disabled read/write lock features being disregarded for host write, and PowerCycle aborting an open Locking SP session before a later method.
- The first review packet was superseded because reviewers wanted explicit source support for TPER_RESET/Programmatic mapping and PowerCycle session abort. The final evidence set added `opal/3.2.3`, `opal/4.2.3.1`, and `core/3.3.7.1.5`, then all reviewers accepted with no concerns.
- No production solver repair was required; existing reset-state logic already matched the official state machine. This is still high-value hidden-score coverage because it asserts post-reset observable cells and aborted-session behavior in longer trajectories.
- 8 `system-table-row-mutation-long-doc` cases exist.
- All 8 `system-table-row-mutation-long-doc` cases passed independent consensus. They cover direct `CreateRow` and `DeleteRow` success responses on MethodID and AccessControl system tables in both Admin SP and Locking SP sessions.
- No solver repair was needed; existing CreateRow/DeleteRow target-kind checks already reject direct row lifecycle mutation on protected system tables. The batch is retained as a compact regression for a common table-method shortcut bug.
- 52 `cpin-genkey-reset-reissue-long-doc` cases exist.
- All 52 `cpin-genkey-reset-reissue-long-doc` cases passed independent consensus. They cover successful C_PIN `GenKey` across reset boundaries, failed `GenKey` non-mutation, default PinLength, PublicExponent/oversized PinLength failures, PowerCycle versus HardwareReset effects on nonpersistent `Tries`, old-PIN invalidation, `Authority.Uses` preservation, and deliberate old-PIN reissue through later C_PIN `Set`.
- No solver repair was needed; existing C_PIN GenKey state, invalidated old-PIN tracking, reset persistence handling, TryLimit/Tries accounting, PIN Set reissue, and Authority Uses tracking already matched the official semantics. This batch is retained as a long-trajectory hidden-score candidate for C_PIN/Auth/GenKey composition.
- 8 `datastore-offset-payload-doc` cases exist.
- All 8 `datastore-offset-payload-doc` cases passed independent consensus. They cover byte-table subrange reads, nonzero-offset writes, and partial overwrite behavior for the DataStore byte table.
- This DataStore offset slice triggered solver repairs: DataStore payload state now records per-byte offsets from `Set Where.Row`, later `Get startRow/endRow` derives the expected payload for the requested interval, and whole-table latest-payload tracking remains as a fallback for older broad cases.
- 33 `datastore-read-window-authority-churn-long-doc` cases exist.
- All 33 `datastore-read-window-authority-churn-long-doc` cases passed independent consensus. They cover repeated DataStore Get ACE replacement between User1/Admins/Admins OR User1, independent Set ACE state, explicit row-window reads, omitted-endRow raw `Get` semantics, failed unauthorized Admin `Set` non-mutation, and later User1 tail/prefix writes after authority churn.
- No new solver repair was needed; existing DataStore byte-state, ACE BooleanExpr, Set/Get independence, and omitted-endRow min-length logic handled the batch. This is now a trusted long-trajectory regression for the hidden-score candidate area around DataStore offset/authorization composition.
- 9 `acl-revertsp-meta-doc` cases exist.
- All 9 `acl-revertsp-meta-doc` cases passed independent consensus. They cover the Locking SP `ThisSP/RevertSP` AccessControl row, where unauthenticated `GetACL` fails because `GetACLACL=ACE_Admin`, Admin `GetACL` can return an ACE uidref list, and `AddACE`/`RemoveACE`/`DeleteMethod` fail because their row-specific meta-ACL columns are empty.
- This AccessControl slice triggered a solver repair: `_known_meta_acl_authorization` now knows the Locking SP `ThisSP/RevertSP` row-specific meta-ACL values, so all GetACL/AddACE/RemoveACE/DeleteMethod paths share the same document-based authorization source instead of relying on a broad Admin-default heuristic.
- 5 `cpin-user-ace-booleanexpr-doc` cases exist.
- All 5 retained `cpin-user-ace-booleanexpr-doc` cases passed independent consensus. They cover supported `ACE_C_PIN_User1_Set_PIN` BooleanExpr personalization to `Admins` and `Admins OR User1`, plus the downstream User1 `C_PIN_User1.PIN` Set authorization result.
- Review correction: the first packet included two `User1`-only BooleanExpr cases. They were archived under `analysis/label_reviews/superseded/2026-05-24-cpin-user-ace-user1-only-ambiguity/` after reviewers flagged that Opal guarantees support for `Admins` and `Admins OR UserMMMM` but does not prove every other implementation-specific value is forbidden. No production solver repair was made from those draft cases.
- 9 `session-manager-control-target-doc` cases exist.
- All 9 retained `session-manager-control-target-doc` cases passed independent consensus. They cover `Properties` on SMUID success, non-SMUID `Properties`/`StartSession` impossible success, and unsupported control-session MethodIDs (`Get`, `Set`, `Authenticate`, `Random`) on SMUID.
- This slice triggered a solver repair: explicit SMUID targets now reject MethodIDs outside the supported Session Manager control-method list before generic SP-method logic is applied. Reviewers also flagged four draft cases whose trace abstraction lacked enough Packet.Session evidence; those packets were pruned before acceptance, leaving only no-concern trusted cases.
- 3 `adminexch-disabled-doc` cases exist.
- All 3 retained `adminexch-disabled-doc` cases passed independent consensus. They cover impossible-success `StartSession` with issued-disabled `AdminExch` as `HostExchangeAuthority`, impossible `Authenticate(AdminExch)` `SUCCESS True`, and impossible explicit `Authenticate(AdminExch)` `NOT_AUTHORIZED`.
- This slice triggered a solver repair: Admin SP `AdminExch` is now modeled as disabled at issuance, and `StartSession` applies `Authority.Enabled` gating to the Host Control Authority chosen from `HostSigningAuthority` or `HostExchangeAuthority`. Two draft PASS packets were pruned because reviewers flagged SyncSession-payload and non-Password proof/challenge representation concerns.
- 15 `syncsession-trans-credit-doc` cases exist.
- All 15 `syncsession-trans-credit-doc` cases passed independent consensus. They cover optional `TransTimeout` lower/upper bounds derived from StartSession requests and Properties Min/MaxTransTimeout, MaxTransTimeout=0 no-upper-limit behavior, optional omission, and nonnegative `InitialCredit`.
- 20 `datastore-byte-table-method-universe-doc` cases exist.
- All 20 `datastore-byte-table-method-universe-doc` cases passed independent consensus. They cover direct DataStore `CreateRow`/`DeleteRow` impossible success and nonexistent `GetACL`/`AddACE`/`RemoveACE`/`DeleteMethod` associations for DataStore row-management methods.
- 20 `mbr-byte-table-method-universe-doc` cases exist.
- All 20 `mbr-byte-table-method-universe-doc` cases passed independent consensus. They mirror the DataStore method-universe assertions for MBR.
- 8 `mbr-byte-payload-doc` cases exist.
- All 8 `mbr-byte-payload-doc` cases passed independent consensus. They cover direct MBR byte-table Set/Get payload tracking for row-zero writes, nonzero offset overwrites, explicit subrange Gets, and omitted-Where prefix writes.
- This MBR payload slice triggered solver repairs: `State.mbr_table_bytes` records offset-addressed bytes, `_apply_set_success` updates MBR bytes with byte-table `Where.Row` semantics, and `_expected_get` validates direct MBR `Get` returned Bytes when an explicit window is known.
- 9 `mbr-shadow-byte-payload-doc` cases exist.
- All 9 `mbr-shadow-byte-payload-doc` cases passed independent consensus. They cover active MBR shadow host reads after nonzero MBR byte-table overwrites, omitted-Where prefix rewrites, `Done=True` disabling shadowing, and `DoneOnReset` reactivating shadowing after PowerCycle.
- This slice triggered a second MBR byte-state repair: `_apply_set_success` now recomputes the contiguous MBR/DataStore byte-table prefix after every successful offset write, so host MBR shadow reads no longer use a stale row-zero pattern after later partial overwrites.
- 10 `getacl-rangennnn-alias-impossible-doc` cases exist.
- All 10 `getacl-rangennnn-alias-impossible-doc` cases passed independent consensus after a source-snippet refresh. They cover successful `GetACL` responses that incorrectly alias `Locking_RangeNNNN` to Range1 ACEs, use K_AES GenKey ACEs for Get associations, or swap `K_AES_128`/`K_AES_256` RangeNNNN GenKey ACEs.
- This AccessControl slice triggered solver repairs: generic RangeNNNN ACE aliases are normalized, exact `GetACL` expectations now synthesize Opal RangeNNNN ACL formulas, and host-created dynamic Locking ranges are tracked separately through `State.created_locking_ranges` so they are not mistaken for preconfigured RangeNNNN rows.
- Review correction: the first packet did not expose all K_AES AccessControl rows in the blind snippets. `tools/label_consensus.py::source_snippets` now includes multiple relevant excerpts from long source sections; the refreshed packet was accepted by all three reviewers with no concerns.
- 8 `ace-rangennnn-cells-impossible-doc` cases exist.
- All 8 `ace-rangennnn-cells-impossible-doc` cases passed independent consensus. They cover impossible successful `ACE.Get` payloads for optional RangeNNNN ACE rows: wrong `BooleanExpr`, omitted `ActiveKey`, read/write lock column swaps, and K_AES GenKey ACEs reporting `Mode` or `Key` instead of `All`.
- No new solver repair was needed; the preceding RangeNNNN normalization and `_known_ace_row` repair already generalized from `GetACL` exact ACLs to ACE row cell validation.
- Deeper cyclic row/Serial/Prev/Next side effects remain unmodeled because the current state does not track durable Log rows.

Repair paths:

- `src/solver_components/parsing.py::parse_event`
- `src/solver_components/expectations.py::expected_status`
- `src/solver_components/expectations.py::_expected_add_log`
- `src/solver_components/expectations.py::_expected_log_maintenance`
- `src/solver_components/expectations.py::_expected_create_log`
- `src/solver_components/expectations.py::_expected_random`
- `src/solver_components/expectations.py::_expected_get_package`
- `src/solver_components/expectations.py::_expected_set_package`
- `src/solver_components/expectations.py::_expected_get_free_space`
- `src/solver_components/expectations.py::_expected_table_query`
- `src/solver_components/transitions.py::_apply_create_log_success`
- `src/solver_components/constants.py::SUPPORTED_METHODS_BY_SP`
- `src/solver_components/transitions.py::apply_transition`
- `src/solver_components/expectations.py::_expected_get`
- `src/solver_components/engine.py::_return_cell_matches`
- `src/solver_components/engine.py::_return_cell_at_least`
- `src/solver_components/engine.py::_return_cell_at_most`
- `src/solver_components/parsing.py::_column_from_name`
- `src/solver_components/parsing.py::_byte_table_set_mandatory_granularity_invalid`
- `src/solver_components/semantics.py::_range`
- `src/solver_components/transitions.py::_update_range_from_columns`
- `src/solver_components/transitions.py::_increment_authority_use`
- `src/solver_components/transitions.py::_apply_reset_event`
- `src/solver_components/expectations.py::_expected_host_io`
- `src/solver_components/parsing.py::_reset_types`
- `src/solver_components/parsing.py::_reset_event_type`
- `src/solver_components/parsing.py::_byte_table_get_range`
- `src/solver_components/parsing.py::_byte_table_set_start_offset`
- `src/solver_components/transitions.py::_apply_set_success`
- `src/solver_components/transitions.py::_contiguous_byte_pattern`
- `src/solver_components/models.py::State.mbr_table_bytes`

## Subagent Task Template

Give each generator one item:

```text
Read only the listed official docs and tools/run_sourced_edges.py.
Handle exactly this backlog item: <item id>.
Return 2-4 minimal PASS/FAIL sourced cases.
For each case include:
- source docs
- rule summary
- trajectory context idea using existing helper names
- expected final response
- concepts
- repair_paths
- any ambiguity that should force quarantine instead of acceptance
Do not edit files.
```

Give each reviewer one blind packet:

```text
Use only evidence and trajectory.
Do not use solver behavior, author labels, or case names.
Return PASS/FAIL, confidence, rationale, concerns, source_refs.
If evidence cannot prove the exact byte/result, write concerns.
```

## Completed 2026-05-26 22:55 KST

- `locking-created-row-long-reset-doc`
  - Added 10 sourced cases for created Locking RangeNNNN rows across long reset trajectories.
  - Concepts: `locking-range`, `create-row`, `rangennnn`, `range-geometry`, `lock-on-reset`, `reset`, `state-observation`, `long-trajectory`.
  - Official docs used: `core/3.3.7.1.5.txt`, `core/5.3.3.4.2.1.txt`, `core/5.3.4.2.3.txt`, `core/5.7.2.2.4.txt` through `core/5.7.2.2.10.txt`, `core/5.7.3.1.1.txt`, `core/5.7.3.1.2.txt`, `core/5.7.3.3.txt`, `opal/3.2.3.txt`, `opal/3.3.5.2.txt`, `opal/4.3.5.2.txt`, `opal/4.3.5.2.2.txt`.
  - Consensus: `locking_created_long_{a,b,c}.jsonl`, 30 review rows, all matched author labels, no concerns.
  - Solver outcome: 10 / 0 mismatches for the tag, 2910 / 0 full sourced, 2828 / 0 consensus gate.
- `locking-created-row-failed-set-reset-doc`
  - Added 10 sourced cases for created Locking RangeNNNN failed Set nonmutation followed by reset/Get observations.
  - Concepts: `locking-range`, `create-row`, `failed-set-nonmutation`, `range-geometry`, `lock-on-reset`, `reset`, `state-observation`, `long-trajectory`.
  - Official docs used: `core/3.3.7.1.5.txt`, `core/5.1.5.11.txt`, `core/5.3.4.2.2.txt`, `core/5.3.4.2.6.txt`, `core/5.7.2.2.4.txt` through `core/5.7.2.2.10.txt`, `core/5.7.3.1.1.txt`, `core/5.7.3.1.2.txt`, `core/5.7.3.3.txt`, `core/5.7.3.4.txt`, `core/5.7.3.5.txt`, `opal/3.2.3.txt`, `opal/3.3.5.2.txt`, `opal/4.3.5.2.txt`, `opal/4.3.5.2.2.txt`.
  - Consensus: `locking_failed_reset_{a,b,c}.jsonl`, 30 review rows, all matched author labels, no concerns.
  - Solver outcome: 10 / 0 mismatches for the tag, 2920 / 0 full sourced, 2838 / 0 consensus gate.
- `accesscontrol-logto-default-doc`
  - Added 10 sourced diagnostic cases for direct `AccessControl.Get` of `LogTo` on issued Locking SP associations.
  - Concepts: `access-control`, `direct-get`, `log-template`, `logto`, `issued-row`, `preconfiguration`.
  - Official docs used: `core/5.3.2.7.txt`, `core/5.3.2.7.15.txt`, `core/5.8.4.1.txt`, `core/5.8.4.5.txt`, `opal/4.3.1.6.txt`.
  - Initial solver outcome: 5 mismatches, all impossible non-empty `LogTo` values accepted.
  - Repair outcome: `LogTo` column parsing and direct AccessControl default-cell expectations added; tag now runs 10 / 0, full sourced 2930 / 0, consensus gate 2838 / 0.
  - Consensus: `accesscontrol_logto_{a,b,c}.jsonl`, 30 review rows, labels matched but concerns remained about direct proof for the concrete AccessControl row UID encodings. All 10 cases are quarantined, not accepted.
- `mbr-shadow-reset-long-doc`
  - Added 10 sourced cases for MBR shadowing across `MBRDoneOnReset`, ProtocolStackReset, enabled TPerReset/Programmatic reset, and failed Programmatic-only DoneOnReset Set.
  - Concepts: `mbr`, `mbr-shadowing`, `byte-table`, `done-on-reset`, `reset-types`, `tper-reset`, `protocol-stack-reset`, `failed-set-nonmutation`, `long-trajectory`.
  - Official docs used: `core/5.1.4.2.3.txt`, `core/5.1.5.11.txt`, `core/5.3.3.7.2.1.txt`, `core/5.3.4.2.6.txt`, `core/5.7.2.5.2.txt`, `core/5.7.2.5.3.txt`, `core/5.7.2.5.4.txt`, `core/5.7.3.6.txt`, `opal/3.2.3.txt`, `opal/3.3.5.2.txt`, `opal/4.2.3.1.txt`, `opal/4.3.5.3.1.txt`, `opal/4.3.5.4.txt`, `opal/4.3.1.6.txt`.
  - Consensus: first review found 2 trajectory-formulation concerns; after splitting successful Enable/Done Set from failed DoneOnReset-only Set, `mbr_shadow_reset_{a,b,c}.jsonl` contains 30 refreshed review rows with no concerns.
  - Solver outcome: 10 / 0 mismatches for the tag, 2940 / 0 full sourced, 2848 / 0 consensus gate.
- `mbr-access-byte-state-doc`
  - Added 10 sourced cases for MBR byte-table `Get`/`Set` access-control split and failed Set nonmutation.
  - Concepts: `mbr`, `byte-table`, `access-control`, `anybody-get`, `admin-set`, `failed-set-nonmutation`, `payload-provenance`, `mbr-shadowing`.
  - Official docs used: `core/5.3.3.6.2.1.txt`, `core/5.3.3.7.1.2.txt`, `core/5.3.3.7.2.1.txt`, `core/5.3.4.2.2.txt`, `core/5.3.4.2.6.txt`, `core/5.7.2.5.2.txt`, `core/5.7.2.5.3.txt`, `core/5.7.3.6.txt`, `opal/4.3.5.4.txt`, `opal/4.3.1.6.txt`.
  - Consensus: initial reviewer concerns over compact raw `Get` arguments and host-read pattern shorthand were resolved by changing final byte observations to explicit `Cellblock` direct MBR `Get`. `mbr_access_byte_state_{a,b,c}.jsonl` now has 30 review rows with no concerns.
  - Solver outcome: 10 / 0 mismatches for the tag, 2950 / 0 full sourced, 2858 / 0 consensus gate.
- `ace-kaes-set-crosscheck-long-doc`
  - Added 24 sourced cases for ACE/K_AES cross-checking.
  - Concepts: `ace`, `k-aes`, `accesscontrol`, `getacl`, `booleanexpr`, `columns`, `personalization`, `long-trajectory`.
  - Official docs used: `core/5.3.2.7.txt`, `core/5.3.2.7.5.txt`, `core/5.3.2.7.9.txt`, `core/5.3.2.9.txt`, `core/5.3.2.9.4.txt`, `core/5.3.3.6.txt`, `core/5.3.3.7.txt`, `core/5.3.3.13.txt`, `core/5.3.3.13.3.1.txt`, `core/5.3.4.3.2.txt`, `core/5.3.4.3.3.txt`, `opal/4.3.1.6.txt`, `opal/4.3.1.7.txt`.
  - Accepted coverage:
    - ACE_ACE_Set_BooleanExpression `Get` must report `Admins` and `BooleanExpr`.
    - K_AES 128/256 GlobalRange and Range1 GenKey ACE rows must report `Admins` and `All`, not `Anybody`, `Mode`, or `Key`.
    - Successful ACE.Set personalization updates later ACE.Get `BooleanExpr`.
    - ACE object `Set` ACLs are distinct from K_AES key-object `GenKey` ACLs.
  - Consensus: `ace_kaes_set_crosscheck_{a,b,c}.jsonl` contains 72 review rows. 16 cases entered trusted consensus; 8 were quarantined.
  - Quarantine follow-up:
    - Rework symbolic `User1` return-value cases to use numeric authority references, or add stronger alias evidence.
    - Rework exact ACE-object Set / K_AES GenKey cases with evidence snippets that visibly include the exact `opal/4.3.1.6` AccessControl rows.
  - Solver outcome: 24 / 0 mismatches for the tag, 2974 / 0 full sourced, 2874 / 0 consensus gate.
- `ace-kaes-crosscheck-evidence-tight-doc`
  - Added 12 reworked sourced cases that directly answer the quarantine reasons from `ace-kaes-set-crosscheck-long-doc`.
  - Concepts: `ace`, `k-aes`, `accesscontrol`, `getacl`, `booleanexpr`, `columns`, `numeric-authority-ref`, `evidence-tightening`.
  - Official docs used: `core/5.3.2.7.txt`, `core/5.3.2.7.5.txt`, `core/5.3.2.7.9.txt`, `core/5.3.2.9.txt`, `core/5.3.2.9.4.txt`, `core/5.3.3.6.txt`, `core/5.3.3.7.txt`, `core/5.3.3.13.txt`, `core/5.3.3.13.3.1.txt`, `core/5.3.4.3.2.txt`, `core/5.3.4.3.3.txt`, `opal/4.3.1.6.txt`, `opal/4.3.1.7.txt`, `opal/4.3.1.8.txt`.
  - Accepted coverage:
    - ACE personalization uses numeric User1 authority UID `0000000900030001` in later `ACE.Get`.
    - `ACE_K_AES_128_GlobalRange_GenKey` and `ACE_K_AES_256_Range1_GenKey` keep `Columns=All` after BooleanExpr personalization.
    - K_AES key-object `GenKey` `GetACL` returns K_AES GenKey ACEs, while ACE-object `Set` `GetACL` returns `ACE_ACE_Set_BooleanExpression`.
  - Consensus: first re-review exposed review-protocol noise, then `ace_kaes_evidence_tight_{a,b,c}.jsonl` produced 36 no-concern reviews. All 12 cases entered trusted consensus.
  - Solver outcome: 12 / 0 mismatches for the tag, 2986 / 0 full sourced, 2886 / 0 consensus gate.
- `cpin-readonly-auth-tries-long-doc`
  - Added 16 sourced cases for explicit `Authenticate` inside successful `Write=False` Locking SP sessions.
  - Concepts: `auth`, `authenticate`, `read-only-session`, `c-pin`, `try-limit`, `tries-column`, `authority-uses`, `long-trajectory`.
  - Official docs used: `core/5.2.3.1.txt`, `core/5.2.3.1.3.txt`, `core/5.3.2.10.txt`, `core/5.3.2.12.txt`, `core/5.3.2.12.6.txt`, `core/5.3.2.12.7.txt`, `core/5.3.3.12.txt`, `core/5.3.3.12.1.txt`, `core/5.3.3.12.2.txt`, `core/5.3.3.12.3.1.txt`, `core/5.3.4.1.1.2.txt`, `core/5.3.4.1.14.txt`, `core/5.3.4.1.14.1.txt`, `opal/4.3.1.8.txt`, `opal/4.3.1.9.txt`.
  - Accepted coverage:
    - Failed read-only `Authenticate` increments C_PIN `Tries` but not Authority `Uses`.
    - `TryLimit=0` keeps `Tries=0` even after repeated failed read-only Authenticate attempts.
    - Successful read-only `Authenticate` clears prior `Tries` and increments `Uses` once.
    - A failed read-only attempt followed by a successful one leaves `Tries=0` and `Uses=1`.
    - TryLimit lockout in read-only session clamps `Tries` and prevents a later true Authenticate result.
  - Consensus: `cpin_readonly_{a,b,c}.jsonl` contains 48 no-concern reviews. All 16 cases entered trusted consensus.
  - Solver outcome: 16 / 0 mismatches for the tag, 3002 / 0 full sourced, 2902 / 0 consensus gate.
- `readonly-explicit-nonpersistence-long-doc`
  - Added 8 sourced cases for explicit host `Set` attempts inside successful `Write=False` sessions.
  - Concepts: `read-only-session`, `nonpersistence`, `set`, `datastore`, `locking`, `ace`, `c-pin`, `authority`, `long-trajectory`.
  - Official docs used: `core/2.3.1.txt`, `core/3.3.7.1.txt`, `core/5.2.3.1.txt`, `core/5.2.3.1.3.txt`, `core/5.3.2.9.txt`, `core/5.3.2.9.4.txt`, `core/5.3.2.10.txt`, `core/5.3.2.12.txt`, `core/5.3.3.7.txt`, `core/5.3.3.7.2.1.txt`, `core/5.3.4.1.1.2.txt`, `core/5.3.4.2.6.txt`, `core/5.3.4.3.3.txt`, `core/5.7.2.2.txt`, `core/5.7.2.2.4.txt` through `core/5.7.2.2.10.txt`, `opal/4.3.1.6.txt`, `opal/4.3.1.7.txt`, `opal/4.3.1.8.txt`, `opal/4.3.1.9.txt`, `opal/4.3.5.2.txt`, `opal/4.3.8.1.txt`.
  - Initial solver outcome: 8 mismatches; successful context `Set` transitions were mutating persistent state even in read-only sessions.
  - Repair outcome: `src/solver_components/transitions.py` now blocks persistent application of explicit host mutation methods while `state.session.write` is false, without blocking C_PIN authentication-counter side effects.
  - Consensus: `readonly_nonpersist_{a,b,c}.jsonl` added 24 review rows. 6 cases entered trusted consensus; 2 were quarantined for indirectness/readability and retained for audit.
- `readonly-explicit-nonpersistence-tight-doc`
  - Added 4 reworked direct-observation cases for the two quarantined read-only nonpersistence concepts.
  - Concepts: `read-only-session`, `nonpersistence`, `direct-get`, `ace`, `authority`, `state-observation`.
  - Accepted coverage:
    - A read-only `ACE_DataStore_Get_All.Set(BooleanExpr=User1)` does not persist; later ACE.Get must still report default `Admins`.
    - A read-only `Authority_User1.Set(Uses=0)` does not persist; later Authority.Get must still report the prior `Uses` value.
  - Additional repair outcome: `src/solver_components/parsing.py` now canonicalizes `ACE_DataStore_Get_All` / `ACE_DataStore_Set_All` aliases to `ACE_0003FC00` / `ACE_0003FC01`, so name-form and UID-form ACE rows share expected-cell and state-transition logic.
  - Consensus: `readonly_nonpersist_tight_{a,b,c}.jsonl` contains 12 no-concern reviews. All 4 reworked cases entered trusted consensus.
  - Solver outcome: long tag 8 / 0, tight tag 4 / 0, full sourced 3014 / 0, consensus gate 2912 / 0.
- `getacl-optional-range-existence-doc`
  - Added 4 sourced diagnostic cases plus paired solver regression tests; consensus accepted all 4.
  - Concepts: `accesscontrol`, `getacl`, `optional-row`, `locking-range`, `k-aes`, `association-existence`, `range-observation`.
  - Official docs used: `core/5.3.2.7.txt`, `core/5.3.2.7.5.txt`, `core/5.3.3.13.txt`, `core/5.3.3.13.3.1.txt`, `core/5.7.2.1.txt`, `core/5.7.2.1.5.txt`, `opal/4.3.1.6.txt`, `opal/4.3.1.7.txt`, `opal/4.3.5.1.txt`, `opal/4.3.5.2.txt`, `opal/4.3.5.5.txt`.
  - Trigger: private score reportedly dropped after AccessControl/GetACL generalization; the likely public-doc overreach was assuming every `RangeNNNN` name denotes an existing optional row.
  - Repair outcome:
    - `LockingInfo.MaxRanges=8` followed by `Locking_Range9.Get` exact ACL success is now rejected.
    - `LockingInfo.MaxRanges=8` followed by `K_AES_256_Range9_Key.GenKey` exact ACL success is now rejected.
    - `Locking_Range8.Get` and `K_AES_256_Range8_Key.GenKey` exact ACLs remain accepted under observed/default Opal minimum support.
  - Consensus: `getacl_optional_range_{a,b,c}.jsonl` contains 12 no-concern reviews. All 4 cases entered trusted consensus.
  - Solver outcome: tag 4 / 0, focused tests 6 / 0, unit suite 884 passed, full sourced 3018 / 0, consensus gate 2916 / 0, synthetic 205 / 0, local eval 100.00.
- `lockinginfo-maxranges-consistency-doc`
  - Added 4 sourced diagnostic cases plus paired solver regression tests; consensus accepted all 4.
  - Concepts: `lockinginfo`, `maxranges`, `locking-range`, `k-aes`, `state-observation`, `range-support`, `consistency`.
  - Official docs used: `core/5.7.2.1.txt`, `core/5.7.2.1.5.txt`, `core/5.7.3.3.txt`, `opal/4.3.5.1.txt`, `opal/4.3.5.2.txt`, `opal/4.3.5.5.txt`.
  - Trigger: after fixing `MaxRanges=8` -> future Range9 GetACL rejection, the inverse consistency direction was still worth pinning down.
  - Accepted coverage:
    - Successful `Locking_Range9.Get` followed by successful `LockingInfo.Get(MaxRanges=8)` is rejected.
    - Successful `K_AES_256_Range9_Key.GenKey` followed by successful `LockingInfo.Get(MaxRanges=8)` is rejected.
    - The same observations for Range8 remain accepted with `MaxRanges=8`.
  - Repair outcome:
    - `src/solver_components/semantics.py::_max_observed_non_global_range_id` tracks the highest known non-global range from created/observed state.
    - `src/solver_components/expectations.py::_expected_get` rejects successful `LockingInfo` responses whose `MaxRanges` is lower than that observed range id.
  - Consensus: `lockinginfo_maxranges_{a,b,c}.jsonl` contains 12 no-concern reviews. All 4 cases entered trusted consensus.
  - Solver outcome: tag 4 / 0, unit suite 887 passed, full sourced 3022 / 0, consensus gate 2920 / 0, synthetic 205 / 0, local eval 100.00.
- `optional-range-direct-presence-doc`
  - Added 7 sourced diagnostic cases plus paired solver regression tests; consensus accepted all 7.
  - Concepts: `lockinginfo`, `maxranges`, `optional-row`, `locking-range`, `k-aes`, `create-row`, `direct-method`, `presence`.
  - Official docs used: `core/5.7.2.1.txt`, `core/5.7.2.1.5.txt`, `core/5.7.3.3.txt`, `opal/4.3.5.1.txt`, `opal/4.3.5.2.txt`, `opal/4.3.5.5.txt`.
  - Trigger: the range-support logic needed to apply to direct methods, not just GetACL and later LockingInfo checks.
  - Accepted coverage:
    - `MaxRanges=8` rejects later direct `Locking_Range9.Get` success.
    - `MaxRanges=8` rejects later direct `Locking_Range9.Set` success.
    - `MaxRanges=8` rejects later direct `K_AES_256_Range9_Key.GenKey` success.
    - `MaxRanges=8` rejects a successful Locking `CreateRow` returning UID `0000080200030009`.
    - Before support is observed, absent optional Range9 `Get`, `Set`, and `GenKey` failures are protocol-compliant.
  - Repair outcome:
    - `src/solver_components/semantics.py::_range_id_support_state` models known present / known absent / unobserved optional support.
    - `src/solver_components/semantics.py::_returned_locking_range_id` extracts returned range ids for `CreateRow` validation.
    - `src/solver_components/expectations.py` applies the support state across direct Locking and K_AES methods.
  - Consensus: `optional_range_direct_{a,b,c}.jsonl` contains 21 no-concern reviews. All 7 cases entered trusted consensus.
  - Solver outcome: tag 7 / 0, unit suite 894 passed, full sourced 3029 / 0, consensus gate 2927 / 0, synthetic 205 / 0, local eval 100.00.
- `optional-range-delete-presence-doc`
  - Added 4 sourced diagnostic cases plus paired solver regression tests; consensus accepted all 4.
  - Concepts: `lockinginfo`, `maxranges`, `optional-row`, `locking-range`, `delete-row`, `delete`, `presence`.
  - Official docs used: `core/5.7.2.1.txt`, `core/5.7.2.1.5.txt`, `core/5.7.3.3.txt`, `opal/4.3.5.1.txt`, `opal/4.3.5.2.txt`.
  - Trigger: deletion methods still needed the same optional-row support model as direct Get/Set/GenKey/CreateRow.
  - Accepted coverage:
    - `MaxRanges=8` rejects later `DeleteRow` success for `Locking_Range9`.
    - `MaxRanges=8` rejects later direct `Delete` success for `Locking_Range9`.
    - Before support is observed, absent optional Range9 `DeleteRow` and direct `Delete` failures are protocol-compliant.
  - Repair outcome:
    - `src/solver_components/expectations.py::_expected_delete_row` and `_expected_delete` now use `_range_id_support_state`.
    - Known absent optional rows forbid deletion success; unobserved optional rows allow absent-row failure.
  - Consensus: `optional_range_delete_{a,b,c}.jsonl` contains 12 no-concern reviews. All 4 cases entered trusted consensus.
  - Solver outcome: tag 4 / 0, unit suite 898 passed, full sourced 3033 / 0, consensus gate 2931 / 0, synthetic 205 / 0, local eval 100.00.
- `optional-range-supported-presence-doc`
  - Added 7 sourced positive-control cases plus paired solver regression tests; consensus accepted all 7.
  - Concepts: `lockinginfo`, `maxranges`, `optional-row`, `locking-range`, `k-aes`, `getacl`, `positive-control`, `presence`.
  - Official docs used: `core/5.3.2.7.txt`, `core/5.3.2.7.5.txt`, `core/5.7.2.1.txt`, `core/5.7.2.1.5.txt`, `core/5.7.3.3.txt`, `opal/4.3.1.6.txt`, `opal/4.3.1.7.txt`, `opal/4.3.5.1.txt`, `opal/4.3.5.2.txt`, `opal/4.3.5.5.txt`.
  - Trigger: after Range9 rejection/absence cases, the corpus needed PASS-side controls for supported Range9.
  - Accepted coverage:
    - `MaxRanges=9` permits direct `Locking_Range9.Get`, `Locking_Range9.Set`, and `K_AES_256_Range9_Key.GenKey` success.
    - `MaxRanges=9` permits exact `GetACL` success for `Locking_Range9.Get` and `K_AES_256_Range9_Key.GenKey`.
    - Prior successful `Locking_Range9.Get` or `K_AES_256_Range9_Key.GenKey` remains consistent with later `LockingInfo.Get(MaxRanges=9)`.
  - Repair outcome: no production repair needed; the existing three-state support model passed the positive controls.
  - Consensus: `optional_range_supported_{a,b,c}.jsonl` contains 21 no-concern reviews. All 7 cases entered trusted consensus.
  - Solver outcome: tag 7 / 0, unit suite 903 passed, full sourced 3040 / 0, consensus gate 2938 / 0, synthetic 205 / 0, local eval 100.00.
- `datastore-empty-booleanexpr-doc`
  - Added 10 sourced diagnostic cases plus paired solver regression tests; consensus accepted all 10.
  - Concepts: `datastore`, `byte-table`, `ace`, `booleanexpr`, `empty-expression`, `authorization`, `failed-set`, `nonmutation`.
  - Official docs used: `core/5.3.4.3.3.txt`, `core/5.3.4.2.2.txt`, `core/5.3.4.2.6.txt`, `opal/4.3.8.1.txt`, `opal/4.3.1.6.txt`, `opal/4.3.1.7.txt`, `opal/5.1.1.2.txt`.
  - Accepted coverage:
    - If `ACE_DataStore_Get_All.BooleanExpr=[]` is successfully set, Admin/User DataStore byte-table Gets return `SUCCESS` with an empty result.
    - If `ACE_DataStore_Set_All.BooleanExpr=[]` is successfully set, Admin DataStore Set is `NOT_AUTHORIZED`.
    - A failed DataStore Set under the empty Set ACE does not mutate previously written bytes.
    - Empty Set ACE state does not remove the separate Get ACE authority.
  - Repair outcome: no production repair needed; existing ACE expression evaluation already made empty authorities unsatisfied and DataStore Get/Set already separated byte-table read/write behavior.
  - Consensus: `datastore_empty_bool_{a,b,c}.jsonl` contains 30 no-concern reviews. All 10 cases entered trusted consensus.
  - Solver outcome: tag 10 / 0, unit suite 910 passed, full sourced 3056 / 0, consensus gate 2952 / 0, synthetic 205 / 0, local eval 100.00.
- `getacl-optional-range-unobserved-doc`
  - Added 6 sourced diagnostic cases plus paired solver regression tests; 4 accepted and 2 quarantined for exact failure-status concerns.
  - Concepts: `access-control`, `getacl`, `acl-column`, `optional-row`, `rangennnn`, `k-aes`, `association-existence`, `unknown-support`.
  - Official docs used: `core/5.3.2.7.txt`, `core/5.3.2.7.5.txt`, `core/5.3.3.13.txt`, `core/5.3.3.13.3.1.txt`, `core/5.7.2.1.txt`, `core/5.7.2.1.5.txt`, `core/5.7.3.3.txt`, `opal/4.3.1.6.txt`, `opal/4.3.1.7.txt`, `opal/4.3.5.1.txt`, `opal/4.3.5.2.txt`, `opal/4.3.5.5.txt`.
  - Accepted coverage:
    - Before `MaxRanges` is observed, exact `Locking_Range9.Get` GetACL success can be protocol-compliant if the optional association exists.
    - Before `MaxRanges` is observed, exact `K_AES_256_Range9_Key.GenKey` GetACL success can be protocol-compliant if the optional association exists.
    - Successful `Locking_Range9.Get` GetACL cannot alias the Range1 ACE list.
    - Successful Range9 GetACL observation conflicts with later `LockingInfo.Get(MaxRanges=8)`.
  - Quarantined coverage:
    - Two cases asserting specific absent-association failure status were quarantined. Reviewers agreed the optional association may be absent but noted the snippets do not pin one exact error code.
  - Repair outcome:
    - AccessControl range-backed object existence now preserves unknown optional support.
    - GetACL can accept optional Range9+ presence or absence before `MaxRanges` is known.
    - Successful Range9 GetACL records observed support for later `MaxRanges` consistency checks.
    - K_AES `GenKey` GetACL no longer rejects unobserved optional Range9+ solely because the support state is unknown.
  - Consensus: `getacl_optional_unknown_{a,b,c}.jsonl` contains 18 reviews. 4 cases accepted, 2 quarantined due concerns.
  - Solver outcome: tag 6 / 0, unit suite 910 passed, full sourced 3056 / 0, consensus gate 2952 / 0, synthetic 205 / 0, local eval 100.00.
- `ace-booleanexpr-capacity-doc`
  - Added 12 sourced cases; consensus accepted all 12.
  - Concepts: `ace`, `booleanexpr`, `or`, `ac-element-capacity`, `authority`, `datastore`, `user-mmmm`, `admin-mmmm`, `failed-set`, `nonmutation`.
  - Official docs used: `core/3.4.2.1.txt`, `core/5.1.5.2.txt`, `core/5.3.2.9.txt`, `core/5.3.2.9.4.txt`, `core/5.3.3.7.3.txt`, `core/5.3.3.7.4.txt`, `core/5.3.4.2.2.txt`, `core/5.3.4.2.6.txt`, `core/5.3.4.3.2.txt`, `core/5.3.4.3.3.txt`, `opal/4.3.1.4.txt`, `opal/4.3.1.6.txt`, `opal/4.3.1.8.txt`, `opal/4.3.1.9.txt`, `opal/4.3.8.1.txt`.
  - Accepted coverage:
    - A 23-entry OR expression over User1..User8 and Admin1..Admin4 can authorize User8 or Admin1.
    - An unauthenticated subject still cannot satisfy the OR expression, so DataStore Get returns an empty result and Set is `NOT_AUTHORIZED`.
    - Failed unauthorized Set does not mutate existing bytes.
  - Repair outcome: no production solver repair was needed; existing ACE evaluation handled the capacity pattern.
  - Consensus: `ace_capacity_{a,b,c}.jsonl` contains 36 no-concern reviews. All 12 cases entered trusted consensus.
  - Solver outcome: tag 12 / 0, full sourced 3138 / 0, consensus gate 3034 / 0, unit suite 917 passed, synthetic 205 / 0, local eval 100.00.
- `startsession-spid-object-uid-doc`
  - Added 12 sourced cases; consensus accepted all 12.
  - Concepts: `startsession`, `spid`, `sp-object`, `uid`, `admin-sp`, `locking-sp`, `object-vs-table`, `invalid-parameter`.
  - Official docs used: `core/5.2.3.1.txt`, `core/5.2.3.1.2.txt`, `opal/4.1.1.2.txt`, `opal/4.2.3.3.txt`, `opal/5.1.1.2.txt`.
  - Accepted coverage:
    - Admin SP object UID can be used as the `SPID`.
    - Activated Locking SP object UID can be used as the `SPID`.
    - SP table UID, SPInfo object UID, Authority object UID, and unissued SP-like UIDs cannot be accepted as successful `SPID`s.
  - Repair outcome: no production solver repair was needed; existing StartSession validation already matched the object-UID interpretation.
  - Consensus: `spid_object_{a,b,c}.jsonl` contains 36 no-concern reviews. All 12 cases entered trusted consensus.
  - Solver outcome: tag 12 / 0, full sourced 3138 / 0, consensus gate 3034 / 0, unit suite 917 passed, synthetic 205 / 0, local eval 100.00.
- `secretprotect-get-cells-tight-doc`
  - Added 4 FAIL-only sourced cases; consensus accepted all 4. Expanded with 4 additional sourced cases for `ProtectMechanisms` type validation.
  - Concepts: `secretprotect`, `k-aes`, `table-cell`, `column-number`, `protect-types`, `protected-column`, `optional-row`, `get`, `wrong-success`.
  - Official docs used: `core/5.3.2.8.txt`, `core/5.3.2.8.2.txt`, `core/5.3.2.8.3.txt`, `core/5.3.2.8.4.txt`, `core/5.1.3.64.txt`, `core/5.3.4.1.1.txt`, `core/5.7.2.3.txt`, `core/5.7.2.3.4.txt`, `core/5.7.2.3.5.txt`, `core/5.7.2.4.txt`, `core/5.7.2.4.4.txt`, `core/5.7.2.4.5.txt`, `opal/4.3.1.10.txt`, `opal/4.3.5.5.txt`.
  - Accepted coverage:
    - If SecretProtect row 0x1D succeeds, it cannot claim the protected table is K_AES_256 or the protected column is Mode column 0x04.
    - If SecretProtect row 0x1E succeeds, it cannot claim the protected table is C_PIN or the protected column is Mode column 0x04.
    - If a concrete SecretProtect row succeeds and returns `ProtectMechanisms`, the value must be a valid `protect_types` set/value, not boolean coercion or an out-of-range value.
    - The batch deliberately avoids a PASS case requiring both rows to exist, because Opal only requires at least one of the shown rows.
  - Repair outcome:
    - `src/solver_components/parsing.py` now parses SecretProtect column names.
    - `src/solver_components/expectations.py` now validates successful concrete SecretProtect Table / ColumnNumber returns for Opal K_AES rows 0x1D and 0x1E.
    - `src/solver_components/engine.py::_protect_types_value_valid` now validates successful `ProtectMechanisms` returns as `protect_types`.
  - Consensus: `secretprotect_tight_{a,b,c}.jsonl` contains 12 no-concern reviews. All 4 cases entered trusted consensus.
  - Solver outcome: tag 4 / 0, full sourced 3138 / 0, consensus gate 3034 / 0, unit suite 917 passed, synthetic 205 / 0, local eval 100.00.
- `authority-default-cells-doc`
  - Added 8 sourced cases; consensus accepted all 8.
  - Concepts: `authority`, `base-template`, `makers`, `isclass`, `class-ref`, `operation`, `issued-row`, `get`.
  - Official docs used: `core/5.3.2.10.txt`, `core/5.3.4.1.2.txt`, `core/5.3.4.1.2.2.txt`.
  - Accepted coverage:
    - `Authority_Makers.Get` must report `IsClass=True` and no parent class when those cells are returned.
    - `Authority_MakerSymK.Get` must report member class `Makers` and Operation `SymK`.
    - `Authority_MakerPuK.Get` must report member class `Makers` and Operation `Sign`.
  - Repair outcome:
    - Authority Get now validates Base Template static cells.
    - Authority class refs compare correctly by UID or symbolic name.
    - Authority operation cells compare against canonical operation names.
  - Consensus: `authority_default_{a,b,c}.jsonl` contains 24 no-concern reviews. All 8 cases entered trusted consensus.
  - Solver outcome: tag 8 / 0, full sourced 3158 / 0, consensus gate 3054 / 0, unit suite 921 passed, synthetic 205 / 0, local eval 100.00.
- `authority-default-cells-expanded-doc`
  - Added 12 sourced cases; consensus accepted all 12.
  - Concepts: `authority`, `base-template`, `preconfigured-row`, `uid-alias`, `isclass`, `class-ref`, `operation`, `get`.
  - Official docs used: `core/5.3.2.10.txt`, `core/5.3.4.1.2.txt`, `core/5.3.4.1.2.2.txt`.
  - Accepted coverage:
    - `Authority_Anybody.Get` must report individual `Sign`, not `Password`.
    - `Authority_Admins.Get` must report class authority, not individual authority.
    - `Authority_SID.Get` must report individual `Password`, not `Sign`.
    - `Authority_TPerSign.Get` must report Operation `TPerSign`, not host `Sign`.
    - `Authority_TPerExch.Get` must report Operation `TPerExchange`, not `Exchange`.
    - `Authority_AdminExch.Get` must report class `Admins` and Operation `Exchange`, not class `Makers`.
  - Repair outcome:
    - Parser now preserves explicit `Authority_*` row names before applying fixed object UID aliases.
    - TCGstorageAPI C_PIN UID aliasing remains active for name-less C_PIN lookup traces but no longer steals explicit Authority row Gets.
    - This batch caught two real pre-repair mismatches: `Authority_Anybody` was parsed as `C_PIN_SID`, and `Authority_TPerSign` could bypass Authority cell validation.
  - Consensus: `authority_default_expanded_{a,b,c}.jsonl` contains 36 no-concern reviews. All 12 cases entered trusted consensus.
  - Solver outcome: tag 12 / 0, full sourced 3158 / 0, consensus gate 3054 / 0, unit suite 921 passed, synthetic 205 / 0, local eval 100.00.
- `authority-class-membership-ace-doc`
  - Added 8 sourced cases; consensus accepted all 8.
  - Concepts: `authority`, `class-authority`, `makers`, `makerpuk`, `makersymk`, `ace`, `access-control`, `set`.
  - Official docs used: `core/3.4.2.2.txt`, `core/5.3.2.10.txt`, `core/5.3.4.1.2.txt`, `core/5.3.4.1.2.2.txt`, `core/5.3.4.3.2.txt`, `core/5.3.4.3.3.txt`, `opal/4.2.1.5.txt`, `opal/4.2.1.6.txt`, `opal/4.2.1.7.txt`.
  - Accepted coverage:
    - Admin SP `Authority_Makers.Set` follows the Admin SP `ACE_Set_Enabled` / `ACE_00030001` BooleanExpr, not the Locking SP `ACE_Authority_Set_Enabled` row.
    - After `ACE_Set_Enabled.BooleanExpr` is personalized to `Anybody`, an Anybody-only Admin SP session may Set `Authority_Makers.Enabled`.
    - After it is personalized to `Makers`, an Anybody-only session cannot satisfy the ACE.
    - `MakerPuK` and `MakerSymK` sessions satisfy a `Makers` class ACE because successful individual-member authentication authenticates the class too.
  - Repair outcome:
    - `_has_authority` now derives `Makers` from authenticated `MakerSymK`/`MakerPuK`.
    - `_ace_authorizes_set` now selects Admin SP `ACE_00030001` for Admin SP Authority Enabled Set and Locking SP `ACE_00039001` for Locking SP Authority Enabled Set.
    - Added regression tests for Admin SP `ACE_Set_Enabled` and `MakerPuK -> Makers` class membership.
  - Consensus: `authority_class_membership_{a,b,c}.jsonl` contains 24 reviews. All 8 cases entered trusted consensus.
  - Solver outcome: tag 8 / 0, full sourced 3166 / 0, consensus gate 3062 / 0, unit suite 923 passed, synthetic 205 / 0, local eval 100.00.
- `syncsession-signedhash-return-doc`
  - Added 6 sourced cases; consensus accepted all 6.
  - Concepts: `session-manager`, `sync-session`, `signedhash`, `response-sign`, `sp-signing-authority`, `return-shape`.
  - Official docs used: `core/5.2.3.2.txt`, `core/5.2.3.2.8.txt`, `core/5.3.2.10.txt`, `core/5.3.4.1.5.txt`, `core/5.3.4.1.7.txt`, `core/5.3.4.1.8.txt`, `opal/4.2.1.7.txt`.
  - Accepted coverage:
    - Fresh Admin SP `Anybody` startup may return ordinary `SyncSession` IDs, but not `SignedHash`.
    - Admin SP `SID` password startup likewise omits `SignedHash` because the preconfigured SID Authority has `ResponseSign=Null`.
    - An explicit prior `Authority_SID.Get` observation of `ResponseSign=Null` keeps the same return-shape constraint.
  - Repair outcome:
    - Authority `ResponseSign` is now tracked in state.
    - SyncSession return validation now treats `SignedHash` as forbidden when the startup control authority has known absent SP signing authority.
    - Regression tests cover unauthenticated Admin SP startup and SID password startup with impossible returned `SignedHash`.
  - Consensus: `syncsession_signedhash_{a,b,c}.jsonl` contains 18 reviews. All 6 cases entered trusted consensus.
  - Solver outcome: tag 6 / 0, full sourced 3172 / 0, consensus gate 3068 / 0, unit suite 925 passed, synthetic 205 / 0, local eval 100.00.
- `ecmqv-startup-return-shape-tight-doc`
  - Added 6 sourced cases; consensus accepted all 6.
  - Concepts: `session-manager`, `start-session`, `sync-session`, `host-exchange-authority`, `ecmqv`, `return-shape`.
  - Official docs used: `core/5.2.3.1.txt`, `core/5.2.3.2.txt`, `core/5.3.2.10.txt`, `core/5.3.4.1.2.5.txt`, `core/5.3.4.1.11.txt`.
  - Accepted coverage:
    - With an observed enabled AdminExch Exchange authority and EC credential, EC-MQV startup maps host public keys to `HostChallenge` / `HostExchangeCert`.
    - Successful EC-MQV `SyncSession` must return the SP ephemeral public key in `SPChallenge`.
    - Successful EC-MQV `SyncSession` must return the SP static public key in `SPExchangeCert`.
    - Omitting either field, or omitting both, is not compliant for this narrow EC-MQV trajectory.
  - Repair outcome:
    - Exchange-certificate startup is now recognized when `HostExchangeAuthority` is Exchange and both `HostChallenge` and `HostExchangeCert` are supplied.
    - `SPChallenge` is no longer forbidden for that narrow exchange flow.
    - Successful EC-MQV exchange startup requires both `SPChallenge` and `SPExchangeCert` in the returned `SyncSession`.
  - Superseded rework:
    - A broader `exchange-startup-return-shape-doc` attempt was moved to `analysis/label_reviews/superseded/2026-05-28-exchange-startup-concerns/` because reviewers recorded concerns about mixing generic `SPChallenge` wording with EC-MQV/EC-DH rules.
  - Consensus: `ecmqv_startup_tight_{a,b,c}.jsonl` contains 18 reviews. All 6 cases entered trusted consensus.
  - Solver outcome: tag 6 / 0, full sourced 3178 / 0, consensus gate 3074 / 0, unit suite 927 passed, synthetic 205 / 0, local eval 100.00.
- `mbr-shadow-dynamic-boundary-doc`
  - Reworked the batch after an ambiguous boundary-spanning status case was quarantined; stale reviews were archived under `analysis/label_reviews/superseded/2026-05-28-mbr-dynamic-boundary-ambiguous/`.
  - Added 4 sourced cases; consensus accepted all 4.
  - Concepts: `host-io`, `mbr-shadowing`, `lockinginfo`, `logical-block-size`, `mbr-table-rows`, `boundary`, `payload-provenance`.
  - Official docs used: `core/5.7.2.5.2.txt`, `core/5.7.2.5.3.txt`, `core/5.7.3.6.txt`, `opal/4.3.5.1.txt`, `opal/4.3.5.4.txt`.
  - Accepted coverage:
    - Observed `LogicalBlockSize=4096` plus default-sized MBR rows moves LBA 40000 outside the shadow region.
    - Observed MBR `Rows=0x10000000` plus 512-byte logical blocks expands the shadow region so LBA 300000 is served from MBR table data.
  - Repair outcome:
    - MBR shadow LBA count is derived from observed LockingInfo and Table rows instead of a fixed 512-byte-block boundary.
  - Consensus: `mbr_dynamic_boundary_{a,b,c}.jsonl` contains 12 no-concern reviews. All 4 cases entered trusted consensus.
- `mbrcontrol-column-ace-split-doc`
  - Added 8 sourced cases; consensus accepted all 8.
  - Concepts: `mbrcontrol`, `access-control`, `ace`, `column-specific-authorization`, `done-to-dor`, `user-personalization`.
  - Official docs used: `core/5.3.4.3.2.txt`, `core/5.3.4.3.3.txt`, `opal/4.3.1.6.txt`, `opal/4.3.1.7.txt`, `opal/4.3.5.3.txt`.
  - Accepted coverage:
    - `ACE_MBRControl_Set_DoneToDOR` personalized to `User1` permits `Done` and `DoneOnReset` Set.
    - The same ACE does not authorize `Enable`, nor a mixed `Enable+Done` Set.
  - Repair outcome:
    - MBRControl Set authorization now requires `ACE_MBRControl_Admins_Set` for column `Enable` even when DoneToDOR is satisfied for other columns.
  - Consensus: `mbrcontrol_column_ace_split_{a,b,c}.jsonl` contains 24 no-concern reviews. All 8 cases entered trusted consensus.
  - Solver outcome: full sourced 3206 / 0, consensus gate 3102 / 0, unit suite 931 passed, synthetic 205 / 0.
- `accesscontrol-meta-method-missing-association-status`
  - Reworked existing AccessControl universe cases so missing AccessControl-row status follows Core `NOT_AUTHORIZED` exactly.
  - Affected accepted tags:
    - `datastore-byte-table-method-universe-doc`: 20 accepted cases.
    - `mbr-byte-table-method-universe-doc`: 20 accepted cases.
    - `accesscontrol-sp-method-scope-doc`: 16 accepted cases.
    - `getacl-optional-range-unobserved-doc`: 6 accepted cases.
    - `acl-revertsp-meta-doc`: 8 accepted cases; three remaining RevertSP meta cases stay quarantined.
  - Concepts: `access-control`, `meta-acl`, `missing-association`, `getacl`, `addace`, `removeace`, `deletemethod`, `status-exactness`.
  - Official docs used: `core/5.1.5.2.txt`, `core/5.3.4.3.txt`, `core/5.3.4.3.1.txt`, plus existing DataStore/MBR/Locking Opal preconfiguration snippets.
  - Accepted coverage:
    - If no AccessControl row represents the parameterized InvokingID/MethodID pair, `GetACL` returns `NOT_AUTHORIZED`.
    - The same exact status applies to `AddACE`, `RemoveACE`, and `DeleteMethod`.
    - Optional Range9+ GetACL may still succeed before `MaxRanges` is known if the optional association exists, but the absent-association failure is `NOT_AUTHORIZED`.
  - Repair outcome:
    - `_expected_get_acl`, `_expected_acl_mutation`, and `_expected_delete_method` now forbid `INVALID_PARAMETER`/`FAIL` for known missing AccessControl associations and require `NOT_AUTHORIZED`.
    - Regression tests now cover missing-association exact status for `GetACL`, `AddACE`, `RemoveACE`, `DeleteMethod`, and optional Range9 absent GetACL.
  - Consensus: `getacl_missing_assoc_*` and `getacl_missing_assoc_meta_*` review files contain no-concern agreement for the repaired cases.
  - Solver outcome: full sourced 3206 / 0, consensus gate 3109 / 0, unit suite 938 passed, synthetic 205 / 0, local eval 100.00.
- `locking-powercycle-lockonreset-tight-doc`
  - Added 4 sourced cases; consensus accepted all 4.
  - Concepts: `locking-range`, `lock-on-reset`, `power-cycle`, `reset-types`, `state-machine`, `host-io`.
  - Official docs used: `core/5.7.2.2.6.txt`, `core/5.7.2.2.7.txt`, `core/5.7.2.2.8.txt`, `core/5.7.2.2.9.txt`, `core/5.7.2.2.10.txt`, `core/5.7.3.1.1.txt`, `core/5.7.3.1.2.txt`, `core/5.7.3.2.txt`, `opal/4.3.5.2.txt`, `opal/4.3.5.2.2.txt`.
  - Accepted coverage:
    - S3-like row with enabled read/write locks, unlocked cells, and `LockOnReset={0}` relocks after PowerCycle.
    - The fresh-session `Get` must report `ReadLocked=true`, `WriteLocked=true`, and preserved `LockOnReset={0}`.
    - Host read/write success inside the relocked range is impossible.
  - Review notes:
    - This reworks the earlier `locking-set-state-transition-doc` quarantine into a tighter source packet.
    - The old concern was packet clarity around reset_types value `0`, not a solver mismatch.
  - Consensus: `locking_powercycle_tight_{a,b,c}.jsonl` contains 12 no-concern reviews.
- `locking-hotplug-fresh-state-tight-doc`
  - Added 12 sourced cases; consensus accepted all 12.
  - Concepts: `reset`, `hotplug`, `lock-on-reset`, `state-observation`, `host-io`, `level0-discovery`, `programmatic-reset`.
  - Official docs used: `core/3.3.6.5.txt`, `core/3.3.6.5.2.txt`, `core/3.3.6.5.3.txt`, `core/5.7.2.2.6.txt`, `core/5.7.2.2.7.txt`, `core/5.7.2.2.8.txt`, `core/5.7.2.2.9.txt`, `core/5.7.2.2.10.txt`, `core/5.7.3.1.1.txt`, `core/5.7.3.1.2.txt`, `core/5.7.3.2.txt`, `opal/3.2.3.txt`, `opal/3.3.5.1.txt`, `opal/3.3.5.2.txt`, `opal/4.3.5.2.2.txt`.
  - Accepted coverage:
    - HotPlug is reset_types value `2`, so it preserves `{0}` and `{0,3}` rows rather than firing them.
    - Already locked power-only cells remain locked and keep Level 0 `Locked` asserted.
    - Unlocked `{0,3}` cells remain unlocked and keep Level 0 `Locked` clear after HotPlug.
    - A later enabled `TPER_RESET` relocks the preserved `{0,3}` Programmatic row.
  - Review notes:
    - The existing `locking-hotplug-reset-boundary-doc` stale-session exact-status case remains quarantined.
    - This tight packet avoids stale-session exact-status claims and relies on fresh-session `Get`, Level 0, and host-I/O impossible-success observations.
  - Consensus: `locking_hotplug_tight_{a,b,c}.jsonl` contains 36 no-concern reviews.
  - Solver outcome: full sourced 3222 / 0, consensus gate 3125 / 0, unit suite 938 passed, synthetic 205 / 0, local eval 100.00.
- `locking-multi-range-hotplug-programmatic-tight-doc`
  - Added 24 sourced cases; consensus accepted all 24.
  - Concepts: `locking-range`, `multi-range`, `lock-on-reset`, `hotplug`, `programmatic-reset`, `power-cycle`, `level0-discovery`, `long-trajectory`.
  - Official docs used: `core/3.3.6.5.txt`, `core/3.3.6.5.2.txt`, `core/3.3.6.5.3.txt`, `core/5.7.2.2.6.txt`, `core/5.7.2.2.7.txt`, `core/5.7.2.2.8.txt`, `core/5.7.2.2.9.txt`, `core/5.7.2.2.10.txt`, `core/5.7.3.1.1.txt`, `core/5.7.3.1.2.txt`, `core/5.7.3.2.txt`, `core/5.7.3.3.txt`, `core/5.7.3.4.txt`, `core/5.7.3.5.txt`, `opal/3.2.3.txt`, `opal/3.3.5.1.txt`, `opal/3.3.5.2.txt`, `opal/4.2.3.1.txt`, `opal/4.3.5.2.txt`, `opal/4.3.5.2.1.1.txt`, `opal/4.3.5.2.1.2.txt`, `opal/4.3.5.2.2.txt`.
  - Accepted coverage:
    - Three independent Locking rows are configured with `LockOnReset={0}`, `{0,3}`, and `[]`.
    - HotPlug preserves all three unlocked rows and keeps Level 0 `Locked` clear.
    - Enabled `TPER_RESET` later relocks only the `{0,3}` row and sets Level 0 `Locked`.
    - A later PowerCycle after manual row2 clear relocks both `{0}` and `{0,3}` rows while `[]` stays unlocked.
  - Review notes:
    - This reworks the useful part of the old `locking-multi-range-reset-clean-doc` quarantine without relying on exact host-I/O error/success status for the unlocked side.
  - Consensus: `locking_multi_hotplug_prog_{a,b,c}.jsonl` contains 72 no-concern reviews.
  - Solver outcome: full sourced 3246 / 0, consensus gate 3149 / 0, unit suite 938 passed, synthetic 205 / 0, local eval 100.00.
- `locking-lifecycle-startup-boundary-tight-doc`
  - Added 10 sourced cases; consensus accepted all 10.
  - Concepts: `lifecycle`, `locking-sp`, `disabled-sp`, `frozen-sp`, `startup-boundary`, `status-code`.
  - Official docs used: `core/4.5.2.txt`, `core/4.5.3.txt`, `core/4.5.4.txt`, `core/5.1.5.5.txt`, `core/5.1.5.6.txt`, `core/5.3.2.1.txt`, `core/5.3.2.1.7.txt`, `core/5.3.5.1.txt`, `core/5.4.2.4.txt`, `core/5.4.2.4.8.txt`, `core/5.7.4.1.txt`, `opal/4.2.3.3.txt`.
  - Accepted coverage:
    - Disabled but not frozen Locking SP still permits fresh `StartSession`.
    - Disabled+Frozen startup returns `SP_FROZEN`.
    - Clearing Frozen while still Disabled restores startup but does not unblock ordinary Locking methods.
    - `SPInfo.Enabled=true` re-enables the SP before later startup.
  - Review notes:
    - This reworks the remaining useful part of the old `locking-lifecycle-disabled-frozen-clean-doc` quarantine without relying on exact `GetFreeRows` result payload.
  - Consensus: `locking_lifecycle_startup_{a,b,c}.jsonl` contains 30 no-concern reviews.
  - Solver outcome: full sourced 3256 / 0, consensus gate 3159 / 0, unit suite 938 passed, synthetic 205 / 0, local eval 100.00.
- `getacl-locking-table-next-evidence-tight-doc`
  - Added 4 sourced cases; consensus accepted all 4.
  - Concepts: `access-control`, `getacl`, `acl-column`, `locking-sp`, `locking-table`, `table-next`, `exact-return-list`, `evidence-tightening`.
  - Official docs used: `core/5.3.2.7.txt`, `core/5.3.2.7.5.txt`, `core/5.3.2.7.9.txt`, `core/5.3.3.13.txt`, `core/5.3.3.13.3.1.txt`, `core/5.3.4.3.1.txt`, `opal/4.3.1.6.txt`, `opal/4.3.1.7.txt`.
  - Accepted coverage:
    - Numeric `0000080200000000/Next` GetACL returns exactly `ACE_Anybody`.
    - Symbolic `LockingTable/Next` GetACL returns exactly `ACE_Anybody`.
    - Empty ACL responses for either exact association are impossible.
  - Review notes:
    - This reworks the useful part of the quarantined `getacl-locking-table-next-exact-acl-doc` cases.
    - The new rule summary intentionally anchors the source snippet around `00 00 08 02 00 00 00 00`, `MethodID=Next`, and `ACL=ACE_Anybody`, removing the old source-truncation concern.
  - Consensus: `getacl_locking_next_tight_{a,b,c}.jsonl` contains 12 no-concern reviews.
  - Solver outcome: tag 4 / 0, consensus gate 4 / 0, full sourced 3266 / 0, full consensus gate 3169 / 0, unit suite 938 passed, synthetic 205 / 0, local eval 100.00.
- `locking-range-accesscontrol-cleanup-tight-doc`
  - Added 6 sourced cases; consensus accepted all 6.
  - Concepts: `locking-range`, `delete-row`, `delete`, `access-control`, `association-cleanup`, `object-lifecycle`, `evidence-tightening`.
  - Official docs used: `core/5.3.2.7.txt`, `core/5.3.3.6.3.txt`, `core/5.3.3.13.4.txt`, `core/5.3.4.2.3.txt`, `core/5.3.4.2.4.txt`, `core/5.7.3.3.txt`, `opal/4.3.5.2.txt`.
  - Accepted coverage:
    - After `DeleteRow` of a created Locking row, stale `GetACL(row/Get)` success is impossible.
    - After `DeleteRow`, direct `Get` on the deleted row object is impossible.
    - Direct object `Delete` has the same stale `GetACL` and direct `Get` consequences.
    - Deleted-row absence persists after ending and reopening a Locking SP session.
  - Review notes:
    - This reworks the reliable core of `locking-range-accesscontrol-cleanup-doc` while avoiding earlier sibling-preservation and host-I/O exact-status concerns.
    - The new evidence packet includes object creation, object deletion, AccessControl-row removal, direct `Get` missing-object failure, and `GetACL` missing-combination failure.
  - Consensus: `range_cleanup_tight_{a,b,c}.jsonl` contains 18 no-concern reviews.
  - Solver outcome: tag 6 / 0, consensus gate 6 / 0, full sourced 3266 / 0, full consensus gate 3169 / 0, unit suite 938 passed, synthetic 205 / 0, local eval 100.00.
- `created-row-delete-object-cleanup-tight-doc`
  - Added 6 sourced cases; consensus accepted all 6.
  - Concepts: `created-row`, `delete`, `access-control`, `association-cleanup`, `object-lifecycle`, `session-boundary`, `evidence-tightening`.
  - Official docs used: `core/5.3.2.7.txt`, `core/5.3.3.3.txt`, `core/5.3.3.3.1.1.txt`, `core/5.3.3.6.3.txt`, `core/5.3.3.13.4.txt`, `core/5.3.4.2.3.txt`, `core/5.3.4.2.4.txt`.
  - Accepted coverage:
    - After direct object `Delete` of a created row, stale `GetACL(row/Get)` success is impossible.
    - Direct `Get` on the deleted row object is impossible.
    - After deleting two created rows, stale `GetACL` success is impossible for both deleted objects.
    - Deleted-row absence persists after ending and reopening a session.
  - Review notes:
    - This reworks the reliable core of `created-row-delete-object-acl-doc`.
    - The new evidence packet avoids exact non-success status requirements and focuses on impossible-success outcomes for absent objects and absent AccessControl associations.
  - Consensus: `created_row_delete_tight_{a,b,c}.jsonl` contains 18 no-concern reviews.
  - Solver outcome: tag 6 / 0, consensus gate 6 / 0, full sourced 3272 / 0, full consensus gate 3175 / 0, unit suite 938 passed, synthetic 205 / 0, local eval 100.00.
- `accesscontrol-logto-self-identifying-tight-doc`
  - Added 10 sourced cases; consensus accepted 6 and quarantined 4 broad-packet DataStore cases.
  - Concepts: `access-control`, `direct-get`, `acl-omission`, `issued-row`, `self-identifying-row`, `logto`, `score-sensitive-region`.
  - Official docs used: `core/5.3.2.7.txt`, `core/5.3.2.7.15.txt`, `core/5.3.4.3.txt`, `core/5.8.4.1.txt`, `core/5.8.4.5.txt`, `opal/4.3.1.6.txt`.
  - Accepted coverage:
    - Direct `AccessControl.Get` over `InvokingID..LogTo` may succeed while omitting the unreadable `ACL` cell.
    - Successful responses for `C_PIN_User1.Set` and `MBRControl.Set/Get` must preserve the exact row identity and empty/default `LogTo`.
    - Returning a non-default `LogList` uidref as `LogTo` for those issued rows is impossible.
  - Review notes:
    - The DataStore cases in this broad packet were quarantined because the reviewers could not always see the DataStore row mapping in the source excerpt.
    - Those cases were reissued under `accesscontrol-logto-datastore-self-identifying-tight-doc` with DataStore-focused evidence.
- `accesscontrol-logto-datastore-self-identifying-tight-doc`
  - Added 4 sourced cases; consensus accepted all 4.
  - Concepts: `access-control`, `direct-get`, `acl-omission`, `datastore`, `self-identifying-row`, `logto`, `evidence-tightening`.
  - Official docs used: `core/5.3.2.7.txt`, `core/5.3.2.7.15.txt`, `core/5.3.4.3.txt`, `core/5.8.4.1.txt`, `core/5.8.4.5.txt`, `opal/4.3.1.6.txt`.
  - Accepted coverage:
    - Direct `AccessControl.Get` over the `DataStore.Get` and `DataStore.Set` AccessControl rows must keep `InvokingID`, `MethodID`, and `LogTo` coherent.
    - The `ACL` cell remains omitted from ordinary `Get` results even when the requested range includes it.
    - A non-default `LogList` uidref in `LogTo` is rejected for the default Opal DataStore rows.
  - Repair outcome:
    - `_expected_get` validates known AccessControl metadata cells even when the request includes the unreadable `ACL` column.
    - `_accesscontrol_expected_cells` now records issued-row identity cells for the repaired rows.
  - Consensus: `accesscontrol_logto_self_{a,b,c}.jsonl` plus `accesscontrol_logto_ds_{a,b,c}.jsonl` record the accepted/quarantined split and the DataStore evidence rework.
  - Solver outcome: full sourced 3286 / 0, consensus gate 3185 / 0, unit suite 938 passed, synthetic 205 / 0, local eval 100.00.
- `accesscontrol-mixed-logging-self-identifying-tight-doc`
  - Added 36 sourced cases; consensus accepted all 36.
  - Concepts: `access-control`, `direct-get`, `acl-omission`, `logging`, `issued-row`, `self-identifying-row`.
  - Official docs used: `core/5.3.2.7.txt`, `core/5.3.2.7.5.txt`, `core/5.3.2.7.6.txt`, `core/5.3.2.7.11.txt`, `core/5.3.2.7.12.txt`, `core/5.3.2.7.13.txt`, `core/5.3.2.7.14.txt`, `core/5.3.2.7.15.txt`, `core/5.3.4.3.txt`, `core/5.8.4.1.txt`, `core/5.8.4.5.txt`, `opal/4.3.1.6.txt`.
  - Accepted coverage:
    - Direct `AccessControl.Get` over `InvokingID..LogTo` may omit `ACL` but must still validate identity, Log, AddACELog, RemoveACELog, GetACLLog, DeleteMethodLog, and LogTo.
    - C_PIN_User1.Set and MBRControl.Set/Get cannot invent LogSuccess/LogFail/LogAlways or non-default LogTo while self-identifying the issued row.
  - Solver outcome: tag 36 / 0, consensus gate 36 / 0.
- `accesscontrol-mixed-logging-datastore-tight-doc`
  - Added 24 sourced cases; consensus accepted all 24.
  - Concepts: `access-control`, `direct-get`, `acl-omission`, `datastore`, `logging`, `issued-row`.
  - Official docs used: same AccessControl/logging docs as the mixed self-identifying packet, with DataStore-focused evidence wording.
  - Accepted coverage:
    - DataStore.Get and DataStore.Set AccessControl rows keep their identity and empty/default logging cells under a wide direct `Get` range that includes the unreadable `ACL` column.
  - Solver outcome: tag 24 / 0, consensus gate 24 / 0.
- `accesscontrol-identity-method-split-tight-doc`
  - Added 8 sourced cases; consensus accepted 4 and quarantined 4.
  - Concepts: `access-control`, `direct-get`, `invokingid`, `methodid`, `method-split`, `mbrcontrol`, `getacl`.
  - Official docs used: `core/5.3.2.7.txt`, `core/5.3.2.7.2.txt`, `core/5.3.2.7.3.txt`, `core/5.3.2.7.5.txt`, `core/5.3.3.13.txt`, `core/5.3.3.13.3.1.txt`, `core/5.3.3.13.4.txt`, `core/5.3.4.3.txt`, `opal/4.3.1.6.txt`.
  - Accepted coverage:
    - `GetACL(MBRControl, Get)` returns the Get ACL, not the Set ACL.
    - `GetACL(MBRControl, Set)` returns the Set ACL, not `ACE_Anybody`.
  - Quarantine notes:
    - Direct identity-only row-UID cases were protocol-plausible but quarantined because the packet did not explicitly prove the row UID to association mapping to every reviewer.
  - Repair outcome:
    - `_accesscontrol_expected_cells` now validates known issued-row identity cells even when only columns 1-2 are requested.
- `locking-generalstatus-readonly-tight-doc`
  - Added 5 sourced cases; consensus accepted all 5.
  - Concepts: `locking-range`, `reencryption`, `general-status`, `host-read-only`, `set`, `nonmutation`.
  - Official docs used: `core/5.7.2.2.14.txt`, `core/5.7.2.2.20.txt`, `core/5.7.3.7.4.txt`, `core/5.3.4.2.6.txt`, `core/5.1.5.11.txt`.
  - Accepted coverage:
    - Host `Set` of `GeneralStatus` cannot succeed.
    - Failed `GeneralStatus` writes do not overwrite active/pending pause status produced by valid ReEncryptRequest transitions.
  - Repair outcome:
    - `_invalid_set_values` now treats Locking column 19 as host read-only.
- `locking-boolean-set-type-tight-doc`
  - Added 6 sourced cases; consensus accepted all 6.
  - Concepts: `locking-range`, `boolean-column`, `type-checking`, `set`, `nonmutation`, `host-io`.
  - Official docs used: `core/5.7.2.2.6.txt`, `core/5.7.2.2.7.txt`, `core/5.7.2.2.8.txt`, `core/5.7.2.2.9.txt`, `core/5.3.4.2.6.txt`, `core/5.1.5.11.txt`.
  - Accepted coverage:
    - ReadLockEnabled, WriteLockEnabled, ReadLocked, and WriteLocked reject non-boolean Set values.
    - Failed boolean type writes leave prior lock cells unchanged.
  - Repair outcome:
    - `_invalid_set_values` now type-checks Locking columns 5-8 as booleans.
- `locking-reset-types-alias-reject-tight-doc`
  - Added 8 sourced cases; consensus accepted all 8.
  - Concepts: `locking-range`, `reset-types`, `protocol-stack-reset`, `lock-on-reset`, `cont-on-reset`, `type-checking`, `nonmutation`.
  - Official docs used: `core/5.7.2.2.10.txt`, `core/5.7.2.2.17.txt`, `core/5.7.2.2.13.txt`, `core/5.7.2.2.20.txt`, `core/5.3.4.2.6.txt`, `core/5.1.5.11.txt`, `opal/3.3.5.2.txt`, `opal/3.3.6.txt`, `opal/4.3.5.2.2.txt`.
  - Accepted coverage:
    - LockOnReset rejects ProtocolStackReset, StackReset, and TCGReset aliases as table reset_types values.
    - Failed alias Set attempts do not add Programmatic relock behavior.
    - ContOnReset rejects ProtocolStackReset and preserves reset-stop pause behavior after failed Set.
  - Repair outcome:
    - `_reset_types` no longer maps protocol-stack reset names to Programmatic.
    - `_reset_list_invalid` and `_reset_condition_list_invalid` reject protocol-stack reset aliases in table reset lists.
- `datastore-no-values-granularity-tight-doc`
  - Added 8 sourced cases; consensus accepted 4 and quarantined 4.
  - Concepts: `datastore`, `byte-table`, `set`, `values-omission`, `mandatory-granularity`, `no-op-set`, `postcondition`.
  - Official docs used: `core/5.3.3.7.2.txt`, `core/5.3.3.7.2.1.txt`, `core/5.3.3.6.2.1.txt`, `core/5.3.4.2.6.txt`, `opal/4.3.8.1.txt`, `opal/5.3.1.1.2.txt`.
  - Accepted coverage:
    - After DataStore MandatoryWriteGranularity is observed, aligned-row Set with omitted Values succeeds as a no-op.
    - The aligned no-op preserves the previously written payload exactly.
  - Quarantine notes:
    - Unaligned-row no-Values Set cases were quarantined because reviewers disagreed whether MandatoryWriteGranularity's start-offset rule still applies when no Values length exists.
  - Solver outcome: full sourced 3381 / 0, consensus gate 3272 / 0, unit suite 938 passed, synthetic 205 / 0, local eval 100.00, covered docs 508.
- `datastore-nested-values-bytes-long-tight-doc`
  - Added 10 sourced cases; consensus accepted all 10.
  - Concepts: `datastore`, `byte-table`, `values`, `bytes`, `nested-payload`, `raw-args`, `offset`, `partial-overwrite`, `postcondition`, `long-trajectory`.
  - Official docs used: `core/5.1.4.2.3.txt`, `core/5.3.3.6.2.1.txt`, `core/5.3.3.7.1.2.txt`, `core/5.3.3.7.2.txt`, `core/5.3.3.7.2.1.txt`, `core/5.3.3.7.4.txt`, `core/5.3.4.2.6.txt`, `opal/4.3.8.1.txt`.
  - Accepted coverage:
    - DataStore byte-table payload tracking works across top-level `Bytes`, nested `Values.Bytes`, list-form `Values`, raw `startRow + Values(Bytes)`, and raw `Where(Row) + Values([Bytes])`.
    - Overlapping raw/nested writes replace only the addressed byte positions.
    - Omitted-Where nested writes rewrite only the prefix rather than truncating the known payload.
    - Later explicit Get windows must reconstruct exact full, interior, and tail-middle byte slices.
  - Consensus:
    - `datastore_nested_values_{a,b,c}.jsonl` all agreed on the 10 labels with no concerns; minimum reviewer confidence was 0.96.
  - Solver outcome:
    - No repair was needed; the existing parser and state transition logic already handled these equivalent encodings.
    - Full sourced 3391 / 0, consensus gate 3282 / 0, unit suite 938 passed, synthetic 205 / 0, local eval 100.00, covered docs 508.
- `locking-rowvalues-encoding-long-tight-doc`
  - Added 10 sourced cases; solver accepted all 10, but consensus accepted 4 and quarantined 6.
  - Concepts: `locking-range`, `set`, `values`, `rowvalues`, `raw-args`, `lockonreset`, `power-cycle`, `host-io`, `postcondition`, `long-trajectory`.
  - Official docs used: `core/5.1.3.67.txt`, `core/5.3.3.7.txt`, `core/5.3.3.7.2.txt`, `core/5.3.3.7.2.2.txt`, `core/5.3.3.6.2.2.txt`, `core/5.3.4.2.6.txt`, `core/5.7.2.2.4.txt`, `core/5.7.2.2.5.txt`, `core/5.7.2.2.6.txt`, `core/5.7.2.2.7.txt`, `core/5.7.2.2.8.txt`, `core/5.7.2.2.9.txt`, `core/5.7.2.2.10.txt`, `opal/3.3.5.2.txt`, `opal/4.3.5.2.2.txt`.
  - Accepted coverage:
    - A subset of RowValues-encoded Locking Set trajectories was judged sufficiently supported.
  - Quarantine notes:
    - Six cases were quarantined because reviewers flagged ambiguous evidence for top-level `RowValues` form, exact host-write failure status, or reset-value interpretation.
    - A local QC issue was also fixed before final verification: a host-write check needed nonzero range geometry (`RangeStart=80`, `RangeLength=8`) before lock-bit postconditions could meaningfully affect I/O.
  - Solver outcome:
    - Full sourced 3401 / 0 after this packet, but only 4 of the 10 cases entered the trusted consensus gate.
- `locking-rowvalues-postcondition-tight-doc`
  - Added 8 sourced cases as an evidence-tight reissue; consensus accepted all 8.
  - Concepts: `locking-range`, `set`, `values`, `rowvalues`, `rowvalue-postcondition`, `lockonreset`, `power-cycle`, `postcondition`, `long-trajectory`.
  - Official docs used: `core/5.1.3.67.txt`, `core/5.3.3.7.txt`, `core/5.3.3.7.2.txt`, `core/5.3.3.7.2.2.txt`, `core/5.3.3.6.2.2.txt`, `core/5.3.4.2.6.txt`, `core/5.7.2.2.4.txt`, `core/5.7.2.2.5.txt`, `core/5.7.2.2.6.txt`, `core/5.7.2.2.7.txt`, `core/5.7.2.2.8.txt`, `core/5.7.2.2.9.txt`, `core/5.7.2.2.10.txt`, `opal/3.3.5.2.txt`, `opal/4.3.5.2.2.txt`.
  - Accepted coverage:
    - Named `Values.RowValues` updates RangeStart, RangeLength, and ReadLockEnabled/WriteLockEnabled cells that later `Get` must report exactly.
    - Numeric row-value cells can update ReadLocked/WriteLocked without mutating disabled lock-enable cells.
    - Out-of-order named RowValues still update the intended columns rather than positional columns.
    - Numeric `LockOnReset=[0]` followed by Power Cycle relocks the stored read/write lock cells.
  - Consensus:
    - `locking_rowvalues_postcondition_{a,b,c}.jsonl` all agreed on the 8 labels with no concerns; confidence range was 0.96-0.98.
  - Solver outcome:
    - No repair was needed; the current parser and Locking transition model already passed the accepted reissue.
    - Full sourced 3409 / 0, consensus gate 3294 / 0, unit suite 938 passed, synthetic 205 / 0, local eval 100.00, covered docs 508.
- `optional-range-maxranges-long-tight-doc`
  - Added 10 sourced cases; consensus accepted all 10.
  - Concepts: `lockinginfo`, `maxranges`, `optional-row`, `locking-range`, `k-aes`, `create-row`, `getacl`, `state-consistency`, `long-trajectory`.
  - Official docs used: `core/5.3.2.7.txt`, `core/5.3.2.7.5.txt`, `core/5.3.3.4.txt`, `core/5.3.3.13.txt`, `core/5.3.3.13.3.1.txt`, `core/5.3.4.3.1.txt`, `core/5.7.2.1.txt`, `core/5.7.2.1.5.txt`, `core/5.7.2.2.txt`, `core/5.7.2.3.txt`, `core/5.7.2.4.txt`, `core/5.7.3.3.txt`, `opal/3.3.5.2.txt`, `opal/4.3.1.6.txt`, `opal/4.3.1.7.txt`, `opal/4.3.5.1.txt`, `opal/4.3.5.2.txt`, `opal/4.3.5.5.txt`.
  - Accepted coverage:
    - `MaxRanges=8` excludes Range10/K_AES Range10 direct operations, CreateRow returns, and exact GetACL success.
    - `MaxRanges=10` permits Range10 direct Get/Set, K_AES Range10 GenKey, and exact Range10 GetACL when the optional row/key is present.
    - Earlier successful Range10 Set, K_AES Range10 GetACL, or CreateRow returning Range10 conflicts with a later successful `LockingInfo.Get` reporting `MaxRanges=8`.
  - Consensus:
    - `optional_range_maxranges_range10_{a,b,c}.jsonl` all agreed on the 10 labels.
    - Two reviewers initially wrote rationale in `concerns`; after schema clarification they confirmed no actual concerns and kept labels unchanged.
  - Solver outcome:
    - No repair was needed; existing optional-range state tracking already matched the official MaxRanges boundary rule.
    - Full sourced 3419 / 0, consensus gate 3304 / 0, unit suite 938 passed, synthetic 205 / 0, local eval 100.00, covered docs 508.
- `authority-presentcertificate-default-doc`
  - Added 8 sourced cases; consensus accepted all 8.
  - Concepts: `auth`, `authority`, `certificate-presentation`, `presentcertificate`, `preconfigured-row`, `get`.
  - Official docs used: `core/5.3.2.10.txt`, `core/5.3.2.10.9.txt`, `core/5.3.4.1.13.txt`, `opal/4.2.1.7.txt`, `opal/4.3.1.8.txt`.
  - Accepted coverage:
    - Exact `Authority.Get` for column `0x08` on Admin SP `Admins`, `SID`, `Admin1`, and Locking SP `User1` must return `false` for fresh issued rows.
    - Returning `true` for those exact default reads is rejected.
  - Consensus:
    - `authority_presentcertificate_{a,b,c}.jsonl` all agreed on all 8 labels with empty concerns; final mix was 4 `PASS` and 4 `FAIL`.
  - Repair outcome:
    - `expectations.py` now models exact column-8 `PresentCertificate=false` defaults for known Opal-issued authorities.
    - The repair is intentionally scoped to exact column-8 requests after QC caught that a broader static-cell treatment would overconstrain unrelated broad Authority returns.
    - Full sourced 3427 / 0, consensus gate 3312 / 0, unit suite 938 passed, synthetic 205 / 0, local eval 100.00, covered docs 509.
- `accesscontrol-full-row-direct-get-tight-doc`
  - Added 25 sourced cases; consensus accepted all 25.
  - Concepts: `access-control`, `direct-get`, `full-row-get`, `acl-omission`, `invokingid`, `methodid`, `logging`, `issued-row`.
  - Official docs used: `core/5.3.2.7.txt`, `core/5.3.2.7.2.txt`, `core/5.3.2.7.3.txt`, `core/5.3.2.7.5.txt`, `core/5.3.2.7.6.txt`, `core/5.3.2.7.11.txt`, `core/5.3.2.7.12.txt`, `core/5.3.2.7.13.txt`, `core/5.3.2.7.14.txt`, `core/5.3.2.7.15.txt`, `core/5.3.3.6.txt`, `core/5.3.3.13.txt`, `core/5.3.3.13.4.txt`, `core/5.3.4.2.2.txt`, `opal/4.3.1.6.txt`.
  - Accepted coverage:
    - Full-row direct `AccessControl.Get` may omit the `ACL` column because `ACL` belongs to the `GetACL` path.
    - If the direct `Get` succeeds and returns issued-row metadata, `InvokingID`, `MethodID`, and log-routing cells must still match the issued association/defaults.
    - Direct `Get` returning an `ACL` payload is rejected.
    - Direct `Get` returning the wrong self-identifying `MethodID` or impossible non-default `LogTo` is rejected.
  - Consensus:
    - `accesscontrol_fullrow_{a,b,c}.jsonl` all completed with 25 labels and matching case order.
    - Final mix was 10 `PASS` and 15 `FAIL`; no cases were quarantined from this packet.
  - Repair outcome:
    - `_expected_get` now applies `_accesscontrol_expected_cells` to successful full-row direct `AccessControl.Get` returns while still forbidding ordinary `ACL` leakage and allowing non-success statuses.
    - This is a general issued-row metadata consistency repair, not a one-off patch for the five generated examples.
    - Full sourced 3452 / 0, consensus gate 3337 / 0, unit suite 938 passed, synthetic 205 / 0, local eval 100.00, covered docs 509.
- `locking-reset-disabled-side-reenable-tight-doc`
  - Added 28 sourced cases; consensus accepted all 28.
  - Concepts: `reset`, `locking-range`, `lock-on-reset`, `disabled-side`, `latent-lock`, `lockenabled`, `locked-cell`, `host-io`, `long-trajectory`.
  - Official docs used: `core/3.3.6.5.txt`, `core/3.3.6.5.2.txt`, `core/3.3.6.5.3.txt`, `core/3.3.7.1.5.txt`, `core/5.7.2.2.6.txt`, `core/5.7.2.2.7.txt`, `core/5.7.2.2.8.txt`, `core/5.7.2.2.9.txt`, `core/5.7.3.1.2.txt`, `core/5.7.3.2.txt`, `opal/4.3.5.2.txt`, `opal/4.3.5.2.2.txt`.
  - Accepted coverage:
    - Matching LockOnReset PowerCycle sets both stored `ReadLocked` and `WriteLocked` cells true when the row has an enabled locking side.
    - A disabled side's stored lock remains ineffective for host I/O while its `*LockEnabled` cell is false.
    - Re-enabling that side later makes the latent stored lock effective for host I/O.
    - Clearing both stored lock cells after re-enable clears Level0 `Locked` and restores reads/writes.
  - QC notes:
    - A tempting side-specific solver repair was tried locally, but full sourced verification caught seven regressions against already accepted GlobalRange/multi-range/crossing reset cases.
    - `core/5.7.2.2.10` confirmed the correct interpretation: LockOnReset sets both stored locked columns true; enable bits control whether those cells are meaningful for I/O.
    - The wrong repair was reverted before acceptance, and the cases were rewritten to lock down the latent-lock interpretation.
  - Consensus:
    - `locking_reset_disabled_side_{a,b,c}.jsonl` all completed with 28 labels and matching case order.
    - All 28 entered the trusted consensus gate; no quarantines from this packet.
  - Solver outcome:
    - No final repair was needed; existing reset semantics already matched the official both-stored-cells rule.
    - Full sourced 3480 / 0, consensus gate 3365 / 0, unit suite 938 passed, synthetic 205 / 0, local eval 100.00, covered docs 509.
- `byte-table-row-uinteger-tight-doc`
  - Added 26 sourced cases; consensus accepted all 26.
  - Concepts: `byte-table`, `row-number`, `uinteger`, `cellblock`, `where`, `datastore`, `mbr`, `invalid-parameter`, `nonmutation`.
  - Official docs used: `core/3.2.5.1.txt`, `core/5.1.4.2.3.txt`, `core/5.3.3.6.3.txt`, `core/5.3.3.7.1.2.txt`, `core/5.3.3.7.2.1.txt`, `core/5.3.3.7.4.txt`, `opal/4.3.8.1.txt`.
  - Accepted coverage:
    - Explicit nonnumeric byte-table row selectors are invalid for `Get` and `Set`.
    - Invalid row tokens must not be treated as omitted selectors or row zero.
    - Failed invalid-row DataStore/MBR Set attempts do not mutate prior bytes.
    - Decimal and hexadecimal uinteger row strings remain valid and address the requested byte offsets.
  - Consensus:
    - `byte_table_row_uinteger_{a,b,c}.jsonl` all completed with 26 labels and matching case order.
    - All 26 entered the trusted consensus gate; no quarantines from this packet.
  - Repair outcome:
    - `parsing.py` now validates explicit byte-table `startRow`, `endRow`, and `Where.Row` values as parseable nonnegative uintegers.
    - This repair closes a false-positive path where malformed row tokens could previously disappear into default row-zero handling.
    - Full sourced 3506 / 0, consensus gate 3391 / 0, unit suite 938 passed, synthetic 205 / 0, local eval 100.00, covered docs 509.
- `getacl-locking-special-object-expanded-doc`
  - Added 32 sourced cases; consensus accepted all 32.
  - Concepts: `access-control`, `getacl`, `special-method-object`, `association-existence`, `methodid`, `sptemplates`, `ordinary-get-alias`.
  - Official docs used: `core/3.2.4.1.txt`, `core/5.1.5.2.txt`, `core/5.3.2.7.txt`, `core/5.3.3.13.txt`, `core/5.3.3.13.3.1.txt`, `core/5.3.3.13.4.txt`, `core/5.3.4.3.txt`, `opal/4.3.1.5.txt`, `opal/4.3.1.6.txt`.
  - Accepted coverage:
    - Special `SPTemplatesObj` and `MethodIDObj` `GetACL` associations exist for issued special objects.
    - Ordinary `Get` association success for those special objects is rejected when the object only belongs to the special-object method path.
    - Exact successful `GetACL` returns still have to match the expected ACE uidref list.
  - Consensus:
    - `getacl_special_expanded_{a,b,c}.jsonl` all completed with 32 labels and matching case order.
    - All 32 entered the trusted consensus gate; no quarantines from this packet.
  - Solver outcome:
    - No repair was needed; current association semantics already passed.
    - Full sourced 3554 / 0, consensus gate 3437 / 0, unit suite 938 passed, synthetic 205 / 0, local eval 100.00, covered docs 514.
- `genkey-result-shape-doc`
  - Added 12 sourced cases; consensus accepted all 12.
  - Concepts: `genkey`, `credential-object`, `c-pin`, `k-aes`, `result-shape`, `empty-return-list`, `postcondition`.
  - Official docs used: `core/5.3.3.16.txt`, `core/5.3.3.16.3.txt`, `core/5.3.3.16.3.1.txt`, `core/5.3.3.16.4.txt`, `core/5.7.2.3.txt`, `core/5.7.2.4.txt`, `opal/4.3.5.5.txt`.
  - Accepted coverage:
    - Successful C_PIN `GenKey` returns an empty result list whether default length or explicit valid `PinLength` is used.
    - Successful K_AES `GenKey` on GlobalRange and Range1 key rows also returns an empty result list.
    - Returning generated credential bytes/key material as method output is rejected.
  - Consensus:
    - `genkey_result_shape_{a,b,c}.jsonl` all completed with 12 labels and matching case order.
    - All 12 entered the trusted consensus gate; no quarantines from this packet.
  - Solver outcome:
    - No repair was needed; current `GenKey` response expectations already passed.
    - Full sourced 3554 / 0, consensus gate 3437 / 0, unit suite 938 passed, synthetic 205 / 0, local eval 100.00, covered docs 514.
- `opal-admin-issuesp-unsupported-doc`
  - Added 4 sourced cases; consensus accepted 2 and quarantined 2.
  - Concepts: `admin-sp`, `issuesp`, `opal-methodid-table`, `unsupported-method`, `getacl`, `exact-status-ambiguity`.
  - Official docs used: `core/5.3.2.6.txt`, `core/5.3.3.13.txt`, `core/5.3.3.13.4.txt`, `core/5.4.3.1.txt`, `core/5.4.4.3.1.txt`, `opal/4.2.1.4.txt`, `opal/4.2.4.txt`.
  - Accepted coverage:
    - A normal `SUCCESS` response to Opal Admin `IssueSP` is rejected.
    - A normal `SUCCESS` response to `GetACL` for an Opal Admin `IssueSP` association is rejected.
  - Quarantine notes:
    - The two positive exact-status cases were quarantined because reviewers treated the broad unsupported-success rule as safer than asserting a single exact non-success status.
    - These cases remain useful evidence notes, but are excluded from the trusted consensus gate.
  - Solver outcome:
    - No repair was needed.
    - Tag-local consensus gate selected 2 accepted cases out of 4 with 0 mismatches; full consensus gate selected 3437 accepted cases out of 3554 with 0 mismatches.
- `startsession-hostsessionid-echo-tight-doc`
  - Added 10 sourced cases; consensus accepted 8 and quarantined 2.
  - Concepts: `session-manager`, `start-session`, `sync-session`, `host-session-id`, `return-shape`, `exact-echo`.
  - Official docs used: `core/3.3.7.1.txt`, `core/5.2.3.1.txt`, `core/5.2.3.1.1.txt`, `core/5.2.3.2.txt`, `core/5.2.3.2.1.txt`, `opal/4.1.1.2.txt`.
  - Accepted coverage:
    - Successful `SyncSession` must return the same host-assigned `HostSessionID` supplied in `StartSession`.
    - Merely returning any `HostSessionID` field is insufficient when the value differs.
    - Decimal and hex-equivalent encodings are accepted when they refer to the same uinteger value.
    - Password-authenticated `StartSession` follows the same echo rule.
  - Quarantine notes:
    - Two lower-camel `hostSessionID` alias cases were quarantined because one reviewer flagged evidence casing ambiguity.
    - The canonical cases are trusted; alias cases remain useful parser robustness notes but are not in the consensus gate.
  - Repair outcome:
    - `ExpectedResponse.expected_return_values` was added and wired into `compare_expected_actual`.
    - `_start_session_success_kwargs` now requires successful `SyncSession.HostSessionID` to echo the `StartSession.HostSessionID` request value.
    - This fixed a concrete false positive discovered during probing.
    - Full sourced 3564 / 0, consensus gate 3445 / 0, unit suite 939 passed, synthetic 205 / 0, local eval 100.00, covered docs 515.
- `session-id-uinteger-tight-doc`
  - Added 10 sourced cases; consensus accepted 9 and quarantined 1.
  - Concepts: `session-manager`, `start-session`, `start-trusted-session`, `host-session-id`, `sp-session-id`, `uinteger`, `parameter-type`.
  - Official docs used: `core/5.2.3.1.txt`, `core/5.2.3.1.1.txt`, `core/5.2.3.2.1.txt`, `core/5.2.3.2.2.txt`, `core/5.2.3.3.txt`, `core/5.2.3.3.1.txt`, `core/5.2.3.3.2.txt`, `core/5.2.3.4.1.txt`, `core/5.2.3.4.2.txt`, `opal/4.1.1.2.txt`.
  - Accepted coverage:
    - Explicit session ID parameters must be nonnegative integer values.
    - `StartSession.HostSessionID` rejects nonnumeric text, negative values, and booleans.
    - `StartTrustedSession.HostSessionID` and `SPSessionID` reject negative values and booleans.
    - Canonical numeric positive controls remain valid.
  - Quarantine notes:
    - A textual `0x2A` positive control was quarantined because reviewers wanted stronger evidence for that lexical encoding of `uinteger`.
  - Repair outcome:
    - `expectations.py` now validates explicitly supplied startup session ID parameters through a shared `_session_id_uinteger_error` helper.
    - The repair fixes a discovered false positive while preserving older abstract records that omit `HostSessionID`.
    - Full sourced 3574 / 0, consensus gate 3454 / 0, unit suite 941 passed, synthetic 205 / 0, local eval 100.00, covered docs 515.
- `startsession-write-boolean-tight-doc`
  - Added 7 sourced cases; consensus accepted 6 and quarantined 1.
  - Concepts: `session-manager`, `start-session`, `write`, `read-write-session`, `read-only-session`, `boolean`, `parameter-type`.
  - Official docs used: `core/5.2.3.1.txt`, `core/5.2.3.1.3.txt`, `opal/4.1.1.2.txt`.
  - Accepted coverage:
    - `StartSession.Write=True` is a valid Read-Write session request.
    - `Write=2`, `Write=-1`, arbitrary text, mode-like text, and structured list payloads are not boolean and cannot produce successful StartSession.
  - Quarantine notes:
    - `Write=False` as a positive control was quarantined because Opal Read-Only support is optional and the trajectory did not establish support.
  - Repair outcome:
    - `expectations.py` now validates explicitly supplied `StartSession.Write` as a boolean literal.
    - The repair fixes a discovered false positive while keeping canonical True/False and 0/1 behavior.
    - Full sourced 3581 / 0, consensus gate 3460 / 0, unit suite 942 passed, synthetic 205 / 0, local eval 100.00, covered docs 515.
- `startsession-timeout-credit-uinteger-tight-doc`
  - Added 8 sourced cases; consensus accepted all 8.
  - Concepts: `session-manager`, `start-session`, `session-timeout`, `trans-timeout`, `initial-credit`, `uinteger`, `parameter-type`.
  - Official docs used: `core/3.3.8.2.txt`, `core/3.3.9.4.txt`, `core/5.2.3.1.txt`, `core/5.2.3.1.9.txt`, `core/5.2.3.1.10.txt`, `core/5.2.3.1.11.txt`, `opal/4.1.1.2.txt`.
  - Accepted coverage:
    - `SessionTimeout=True` and structured-list timeout values cannot succeed.
    - `TransTimeout=True` and structured-list timeout values cannot succeed.
    - `InitialCredit` rejects negative, boolean, nonnumeric text, and structured-list values.
  - Consensus:
    - `startsession_timeout_credit_{a,b,c}.jsonl` all labeled the 8 cases `FAIL` with no concerns.
  - Repair outcome:
    - Timeout validators now reject booleans through the shared uinteger helper.
    - `InitialCredit` gained explicit startup parameter validation.
    - Full sourced 3589 / 0, consensus gate 3468 / 0, unit suite 944 passed, synthetic 205 / 0, local eval 100.00, covered docs 516.
- `next-count-uinteger-tight-doc`
  - Added 5 sourced cases; consensus accepted all 5.
  - Concepts: `basic-table-method`, `next`, `count`, `uinteger`, `parameter-type`, `result-shape`.
  - Official docs used: `core/5.3.3.8.txt`, `core/5.3.3.8.2.txt`, `core/5.3.3.8.3.txt`, `core/5.1.3.82.txt`, `core/5.3.2.12.txt`, `opal/4.2.1.3.txt`, `opal/4.2.1.5.txt`.
  - Accepted coverage:
    - Omitted `Count` remains valid and iterates to the last row.
    - Numeric `Count` remains valid.
    - `Count=True`, `Count=False`, and `Count=[True]` are not `uinteger` parameters and cannot produce successful `Next`.
  - Consensus:
    - `next_count_uinteger_{a,b,c}.jsonl` all labeled the 5 cases with the author labels and no concerns.
  - Repair outcome:
    - `parsing.py::_next_count_invalid` now rejects boolean values after scalar/list unwrapping.
    - Full sourced 3594 / 0, consensus gate 3473 / 0, unit suite 945 passed, synthetic 205 / 0, local eval 100.00, covered docs 517.
- `random-count-uinteger-tight-doc`
  - Added 6 sourced cases; consensus accepted 5 and quarantined 1.
  - Concepts: `crypto-template`, `random`, `count`, `uinteger`, `parameter-type`, `return-values`.
  - Official docs used: `core/5.6.4.1.txt`, `core/5.6.4.1.1.txt`, `core/5.1.3.82.txt`, `opal/4.2.9.1.txt`, `opal/4.3.4.1.txt`.
  - Accepted coverage:
    - `Count=32` returns a 32-byte random byte string.
    - `Count=True`, `Count=False`, and `Count=[True]` are not `uinteger` values and cannot produce successful `Random`.
    - Named-pair `("Count", True)` is likewise rejected.
  - Quarantine notes:
    - Raw positional `args=True` was quarantined because one reviewer noted encoding ambiguity: it is intended as positional Count but is not named in the abstract packet.
  - Repair outcome:
    - `parsing.py::_random_count` now rejects boolean values before integer parsing.
    - Full sourced 3600 / 0, consensus gate 3478 / 0, unit suite 947 passed, synthetic 205 / 0, local eval 100.00, covered docs 517.
- `genkey-pinlength-uinteger-tight-doc`
  - Added 4 sourced cases; consensus accepted 3 and quarantined 1.
  - Concepts: `genkey`, `c-pin`, `pin-length`, `uinteger`, `parameter-type`, `credential-rotation`.
  - Official docs used: `core/5.3.3.16.txt`, `core/5.3.3.16.2.txt`, `core/5.3.3.16.3.1.txt`, `core/5.3.3.16.4.txt`, `core/5.1.3.82.txt`.
  - Accepted coverage:
    - `PinLength=32` remains valid for C_PIN GenKey.
    - `PinLength=True` and `PinLength=False` are not `uinteger` values and cannot produce successful C_PIN GenKey.
  - Quarantine notes:
    - `PinLength=0` was quarantined due to reviewer concern that the packet proves uinteger and max 32 but not a separate PinLength-specific lower bound.
  - Repair outcome:
    - `expectations.py::_expected_genkey` validates C_PIN `PinLength` through the shared uinteger helper before range checking.
    - Full sourced 3604 / 0, consensus gate 3481 / 0, unit suite 948 passed, synthetic 205 / 0, local eval 100.00, covered docs 517.
- `log-createlog-size-uinteger-tight-doc`
  - Added 4 sourced cases; consensus accepted all 4.
  - Concepts: `log-template`, `createlog`, `minsize`, `maxsize`, `hintsize`, `uinteger`, `parameter-type`.
  - Official docs used: `core/5.8.3.2.txt`, `core/5.8.3.2.3.txt`, `core/5.8.3.2.4.txt`, `core/5.8.3.2.5.txt`, `core/5.1.3.82.txt`.
  - Accepted coverage:
    - Numeric `MinSize`, `MaxSize`, and `HintSize` remain valid when otherwise consistent.
    - `MinSize=True`, `MaxSize=True`, and `HintSize=True` are not `uinteger` values and cannot produce successful `CreateLog`.
  - Consensus:
    - `log_createlog_size_uinteger_{a,b,c}.jsonl` all labeled the 4 cases with the author labels and no concerns.
  - Repair outcome:
    - `expectations.py::_expected_create_log` and `_expected_create_table` now reject boolean size parameters through the shared uinteger helper.
    - Full sourced 3608 / 0, consensus gate 3485 / 0, unit suite 948 passed, synthetic 205 / 0, local eval 100.00, covered docs 518.
- `create-table-size-uinteger-tight-doc`
  - Added 4 sourced cases; consensus accepted all 4.
  - Concepts: `table-methods`, `create-table`, `minsize`, `maxsize`, `hintsize`, `uinteger`, `parameter-type`.
  - Official docs used: `core/5.3.3.2.txt`, `core/5.3.3.2.5.txt`, `core/5.3.3.2.6.txt`, `core/5.3.3.2.7.txt`, `core/5.1.3.82.txt`.
  - Accepted coverage:
    - Numeric `MinSize`, `MaxSize`, and `HintSize` remain valid when otherwise consistent.
    - `MinSize=True`, `MaxSize=True`, and `HintSize=True` are not `uinteger` values and cannot produce successful `CreateTable`.
  - Consensus:
    - `create_table_size_uinteger_{a,b,c}.jsonl` all labeled the 4 cases with the author labels and no concerns.
  - Repair outcome:
    - No additional repair was needed after the shared CreateLog/CreateTable size repair.
    - Full sourced 3612 / 0, consensus gate 3489 / 0, unit suite 948 passed, synthetic 205 / 0, local eval 100.00, covered docs 518.
- `locking-range-uinteger-tight-doc`
  - Added 8 sourced cases; consensus accepted all 8.
  - Concepts: `locking-range`, `range-geometry`, `uinteger`, `range-start-length`, `create-row`, `set`.
  - Official docs used: `core/5.1.3.82.txt`, `core/5.7.2.2.txt`, `core/5.7.2.2.4.txt`, `core/5.7.2.2.5.txt`, `core/5.7.3.3.txt`, `opal/4.3.5.2.1.1.txt`, `opal/4.3.5.2.1.2.txt`.
  - Accepted coverage:
    - `CreateRow` with boolean `RangeStart` cannot succeed.
    - `CreateRow` with boolean `RangeLength` cannot succeed.
    - Non-global Locking row `Set` with boolean `RangeStart` cannot succeed.
    - Non-global Locking row `Set` with boolean `RangeLength` cannot succeed.
  - Consensus:
    - `locking_uinteger_{a,b,c}.jsonl` all labeled the 8 cases with the author labels and no concerns.
  - Repair outcome:
    - `semantics.py::_range_values_invalid_for_geometry` now rejects boolean values for `RangeStart` / `RangeLength` before `_parse_int` coercion.
    - Full sourced 3620 / 0, consensus gate 3497 / 0, unit suite 950 passed, synthetic 205 / 0, local eval 100.00, covered docs 518.
- `locking-reencrypt-enum-type-tight-doc`
  - Added 14 sourced cases; consensus accepted 12 and quarantined 2.
  - Concepts: `locking-range`, `re-encryption`, `enum-type`, `reset-types`, `adv-key-mode`, `cont-on-reset`, `set`.
  - Official docs used: `core/5.1.3.6.txt`, `core/5.1.3.65.txt`, `core/5.1.3.67.txt`, `core/5.7.2.2.txt`, `core/5.7.2.2.14.txt`, `core/5.7.2.2.15.txt`, `core/5.7.2.2.17.txt`, `core/5.7.3.7.1.txt`, `core/5.7.3.7.4.txt`, `core/5.7.3.7.5.txt`.
  - Accepted coverage:
    - Numeric `AdvKeyMode=1` remains valid.
    - `ReEncryptRequest=START_req` remains valid from IDLE.
    - Explicit `ContOnReset=[0,2]` reset entries remain valid.
    - Boolean `AdvKeyMode`, boolean `ReEncryptRequest`, and boolean `ContOnReset` cannot succeed by coercion.
  - Quarantine notes:
    - Two cases were held out due to reviewer concern around reset-set interpretation boundaries.
  - Consensus:
    - `locking_reencrypt_enum_{a,b,c}.jsonl` each contained 7 PASS / 7 FAIL labels; matrix accepted 12 and quarantined 2.
  - Repair outcome:
    - `parsing.py::_parse_reencrypt_request` rejects booleans before integer parsing.
    - `parsing.py::_contains_bool_token` and `semantics.py::_invalid_set_values` reject boolean tokens in `AdvKeyMode` / `ContOnReset`.
    - Full sourced 3634 / 0, consensus gate 3509 / 0, unit suite 953 passed, synthetic 205 / 0, local eval 100.00, covered docs 518.
- `tcgstorageapi-wrapper` positional `setRange` signature alignment
  - Updated the score-first wrapper regression to distinguish the documented wrapper order from low-level Locking column order.
  - Concepts: `tcgstorageapi-wrapper`, `setRange`, `positional-args`, `locking-range`, `read-locked`, `write-locked`, `read-lock-enabled`, `write-lock-enabled`.
  - Local source basis:
    - `materials/tcgstorageapi_offline_rule_based_verifier_instructions.md` describes `setRange(... RangeStart, RangeLength, ReadLocked, WriteLocked, ReadLockEnabled, WriteLockEnabled, LockOnReset)`.
    - The same file separately maps those semantic fields to Locking table columns 3-9.
  - Added/updated coverage:
    - Positional `setRange(Admin1, 1, 80, 8, True, False, True, True)` must later report `ReadLocked=1`, `WriteLocked=0`, `ReadLockEnabled=1`, `WriteLockEnabled=1`.
    - This specific boolean pattern would fail if the parser accidentally treated wrapper positional order as low-level column order.
  - Consensus:
    - Synthetic wrapper cases remain outside the official-doc reviewer consensus matrix.
  - Repair outcome:
    - `parsing.py` now translates positional wrapper arguments into the documented semantic fields before low-level Locking state tracking.
    - Keyword `setRange` traces remain unchanged.
    - Wrapper synthetic 30 / 0, unit suite 1009 passed, full sourced 3743 / 0, local eval 100.00.
- `crypto-cellblock-accesscontrol-doc`
  - Added 10 sourced cases; not yet consensus-promoted.
  - Concepts: `crypto-template`, `cellblock`, `datastore`, `access-control`, `buffer-in`, `buffer-out`, `get-acl`, `set-acl`.
  - Official docs used: `core/5.6.4.4.1.2.txt`, `core/5.6.4.4.4.txt`, `core/5.6.4.7.1.2.txt`, `core/5.6.4.7.4.txt`, `core/5.6.4.9.1.2.txt`, `core/5.6.4.9.4.txt`, `core/5.6.4.11.1.2.txt`, `core/5.6.4.11.3.txt`, `core/5.6.4.12.1.2.txt`, `core/5.6.4.12.3.txt`, `core/5.6.4.13.2.txt`, `core/5.6.4.15.1.2.txt`, `core/5.6.4.15.3.txt`, `core/5.6.4.17.3.1.txt`, `core/5.6.4.17.3.2.txt`, `opal/4.3.1.6.txt`, `opal/4.3.1.7.txt`.
  - Added coverage:
    - DataStore input cellblocks require the DataStore Get ACE to be satisfied.
    - DataStore BufferOut cellblocks require the DataStore Set ACE to be satisfied.
    - Empty BooleanExpr on the corresponding ACE blocks `Encrypt`, `Decrypt`, `Sign`, `Hash`, and `HMAC` impossible-success responses.
  - Consensus:
    - Awaiting independent reviewer labels; current consensus gate remains 3591 accepted cases and excludes the new tag.
  - Repair outcome:
    - `expectations.py` now recognizes explicit DataStore cellblock references in crypto input/output parameters and applies the already-modeled DataStore Get/Set ACE state.
    - Direct `Bytes` crypto shorthand remains unchanged.
    - Targeted tag 10 / 0 after cross-method expansion.
    - Full sourced 3747 / 0, consensus gate 3591 / 0, unit suite 1011 passed, synthetic 235 / 0, local eval 100.00, covered docs 594 before expansion.
- `type-column-metadata-table-doc`
  - Added 6 sourced cases; not yet consensus-promoted.
  - Concepts: `metadata-table`, `column-table`, `type-table`, `type-size`, `readonly`, `get-acl`, `set`.
  - Official docs used: `core/5.3.2.4.txt`, `core/5.3.2.5.txt`, `core/5.3.2.5.5.txt`, `opal/4.3.1.4.txt`.
  - Added coverage:
    - `Type.Size` column 0x04 is TPer-calculated and cannot be host-modified with successful `Set`.
    - `Type.CreateRow` cannot specify `Size`.
    - `ColumnTable` and `TypeTable` are recognized as system metadata tables for AccessControl association checks.
  - Consensus:
    - Awaiting independent reviewer labels; current consensus gate excludes the new tag until promoted.
  - Repair outcome:
    - Fixed-object UID and alias recognition now includes `ColumnTable` and `TypeTable`.
    - `SYSTEM_METADATA_TABLE_ASSOCIATION_LIMITS` includes Column/Type metadata tables.
    - `semantics.py::_invalid_set_values` rejects host `Set` of `Type_*` `Size`.
    - Targeted tag 6 / 0, unit suite 1013 passed.
- `locking-accesscontrol-logalways-doc`
  - Added 6 sourced cases; not yet consensus-promoted.
  - Concepts: `access-control`, `direct-get`, `log-template`, `log-select`, `locking-range`, `set`, `default-logging`.
  - Official docs used: `core/5.3.2.7.txt`, `core/5.3.2.7.6.txt`, `core/5.1.3.49.txt`, `core/5.7.3.8.txt`, `opal/4.3.1.6.txt`, `opal/4.3.5.2.txt`.
  - Added coverage:
    - Locking object Set AccessControl rows `0003F000..0003F7FF` report `LogAlways` in the Log column.
    - Empty/default no-log values are rejected for GlobalRange/Range1/Range2 Set rows.
  - Consensus:
    - Awaiting independent reviewer labels; current consensus gate excludes the new tag until promoted.
  - Repair outcome:
    - `expectations.py::_accesscontrol_expected_cells` now applies `LogAlways` only to Locking object Set rows.
    - Existing empty-log expectations for DataStore, C_PIN_User1, and MBRControl rows remain unchanged.
    - Full sourced 3765 / 0, consensus gate 3591 / 0, unit suite 1014 passed, synthetic 235 / 0, local eval 100.00, covered docs 603.
- `opal-clock-template-unsupported-doc`
  - Added/expanded 28 sourced cases; not yet consensus-promoted.
  - Concepts: `clock-template`, `methodid`, `access-control`, `getacl`, `opal-ssc`, `unsupported-method`, `setclock`, `setlag`, `timer-mode`.
  - Official docs used: `core/5.5.2.txt`, `core/5.5.4.1.txt`, `core/5.5.4.2.txt`, `core/5.5.4.3.txt`, `core/5.5.4.3.2.1.txt`, `core/5.5.4.4.txt`, `core/5.5.4.4.2.1.txt`, `core/5.5.4.5.txt`, `core/5.5.4.5.2.1.txt`, `core/5.5.4.5.3.txt`, `core/5.5.4.6.txt`, `core/5.5.4.6.2.1.txt`, `core/5.5.4.7.txt`, `core/5.5.5.1.1.txt`, `core/5.5.5.1.2.txt`, `core/5.5.5.1.3.txt`, `core/5.5.5.4.txt`, `opal/4.2.1.4.txt`, `opal/4.2.4.txt`, `opal/4.3.1.5.txt`, `opal/4.3.2.txt`.
  - Added coverage:
    - Opal Admin SP rejects successful Clock Template method invocations.
    - Opal Locking SP rejects successful Clock Template method invocations.
    - Opal Admin SP rejects successful GetACL associations for Clock Template methods.
    - Opal Locking SP rejects successful GetACL associations for Clock Template methods.
  - Consensus:
    - Awaiting independent reviewer labels; current consensus gate excludes the new tag until promoted.
  - Repair outcome:
    - No production change required; existing `SUPPORTED_METHODS_BY_SP` boundary already rejects the unsupported methods.
    - Existing AccessControl association checks also reject Clock Template method associations in Opal SPs.
    - Targeted tag 28 / 0, full sourced 3944 / 0, synthetic 235 / 0, unit suite 1045 passed, covered docs 668.
- `authority-limit-uses-uinteger-tight-doc`
  - Added 8 sourced cases; consensus accepted all 8.
  - Concepts: `auth`, `authority`, `limit`, `uses`, `uinteger`, `parameter-type`, `set`.
  - Official docs used: `core/5.1.3.82.txt`, `core/5.1.3.93.txt`, `core/5.3.2.10.txt`, `opal/4.3.1.8.txt`.
  - Accepted coverage:
    - `Authority.Limit=True` and `Authority.Limit=False` cannot succeed by boolean-to-counter coercion.
    - `Authority.Uses=True` and `Authority.Uses=False` cannot succeed by boolean-to-counter coercion.
    - The paired correct `INVALID_PARAMETER` responses remain valid.
  - Consensus:
    - `authority_limit_uses_uinteger_{a,b,c}.jsonl` each contained 4 PASS / 4 FAIL labels, with no concerns.
    - Matrix accepted 8/8 and quarantined 0.
  - Repair outcome:
    - `semantics.py::_invalid_set_values` rejects boolean values for Authority columns 15 and 16 before `_parse_int`.
    - Full sourced 3642 / 0, consensus gate 3517 / 0, unit suite 955 passed, synthetic 205 / 0, local eval 100.00, covered docs 518.
- `cpin-trylimit-tries-uinteger-tight-doc`
  - Added 8 sourced cases; consensus accepted all 8.
  - Concepts: `c-pin`, `try-limit`, `tries`, `uinteger`, `authentication-attempts`, `parameter-type`, `set`.
  - Official docs used: `core/5.1.3.82.txt`, `core/5.1.3.93.txt`, `core/5.3.2.12.txt`, `core/5.3.2.12.6.txt`, `core/5.3.2.12.7.txt`, `core/5.3.4.1.1.2.txt`, `opal/4.3.1.9.txt`.
  - Accepted coverage:
    - `C_PIN.TryLimit=True` and `C_PIN.TryLimit=False` cannot succeed by boolean-to-counter coercion.
    - `C_PIN.Tries=True` and `C_PIN.Tries=False` cannot succeed by boolean-to-counter coercion.
    - The paired correct `INVALID_PARAMETER` responses remain valid.
  - Consensus:
    - `cpin_trylimit_tries_uinteger_{a,b,c}.jsonl` each contained 4 PASS / 4 FAIL labels, with no concerns.
    - Matrix accepted 8/8 and quarantined 0.
  - Repair outcome:
    - `semantics.py::_invalid_set_values` rejects boolean values for `TryLimit` / `Tries` before `_parse_int`.
    - Full sourced 3650 / 0, consensus gate 3525 / 0, unit suite 957 passed, synthetic 205 / 0, local eval 100.00, covered docs 518.
- `tcgstorageapi-wrapper`
  - Added 6 synthetic score-first cases; synthetic wrapper smoke now has 30 cases.
  - Concepts: `tcgstorageapi-wrapper`, `checkPIN`, `params`, `setRange`, `positional-args`, `getRange`, `revertLockingSP`, `KeepGlobalRangeKey`.
  - Official/local source basis:
    - `materials/tcgstorageapi_offline_rule_based_verifier_instructions.md` prioritizes `checkPIN`, `setRange`, `getRange`, `revert`, and ownership/wrapper flows.
    - The same instructions describe `setRange(... RangeStart, RangeLength, ReadLocked, WriteLocked, ReadLockEnabled, WriteLockEnabled, LockOnReset)` as a Locking range configuration flow.
  - Added coverage:
    - `checkPIN(params=[SID, new]) -> True` after SID PIN update is valid.
    - `checkPIN(params=[SID, wrong]) -> True` is invalid.
    - Positional `setRange(Admin1, 1, 80, 8, True, True, False, True)` updates later `getRange`.
    - Stale `getRange` after positional `setRange` is invalid.
    - `revertLockingSP(... KeepGlobalRangeKey=True)` preserves global data when not blocked.
    - The same keep-key wrapper call cannot succeed when GlobalRange is both read-locked and write-locked.
  - Consensus:
    - Synthetic wrapper cases are not part of the independent official-doc consensus matrix.
    - They are tracked as score-first smoke cases for high-level API input-shape coverage.
  - Repair outcome:
    - `parsing.py` now accepts `checkPIN` `params` / `parameters`.
    - `parsing.py` now maps positional `setRange` tail values into Locking columns.
    - `parsing.py` now forwards `KeepGlobalRangeKey` through `revertLockingSP`.
    - Full synthetic 235 / 0, wrapper synthetic 30 / 0, unit suite 999 passed, local eval 100.00.
- `accesscontrol-pattern-direct-identity-tight-doc`
  - Added 4 sourced cases; not yet consensus-promoted.
  - Concepts: `accesscontrol`, `direct-get`, `identity-cells`, `cpin-user-mmmm`, `kaes-rangennnn`, `methodid`, `opal-pattern-rows`.
  - Official docs used: `core/5.3.2.7.txt`, `core/5.3.2.7.2.txt`, `core/5.3.2.7.3.txt`, `core/5.3.2.7.5.txt`, `core/5.3.3.6.txt`, `core/5.3.4.2.2.txt`, `core/5.3.4.3.txt`, `opal/4.3.1.6.txt`, `opal/4.3.1.7.txt`, `opal/4.3.1.8.txt`, `opal/4.3.1.9.txt`, `opal/4.3.5.5.txt`.
  - Added coverage:
    - Direct Get of `AccessControl_0003A802` must report the `C_PIN_User2 Set` identity, not User1.
    - Direct Get of `AccessControl_0003B801` must report the `K_AES_256_Range1_Key GenKey` identity, not `Get`.
  - Consensus:
    - Awaiting independent reviewer labels; current consensus gate still selects 3567 accepted cases and excludes the new tag.
  - Repair outcome:
    - `expectations.py::_accesscontrol_expected_cells` now validates conservative identity expectations for documented User1..8 and K_AES Range1..8 GenKey pattern rows.
    - Full sourced 3696 / 0, consensus gate 3567 / 0, unit suite 999 passed, local eval 100.00, covered docs 519.
- `locking-verify-mode-enum-doc`
  - Added 6 sourced cases; not yet consensus-promoted.
  - Concepts: `locking-range`, `reencryption`, `verify-mode`, `reserved-enum`, `set`, `get-postcondition`.
  - Official docs used: `core/5.1.3.98.txt`, `core/5.7.2.2.16.txt`, `core/5.7.3.7.5.txt`.
  - Added coverage:
    - Locking `VerifyMode=1` is a valid successful Set value.
    - Locking `VerifyMode=2` cannot be accepted as a successful Set value.
    - A successful Locking `Get` of `VerifyMode` may report value `0`, but cannot report reserved value `7`.
  - Consensus:
    - Awaiting independent reviewer labels; current consensus gate excludes the new tag until promoted.
  - Repair outcome:
    - `semantics.py::_invalid_set_values` now validates Locking column 0x0F as `verify_mode`.
    - `expectations.py::_expected_get` and `engine.py::_return_cell_type_valid` now reject reserved `verify_mode` values in successful Get returns.
    - Targeted tag 6 / 0, full sourced 3785 / 0, unit suite 1017 passed, covered docs 628.
- `crsa-padding-type-enum-doc`
  - Added 8 sourced cases; not yet consensus-promoted.
  - Concepts: `c-rsa`, `credential`, `padding-type`, `reserved-enum`, `set`, `get-postcondition`.
  - Official docs used: `core/5.1.3.62.txt`, `core/5.3.2.13.txt`, `core/5.3.2.14.txt`.
  - Added coverage:
    - C_RSA `Format=3` is a valid `padding_type`.
    - C_RSA `Format=9` cannot be accepted as a successful Set value.
    - C_RSA `Format=True` cannot be accepted by boolean-to-enum coercion.
    - A successful C_RSA `Format` Get may return defined value `4`, but cannot return reserved value `15`.
  - Consensus:
    - Awaiting independent reviewer labels; current consensus gate excludes the new tag until promoted.
  - Repair outcome:
    - `semantics.py::_invalid_set_values` now validates C_RSA column 0x03 as `padding_type`.
    - `expectations.py::_expected_get` and `engine.py::_return_cell_type_valid` now reject reserved `padding_type` values in successful Get returns.
    - Targeted tag 8 / 0, full sourced 3793 / 0, unit suite 1020 passed, covered docs 631.
- `lockinginfo-readonly-doc`
  - Expanded from 6 to 7 sourced cases; not yet re-consensus-promoted after expansion.
  - Added evidence: `core/5.7.2.1.7.txt`, `core/5.1.3.43.txt`.
  - Added coverage:
    - Host cannot modify LockingInfo `KeysAvailableCfg`.
  - Repair outcome:
    - No production solver change was needed; LockingInfo Set was already rejected as read-only.
    - This deliberately avoids changing Opal LockingInfo column 0x07 Get semantics, because Opal also uses column 0x07 for `AlignmentRequired`.
    - Targeted tag 7 / 0, covered docs 633.
- `credential-hash-protocol-enum-doc`
  - Added 20 sourced cases; not yet consensus-promoted.
  - Concepts: `credential`, `hash-protocol`, `reserved-enum`, `set`, `get-postcondition`, `crypto-template`.
  - Official docs used: `core/5.1.3.35.txt`, `core/5.3.2.13.txt`, `core/5.3.2.14.txt`, `core/5.3.2.15.txt`, `core/5.3.2.16.txt`, `core/5.3.2.20.txt`, `core/5.3.2.27.txt`.
  - Added coverage:
    - C_RSA/C_AES/C_EC/C_HMAC Hash columns accept valid SHA-512 hash_protocol value.
    - The same credential families reject reserved hash_protocol values.
    - Boolean-to-enum coercion is rejected.
    - Get of a C_HMAC Hash cell rejects reserved hash_protocol values.
  - Repair outcome:
    - Credential Hash columns are now typed as `hash_protocol` on Set and Get.
    - Targeted tag 20 / 0, full sourced 3814 / 0, unit suite 1023 passed, covered docs 638.
- `caes-mode-feedback-doc`
  - Added 18 sourced cases; not yet consensus-promoted.
  - Concepts: `credential`, `c-aes`, `symmetric-mode`, `feedback-size`, `reserved-enum`, `uinteger`, `set`, `get-postcondition`.
  - Official docs used: `core/5.1.3.31.txt`, `core/5.1.3.72.txt`, `core/5.3.2.15.txt`, `core/5.3.2.16.txt`.
  - Added coverage:
    - C_AES_128/C_AES_256 Mode accepts valid `symmetric_mode` value `11`.
    - C_AES_128/C_AES_256 Mode rejects reserved `symmetric_mode` value `12`.
    - C_AES Mode rejects boolean-to-enum coercion.
    - C_AES same-call `Mode=CFB` rejects FeedbackSize `0` and `17`.
    - C_AES Mode Get rejects reserved `symmetric_mode` value `23`.
    - C_AES FeedbackSize Get rejects boolean uinteger coercion.
  - Consensus:
    - Awaiting independent reviewer labels; current consensus gate excludes the new tag until promoted.
  - Repair outcome:
    - `semantics.py::_invalid_set_values` now validates C_AES Mode and conservative FeedbackSize constraints.
    - `expectations.py::_expected_get` and `engine.py::_return_cell_type_valid` now reject invalid C_AES Mode/FeedbackSize successful Get returns.
    - Targeted tag 18 / 0, full sourced 3832 / 0, unit suite 1028 passed, covered docs 643.
- `lockinginfo-encryptsupport-enum-doc`
  - Added 4 sourced cases; not yet consensus-promoted.
  - Concepts: `lockinginfo`, `enc-supported`, `reserved-enum`, `get-postcondition`, `typed-return`.
  - Official docs used: `core/5.1.3.30.txt`, `core/5.7.2.1.txt`, `core/5.7.2.1.4.txt`.
  - Added coverage:
    - LockingInfo EncryptSupport Get accepts defined `enc_supported` value `0`.
    - LockingInfo EncryptSupport Get accepts named value `Media Encryption`.
    - LockingInfo EncryptSupport Get rejects reserved value `2`.
    - LockingInfo EncryptSupport Get rejects boolean-to-enum coercion.
  - Consensus:
    - Awaiting independent reviewer labels; current consensus gate excludes the new tag until promoted.
  - Repair outcome:
    - `expectations.py::_expected_get` now marks LockingInfo column `0x03` as `enc_supported`.
    - `engine.py::_return_cell_type_valid` now validates returned `enc_supported` cells.
    - Targeted tag 4 / 0, full sourced 3836 / 0, unit suite 1030 passed, covered docs 644.
- `sp-lifecycle-state-enum-doc`
  - Added 6 sourced cases; not yet consensus-promoted.
  - Concepts: `sp-table`, `lifecycle`, `life-cycle-state`, `reserved-enum`, `get-postcondition`, `typed-return`.
  - Official docs used: `core/5.1.3.46.txt`, `core/5.4.2.4.txt`, `core/5.4.2.4.7.txt`, `opal/5.2.3.txt`.
  - Added coverage:
    - SP LifeCycleState Get accepts Core `Issued`.
    - SP LifeCycleState Get accepts Opal `Manufactured`.
    - SP LifeCycleState Get rejects reserved/unassigned values `5` and `15`.
    - SP LifeCycleState Get rejects boolean-to-enum coercion.
  - Consensus:
    - Awaiting independent reviewer labels; current consensus gate excludes the new tag until promoted.
  - Repair outcome:
    - `expectations.py::_expected_get` now marks SP column `0x06` as `life_cycle_state`.
    - `engine.py::_return_cell_type_valid` now validates returned lifecycle states.
    - Targeted tag 6 / 0, full sourced 3842 / 0, unit suite 1032 passed, covered docs 646.
- `caes-fixed-bytes-doc`
  - Added 14 sourced cases; not yet consensus-promoted.
  - Concepts: `credential`, `c-aes`, `bytes-16`, `bytes-32`, `fixed-size-bytes`, `set`, `get-postcondition`.
  - Official docs used: `core/5.1.3.17.txt`, `core/5.1.3.19.txt`, `core/5.3.2.15.txt`, `core/5.3.2.15.4.txt`, `core/5.3.2.15.7.txt`, `core/5.3.2.16.txt`, `core/5.3.2.16.4.txt`, `core/5.3.2.16.7.txt`.
  - Added coverage:
    - C_AES_128 Key accepts exact `bytes_16` and rejects short values.
    - C_AES_256 Key accepts exact `bytes_32` and rejects `bytes_16`.
    - C_AES ResidualData rejects boolean bytes coercion.
    - Successful C_AES Key/ResidualData Get returns must match exact byte lengths.
  - Consensus:
    - Awaiting independent reviewer labels; current consensus gate excludes the new tag until promoted.
  - Repair outcome:
    - `semantics.py::_invalid_set_values` now validates C_AES fixed byte-length cells.
    - `expectations.py::_expected_get` and `engine.py::_return_cell_type_valid` now reject wrong-length C_AES byte cells in successful Get returns.
    - Targeted tag 14 / 0, full sourced 3856 / 0, unit suite 1035 passed, covered docs 652.
- `cpin-password-return-type-doc`
  - Added 4 sourced cases; not yet consensus-promoted.
  - Concepts: `c-pin`, `password`, `max-bytes-32`, `get-postcondition`, `typed-return`.
  - Official docs used: `core/5.1.3.63.txt`, `core/5.3.2.12.txt`, `core/5.3.2.12.4.txt`.
  - Added coverage:
    - C_PIN_MSID PIN Get accepts returned password value up to 32 bytes.
    - C_PIN_MSID PIN Get rejects returned password value longer than 32 bytes.
    - Returned PIN cells reject boolean password coercion.
  - Consensus:
    - Awaiting independent reviewer labels; current consensus gate excludes the new tag until promoted.
  - Repair outcome:
    - `expectations.py::_expected_get` now marks returned C_PIN PIN cells as `password`.
    - `engine.py::_return_cell_type_valid` now validates password max-bytes length.
    - Targeted tag 4 / 0, full sourced 3860 / 0, unit suite 1037 passed, covered docs 653.
- `authority-password-operation-doc`
  - Added 8 sourced cases; not yet consensus-promoted.
  - Concepts: `authority`, `operation`, `auth_method`, `password-authority`, `preconfigured-row`, `get-postcondition`.
  - Official docs used: `core/5.1.3.8.txt`, `core/5.3.2.10.txt`, `core/5.3.2.10.10.txt`, `opal/4.2.1.7.txt`, `opal/4.3.1.8.txt`.
  - Added coverage:
    - Admin SP Admin1 Authority.Get Operation accepts Password and numeric auth_method value 1.
    - Admin SP Admin1 Authority.Get Operation rejects Sign, reserved value 8, and boolean coercion.
    - Locking SP User1 Authority.Get Operation accepts Password and rejects Exchange.
  - Consensus:
    - Awaiting independent reviewer labels; current consensus gate excludes the new tag until promoted.
  - Repair outcome:
    - `expectations.py::_authority_static_cells` now models issued AdminN/UserN Password Operation defaults.
    - `expectations.py::_expected_get` applies `auth_method` return typing to Authority Operation cells.
    - `engine.py::_operation_cell_matches` now rejects bools and accepts numeric aliases for documented operations.
    - Targeted tag 8 / 0, full sourced 3868 / 0, synthetic 235 / 0, unit suite 1039 passed, covered docs 654.
- `get-set-absent-object-doc`
  - Added 4 sourced cases; not yet consensus-promoted.
  - Concepts: `table-methods`, `get`, `set`, `object-existence`, `invalid-invoking-id`.
  - Official docs used: `core/5.3.3.6.txt`, `core/5.3.3.6.3.txt`, `core/5.3.3.7.txt`, `core/5.3.3.7.4.txt`.
  - Added coverage:
    - Null UID and all-ones UID cannot be successful Get/Set InvokingIDs when no object symbol resolves.
  - Consensus:
    - Awaiting independent reviewer labels; current consensus gate excludes the new tag until promoted.
  - Repair outcome:
    - `expectations.py::_expected_get` and `_expected_set` now reject success for definitely absent null/all-ones objects.
    - The repair intentionally does not reject all unknown symbols, preserving optional/vendor row tolerance.
    - Targeted tag 4 / 0, full sourced 3872 / 0, synthetic 235 / 0, unit suite 1040 passed, covered docs 654.
- `enum-bool-coercion-doc`
  - Added/expanded 12 sourced cases; not yet consensus-promoted.
  - Concepts: `enum`, `typed-return`, `boolean-coercion`, `credential`, `media-key`, `locking-range`, `get-postcondition`.
  - Official docs used: `core/3.2.1.4.txt`, `core/5.1.3.35.txt`, `core/5.1.3.34.txt`, `core/5.1.3.45.txt`, `core/5.1.3.62.txt`, `core/5.1.3.73.txt`, `core/5.1.3.98.txt`, `core/5.3.2.13.txt`, `core/5.3.2.26.txt`, `core/5.7.2.2.txt`, `core/5.7.2.4.txt`.
  - Added coverage:
    - C_RSA Format Get rejects boolean padding_type.
    - C_HMAC Hash Get rejects boolean hash_protocol.
    - K_AES Mode Get rejects boolean symmetric_mode_media.
    - Locking VerifyMode, LastReEncStat, and GeneralStatus Get reject boolean enum coercion.
  - Consensus:
    - Awaiting independent reviewer labels; current consensus gate excludes the new tag until promoted.
  - Repair outcome:
    - `engine.py` enum validators now reject booleans before numeric parsing for several declared enum types.
    - Targeted tag 12 / 0, full sourced 3884 / 0, synthetic 235 / 0, unit suite 1041 passed, covered docs 656.
- `delete-absent-object-doc`
  - Added 2 sourced cases; not yet consensus-promoted.
  - Concepts: `table-methods`, `delete`, `object-existence`, `invalid-invoking-id`.
  - Official docs used: `core/5.3.3.3.txt`, `core/5.3.3.3.1.txt`, `core/5.3.3.3.2.txt`.
  - Added coverage:
    - Delete on NULL UID cannot succeed.
    - Delete on all-ones UID cannot succeed.
  - Repair outcome:
    - No solver code change was required; the existing Delete expectation already rejected success for non-deletable/non-existing invoking objects.
    - Unit coverage was extended so Get/Set/Delete all share the absent-object regression test.
    - Targeted tag 2 / 0, full sourced 3886 / 0, synthetic 235 / 0, unit suite 1041 passed, covered docs 657.
- `chmac-fixed-bytes-doc`
  - Added 24 sourced cases; not yet consensus-promoted.
  - Concepts: `credential`, `c-hmac`, `fixed-bytes`, `key-material`, `set`, `get-postcondition`.
  - Official docs used: `core/5.1.3.18.txt`, `core/5.1.3.19.txt`, `core/5.1.3.20.txt`, `core/5.1.3.21.txt`, `core/5.3.2.26.txt`, `core/5.3.2.27.txt`, `core/5.3.2.28.txt`, `core/5.3.2.29.txt`.
  - Added coverage:
    - C_HMAC_160/256/384/512 Key Set accepts exact bytes_20/32/48/64 and rejects short fixed-byte values.
    - C_HMAC_160/256/384/512 Key Get accepts exact fixed-byte returns and rejects short successful return cells.
  - Repair outcome:
    - `semantics.py::_chmac_key_length` now enforces fixed Key length on successful Set attempts.
    - `expectations.py::_credential_get_column_types` maps C_HMAC Key columns to bytes_20/32/48/64.
    - `engine.py::_return_cell_type_valid` now validates bytes_20, bytes_48, and bytes_64 successful return cells.
    - Targeted tag 24 / 0, full sourced 3914 / 0, synthetic 235 / 0, unit suite 1044 passed, covered docs 663.
- `hsha-fixed-bytes-doc`
  - Added 16 sourced cases; not yet consensus-promoted.
  - Concepts: `crypto-template`, `h-sha`, `fixed-bytes`, `proof`, `accumulator`, `get-postcondition`.
  - Official docs used: `core/5.1.3.18.txt`, `core/5.1.3.19.txt`, `core/5.1.3.20.txt`, `core/5.1.3.21.txt`, `core/5.6.3.1.txt`, `core/5.6.3.2.txt`, `core/5.6.3.3.txt`, `core/5.6.3.4.txt`.
  - Added coverage:
    - H_SHA_1/256/384/512 Proof and Accumulator Get accepts exact bytes_20/32/48/64 and rejects short successful return cells.
  - Repair outcome:
    - `expectations.py::_credential_get_column_types` maps H_SHA Proof/Accumulator to bytes_20/32/48/64.
    - `expectations.py::_expected_get` now applies those fixed-byte validators to H_SHA successful Get responses.
    - Targeted tag 16 / 0, full sourced 3930 / 0, synthetic 235 / 0, unit suite 1045 passed, covered docs 667.
- `tperinfo-get-types-doc`
  - Added/expanded 10 sourced cases; not yet consensus-promoted.
  - Concepts: `tperinfo`, `get`, `typed-return`, `uid`, `gudid`, `bytes-12`, `uinteger`, `programmatic-reset`, `boolean`.
  - Official docs used: `core/5.1.3.txt`, `core/5.1.3.10.txt`, `core/5.1.3.16.txt`, `core/5.1.3.81.txt`, `core/5.1.3.82.txt`, `core/5.1.3.93.txt`, `core/5.1.3.97.txt`, `core/5.4.2.1.txt`, `core/5.4.2.1.1.txt`, `core/5.4.2.1.3.txt`, `opal/4.2.3.1.txt`.
  - Added coverage:
    - TPerInfo UID Get accepts uid/bytes_8 and rejects short bytes.
    - TPerInfo GUDID Get accepts bytes_12 and rejects short bytes.
    - TPerInfo ProgrammaticResetEnable Get accepts boolean and rejects non-boolean text.
    - TPerInfo Bytes Get accepts uinteger_8 and rejects boolean coercion.
    - TPerInfo ProtocolVersion Get accepts uinteger_4 and rejects negative values.
  - Repair outcome:
    - `expectations.py::_expected_get` now applies TPerInfo return-cell type validation for UID, uinteger metadata columns, GUDID, and ProgrammaticResetEnable.
    - `engine.py::_return_cell_type_valid` now validates `boolean`, `bytes_8`, `bytes_12`, and uinteger typed return cells.
    - Targeted tag 10 / 0, full sourced 3954 / 0, synthetic 235 / 0, unit suite 1046 passed, covered docs 673.
- `sp-frozen-get-type-doc`
  - Added/expanded 6 sourced cases; not yet consensus-promoted.
  - Concepts: `sp-table`, `get`, `typed-return`, `uid`, `bytes`, `uinteger`, `frozen`, `boolean`, `lifecycle`.
  - Official docs used: `core/5.1.3.10.txt`, `core/5.1.3.81.txt`, `core/5.1.3.97.txt`, `core/5.4.2.4.txt`, `core/5.4.2.4.1.txt`, `core/5.4.2.4.6.txt`, `core/5.4.2.4.8.txt`.
  - Added coverage:
    - SP UID Get accepts uid/bytes_8 and rejects short bytes.
    - SP Bytes Get accepts uinteger_8 and rejects boolean coercion.
    - SP Frozen Get accepts boolean and rejects arbitrary text in a successful response.
  - Repair outcome:
    - `expectations.py::_expected_get` now applies return-cell validation to SP UID, Bytes, LifeCycleState, and Frozen columns.
    - Reuses the shared bytes/uinteger/boolean typed-return validators introduced during the typed-return sweep.
    - Targeted tag 6 / 0, full sourced 3960 / 0, synthetic 235 / 0, unit suite 1047 passed, covered docs 673.
- `lockinginfo-get-types-doc`
  - Added 6 sourced cases; not yet consensus-promoted.
  - Concepts: `locking-info`, `get`, `typed-return`, `uid`, `uinteger`, `maxranges`, `max-reencryptions`.
  - Official docs used: `core/5.1.3.81.txt`, `core/5.1.3.93.txt`, `core/5.7.2.1.txt`, `core/5.7.2.1.1.txt`, `core/5.7.2.1.3.txt`, `core/5.7.2.1.5.txt`, `core/5.7.2.1.6.txt`.
  - Added coverage:
    - LockingInfo UID Get accepts uid/bytes_8 and rejects short bytes.
    - LockingInfo MaxRanges Get accepts uinteger_4 and rejects boolean coercion.
    - LockingInfo MaxReEncryptions Get accepts uinteger_4 and rejects negative values.
  - Repair outcome:
    - `expectations.py::_expected_get` now applies return-cell type validation to LockingInfo UID, Version, EncryptSupport, MaxRanges, and MaxReEncryptions.
    - Reuses shared bytes/uinteger/enum typed-return validators.
    - Targeted tag 6 / 0, full sourced 3966 / 0, synthetic 235 / 0, unit suite 1048 passed, covered docs 673.
- `source-backfill-2026-05-31-lifecycle-types-data-removal`
  - Added source links only; no new cases and not consensus-promoted as a separate tag.
  - Official docs linked: `core/5.1.2.txt`, `core/4.1.txt`, `opal/1.7.txt`.
  - Existing tags strengthened:
    - `set-rowvalues-doc` now cites Types Encoding for Named/List Set value grouping.
    - `locking-feature-lifecycle-doc` now cites SP lifecycle overview.
    - `data-removal-doc` now cites Opal terminology for data removal / Eradicate.
  - Verification:
    - Targeted tags all 0 mismatches.
    - Doc coverage improved to 676 covered docs and 74 untriaged A/B.
- `source-backfill-2026-05-31-boolean-ace`
  - Added source link only; no new cases and not consensus-promoted as a separate tag.
  - Official doc linked: `core/5.1.3.11.txt`.
  - Existing tag strengthened:
    - `ace-booleanexpr-capacity-doc` now cites the boolean_ACE operator definition directly.
  - Verification:
    - `ace-booleanexpr-capacity-doc`: 12 / 0.
    - Doc coverage improved to 677 covered docs and 73 untriaged A/B.
- `source-backfill-2026-05-31-clock-types`
  - Added source links only; no new cases and not consensus-promoted as a separate tag.
  - Official docs linked: `core/5.1.3.23.txt`, `core/5.1.3.24.txt`, `core/5.1.3.44.txt`.
  - Existing tag strengthened:
    - `opal-clock-template-unsupported-doc` now cites Clock Template type internals as well as method definitions.
  - Verification:
    - `opal-clock-template-unsupported-doc`: 28 / 0.
    - Doc coverage improved to 680 covered docs and 70 untriaged A/B.
- `source-backfill-2026-05-31-lifecycle-reference-types`
  - Added source links only; no new cases and not consensus-promoted as a separate tag.
  - Official docs linked:
    - `core/4.4.txt`
    - `core/5.4.5.1.txt`
    - `opal/5.2.1.2.txt`
    - `core/5.1.3.4.txt`
    - `core/5.1.3.9.txt`
    - `core/5.1.3.12.txt`
    - `core/5.1.3.47.txt`
    - `core/5.1.3.54.txt`
    - `core/5.1.3.61.txt`
    - `core/5.1.3.70.txt`
    - `core/5.1.3.75.txt`
    - `core/5.1.3.78.txt`
  - Existing tags strengthened:
    - `authority-default-cells-doc`
    - `opal-admin-issuesp-unsupported-doc`
    - `getacl-exact-acl-doc`
    - `getacl-expanded-exact-acl-doc`
    - `getacl-admin-exact-acl-doc`
    - `getacl-admin-common-exact-acl-doc`
    - `getacl-admin-locking-remaining-exact-acl-long-doc`
    - `getacl-locking-special-object-method-universe-doc`
    - `getacl-template-get-exact-acl-doc`
    - `accesscontrol-logto-default-doc`
    - `datastore-payload-doc`
  - Verification:
    - All targeted tags passed with 0 mismatches.
    - Doc coverage improved to 692 covered docs and 58 untriaged A/B.
- `source-backfill-2026-05-31-ab-coverage-closure`
  - Added source links and triage only; no new cases and not consensus-promoted as a separate tag.
  - Source-linked themes:
    - `AC_element`, certificate object refs, `type_def`, fixed key/max-bytes/name/SSC types.
    - Clock date/time name-value and enum shards, including `ExactTime` and `SetClockLow Result`.
    - integer/uinteger simple type shards.
    - RevertSP support and lifecycle heading shards.
  - Manual triage:
    - Informative purpose/scope shards: `core/1.1.txt`, `opal/1.1.txt`.
    - Duplicate pointer shards: `core/3.2.3.5.1.2.txt`, `core/3.2.3.5.1.3.txt`.
    - Parent/informative lifecycle shards: `opal/5.2.txt`, `opal/5.2.1.1.txt`.
  - Verification:
    - Full sourced suite: 3966 / 0.
    - Synthetic suite: 235 / 0.
    - Unit suite: 1048 passed.
    - Doc coverage: 744 covered docs and 0 untriaged A/B.
- `startsession-sp-busy-doc`
  - Added sourced cases and production solver repair.
  - Official docs linked:
    - `core/5.1.5.3.txt`
    - `core/5.2.3.1.txt`
    - `core/5.2.3.1.3.txt`
    - `core/5.2.3.2.txt`
    - `core/3.3.7.1.5.txt`
  - Added coverage:
    - Same-SP read-write StartSession while read-write session is open returns `SP_BUSY`.
    - Same-SP read-only StartSession while read-write session is open returns `SP_BUSY`.
    - Same-SP read-write StartSession while read-only session is open returns `SP_BUSY`.
    - Same request after `EndSession` can succeed and must not be reported as `SP_BUSY`.
  - Repair outcome:
    - Added `SP_BUSY` constant.
    - `expectations.py::_expected_start_session` now delegates open-session checks to `_expected_start_session_while_open`.
    - The rule uses reconstructed session state rather than hard-coding the new fixtures.
  - Verification:
    - `startsession-sp-busy-doc`: 8 / 0.
    - Full sourced suite: 3974 / 0.
    - Synthetic suite: 235 / 0.
    - Unit suite: 1048 passed.
    - Doc coverage: 754 covered docs and 0 untriaged A/B.
- `adminsp-rw-session-combination-doc`
  - Added sourced cases and production solver repair.
  - Official docs linked:
    - `core/5.4.4.3.txt`
    - `core/5.2.3.1.txt`
    - `core/5.2.3.1.3.txt`
    - `core/3.3.7.1.5.txt`
  - Added coverage:
    - AdminSP read-write session open, then LockingSP read-write startup cannot report `SUCCESS`.
    - AdminSP read-write session open, then LockingSP read-only startup cannot report `SUCCESS`.
    - LockingSP read-write or read-only session open, then AdminSP read-write startup cannot report `SUCCESS`.
    - AdminSP read-write startup can succeed after the LockingSP session closes.
  - Repair outcome:
    - `_expected_start_session_while_open` now enforces AdminSP read-write cross-SP exclusivity using session state.
    - The repair composes with the previous same-SP `SP_BUSY` rule and does not change EndSession cleanup.
  - Verification:
    - `adminsp-rw-session-combination-doc`: 6 / 0.
    - Full sourced suite: 3980 / 0.
    - Synthetic suite: 235 / 0.
    - Unit suite: 1048 passed.
    - Doc coverage: 757 covered docs and 0 untriaged A/B.
- `source-backfill-triage-2026-05-31-c-priority-session-level0`
  - Added source links and manual triage only; no solver change beyond the two session repairs above.
  - Source-linked docs:
    - `core/5.5.5.2.txt` into Clock Template unsupported boundary cases.
    - `opal/3.1.1.txt` into Level 0 feature descriptor cases.
  - Manual triage:
    - Packet/interface deferred: `core/3.2.3.2.1.4.txt`, `core/3.2.3.2.1.5.txt`, `core/3.3.4.3.1.txt`, `core/3.3.4.7.2.txt`.
    - Token/stream deferred: `opal/3.3.4.1.1.txt`, `opal/3.3.4.1.3.txt`.
    - Informative/covered supporting shards: `core/3.3.4.txt`, `core/3.3.4.5.txt`, `core/5.4.4.4.txt`, `core/6.2.txt`.
    - Metadata deferred: `core/5.4.2.3.txt`.
- `source-backfill-triage-2026-05-31-c-priority-clock-crypto-packet`
  - Added source links and manual triage only; no new solver behavior.
  - Source-linked themes:
    - Clock/ClockTime internals to Opal Clock Template unsupported-method boundary.
    - Column metadata IsUnique/Transactional/Next to metadata-table read-only cases.
    - TPer support flag bits and Locking Feature subfields to Level 0/Properties descriptor cases.
    - Crypto stream Fails sections to stream-open/Finalize state cases.
    - Opal byte-table granularity overview to byte-table descriptor/granularity cases.
  - Manual triage:
    - Raw token/packet/interface shards deferred for a future fixture layer.
    - Informative list-format, architecture, template, threat/use-case overview shards marked informative.
    - Generic status/type support shards marked covered indirectly where concrete method cases already exercise them.
  - Verification:
    - Targeted tags all passed with 0 mismatches.
    - Doc coverage: 786 covered docs and 0 untriaged A/B.
- `source-backfill-triage-2026-05-31-c-priority-closure`
  - Added source links and manual triage only; no new solver behavior.
  - Source-linked themes:
    - Remaining ClockTime/Clock method result/fail/lag-time shards.
    - Remaining communication property limits.
    - Remaining crypto stream result/fail shards.
    - Opal Activate support.
  - Manual triage:
    - Remaining C-priority leaf UID/CommonName/Proof/status/type shards were marked covered indirectly.
    - Secure-session key/KDF and packet fields were marked deferred for future packet/secure-message fixtures.
    - Formatting and overview shards were marked informative.
  - Verification:
    - Full sourced suite: 3980 / 0.
    - Synthetic suite: 235 / 0.
    - Unit suite: 1048 passed.
    - Doc coverage: 811 covered docs, 0 untriaged A/B/C, 349 untriaged D.
