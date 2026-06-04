# Presentation Audit Trail

Last updated: 2026-05-29 00:15 KST

This is the human-readable index for explaining how the official-document edge-case loop works, what changed in the rule-based solver, how independent consensus was recorded, and how rejected or ambiguous cases were handled.

## Current Snapshot

- Official parsed document shards: 1376
- Sourced official-document edge cases: 3692
- Consensus-accepted sourced cases: 3567
- Quarantined sourced cases: 125
- Completed independent review rows: 12006
- Official document shards referenced by sourced tests: 519
- Pending A/B cartography shards: 232
- Unit regressions: 992 passing
- Synthetic smoke cases: 229, 0 mismatches
- Full sourced run: 3692 cases, 0 mismatches
- Consensus-gated sourced run: 3567 accepted cases, 0 mismatches
- Public eval: 100.00

## Source Of Truth Files

- `tools/run_sourced_edges.py`: all official-document-sourced test definitions, evidence sources, rule summaries, tags, concepts, repair paths, and repair hints.
- `analysis/label_reviews/*.todo.jsonl`: blind packets sent to independent reviewers.
- `analysis/label_reviews/*.jsonl`: completed independent reviewer labels, confidence, rationale, concerns, and source refs.
- `analysis/label_consensus_matrix.json`: one row per sourced case with author label, reviewer votes, evidence, concepts, repair paths, consensus status, and quarantine reason.
- `analysis/accepted_sourced_cases.json`: trusted consensus corpus used by `--consensus-gate`.
- `analysis/quarantined_sourced_cases.json`: cases withheld from trusted regression data because reviewers recorded concerns or labels disagreed.
- `analysis/label_reviews/superseded/`: stale or ambiguous review rounds that were intentionally archived instead of being mixed into the current consensus.
- `analysis/solver_update_log.md`: chronological narrative of solver updates, sourced batches, review outcome, and verification commands.
- `analysis/coverage_gap_summary.md`, `analysis/doc_coverage_report.md`, `analysis/doc_inventory.jsonl`: document coverage and remaining cartography state.
- `analysis/spec_graph/`: generated rule/case/document link graph for explaining what official sections connect to which tests.

## Consensus Process

Each new sourced tag follows the same loop:

1. Add cases with explicit official evidence, rule summary, concepts, repair paths, and repair hint.
2. Run the tag locally and require 0 solver mismatches after any justified rulebase repair.
3. Export three blind review packets with `tools/label_consensus.py export`.
4. Three independent reviewers label each final response as PASS or FAIL using only packet evidence and trajectory.
5. Run `tools/label_consensus.py report`.
6. Only cases with agreement and no reviewer concerns enter `accepted_sourced_cases.json`.
7. Any concern, ambiguity, or stale packet is quarantined or archived under `analysis/label_reviews/superseded/`.

## Recent Wrapper Regressions

These cases are score-priority project/API wrapper regressions. They are verified by unit and synthetic tests, while the official sourced corpus remains reserved for literal TCG/Opal document evidence.

| Area | New Synthetic Coverage | What It Proves | Solver Impact |
| --- | ---: | --- | --- |
| C_PIN `password` max-bytes | 3 | C_PIN password values are `max_bytes(32)`: 32-byte updates can pass, 33-byte updates cannot pass, and failed overlong updates cannot poison credential state | Added maximum credential-length validation for C_PIN `PIN` writes |
| TCGstorageAPI `changePIN` | 2 | Native booleans are invalid C_PIN PIN credential payloads, and failed boolean PIN updates must not poison later authentication state | Rejected boolean values for C_PIN `PIN` before credential text conversion |
| TCGstorageAPI `lockingInfo` | 3 | Repeated LockingInfo observations may be partial, but any returned field already known from prior LockingInfo state must remain stable | Added field-present comparison for known LockingInfo values through named wrapper returns and optional cell returns |
| TCGstorageAPI `getAuthority` | 4 | `getAuthority(UserN)` must return the tracked `Authority.Enabled` boolean after successful `enableAuthority`, and failed `enableAuthority` must not mutate that tracked value | Added high-level `getAuthority` wrapper detection and boolean return validation against reconstructed Authority state |
| TCGstorageAPI `setMinPINLength` | 2 | Boolean `True`/`False` must not be coerced into `_MinPINLength` values, and a failed boolean call must not lower the previously tracked PIN minimum | Rejected native booleans before `_MinPINLength` integer parsing in `_invalid_set_values` |
| TCGstorageAPI `getMEK` | 2 | Wrapper return payloads such as `K_AES_256_Range1_Key_UID` must match the tracked Locking `ActiveKey` UID rather than raw Locking column-cell shape | Added high-level `getMEK` wrapper detection and UID-ref comparison |
| TCGstorageAPI `getRange` | 4 | After successful `setRange`, wrapper `getRange` responses must reflect tracked geometry and lock-state fields; failed `setRange` must not mutate state | Added named-field stale-state validation for high-level `getRange` |
| TCGstorageAPI `readData` | 4 | Wrapper `readData()` should return the tracked full multi-byte payload, and DataStore ACE replacement/failed writes must preserve exact bytes | Split high-level wrapper payload validation from raw byte-table omitted-endRow semantics |

## Recent Accepted Batches

| Tag | Accepted | What It Proves | Solver Impact |
| --- | ---: | --- | --- |
| `accesscontrol-meta-self-association-doc` | 12 | AccessControl meta-ACL columns (`AddACEACL`, `RemoveACEACL`, `GetACLACL`, `DeleteMethodACL`) do not themselves create AccessControl rows for the meta-methods; self-association attempts cannot succeed because the InvokingID/MethodID combination does not exist | Added a meta-method exclusion in AccessControl association existence checks so `AccessControl.GetACL`/`AddACE`/`RemoveACE`/`DeleteMethod` are not treated as callable associations |
| `syncsession-return-shape-doc` | 10 | Successful session startup must return both `HostSessionID` and `SPSessionID`; `SPChallenge` and `SPResponse` are conditional on the documented signing/challenge flow rather than always present | Added generic required/forbidden return-name validation and tracked startup `HostChallenge` state for later trusted-session response-shape checks |
| `host-properties-response-reset-long-doc` | 18 | Opal mandatory HostProperties are required in `Properties(HostProperties)` responses, while optional Core HostProperties may be omitted when unsupported; returned optional properties are still value-checked when present | Repaired HostProperties expectations to use Opal mandatory support and optional-present validation, restoring public eval to 100.00 without weakening sourced HostProperties regressions |
| `adminexch-disabled-doc` | 3 | Admin SP `AdminExch` is issued disabled: it cannot successfully start a session as `HostExchangeAuthority`, and explicit `Authenticate(AdminExch)` cannot return `SUCCESS True` or `NOT_AUTHORIZED` | Modeled Admin SP `AdminExch` as disabled by default and added Host Control Authority Enabled gating for `HostExchangeAuthority`; pruned two PASS packets after reviewer representation concerns |
| `session-manager-control-target-doc` | 9 | Session Manager control-session invocations are bounded by SMUID and the supported control-method list: non-SMUID `Properties`/`StartSession` and SP methods such as `Get`/`Set`/`Authenticate`/`Random` on SMUID cannot return normal `SUCCESS` | Added explicit SMUID non-control-method rejection in `expected_status`; pruned four draft cases after reviewer concerns about Packet.Session/trajectory abstraction |
| `tper-properties-response-constraints-doc` | 16 | Returned TPer `Properties` values must obey Table 167/168 constraints: size minimum-or-zero rules, nonnegative uinteger values, boolean typing, `AckNak` requiring `SequenceNumbers`, and `Asynchronous` requiring `MaxMethods=0` | Added TPer `Properties` parsing separate from `HostProperties` and generic known-property payload validation |
| `host-properties-response-reset-long-doc` | 18 | `Properties(HostProperties)` must return all supported current host properties; below-minimum values are coerced to Table 168 initial assumptions; later submissions supersede only supplied values; `AckNak=True` with `SequenceNumbers=False` returns both false; PowerCycle/HardwareReset/ProtocolStackReset reset HostProperties knowledge while programmatic TPerReset does not | Added HostProperties parsing, cumulative `State.host_properties`, response validation, and reset-specific HostProperties transition handling |
| `cpin-genkey-reset-reissue-long-doc` | 52 | C_PIN `GenKey` rotates the credential, resets `Tries`, leaves `Authority.Uses` unchanged, invalidates the old PIN across reset boundaries, and later explicit C_PIN `PIN` Set can intentionally reissue the old byte value | Existing C_PIN GenKey, invalidated-PIN, reset persistence, TryLimit/Tries, PIN Set reissue, and Authority Uses tracking validated; no solver repair required |
| `system-table-row-mutation-long-doc` | 8 | MethodID and AccessControl system-table rows cannot be directly created or deleted by host table-row methods in Admin or Locking SP sessions | Existing table-method target-kind checks validated; no solver repair required |
| `datastore-read-window-authority-churn-long-doc` | 33 | DataStore Get/Set ACE replacement, authority churn, explicit row windows, omitted-endRow reads, failed unauthorized Set non-mutation, and offset payload state compose correctly over long traces | Existing DataStore byte-state, ACE BooleanExpr, independent Get/Set ACE, and omitted-endRow min-length logic validated; no solver repair required |
| `authenticate-proof-tries-uses-long-doc` | 26 | `Authenticate` `Proof` is a password credential input: correct Proof returns true, failed Proof returns false and updates Tries, successful Proof resets Tries and increments Uses, and TryLimit/Authority Limit still apply | Existing Proof parsing, Authenticate boolean validation, C_PIN Tries, and Authority Uses transitions validated; no solver repair required |
| `spinfo-addace-persistence-long-doc` | 21 | Admin SP `SPInfo/Get` permits `AddACE` through `AddACEACL=ACE_Anybody`, but empty `RemoveACEACL`/`GetACLACL`/`DeleteMethodACL` remain empty; failed meta-methods do not undo ACL additions or tombstone the association | Existing dynamic ACL additions, duplicate detection, failed-meta non-mutation, and deleted-association tracking validated; no solver repair required |
| `locking-toggle-reenable-long-doc` | 34 | Disabled read/write lock features make stored lock cells ineffective but do not prevent Set from changing those cells; re-enable exposes the current stored value, and matching LockOnReset only locks after the feature is enabled before reset | Existing Locking RangeState Set transitions, disabled-lock host I/O, reset handling, and Level 0 Locked computation validated; no solver repair required |
| `cpin-genkey-tries-limit-long-doc` | 26 | `GenKey` on `C_PIN_User1` rotates the credential, resets observable `Tries`, rejects oversized `PinLength`/non-RSA `PublicExponent`, invalidates the prior PIN for `StartSession` and `Authenticate`, and does not increment `Authority.Uses` | Existing GenKey, invalidated-PIN, C_PIN Tries, and Authority Uses state tracking validated; no solver repair required |
| `getacl-admin-locking-remaining-exact-acl-long-doc` | 34 | Remaining issued Admin/Locking AccessControl rows must return the exact documented ACL through `GetACL`, including descriptor-object rows, MethodID object rows, Admin `Authority_Admin1.Set`, and Locking ACE-object `Set` rows | Generalized exact GetACL validation for Admin wildcard descriptor/MethodID/ACE/Authority/Template rows and Locking descriptor/MethodID/ACE rows; updated one unit to include the required `ACE_Anybody` return payload |
| `datastore-split-ace-offset-granularity-long-doc` | 30 | DataStore Get and Set ACEs are independent and replaceable; authorized writes at structured row offsets, raw `startRow` offsets, and omitted `Where` compose into exact byte payloads; unauthorized Set and mandatory-granularity failures do not mutate later reads | Existing DataStore ACE replacement, byte-offset reconstruction, unauthorized-Get empty result, failed-Set non-mutation, and granularity validation were stress-tested; no solver repair required |
| `ace-booleanexpr-long-doc` | 19 | ACE `BooleanExpr` is evaluated against the authorities authenticated in the current session: OR preserves either Admin/User access, AND requires both authorities in the same session, and successful ACE.Set changes later C_PIN/DataStore authorization | Existing ACE expression evaluator and explicit-authentication session state validated; no solver repair required |
| `protocol-stack-reset-long-doc` | 30 | `TCGReset`/`ProtocolStackReset`/`StackReset` abort stale sessions and pending StartTrustedSession startup IDs, but do not apply Opal `LockOnReset` or `MBRDoneOnReset`; fresh sessions can observe preserved Locking, MBRControl, DataStore, and TPerInfo state | Existing protocol-stack reset model validated under long trajectories; no solver repair required |
| `locking-disabled-disregard-long-doc` | 25 | Disabled read/write lock features make their stored locked cells and matching LockOnReset ineffective for host I/O and Level 0 Locked without erasing stored cells; re-enabling a feature makes the stored locked cell meaningful again | Fixed reset handling for the S0 disabled state so matching LockOnReset does not set locked cells when both read and write locking are disabled |
| `create-table-name-commonname-long-doc` | 21 | `CreateTable` reserves exactly the successful `NewTableName`/`CommonName` pair within the SP Table table: identical pairs cannot be created twice, same-name or same-CommonName alone is allowed, and failed attempts do not reserve a pair | Existing created-table name tracking validated with three-reviewer consensus and no concerns |
| `level0-range-crossing-locking-doc` | 11 | The observed Opal SSC V2 `RangeCrossingBehavior` bit constrains later unlocked host read/write behavior across multiple Locking ranges, while single-range I/O and locked-range protection remain separate | Added `State.range_crossing_behavior`, Level 0 descriptor transition tracking, and host-I/O enforcement for multi-range read/write commands |
| `getacl-admin-common-exact-acl-doc` | 30 | Remaining Admin SP preconfigured common table/SP method associations must return the exact documented ACL list from `GetACL` | Expanded Admin SP exact GetACL mappings and corrected the `LockingSP.Activate` association interpretation |
| `level0-opal-ssc-v2-feature-doc` | 12 | Opal SSC V2 Level 0 descriptor fields must satisfy fixed length/code, minimum ComID/Admin/User authority counts, and allowed enum-like values for minor version, range crossing, SID PIN indicator, and SID PIN-on-Revert behavior | Added generic allowed-value return validation and Opal SSC V2 feature semantic expectations |
| `level0-geometry-feature-doc` | 8 | Geometry Reporting Level 0 descriptor fields must mirror observed LockingInfo logical block size, alignment granularity, lowest aligned LBA, and alignment-required state | Added descriptor value validation against reconstructed LockingInfo geometry state |
| `locking-reset-session-boundary-doc` | 14 | Reset events abort open sessions; only matching reset types apply matching `LockOnReset` cells; disabled TPER reset leaves open-session/state observations unchanged | Validated existing reset/session/LockOnReset state machine under longer trajectories |
| `created-table-deletemethod-tombstone-doc` | 7 | Successful `DeleteMethod` tombstones a created table method association, so later `GetACL`/`AddACE`/`RemoveACE`/second `DeleteMethod` cannot succeed | Validated existing deleted-association state tracking under longer meta-ACL trajectories |
| `ace-get-preconfig-cells-doc` | 13 | Authorized `ACE.Get` must report documented preconfigured `BooleanExpr`/`Columns`, and later `BooleanExpr` observations follow successful personalization; three representation-concern cases were quarantined | Added ACE returned-cell validation, personalization-aware ACE Get expectations, and official string BooleanExpr parsing |
| `reencrypt-status-enum-doc` | 6 | `LastReEncStat` and `GeneralStatus` Get responses must not return reserved enum values; two spelling/range-ambiguity cases were quarantined | Added returned enum validators for re-encryption status cells |
| `reencrypt-progress-status-postcondition-doc` | 6 | `PAUSE_req` origin determines `GeneralStatus`, and `START_req` begins with all-ones `LastReEncryptLBA` before progress | Fixed re-encryption request side effects for progress/status cells and later Get validation |
| `reencrypt-request-postcondition-doc` | 10 | Successful `START`, `PAUSE`, `CONT`, and `RETIDLE` requests must be visible in later `ReEncryptState` Gets | Locked in existing request-transition model with longer consensus-reviewed postcondition traces |
| `data-removal-interrupted-bit-doc` | 7 | Fresh and post-successful-`GenKey` Data Removal Feature descriptors must report the Interrupted bit clear; a shortened field-name alias was quarantined | Added conditional explicit-field validation for `DataRemovalOperationInterrupted` |
| `activekey-advkey-state-doc` | 12 | `ActiveKey`/`NextKey` observations follow direct Set and `ADVKEY_req` transitions, including K_AES family/range refs | Added known-state tracking and canonical media-key ref comparison for Locking Get cells |
| `getacl-admin-exact-acl-doc` | 16 | Exact GetACL lists for Admin SP C_PIN, Authority, TPerInfo, and DataRemovalMechanism preconfigured rows | Expanded Admin SP exact ACL mappings and ACE canonicalization |
| `getacl-global-kaes-exact-acl-doc` | 16 | Exact GetACL lists for Locking_GlobalRange and K_AES_128/K_AES_256 GlobalRange/Range1 Get/GenKey associations | Expanded exact ACL mapping and ACE canonicalization for GlobalRange and K_AES family/range-specific GenKey ACEs |
| `auth-tries-uses-composite-doc` | 10 | Long authentication trajectories combining C_PIN `TryLimit`/`Tries` with Authority `Limit`/`Uses` | Fixed Authority `Limit`/`Uses` Set tracking when columns 15/16 are written without companion Authority columns |
| `getacl-expanded-exact-acl-doc` | 10 | Exact GetACL lists for Locking_Range1 Get/Set, K_AES_256_Range1_Key Get, and Authority_User1 Set | Expanded exact ACL mapping and made GetACL uidref comparison equality-based |
| `datastore-ace-replacement-doc` | 8 | DataStore Get/Set ACE BooleanExpr personalization replaces the Admins default; Admins no longer remains implicitly authorized | Fixed DataStore Get/Set authorization to follow configured ACE BooleanExpr instead of hard-coded Admins |
| `datastore-sparse-rework-doc` | 4 | Narrow rework of sparse-fill ambiguity with final reads under explicitly authorized authorities | Keeps trusted sparse-fill regression separate from disputed Admin-after-personalization cases |
| `datastore-sparse-fill-doc` | 8 | Sparse DataStore writes, later gap fill, partial overwrite, Set-only User1 behavior, Get ACE personalization, and failed-Set non-mutation | Existing DataStore offset/payload model validated; two Admin-after-Get-ACE-personalization cases quarantined |
| `datastore-authority-churn-long-doc` | 26 | Long DataStore traces across Admin/User1 authority changes, Set/Get ACE replacement, Set-only writes, failed unauthorized writes, mandatory granularity, no-op Set, and exact byte-slice Gets | Existing DataStore payload/ACE/granularity model validated with three-reviewer consensus and no concerns |
| `auth-tries-uses-long-doc` | 22 | Long C_PIN/Authority traces across explicit Authenticate, failed and successful StartSession, host Tries/PIN/Uses Set, TryLimit zero, and Authority Limit exhaustion | Existing TryLimit/Tries and Authority Limit/Uses state model validated with three-reviewer consensus and no concerns |
| `created-table-association-scope-long-doc` | 28 | Long created-table AccessControl traces proving AddACE/RemoveACE/DeleteMethod state is scoped to the exact InvokingID/MethodID pair across TableUID Get/Set/Next and descriptor Get | Existing dynamic ACL and DeleteMethod tombstone scoping validated with three-reviewer consensus and no concerns |
| `datastore-offset-stress-long-doc` | 34 | Long DataStore byte-table traces across overlapping writes, raw `startRow` Set, omitted-Where leading overwrite, no-op Set, invalid column Values, mandatory-granularity failures, and exact row-bounded Gets | Existing DataStore offset/payload/granularity model validated with three-reviewer consensus and no concerns |
| `session-startup-security-long-doc` | 32 | Long StartSession security traces across HostChallenge password matching, latest Authority `Secure`/`HashAndSign` state, SignedHash presence, exchange-authority role mismatches, and C_PIN-as-inappropriate exchange credential | Reviewer feedback exposed a general model bug: exchange credentials were treated as valid when merely non-null. Added credential-symbol tracking and reject C_PIN password credentials for session-key exchange |
| `starttrusted-session-id-long-doc` | 16 | StartTrustedSession must use the HostSessionID and SPSessionID assigned in the preceding StartSession/SyncSession exchange, including non-default IDs and restarted-session stale-ID rejection | Added session ID tracking to `Session`, parsed returned startup IDs, and rejected mismatched StartTrustedSession IDs |
| `accesscontrol-meta-acl-columns-long-doc` | 27 | AccessControl `ACL`, `AddACEACL`, `RemoveACEACL`, `GetACLACL`, and `DeleteMethodACL` are independent row columns; successful ACL mutation does not change meta-ACL authorization | Existing meta-ACL model validated with long trajectories across Admin SP SPInfo/Get, Locking C_PIN_User1/Set, DataStore, MBRControl, and K_AES associations |
| `locking-reset-long-trajectory-doc` | 10 | Longer LockOnReset traces across enable columns, manual lock clearing, Programmatic reset, host I/O, and Level 0 Locked | Existing Locking state machine validated on hidden-score-like trajectories |
| `locking-multi-range-long-get-doc` | 20 | Long multi-range Locking traces across PowerCycle, HardwareReset, Programmatic reset, manual unlocks, enabled-column changes, stored-cell Gets, and Level 0 Locked | Existing independent per-row LockOnReset/stored-cell/Level0 logic validated with three-reviewer consensus and no concerns |
| `created-table-delete-object-doc` | 4 | `Delete` on a created Table descriptor is a table-deletion path and removes stale AccessControl associations | Added descriptor-object Delete handling and reused created-table lifecycle cleanup |
| `created-table-delete-acl-doc` | 4 | Deleting a created table descriptor removes stale AccessControl associations for both the table UID and descriptor UID | Added created-table lifecycle cleanup for descriptor DeleteRow, including table/descriptor ACL state cleanup |
| `created-table-meta-acl-doc` | 6 | `CreateTable` creates AccessControl associations for the new table, and `GetSetACL` controls `GetACL`/`DeleteMethod` meta-method authorization | Added created-table `GetSetACL` state tracking, created association existence, and post-`DeleteMethod` association removal checks |
| `created-table-dynamic-getacl-doc` | 10 | Successful created-table `AddACE`/`RemoveACE` mutations must be visible in later `GetACL` results, without assuming otherwise unknown initial ACL members | Added required/forbidden returned UID-ref constraints and wired dynamic ACL addition/removal state into `GetACL` payload validation |
| `created-row-accesscontrol-doc` | 10 | `CreateRow` creates row-object AccessControl associations with non-empty ACE uidref ACLs, and `DeleteRow` removes only the deleted row's stale associations | Added created-row association recognition, minimum GetACL uidref-list length checks, strict uidref-list validation, and row-level ACL cleanup after DeleteRow |
| `created-row-delete-object-acl-doc` | 10 | Direct `Delete` on a created row object has DeleteRow-equivalent side effects: empty success return, row ACL cleanup, unique-value release for that row, and sibling preservation | Added created-row handling in `_expected_delete` and reused row-state cleanup from `_apply_delete_success` |
| `created-row-meta-acl-state-doc` | 12 | Created row object AccessControl associations support meta-ACL state: AddACE/RemoveACE mutate later ACL observations and DeleteMethod tombstones the association | Added created-row meta-ACL authority tracking from the creation session and routed meta-method authorization through that state |
| `created-row-method-association-doc` | 11 | `DeleteMethod` tombstones only the specified row-object method association: row `Delete` tombstone blocks direct Delete, while sibling rows and unrelated methods survive | Validated per-method tombstone scoping after the created-row meta-ACL repair |
| `created-row-failed-meta-nonmutation-doc` | 9 | Failed created-row AddACE/RemoveACE/DeleteMethod attempts do not mutate ACL or tombstone state; later successful calls still define behavior | Validated success-only transition application for row-object meta-methods |
| `created-row-cleanup-acl-state-doc` | 8 | Row deletion cleans up dynamic ACL additions/removals and DeleteMethod tombstones for the deleted row without leaking to siblings | Validated row-level cleanup after DeleteRow and direct row-object Delete |
| `datastore-long-trajectory-doc` | 6 | Interleaved Admin/User DataStore partial overwrites, Set-only read denial, later Get ACE personalization, and failed-Set non-mutation | Existing DataStore payload/ACE model validated on longer traces |
| `genkey-reencrypt-state-doc` | 5 | K_AES range-key `GenKey` cannot report `SUCCESS` while the associated range `ReEncryptState` is non-IDLE | Existing GenKey/ReEncryptState gate validated with stronger evidence |
| `addace-acl-state-doc` | 4 | `AddACE` mutates ACL state and duplicate additions are invalid | Added dynamic AccessControl ACL state tracking |
| `locking-host-io-impossible-doc` | 4 | Enabled locked host I/O cannot report normal `SUCCESS`; avoids exact Data Protection Error status claims | Existing host I/O lock model validated with stronger evidence |
| `data-removal-feature-doc` | 12 | Level 0 Data Removal Feature descriptor version, length, processing bit, and mechanism/operation bit masks | Added descriptor bit-mask expectations and comparison |
| `meta-acl-preconfig-empty-doc` | 8 | Known Opal preconfigured AccessControl rows can have empty AddACE/RemoveACE/DeleteMethod meta-ACL columns | Generalized row-specific meta-ACL authorization |
| `locking-feature-reset-doc` | 8 | LockOnReset reset effects are visible in the Level 0 Locking Feature Locked bit | Existing reset/descriptor logic validated |
| `locking-feature-mbr-reset-doc` | 8 | MBRControl DoneOnReset effects are visible in the Level 0 MBRDone bit | Existing reset/descriptor logic validated after evidence refresh |
| `mbrcontrol-reset-get-doc` | 8 | Reset effects must also be visible through later `MBRControl.Get` cells | Existing MBR state tracking validated |
| `datastore-cross-authority-doc` | 8 | User1 Set-only DataStore writes mutate bytes, unauthorized User1 Get returns empty, later Admin Get sees current bytes | Existing DataStore offset/payload and ACE-state model validated |
| `getacl-exact-acl-doc` | 12 | `GetACL` must return the exact ACE uidrefs for known preconfigured associations | Added exact expected ACE uidref validation |

## Rejected Or Reworked Cases

- `analysis/quarantined_sourced_cases.json` currently holds 49 cases. They are not part of trusted regression data.
- `adminexch-disabled-doc`, `session-manager-control-target-doc`, `tper-properties-response-constraints-doc`, `host-properties-response-reset-long-doc`, `cpin-genkey-reset-reissue-long-doc`, `system-table-row-mutation-long-doc`, `datastore-read-window-authority-churn-long-doc`, `locking-reset-session-boundary-doc`, `level0-geometry-feature-doc`, `level0-opal-ssc-v2-feature-doc`, `getacl-admin-common-exact-acl-doc`, `level0-range-crossing-locking-doc`, `create-table-name-commonname-long-doc`, `locking-disabled-disregard-long-doc`, `protocol-stack-reset-long-doc`, `ace-booleanexpr-long-doc`, `datastore-split-ace-offset-granularity-long-doc`, and `getacl-admin-locking-remaining-exact-acl-long-doc` had no quarantined cases in their retained packets: all promoted labels passed three-reviewer consensus with no recorded concerns.
- Two draft `adminexch-disabled-doc` PASS packets were pruned before promotion: the exact `NOT_AUTHORIZED` StartSession PASS packet abstracted away failure `SyncSession` identifiers, and the exact explicit `Authenticate SUCCESS False` PASS packet had one reviewer concern about proof/challenge syntax for a non-Password authority. The retained three impossible-response cases still validate the model repair without carrying those representation caveats.
- Four draft `session-manager-control-target-doc` packets were removed before promotion rather than quarantined because reviewers correctly flagged Packet.Session/trajectory-abstraction concerns for cases that tried to assert SMUID `Get`/`Set`/`GetACL` behavior after a regular SP session was open, plus one abstract `StartSession` PASS packet with incomplete startup-field representation. The retained nine-case batch is the trusted source.
- `ace-get-preconfig-cells-doc-eb108b7799`: quarantined because reviewers accepted the `ACE_C_PIN_User1_Set_PIN` default `Admins OR User1` label but recorded concerns about how the `*ACE1` support annotation is represented in the returned BooleanExpr.
- `ace-get-preconfig-cells-doc-7e83181090` and `ace-get-preconfig-cells-doc-e570c05a49`: quarantined because reviewers agreed with the labels but recorded concerns that the trajectory set the ACE expression using the User1 UID and later observed/rendered it as symbolic `User1`. The accepted cases still cover preconfigured ACE `Columns`/`BooleanExpr` validation and non-ambiguous personalization behavior.
- `reencrypt-status-enum-doc-88728e441d`: quarantined because one reviewer accepted the named enum value `Success` but recorded a concern that the target used an associated-value name rather than a numeric enum value.
- `reencrypt-status-enum-doc-55404770cc`: quarantined because one reviewer agreed with the FAIL label but recorded a concern about reconciling the `gen_status` table's state-range wording with the reserved-value rows.
- `data-removal-interrupted-bit-doc-d14ca120e9`: quarantined because the target response used the shortened spelling `OperationInterrupted` rather than the official descriptor field name `Data Removal Operation Interrupted`; one reviewer labeled it FAIL and the other two recorded concerns/low confidence.
- `datastore-sparse-fill-doc-25d98e253f` and `datastore-sparse-fill-doc-1f3d6b78ca`: quarantined because one reviewer still treated Admins as authorized after DataStore Get ACE personalization to User1, while two reviewers applied ACE replacement semantics. The direct `datastore-ace-replacement-doc` cases cover the replacement rule and are accepted.
- `created-table-delete-acl-doc-e1be4004ed`: quarantined because two reviewers recorded concerns that the packet inferred `NewTableName`/`CommonName` reuse after descriptor deletion without an explicit reuse-policy source. The AccessControl deletion cases in the same batch remain accepted.
- `analysis/label_reviews/superseded/2026-05-24-cpin-user-ace-user1-only-ambiguity/`: archived draft cases that assumed `User1`-only C_PIN ACE BooleanExpr was forbidden. Reviewers correctly noted the cited Opal text guarantees `Admins` and `Admins OR UserMMMM`, but does not prove every vendor extension is impossible.
- `analysis/label_reviews/superseded/2026-05-24-locking-reset-evidence-refresh/`: archived reset cases whose first packet lacked enough reset-type mapping evidence.
- `analysis/label_reviews/superseded/2026-05-24-locking-feature-mbr-reset-evidence-refresh/`: archived MBR reset descriptor cases until explicit Programmatic/TPer reset support was added to the evidence set.
- `analysis/label_reviews/superseded/2026-05-24-datastore-raw-bytes/`: archived an earlier DataStore payload review round before the DataStore byte-table assertions were narrowed and strengthened.
- `analysis/label_reviews/superseded/2026-05-24-getacl-exact-acl-order-refresh/`: archived first exact-GetACL review round because a reviewer flagged possible ACE-list order ambiguity. The accepted regenerated packet uses Opal table order for the multi-ACE `MBRControl.Set` ACL.
- `addace-acl-state-doc` arbitrary nonexistent ACE UID case: kept in quarantine because reviewers noted the evidence did not fully exclude vendor extension ACE rows. The duplicate/preexisting ACE cases remain accepted.
- Earlier `locking-doc` exact-status cases: regenerated as `locking-host-io-impossible-doc` with explicit MBRControl inactive context and only impossible-`SUCCESS` assertions. The regenerated cases passed consensus; the original exact-status quarantines remain historical.
- Earlier `genkey-doc` ReEncryptState cases: regenerated as `genkey-reencrypt-state-doc` with symbolic `ReEncryptState` values and explicit ReEncryptState/K_AES evidence. The regenerated cases passed consensus; the original raw-column quarantines remain historical.

## Algorithm Repairs That Came From Missed Edge Cases

- AdminExch issued-disabled startup/authentication:
  - Admin SP `AdminExch` is now treated as disabled by default in `_authority_is_enabled`.
  - `StartSession` now derives the Host Control Authority from `HostSigningAuthority` or, when absent, `HostExchangeAuthority`, and rejects disabled host-control authorities before allowing startup success.
  - This fixes the broad class of startup traces where an exchange authority was syntactically valid for the parameter role but still not authenticatable because its Authority state is disabled.
- Session Manager control-session boundary:
  - Added an explicit `CONTROL_SESSION_METHODS` guard in `expected_status`.
  - Explicit SMUID targets now reject non-control MethodIDs such as `Get`, `Set`, `Authenticate`, and `Random` instead of falling through to generic SP-method logic.
  - Non-SMUID `Properties` and `StartSession` impossible-success cases are recorded as sourced regressions; draft cases with Packet.Session ambiguity were pruned before acceptance.
- TPer Properties response validation:
  - Added `ExpectedResponse.validate_tper_properties`.
  - Added `_returned_tper_properties` so returned TPer `Properties` are parsed separately from returned `HostProperties`.
  - Added `_tper_properties_valid` to reject impossible known-property payloads: below-minimum size values, negative uinteger properties, non-boolean boolean properties, `AckNak=True` with `SequenceNumbers=False`, and `Asynchronous=True` with nonzero `MaxMethods`.
  - Omitted unsupported properties and vendor extension name/value pairs remain tolerated.
- HostProperties state and response validation:
  - Added `ExpectedResponse.expected_return_properties` and HostProperties comparison in `compare_expected_actual`.
  - Added `ExpectedResponse.optional_return_properties` so optional Core HostProperties are checked when present without requiring unsupported Opal devices to return them.
  - Added `State.host_properties` to track the TPer's cumulative knowledge of host communication capabilities.
  - `Properties(HostProperties)` now requires the Opal mandatory host-property set, validates returned optional properties when present, and preserves prior observed support across later responses.
  - PowerCycle, HardwareReset, and ProtocolStackReset reset HostProperties knowledge to initial assumptions; programmatic TPerReset and other reset events preserve it.
- SyncSession/StartTrustedSession return-shape validation:
  - Added generic required and forbidden return-name checks for successful method responses.
  - Successful StartSession now requires `HostSessionID` and `SPSessionID`.
  - `SPChallenge` is forbidden unless the host signing authority directly invokes a signing credential, and `SPResponse` is forbidden in StartTrustedSession unless the original startup contained a host challenge.
  - `Session.startup_host_challenge` records this startup context for the later trusted-session exchange.
- AccessControl meta-method non-association:
  - The AccessControl table has meta-ACL columns for `AddACE`, `RemoveACE`, `GetACL`, and `DeleteMethod`, but those column names are not AccessControl associations for the meta-methods themselves.
  - `_combo_exists_for_get_acl` now rejects associations whose target MethodID is one of those meta-methods, so self-association `SUCCESS` outputs are rejected broadly instead of case-by-case.
- Data Removal Feature descriptor:
  - Added `ExpectedResponse.expected_return_bit_masks`.
  - Added bit-mask validation in `compare_expected_actual`.
  - Added `_expected_level0_data_removal_feature`.
  - Added explicit `DataRemovalOperationInterrupted=0` validation when that descriptor field is present in fresh/no-interruption or successful-completion trajectories.
- AccessControl meta-ACL:
  - Generalized `_known_meta_acl_authorization` so known preconfigured rows use row-specific empty/nonempty meta-ACL columns.
  - Prevented broad Admin-success behavior from overriding empty meta-ACL columns.
- Exact GetACL returns:
  - Added `ExpectedResponse.expected_return_uid_refs`.
  - Added `_return_uid_refs` and ACE canonicalization in the engine.
  - Added `_known_acl_return_refs` for DataStore, MBRControl, C_PIN_User1, ThisSP/RevertSP, Authority_User1 Set, Admin SP C_PIN/Authority/TPerInfo/DataRemovalMechanism rows, Locking_Range1 Get/Set, Locking_GlobalRange Get/Set, K_AES_128/K_AES_256 GlobalRange/Range1 Get and GenKey associations.
  - Now a syntactically valid, omitted, extra, or wrong-association ACE list fails.
- ACE Get cells and BooleanExpr parsing:
  - Added preconfigured ACE `BooleanExpr`/`Columns` return-cell validation for Admin SP and Locking SP ACE rows.
  - Successful `ACE.Set(BooleanExpr)` now changes later expected `ACE.Get(BooleanExpr)` values rather than leaving the preconfigured default in force.
  - Official string forms such as `Admins OR SID`, `Admins AND SID`, and `Admins OR User1 *ACE1` now parse into the same authority/operator model as token-list forms.
- DataStore ACE replacement semantics:
  - Added `_datastore_ace_configured`.
  - DataStore Set no longer grants Admins through the default rule once the corresponding DataStore Set ACE has been personalized.
  - DataStore Get no longer grants Admins through the default rule once the corresponding DataStore Get ACE has been personalized; unauthorized byte-table Get still returns `SUCCESS` with an empty result list.
- Authority Limit/Uses state tracking:
  - Successful `Authority.Set` of columns `0x0F`/`0x10` now updates reconstructed `Limit`/`Uses` state even when no `Enabled`, `Secure`, credential, or response-exchange column is present in the same Set.
  - Later `Authority.Get`, `StartSession`, and `Authenticate` predictions use that state, so a Limit-only Set can be observed and can block future authentication when `Uses >= Limit`.
- AddACE ACL state:
  - Added dynamic ACL addition/removal state to `State`.
  - Successful `AddACE` now mutates reconstructed ACL state.
  - Later `AddACE` rejects an ACE already present in the current ACL.
- Created-table AccessControl meta-ACL:
  - Added `State.created_table_getset_acls` and captured `CreateTable.GetSetACL` after successful table creation.
  - `GetACL`/`DeleteMethod` now recognize AccessControl associations created for newly created tables and descriptors.
  - Created-table meta-method authorization now follows the stored `GetSetACL`; empty `GetSetACL` rejects meta-method success, while `ACE_Anybody` permits it.
  - Successful `DeleteMethod` removes the created AccessControl association, so a later `GetACL` for the same pair fails.
- Created-table deletion lifecycle:
  - Added `State.created_table_name_by_uid` and a unified created-table cleanup path.
  - Successful `DeleteRow` of a created Table descriptor now removes the created table, descriptor mapping, stored rows, size/allocation state, `GetSetACL`, dynamic ACL mutations, and stale deleted-method tombstones.
  - Successful `Delete` invoked directly on a created Table descriptor now uses the same cleanup path and must return an empty list.
  - Later `GetACL` for deleted table or descriptor associations now fails because the AccessControl rows are gone.
- DataStore payload provenance:
  - Earlier repair tracks DataStore bytes by offset, applies partial overwrites, handles omitted `Where` as row zero, and compares later `Get` ranges to the reconstructed byte state.
  - Longer accepted traces now verify that failed unauthorized `Set` attempts do not mutate bytes, that Set-only User1 writes are visible to later Admin reads, and that later Get ACE personalization exposes the current payload to User1.
- Locking Feature descriptor and reset state:
  - Earlier repair maps Locking and MBR state into Level 0 descriptor bits and high-level `hasLockedRange`.
  - Reset trajectories reuse the same official state model rather than one-off case-specific patches.
  - Longer accepted LockOnReset traces now verify disabled lock-enable semantics, manual clearing after a reset, nonmatching reset preservation, enabled Programmatic reset relocking, host I/O effects, and Level 0 Locked consistency.
- Locking ActiveKey/NextKey state:
  - Added known-state tracking for `ActiveKey` and `NextKey`.
  - Successful direct `ActiveKey`/`NextKey` Set and `ADVKEY_req` transitions now constrain later `Locking.Get` values.
  - `ADVKEY_req` from `COMPLETED` or `PAUSED` moves `NextKey` to `ActiveKey` and clears `NextKey`; stale or wrong K_AES refs now fail.
- ReEncryptRequest state-machine postconditions:
  - Existing `START_req`, `PAUSE_req`, `CONT_req`, `RETIDLE_req`, and `ADVKEY_req` transition handling is now covered by later `Locking.Get(ReEncryptState)` sourced regressions.
  - These cases catch stale state reports after successful request writes.
- ReEncrypt progress/status side effects:
  - `START_req` now initializes `LastReEncryptLBA` to the all-ones sentinel when no LBA has been re-encrypted.
  - `PAUSE_req` now records `GeneralStatus=3` when pausing from `ACTIVE` and `GeneralStatus=4` when pausing from `PENDING`.
  - Later `Locking.Get` validates known `LastReEncryptLBA`, `LastReEncStat`, and `GeneralStatus` cells.
- ReEncrypt status enum validation:
  - `Locking.Get` now rejects reserved `LastReEncStat` and `GeneralStatus` enum values when those cells are returned.
  - Numeric and named valid values are handled, but name-spelling cases with reviewer concern remain quarantined out of the trusted corpus.
- Level 0 descriptor semantic validation:
  - Added `ExpectedResponse.expected_return_allowed_values`.
  - Geometry Reporting descriptors now mirror known LockingInfo geometry/alignment cells instead of being accepted as generic successful discovery payloads.
  - Opal SSC V2 descriptors now validate required fixed fields, minimum authority/ComID counts, and allowed enum-like field values.
- Admin SP exact GetACL coverage:
  - Expanded exact ACL return checking to Admin SP common preconfigured associations, including table `Next`/`Get`, `ThisSP.Authenticate`, `ThisSP.Random`, `AdminSP.Revert`, and `LockingSP.Activate`.
- RangeCrossingBehavior state:
  - Added `State.range_crossing_behavior`.
  - Successful Level 0 Opal SSC V2 discovery now records the observed range-crossing bit.
  - Later host read/write predictions apply that bit to unlocked multi-range commands while preserving locked-range protection.
- Locking SP exact GetACL coverage:
  - Expanded exact ACL return checking to additional Locking SP preconfigured AccessControl associations.
  - Added empty-ACL handling for rows where `CommonName` is populated but `ACL` is empty, preventing `ACE_Anybody` from being accepted as a returned ACL merely because it is the row common name.
  - Added ACE name aliases for Locking SP ACE/Authority/C_PIN preconfiguration rows so official names and UID references normalize to the same comparison set.
  - Quarantined two `LockingTable.Next` cases because independent reviewers could not see the exact row in the truncated blind packet snippet; these are preserved as rework candidates rather than trusted regression data.
- Failed Locking Set no-mutation:
  - Added accepted long-trajectory checks proving that failed Locking `Set` operations do not mutate later observable row state.
  - Covered overlap failures, alignment failures, duplicate-column failures, and multi-column failed `Set` cases where none of the proposed RangeStart/RangeLength/lock-state/LockOnReset changes may leak into later `Get`.
  - No solver patch was needed because existing transition handling already applied state updates only after successful events; the value is now documented and regression-tested.
- Created-table AddACE/RemoveACE runtime ACL state:
  - Added `created-table-addace-removeace-state-doc` cases around host-created table AccessControl associations whose meta-ACLs come from `CreateTable.GetSetACL`.
  - Fixed duplicate `AddACE` detection so it considers runtime ACL additions even when the association is host-created and not present in the static exact-ACL map.
  - Verified add/add failure, add/remove/add success, add/remove/add/add failure, empty `GetSetACL` authorization failure, and empty success payload shape.
  - Consensus accepted 7 of 9 cases. The two rejected/quarantined cases are preserved with reviewer rationales: one lacked numeric ACE alias evidence, and one depended on a failed-method no-mutation inference.
- Created-table RemoveACE return/authorization checks:
  - Added `created-table-removeace-failure-doc` cases for successful `RemoveACE` empty result, non-empty payload rejection, and empty-`GetSetACL` `NOT_AUTHORIZED`.
  - Consensus accepted 3 of 6. The quarantined cases document why the pipeline avoids overclaiming: nonexistent-ACE status and absent-from-ACL semantics were not explicit enough in the blind evidence packets.
- Locking Set-driven state transitions:
  - Added `locking-set-state-transition-doc` long trajectories for direct Set transitions among Locking states.
  - Verified that `LockOnReset` changes do not silently flip `ReadLocked`/`WriteLocked`, `Locked` changes do not silently clear `LockOnReset`, and disabling lock features makes stored locked cells ineffective for host I/O while leaving those cells observable.
  - Consensus accepted 14 of 16; two reset-after-Set cases were quarantined because one reviewer wanted the PowerCycle reset type mapping to be more explicit in the blind packet.
- Locking SP Disabled/Frozen lifecycle status:
  - Added `locking-lifecycle-disabled-frozen-doc` trajectories around `SPInfo.Enabled`, Admin SP `SP.Frozen`, disabled session startup, disabled in-session method blocking, re-enable `Set`, `DeleteSP`, and control-session exceptions.
  - Fixed the rulebase to recognize exact `SP_FROZEN` for frozen startup failures and exact `SP_DISABLED` for disallowed methods inside Issued-Disabled SP sessions, instead of treating those official statuses as unknown failures.
  - Consensus accepted 26 of 32; quarantined cases preserve disagreements/concerns about observed-via-Get frozen state, failure response payload shape, and ambiguous wording around setting `SPInfo.Enabled=False` while already disabled.
- Clean Disabled/Frozen lifecycle rework:
  - Added `locking-lifecycle-disabled-frozen-clean-doc` as a follow-up to convert some quarantined status checks into cleaner empty-payload failure trajectories.
  - Consensus accepted 6 of 8; the two remaining quarantines document successful `GetFreeRows` payload-content uncertainty rather than lifecycle status uncertainty.
- Admin Revert SID VU behavior:
  - Added state tracking for the Opal SSC V2 `BehaviorOfCPINSIDPINUponTPerRevert` field so behavior `0xFF` no longer incorrectly treats the old SID PIN as MSID after successful Admin SP `Revert`.
  - The new VU-specific sourced cases were intentionally quarantined by consensus because reviewers agreed on the labels but noted that the exact vendor-unique replacement value is not observable in the packet.
  - This is logged as a grounded solver repair with quarantine-limited test trust, not as a trusted edge-case score claim.
- Admin Revert Locking lifecycle clean rework:
  - Added explicit Locking SP lifecycle observation after `Activate` before applying Admin SP `Revert`, so the trusted cases no longer depend on an implicit assumption that the Locking SP had reached Manufactured.
  - Consensus accepted the later `LockingEnabled=0` consequence after Admin SP `Revert` and quarantined only the exact StartSession status variant, preserving the reviewers' status-code caveat.
  - No solver patch was needed because the existing Admin SP `Revert` model already reset an activated Locking SP to Manufactured-Inactive/OFS.
- Multi-range LockOnReset stored-cell repair:
  - The first multi-range reset attempt was intentionally rejected by two reviewers because matching reset types should set stored `ReadLocked` and `WriteLocked` cells true, even when the corresponding enabled column makes one side behaviorally ignored.
  - The solver was repaired at the reset-transition level, not by special-casing the generated examples.
  - A clean rework then validated multiple Locking rows with distinct `LockOnReset` sets, PowerCycle, Programmatic TPER_RESET, later manual unlocks, host I/O checks, and Level 0 `Locked` checks.
  - This is a strong presentation example of the consensus loop finding a real model bug before promotion to the trusted corpus.
- DataStore failed-mutation and Cellblock-default repair:
  - Added `datastore-failed-mutation-defaults-doc` to stress long DataStore byte-table trajectories where invalid column-value `Set`, no-`Values` no-op `Set`, mandatory-granularity failures, and later aligned overwrites are composed before exact `Get` checks.
  - All 19 new cases were accepted by three independent reviewers with no concerns, giving a clean example of the pipeline promoting a difficult but well-sourced DataStore batch.
  - The model was also tightened for raw byte-table `Get` calls with omitted `endRow`: Core `cell_block` defaults make the read extend to the last row, so the verifier no longer treats `Get(startRow=0)` as a one-byte exact read. The higher-level `readData()` wrapper remains payload-exact because it represents the API's host-data abstraction rather than raw Cellblock semantics.
  - A later wrapper probe found the complementary bug on the API side: high-level `readData()` with a multi-byte stored payload such as `AABB` was accidentally compared as if it were a one-byte raw `Get`. The repair now keeps raw CellBlock semantics and wrapper payload semantics separate.
  - This is a useful presentation contrast with the LockOnReset repair: here the generated cases passed after a small general semantic hardening, and consensus accepted the whole batch rather than quarantining uncertain variants.
- TryLimit explicit Authenticate result repair:
  - Added `trylimit-authenticate-result-doc` to separate session-startup lockout from explicit `Authenticate` result semantics.
  - The solver now keeps StartSession TryLimit lockout as a startup failure while modeling explicit `Authenticate` under TryLimit lockout as `SUCCESS` with result `False`, rejecting impossible `True` authentication.
  - All 11 new cases were accepted by three independent reviewers with no concerns. This gives another presentation example where a local edge-case probe exposed a general model behavior difference, then consensus promoted the repaired rule.
- Disabled authority reactivation stress:
  - Added `auth-disabled-reactivation-long-doc` to combine `Authority.Enabled=False` with preserved `C_PIN.Tries/TryLimit` and `Authority.Uses/Limit` state.
  - The accepted cases verify that disabled `Authenticate`/`StartSession` attempts gate authentication without silently clearing counters; after re-enable, lockout and use-limit checks still follow the preserved or explicitly reset cells.
  - No solver repair was needed, which is still useful for the presentation: the pipeline can document a hard official-doc corner as trusted regression even when the current model already handles it.
- RangeCrossingBehavior plus LockOnReset stress:
  - Added `locking-crossing-reset-long-doc` to combine Opal SSC V2 RangeCrossingBehavior with PowerCycle, TCGReset, enabled TPER_RESET, disabled lock sides, and manual unlock/relock flows.
  - The accepted cases pin down the intended composition: RangeCrossingBehavior=0 only helps when all crossed ranges are unlocked; RangeCrossingBehavior=1 terminates crossing transfers even if reset locks were skipped; and single-range transfers are not rejected solely because the bit is 1.
  - No solver repair was needed, but this is a strong dashboard-facing regression set because it hits the Locking state-machine area previously associated with score movement.
- TCGstorageAPI Locking wrapper repair:
  - A score-prioritized wrapper probe found that high-level `getRange()` did not validate named return values after a prior high-level `setRange()`, because no raw CellBlock columns were present in the API-shaped call.
  - The repair compares wrapper `getRange()` returns against tracked Locking geometry and lock cells only after that range has been observed or mutated, keeping raw Locking `Get` column semantics separate from TCGstorageAPI wrapper semantics.
  - A follow-up `getMEK()` probe found the same raw-vs-wrapper boundary in the K_AES path: the API returns key UID wrappers such as `K_AES_256_Range1_Key_UID`, not a raw Locking column 10 cell. The solver now checks that UID against the tracked `ActiveKey`.
  - This is presentation-useful because it shows the pipeline using the official-doc model to repair a realistic dashboard trace format, not only the canonical raw packet format.
- DataStore BooleanExpr and offset stress:
  - Added `datastore-booleanexpr-and-offset-long-doc` to combine separate DataStore Get/Set ACEs with `Admins AND User1`, `Admins OR User1`, explicit `Authenticate(User1)`, and overlapping byte-table writes.
  - The accepted cases show that payload correctness and authorization correctness are both required: a single-authority session may write but not read, or read but not write, depending on which ACE was personalized.
  - No solver repair was needed, but the batch gives a presentation-ready example of the system producing difficult, high-signal regressions rather than only patch-triggering cases.
- DataStore read-window authority churn stress:
  - Added `datastore-read-window-authority-churn-long-doc` to make the DataStore traces longer and more score-relevant: Get ACE replacement moves through User1-only, Admins-only, and Admins OR User1 while the Set ACE stays independent.
  - The accepted cases verify that unauthorized byte-table `Get` returns `SUCCESS` with empty results for both explicit windows and omitted-endRow windows, authorized omitted-endRow `Get` is not a short exact read, raw and structured Set offsets compose, and failed unauthorized Admin Set calls do not mutate bytes later visible to an authorized reader.
  - No solver repair was needed. This is still high-value audit material because it records a hard official-doc trajectory in the trusted corpus and maps any future failure directly to DataStore ACE evaluation, byte-window reconstruction, or cellblock-default logic.
- System table row-mutation guard:
  - Added `system-table-row-mutation-long-doc` to pin down a compact but important table-lifecycle invariant: MethodID and AccessControl system tables cannot be directly mutated with `CreateRow` or `DeleteRow`.
  - The accepted cases exercise both Admin SP and Locking SP sessions so a future broad “Admins can row-mutate object tables” shortcut cannot accidentally admit protected system tables.
  - No solver repair was needed; the value is in preserving this official restriction as trusted regression data alongside the richer AccessControl/GetACL batches.
- C_PIN GenKey/reset/reissue stress:
  - Added `cpin-genkey-reset-reissue-long-doc` to lengthen the C_PIN/Auth trajectory around successful and failed `GenKey`, reset persistence, old-PIN invalidation, and later authorized PIN reissue.
  - The accepted cases verify that successful `GenKey` resets `Tries`, changes the credential, and does not increment `Authority.Uses`; failed `GenKey` leaves the old PIN and `Tries` state intact; PowerCycle resets nonpersistent `Tries` while HardwareReset does not; and a later C_PIN `Set` can intentionally make the old byte value valid again.
  - No solver repair was needed. This is useful presentation material because it shows the pipeline can build a long, high-signal trusted corpus even when the model already has the right general semantics.
- GetACL/ACE separation stress:
  - Added `getacl-personalized-ace-invariant-doc` to verify that personalizing an ACE row's BooleanExpr does not change the AccessControl association's ACL uidref list returned by `GetACL`.
  - The accepted cases are useful for explaining why the system records concept metadata: a failure here would point at exact GetACL return validation or ACE/ACL state separation, not byte-table payload logic.
  - No solver repair was needed.
- Created-table dynamic GetACL repair:
  - Added `created-table-dynamic-getacl-doc` to verify that successful `AddACE` and `RemoveACE` calls on a host-created table AccessControl association are observable through later `GetACL`.
  - The solver now supports required/forbidden returned UID refs, so it can require newly added ACEs and forbid removed ACEs even when the exact initial ACL of a host-created table is not fully known.
  - The first review round correctly agreed on labels but quarantined one numeric uidref case because the packet did not prove `ACE_Admin` equals `0000000800000002`. After adding Opal Admin SP ACE preconfiguration evidence and rerunning the same reviewer ids, all 10 cases were accepted with no concerns.
- Created-row AccessControl repair:
  - Added `created-row-accesscontrol-doc` to cover the Core side effect that `CreateRow` creates AccessControl rows for the new object and those rows reference a newly created ACE.
  - The solver now recognizes created row object `Get`/`Set`/`Delete` associations, requires non-empty `GetACL` uidref lists for them, and removes the row's association state after `DeleteRow` without deleting sibling rows.
  - This batch also found a general uidref-list bug: arbitrary strings could pass because `_clean_uid` extracted hex letters. UID-list validation now uses canonical uidref/ACE-ref parsing.
  - First review round quarantined exact missing-row status claims after deletion; the clean rework avoids exact status and asserts stale `SUCCESS` impossibility. The final 10 cases were accepted with no concerns.
- Created-row Delete object repair:
  - Added `created-row-delete-object-acl-doc` to cover direct `Delete` on a row object created by `CreateRow`.
  - The solver now treats row-object `Delete` as a valid created-row deletion path, requires an empty success result, reuses row-state cleanup, removes stale row-object AccessControl state, releases only the deleted row's unique-column occupancy, and preserves sibling rows.
  - Three reviewers accepted all 10 cases with no concerns, so the batch entered the trusted corpus without rework.
- Created-row meta-ACL state repair:
  - Added `created-row-meta-acl-state-doc` to cover `AddACE`, `RemoveACE`, `GetACL`, and `DeleteMethod` on AccessControl associations created by `CreateRow`.
  - The solver now stores the authorities that seeded row-object ACL/meta-ACL state at creation time and uses that state before the generic preconfigured-row fallback.
  - The first review pass flagged two exact generated ACE UID assumptions; those packets were archived, cases were reworked to avoid exact generated UID claims, and the final 12 cases were accepted with no concerns.
- Created-row per-method tombstone validation:
  - Added `created-row-method-association-doc` to stress that `DeleteMethod` on a row object's `Delete` or `Set` association tombstones only that InvokingID/MethodID pair.
  - This batch validates that direct row `Delete` is blocked only after the row `Delete` association is tombstoned, while row `Get`, row `Set`, and sibling row associations keep their independent lifecycle.
- Created-row failed meta-method non-mutation:
  - Added `created-row-failed-meta-nonmutation-doc` to stress failed `AddACE`, `RemoveACE`, and `DeleteMethod` attempts before later successful meta-method calls.
  - No solver repair was needed; this locks in that only successful meta-method calls update dynamic ACL additions/removals or deleted-association tombstones.
  - First review flagged one `GetACL` shape concern; the packet was archived and reworked to an equivalent duplicate-`AddACE` assertion, then all 9 cases were accepted.
- Created-row cleanup validation:
  - Added `created-row-cleanup-acl-state-doc` to verify dynamic ACL/tombstone cleanup after `DeleteRow` and direct row-object `Delete`.
  - First review flagged one table-deletion cascade inference; the packet was archived and reworked into an explicit row-level `DeleteRow` cleanup case.
  - The accepted batch verifies stale row meta-method calls fail after row deletion while sibling row associations remain usable.
- SyncSession credit/timeout return-shape extension:
  - Added `syncsession-trans-credit-doc` with 15 accepted cases around optional `TransTimeout` and `InitialCredit` values returned in `SyncSession`.
  - The first blind review packets were archived as stale after the cases were tightened away from ambiguous equality boundaries; fresh packets were then reviewed by three independent agents and accepted with no concerns.
  - No solver repair was needed beyond the already-general optional return min/max validation added for SyncSession return values.
- DataStore/MBR byte-table method universe:
  - Added `datastore-byte-table-method-universe-doc` and `mbr-byte-table-method-universe-doc`, 40 accepted cases total.
  - These cases combine Core byte-table row-management rules with Opal AccessControl preconfiguration: DataStore and MBR have Get/Set associations, not CreateRow/DeleteRow associations. Direct row-management success and meta-method success for those nonexistent associations are rejected.
  - No solver repair was needed; the value is trusted regression coverage for a high-risk broad heuristic: "Admins can mutate tables" must not leak into byte tables.
- MBR direct byte payload repair:
  - Added `mbr-byte-payload-doc` with 8 accepted cases for direct MBR byte-table `Set`/`Get` postconditions.
  - This found a real rulebase gap: MBR payload state was tracked for host shadowing, but direct `MBR.Get` did not compare returned Bytes against prior `MBR.Set` writes.
  - The solver now tracks MBR bytes by offset, applies `Where.Row` and omitted-Where row-zero semantics, validates explicit Get windows, and clears that state on Locking SP reset/revert.
  - This is a good presentation example of the intended loop: official docs -> generated edge cases -> independent agreement -> model gap -> general semantic repair -> regression gate.
- MBR shadow byte payload repair:
  - Added `mbr-shadow-byte-payload-doc` with 9 accepted cases tying MBR byte-table offset writes to active host MBR shadow reads.
  - The first run found 3 real mismatches: the solver still expected stale `AABBCCDD` after a nonzero-row overwrite changed the canonical bytes to `AA1122DD`, including after `DoneOnReset` reactivated shadowing.
  - The solver now recomputes the contiguous byte-table prefix after every successful MBR/DataStore byte write, so direct byte-table Gets and host shadow reads share the same state source.
  - This is another clean presentation example: the case was not a one-off fix; it tightened the shared byte-table state representation used by multiple paths.

## Verification Commands

Latest successful verification:

```bash
.venv/bin/python -m pytest -q
python3 tools/run_sourced_edges.py
python3 tools/label_consensus.py report --min-reviewers 3 --min-confidence 0.75
python3 tools/run_sourced_edges.py --consensus-gate
python3 tools/run_synthetic_edges.py
python3 tools/doc_coverage.py
python3 tools/build_doc_inventory.py
python3 tools/build_spec_graph.py
```

Observed results:

- `795 passed`
- `sourced edge cases: 2276`, `mismatches: 0`
- `cases=2276 reviews=7098 accepted=2227 quarantined=49`
- `consensus gate: selected 2227 accepted case(s) out of 2276`, `mismatches: 0`
- `synthetic edge cases: 205`, `mismatches: 0`
- `docs=1376 cases=2276 covered_docs=466 untriaged_A_B=265`
- `spec_graph sections=1376 entities=2334 rules=27 edges=24061 test_links=2276`

## Presentation Caveat

The consensus process proves that the local official-document cases are internally consistent and independently reviewed. It does not directly expose private dashboard labels. Dashboard impact is inferred from score movement, actual solver changes, and official-document coverage, not from inspecting private answers.

## 2026-05-25 22:34 KST - Locking zero-length and byte-table row-bound repairs

- Added `locking-zero-length-range-state-doc` cases for explicit non-global `RangeLength=0`: stored lock cells remain observable but do not affect host I/O, range crossing, or Level0 `Locked` until `RangeLength` later becomes nonzero.
- Fixed `RangeState.range_length_known` plus `expectations._locking_feature_locked` so explicit zero-length rows are ignored for Level0 locked state without treating unknown preconfigured row length as ineffective.
- Added `byte-table-row-bounds-doc` cases for negative DataStore/MBR `startRow`, `endRow`, and `Where.Row`; fixed byte-table row address validation so negative rows cannot succeed or mutate bytes.
- Added `byte-table-observed-rows-bounds-doc` cases for descriptor-observed `Rows=N`; fixed state tracking of byte-table descriptor Rows and rejected Get/Set at row `N` or beyond.
- Verification: `run_sourced_edges.py` = 2317 cases / 0 mismatches, `run_synthetic_edges.py` = 205 cases / 0 mismatches, `pytest tests/test_solver_rules.py` = 795 passed, `evaluate.py` = 100.00.

## 2026-05-25 23:02 KST - Score-targeted AccessControl/C_PIN Repair Batch

- Why this batch matters:
  - The previous score jumps suggested remaining private failures were likely in AccessControl association identity, C_PIN state, and byte-table boundary handling. This batch deliberately focused there instead of broadly adding easy cases.
- New failure modes found:
  - AccessControl association overreach: the model accepted `DataStore/Authenticate`, `DataStore/Random`, `MBR/Authenticate`, and `MBR/Random` as if SP methods existed on byte-table objects.
  - DeleteMethod bypass: after deleting a created table's `Get` association, direct `Get` on the same UID could still pass when the event used display name `Table`.
  - C_PIN column bleed: User1's `ACE_C_PIN_User1_Set_PIN` could incorrectly authorize a mixed PIN+TryLimit update.
  - SetPackage credential replacement: old C_PIN values were treated as merely unknown after `SetPackage`, allowing old-PIN success in low-confidence paths.
  - RevertSP association aliasing: `LockingSP/RevertSP` was treated as the same AccessControl association as `ThisSP/RevertSP`.
- General repairs made:
  - Narrowed AccessControl existence checks to concrete documented InvokingID/MethodID pairs.
  - Made method tombstones UID-aware for created objects.
  - Made C_PIN user self-authorization column-aware rather than object-wide.
  - Made `SetPackage` invalidate the prior known C_PIN value like a credential-replacement method.
  - Kept quarantined cases quarantined when reviewers raised concerns, even if all labels agreed.
- Evidence state:
  - `scope_batch_{a,b,c}.jsonl`: completed 74-case independent reviews, all schema-validated.
  - `setpackage_{a,b,c}.jsonl`: completed 4-case reviews, unanimous labels but quarantined due one reviewer concern about opaque package contents.
  - `revertsp_identity_{a,b,c}.todo.jsonl`: exported for the new RevertSP identity cases and pending review completion.
- Verification snapshot:
  - Full sourced corpus: 2359 / 0 mismatches.
  - Synthetic corpus: 205 / 0 mismatches.
  - Unit tests: 795 passed.
  - Local evaluation: 100.00.
  - Consensus gate before RevertSP review: 2292 accepted / 0 mismatches.

## 2026-05-25 23:35 KST - Object Lifecycle Cleanup Audit

- What changed:
  - Added official-doc cases for deletion cleanup across Locking ranges, host-created tables, table descriptors, and host-created rows.
  - The central invariant is now recorded explicitly: once an object is deleted, stale object-method `SUCCESS` results and stale AccessControl meta-method successes should not survive unless the object is later recreated.
- Mismatches found:
  - Locking range deletion initially left stale AccessControl/direct-method paths alive; 7 new sourced cases caught that.
  - Created-table deletion initially let direct `Get` through when the trace used a generic `Table` display name for a deleted UID; 2 new sourced cases caught that.
  - Created-row direct cleanup then passed under the same generalized repair, which is useful evidence that the fix was semantic rather than case-specific.
- How the algorithm was fixed:
  - Added UID/method tombstones for deleted objects in the transition layer.
  - Made semantic method-combo checks consult exact UID tombstones even after deleted objects have been removed from live state maps.
  - Cleared tombstones on legitimate recreation so the model does not overblock future created objects that reuse a UID.
- How consensus handled it:
  - Independent reviewers validated the new packets.
  - Some cases were quarantined because of reviewer concerns, even when labels mostly agreed. This is intentional: the presentation should say the accepted set is conservative, and quarantined packets are kept as review artifacts rather than silently thrown away.
- Latest evidence snapshot:
  - Full sourced corpus: 2382 / 0 mismatches.
  - Consensus gate: 2303 accepted / 79 quarantined / 0 mismatches.
  - Synthetic corpus: 205 / 0 mismatches.
  - Unit tests: 795 passed.
  - Local evaluation: 100.00.
  - Spec graph: 1376 sections, 2440 entities, 24967 edges, 2382 test links.

## 2026-05-26 00:16 KST - High-Score Locking/DataStore Sweep + SP Scope Tightening

- What changed:
  - Added harder Locking state-machine cases around GlobalRange, LockOnReset, zero-length rows, atomic geometry updates, and adjacent range crossing.
  - Added DataStore byte-table cases around exact byte payloads, observed last row, omitted endRow, Cellblock column invalidity, and granularity semantics.
  - Added dynamic created-table SP-scope cases after finding that Admin-created table associations could leak into Locking SP and vice versa.
- Mismatches found:
  - DataStore omitted-endRow reads at the observed final row could accept an empty result even after the final byte was known.
  - Created dynamic table UIDs were not consistently scoped to the SP where they were created, so cross-SP `GetACL`/direct method `SUCCESS` could pass.
- How the algorithm was fixed:
  - Byte-table Get reconstruction now uses known descriptor Rows when endRow is omitted, and only asserts exact payloads when the tracked byte range is actually known.
  - Dynamic created objects now carry SP ownership through semantic checks; AccessControl existence and direct `Get`/`Set`/`Delete` reject cross-SP dynamic objects.
- How consensus handled it:
  - Three reviewers validated the 56 Locking/DataStore new cases with no low-confidence rows.
  - For SP-scope, reviewers correctly objected to exact `NOT_AUTHORIZED` claims for `Get`/`Set`; the case set was narrowed to impossible-`SUCCESS` only before being accepted.
- Latest evidence snapshot:
  - Full sourced corpus: 2462 / 0 mismatches.
  - Consensus gate: 2381 accepted / 81 quarantined / 0 mismatches.
  - Synthetic corpus: 205 / 0 mismatches.
  - Unit tests: 799 passed.
  - Local evaluation: 100.00.
  - Doc coverage: 468 / 1376 docs covered by sourced cases; 264 high-priority A/B docs still untriaged.

## 2026-05-26 00:40 KST - AccessControl SP-Method Alias Tightening

- What changed:
  - Added 8 official-doc cases for `GetACL` on `AdminSP`/`LockingSP` display aliases paired with SP methods such as `GetFreeSpace`, `CreateTable`, and `DeleteSP`.
  - Strengthened the `accesscontrol-sp-method-scope-doc` rule with Core `ThisSP` method definitions so the case family records why `ThisSP.GetFreeSpace` does not imply `AdminSP/GetFreeSpace` or `LockingSP/GetFreeSpace` AccessControl rows.
- Mismatch found:
  - The model accepted AccessControl association success for SP-method aliases. This was a semantic overreach from method availability to AccessControl row existence.
- How the algorithm was fixed:
  - `_combo_exists_for_get_acl` now treats `GetFreeSpace`, `CreateTable`, and `DeleteSP` association checks as concrete `ThisSP` rows only.
  - The repair is scoped to GetACL/AccessControl association identity and does not change direct SP method invocation behavior.
- How consensus handled it:
  - Three subagents reviewed the 8 new packets. All labeled the target `SUCCESS` responses as `FAIL`.
  - A schema hiccup was caught: one early output wrote `decision` instead of the consensus `label`; it was archived and the agents rewrote all three review files in the standard schema before the gate was rerun.
- Latest evidence snapshot:
  - Full sourced corpus: 2470 / 0 mismatches.
  - Consensus gate: 2389 accepted / 81 quarantined / 0 mismatches.
  - Synthetic corpus: 205 / 0 mismatches.
  - Unit tests: 801 passed.
  - Local evaluation: 100.00.
  - Doc coverage: 468 / 1376 docs covered by sourced cases; 264 high-priority A/B docs still untriaged.

## 2026-05-26 01:05 KST - Deep DataStore Authority/Window Churn

- What changed:
  - Added 16 accepted cases from 8 long DataStore trajectories, each 21-30 steps.
  - The trajectories combine Admin/User1 session churn, separate Get/Set ACE rewrites, structured byte-table writes, raw `startRow` writes, omitted-Where prefix writes, unauthorized Set non-mutation, and final exact read windows.
- Mismatch found:
  - No solver mismatch. The existing byte-table payload tracking and ACE BooleanExpr model handled these harder composed traces.
- How consensus handled it:
  - Three reviewers independently labeled all 16 packets with the expected 8 PASS / 8 FAIL split.
  - No concerns were recorded, so all 16 entered the accepted set and quarantine remained 81.
- Latest evidence snapshot:
  - Full sourced corpus: 2486 / 0 mismatches.
  - Consensus gate: 2405 accepted / 81 quarantined / 0 mismatches.
  - Synthetic corpus: 205 / 0 mismatches.
  - Unit tests: 801 passed.
  - Local evaluation: 100.00.
  - Doc coverage: 468 / 1376 docs covered by sourced cases; 264 high-priority A/B docs still untriaged.

## 2026-05-26 01:22 KST - AccessControl System Metadata Method Universe

- What changed:
  - Added 24 impossible-success cases for `GetACL` on missing system metadata table associations: `Table`, `SPTemplates`, and `Template` paired with `Set`, `CreateRow`, `DeleteRow`, and `GetFreeRows`.
- Mismatch found:
  - The solver accepted `GetACL SUCCESS` for system table/method pairs that are not concrete rows in the Opal AccessControl preconfiguration.
- How the algorithm was fixed:
  - `_combo_exists_for_get_acl` now separates Core table-method availability from concrete AccessControl row existence for system metadata tables.
  - `Get`/`Next` rows remain allowed where preconfigured, while `Set/CreateRow/DeleteRow/GetFreeRows` are rejected for the covered system tables.
- How consensus handled it:
  - Three reviewers labeled all 24 packets as `FAIL`, with no concerns.
  - All 24 entered the accepted set; quarantine stayed at 81.
- Latest evidence snapshot:
  - Full sourced corpus: 2510 / 0 mismatches.
  - Consensus gate: 2429 accepted / 81 quarantined / 0 mismatches.
  - Synthetic corpus: 205 / 0 mismatches.
  - Unit tests: 803 passed.
  - Local evaluation: 100.00.
  - Doc coverage: 468 / 1376 docs covered by sourced cases; 264 high-priority A/B docs still untriaged.

## 2026-05-26 02:00 KST - AccessControl Row Existence Universe Tightening

- What changed:
  - Added 98 new impossible-success cases across four AccessControl families:
    - 4 `SPInfo/Set` association cases.
    - 6 cross-SP object-scope cases for Admin-only `TPerInfo` and Locking-only `LockingInfo`.
    - 60 metadata table method-universe cases for MethodID, AccessControl, ACE, Authority, and C_PIN table-level associations.
    - 28 template/table method-universe cases for SP, SecretProtect, and K_AES table-level associations.
- Mismatches found:
  - The model was still too permissive when deciding whether a concrete InvokingID/MethodID association existed.
  - It confused Core table-method availability with Opal AccessControl preconfiguration rows, and it did not fully enforce the current SP ownership of the target object.
- How the algorithm was fixed:
  - `_combo_exists_for_get_acl` now enforces target SP ownership for AccessControl lookups.
  - The system metadata/table limit was expanded so missing table-level `Set/CreateRow/DeleteRow/GetFreeRows` associations are rejected while documented row-level associations remain valid.
  - Explicit preservation checks keep true associations alive: Admin `TPerInfo/Set`, Locking `LockingInfo/Get`, Locking `ACE row Set`, Admin `Authority row Set`, and Locking `CreateRow`.
- How consensus handled it:
  - 3 reviewers validated each batch independently.
  - All 98 new targets were labeled `FAIL`, with no concerns.
  - Accepted sourced cases rose to 2527 while quarantine stayed at 81.
- Latest evidence snapshot:
  - Full sourced corpus: 2608 / 0 mismatches.
  - Consensus gate: 2527 accepted / 81 quarantined / 0 mismatches.
  - Synthetic corpus: 205 / 0 mismatches.
  - Unit tests: 819 passed.
  - Local evaluation: 100.00.
  - Doc graph: 1376 sections, 2666 entities, 27345 edges, 2608 test links.
  - Doc coverage: 468 / 1376 docs covered by sourced cases; 264 high-priority A/B docs still untriaged.

## 2026-05-26 09:36 KST - AccessControl Missing-Association Meta-Methods

- What changed:
  - Added 36 impossible-success cases for `AddACE`, `RemoveACE`, and `DeleteMethod` on missing AccessControl associations.
  - The selected missing associations mirror the recent row-existence repairs: Admin metadata/template table targets and Locking C_PIN/K_AES/SecretProtect table-level targets.
- Mismatch found:
  - None. The previous row-existence repair already generalized to these meta-methods.
- How the algorithm was fixed:
  - No new code change was required in this round.
  - The important verified behavior is that a non-existent InvokingID/MethodID row cannot be created, edited, or deleted by reporting `SUCCESS` through AccessControl meta-methods.
- How consensus handled it:
  - 3 reviewers independently labeled all 36 targets as `FAIL`, with no concerns.
  - Accepted sourced cases rose to 2563 while quarantine stayed at 81.
- Latest evidence snapshot:
  - Full sourced corpus: 2644 / 0 mismatches.
  - Consensus gate: 2563 accepted / 81 quarantined / 0 mismatches.
  - Synthetic corpus: 205 / 0 mismatches.
  - Unit tests: 819 passed.
  - Local evaluation: 100.00.
  - Doc graph: 1376 sections, 2702 entities, 27561 edges, 2644 test links.
  - Doc coverage: 468 / 1376 docs covered by sourced cases; 264 high-priority A/B docs still untriaged.

## 2026-05-26 10:15 KST - GetACL Exact ACL And Table/Row Boundary

- What changed:
  - Added 18 new sourced cases across three tags:
    - 8 `SPTable/Get` and `SecretProtectTable/Get` exact ACL cases.
    - 4 `TemplateTable/Get` exact ACL cases.
    - 6 Locking/K_AES table-level `Get` missing-association cases.
- Mismatches found:
  - The model accepted arbitrary or empty `GetACL` return lists for existing wildcard object `Get` associations that should return `ACE_Anybody`.
  - It also treated some object-table UIDs as if they had table-level `Get` AccessControl rows, even though Opal preconfigures `Next` at table level and `Get` on concrete object rows.
- How the algorithm was fixed:
  - Added exact ACL mappings for `SPTable.Get`, `TemplateTable.Get`, and `SecretProtectTable.Get`.
  - Added a table-level `Get` deny list for `LockingTable`, `K_AES_128Table`, and `K_AES_256Table`, while preserving concrete K_AES key-row `Get` associations.
- How consensus handled it:
  - SP/SecretProtect: 3 reviewers ultimately agreed on 4 PASS / 4 FAIL. One reviewer initially misread PASS target returns as empty; the audit caught this and the reviewer rewrote the file before consensus was accepted.
  - Template: 3 reviewers agreed on 2 PASS / 2 FAIL.
  - Locking/K_AES table Get: 3 reviewers agreed on 6 FAIL.
  - All 18 new cases entered the accepted set; quarantine remained 81.
- Latest evidence snapshot:
  - Full sourced corpus: 2662 / 0 mismatches.
  - Consensus gate: 2581 accepted / 81 quarantined / 0 mismatches.
  - Synthetic corpus: 205 / 0 mismatches.
  - Unit tests: 828 passed.
  - Local evaluation: 100.00.
  - Doc graph: 1376 sections, 2720 entities, 27703 edges, 2662 test links.
  - Doc coverage: 468 / 1376 docs covered by sourced cases; 264 high-priority A/B docs still untriaged.

## 2026-05-26 10:26 KST - Locking/K_AES Table-Level AccessControl Universe

- What changed:
  - Added 10 impossible-success cases:
    - 6 for missing `LockingTable.Set/DeleteRow/GetFreeRows` AccessControl rows.
    - 4 for missing `K_AES_128Table.Next` and `K_AES_256Table.Next` AccessControl rows.
- Mismatches found:
  - The model was still overgeneralizing direct table method availability into AccessControl association existence.
- How the algorithm was fixed:
  - Added a Locking table method deny list for table-level `Set/DeleteRow/GetFreeRows`.
  - Added a K_AES table-level `Next` deny list.
  - Preservation checks keep `LockingTable.Next`, `Locking/CreateRow`, and K_AES key-row `Get` valid.
- How consensus handled it:
  - 3 reviewers labeled all 6 LockingTable method cases as `FAIL`.
  - 3 reviewers labeled all 4 K_AES table `Next` cases as `FAIL`.
  - All 10 entered the accepted set; quarantine remained 81.
- Latest evidence snapshot:
  - Full sourced corpus: 2672 / 0 mismatches.
  - Consensus gate: 2591 accepted / 81 quarantined / 0 mismatches.
  - Synthetic corpus: 205 / 0 mismatches.
  - Unit tests: 833 passed.
  - Local evaluation: 100.00.
  - Doc graph: 1376 sections, 2730 entities, 27747 edges, 2672 test links.
  - Doc coverage: 468 / 1376 docs covered by sourced cases; 264 high-priority A/B docs still untriaged.

## 2026-05-26 10:38 KST - Locking CreateRow vs GetACL Association

- What changed:
  - Added 4 sourced impossible-success cases under `accesscontrol-locking-create-row-universe-doc`.
  - The cases cover `LockingTable`, shorthand `Locking`, Locking table UID `0000080200000000`, and table descriptor UID `0000000100000802` paired with `MethodID=CreateRow` through `GetACL`.
- Mismatches found:
  - The model had overgeneralized direct Locking table `CreateRow` behavior into `AccessControl` row existence.
  - The official-doc distinction is sharper: direct Locking `CreateRow` can create a range, but Opal does not preconfigure `LockingTable/CreateRow` as a `GetACL`-retrievable association.
- How the algorithm was fixed:
  - Added `CreateRow` to the Locking table AccessControl deny list.
  - Added a small alias set so both `LockingTable` and `Table_Locking` are denied for the same missing association.
  - Existing tests that incorrectly preserved `GetACL(Locking/CreateRow)` were updated to reject it, while direct `CreateRow` range lifecycle tests remain valid.
- How consensus handled it:
  - Two explorer agents first checked the official parsed docs and recommended reject, not quarantine.
  - 3 reviewers then labeled all 4 generated targets as `FAIL`; all 4 entered the accepted set.
  - Quarantine remained 81.
- Latest evidence snapshot:
  - Full sourced corpus: 2676 / 0 mismatches.
  - Consensus gate: 2595 accepted / 81 quarantined / 0 mismatches.
  - Synthetic corpus: 205 / 0 mismatches.
  - Unit tests: 834 passed.
  - Local evaluation: 100.00.
  - Doc graph: 1376 sections, 2734 entities, 27779 edges, 2676 test links.
  - Doc coverage: 468 / 1376 docs covered by sourced cases; 264 high-priority A/B docs still untriaged.

## 2026-05-26 15:03 KST - CreateRow Meta-Method Generalization + HostProperties ComID Scope

- What changed:
  - Added `accesscontrol-locking-create-row-meta-method-doc`: 12 missing-association cases proving `AddACE`, `RemoveACE`, and `DeleteMethod` cannot succeed for the absent `LockingTable/CreateRow` AccessControl row.
  - Added `host-properties-per-comid-doc`: 16 long state cases covering ComID-specific HostProperties, same-ComID omitted-value preservation, cross-ComID isolation, targeted `ProtocolStackReset`, and all-ComID `PowerCycle`/`HardwareReset`.
- Mismatches found:
  - No mismatch for the CreateRow meta-method batch; the previous `GetACL` association fix generalized correctly.
  - A real HostProperties bug was found: the model did not yet represent HostProperties as ComID-scoped state and could reject a valid trace where ComID 2 remains at initial assumptions after ComID 1 changes.
  - A parser robustness gap was also found for flat `invoking_uid` plus `output.values` records.
- How the algorithm was fixed:
  - Added `Event.comid` and `State.host_properties_by_comid`.
  - Parsed ComID from method args, host reset args, high-level events, and flat input shapes.
  - Updated HostProperties expectations/transitions so submitted values are cumulative for the associated ComID, not global.
  - Updated reset handling so PowerCycle/HardwareReset reset all known ComIDs, while ProtocolStackReset resets only the targeted ComID.
  - Added unit tests for per-ComID tracking, cross-ComID leak rejection, targeted/global reset behavior, and flat schema parsing.
- How consensus handled it:
  - CreateRow meta-method: 3 reviewers labeled all 12 cases `FAIL`, no concerns.
  - HostProperties per-ComID: an explorer first confirmed the official-doc interpretation; then 3 reviewers labeled the 16 cases as 8 PASS / 8 FAIL with no concerns.
  - All 28 new cases entered the accepted set; quarantine is still 81.
- Latest evidence snapshot:
  - Full sourced corpus: 2704 / 0 mismatches.
  - Consensus gate: 2623 accepted / 81 quarantined / 0 mismatches.
  - Synthetic corpus: 205 / 0 mismatches.
  - Unit tests: 841 passed.
  - Local evaluation: 100.00.
  - Doc graph: 1376 sections, 2762 entities, 27983 edges, 2704 test links.
  - Doc coverage: 469 / 1376 docs covered by sourced cases; 263 high-priority A/B docs still untriaged.
- Presentation angle:
  - This batch gives a crisp story for “we are not just making cases; we are discovering missing state dimensions.” The key model update is not packet-specific: it adds ComID as a first-class state axis for HostProperties and keeps reset semantics aligned with the official documents.

## 2026-05-26 15:43 KST - ProtocolStackReset ComID Scope for Sessions

- What changed:
  - Added `protocol-stack-reset-comid-session-doc`: 16 sourced cases for sessions and pending session startup across different ComIDs.
  - The cases deliberately pair local `ProtocolStackReset(ComID=n)` with global `PowerCycle` / enabled `TPER_RESET` to prevent the model from collapsing all resets into one behavior.
- Mismatches found:
  - The rulebase initially aborted the current session for any `ProtocolStackReset`, even when the reset targeted a different ComID.
  - This made a valid long trace fail: `StartSession(AdminSP, SID, ComID=1)`, then `ProtocolStackReset(ComID=2)`, then an Admin SP operation under the still-open ComID 1 session.
- How the algorithm was fixed:
  - Added `Session.comid` to the state model.
  - Stored ComID during explicit and implicit session creation.
  - Made `ProtocolStackReset` abort only matching or unknown-ComID sessions, preserving legacy conservative behavior when old traces do not expose ComID.
  - Kept `PowerCycle`, `HardwareReset`, and enabled `TPER_RESET` global, so the repair does not over-preserve sessions.
- How consensus handled it:
  - One explorer mapped the rule to official Core/Opal text: `ProtocolStackReset` is per-ComID; enabled `TPER_RESET` is all-ComID.
  - Three reviewers validated the 16 cases. One reviewer initially produced low confidence for the global reset rows because the evidence packet was weak.
  - Those rows were not treated as settled until the evidence set was corrected with explicit global-reset sources and the reviewer re-ran the labels.
  - Final state: all 16 accepted, 0 new quarantine rows, total quarantine remains 81.
- Latest evidence snapshot:
  - Full sourced corpus: 2720 / 0 mismatches.
  - Consensus gate: 2639 accepted / 81 quarantined / 0 mismatches.
  - Synthetic corpus: 205 / 0 mismatches.
  - Unit tests: 844 passed.
  - Local evaluation: 100.00.
  - Doc graph: 1376 sections, 2778 entities, 28055 edges, 2720 test links.
  - Doc coverage: 470 / 1376 docs covered by sourced cases; 263 high-priority A/B docs still untriaged.
- Presentation angle:
  - This batch is a clean “bad abstraction got split into the right state machine” story: not all resets are equal, and official ComID scope decides whether a session survives.

## 2026-05-26 16:18 KST - DataStore Byte-Table Set Shape and Sparse Get Windows

- What changed:
  - Added `datastore-set-where-row-only-doc`: 8 cases for invalid DataStore `Set` parameterization where `Where.Row` is combined with `EndRow`.
  - Added `datastore-sparse-window-position-doc`: 8 cases for sparse writes followed by explicit Get windows that include vendor-unique/unwritten bytes plus known written bytes.
- Mismatches found:
  - The verifier treated `EndRow` inside byte-table `Set.Where` as harmless if a valid `Row` was also present.
  - The verifier could accept a sparse Get window that returned only the known bytes shifted to the front, instead of preserving their row-relative position inside the requested window.
- How the algorithm was fixed:
  - Tightened byte-table Set validation so `EndRow` in `Where` is invalid for DataStore Set.
  - Added a return-byte-position expectation to the engine. Unknown/VU bytes remain unconstrained, while known offsets from successful Set operations must appear in the right returned positions.
  - Added unit regressions for invalid Set shape, non-mutation, sparse window length, and wrong/shifted known bytes.
- How consensus handled it:
  - A DataStore explorer identified these gaps from official Core and Opal text.
  - Three reviewers labeled 16 cases independently, each converging on 8 PASS / 8 FAIL with no concerns.
  - All 16 entered the accepted set; quarantine remains 81.
- Latest evidence snapshot:
  - Full sourced corpus: 2736 / 0 mismatches.
  - Consensus gate: 2655 accepted / 81 quarantined / 0 mismatches.
  - Synthetic corpus: 205 / 0 mismatches.
  - Unit tests: 849 passed.
  - Local evaluation: 100.00.
  - Doc graph: 1376 sections, 2794 entities, 28191 edges, 2736 test links.
  - Doc coverage: 470 / 1376 docs covered by sourced cases; 263 high-priority A/B docs still untriaged.
- Presentation angle:
  - This is a nice “partial knowledge” story: the model learned to be strict only where the spec gives certainty. VU bytes are unknown, but byte positions created by a successful Set are not.

## 2026-05-26 19:35 KST - Byte Table Descriptor Optional Cells and AccessControl Direct ACL Omission

- What changed:
  - Added `byte-table-descriptor-column-doc`: 8 sourced cases for DataStore/MBR byte-table descriptor `Column` and `NumColumns`.
  - Added `accesscontrol-direct-get-acl-omission-doc`: 8 sourced cases for direct `AccessControl.Get` ACL-column behavior.
- Mismatches found:
  - The verifier accepted bad byte-table descriptor return values such as non-null `Column` and `NumColumns != 1`.
  - The initial descriptor repair was too strict because descriptor cells 5/6 may be omitted from a valid response even when other descriptor cells are returned.
  - Direct `AccessControl.Get` needed a more precise model: success with no ACL cell is acceptable, but returning the ACL list directly is not.
- How the algorithm was fixed:
  - Added optional returned-cell expectations so descriptor cells are checked if present without making them mandatory in every partial response.
  - Added null UID normalization for byte-table descriptor `Column`.
  - Added AccessControl-specific column-name parsing for `ACL` and meta-ACL columns.
  - Changed direct `AccessControl.Get` expectations to forbid ACL leakage while permitting empty/omitted successful results.
- How consensus handled it:
  - Descriptor reviewer A initially objected to a "correct" MBR row that encoded null as a blank string. That case was corrected to explicit null UID and re-reviewed.
  - Final descriptor reviews: three reviewers, 8 cases, 4 PASS / 4 FAIL, no concerns.
  - Final AccessControl reviews: three reviewers, 8 cases, 4 PASS / 4 FAIL, no concerns.
  - All 16 new cases entered the accepted set; quarantine remains 81.
- Latest evidence snapshot:
  - Full sourced corpus: 2752 / 0 mismatches.
  - Consensus gate: 2671 accepted / 81 quarantined / 0 mismatches.
  - Synthetic corpus: 205 / 0 mismatches.
  - Unit tests: 855 passed.
  - Local evaluation: 100.00.
  - Doc graph: 1376 sections, 2810 entities, 28295 edges, 2752 test links.
  - Doc coverage: 470 / 1376 docs covered by sourced cases; 263 high-priority A/B docs still untriaged.
- Presentation angle:
  - This is a good example of "not overfitting the case." The model learned a reusable distinction: optional fields can be omitted, but when returned they must satisfy the descriptor rule; ACL contents must flow through `GetACL`, not through direct cell leakage.

## 2026-05-26 20:41 KST - Row Options, Special Associations, HotPlug, and Reset-List Evidence Repair

- What changed:
  - Added `datastore-byte-table-row-option-doc`: 12 cases proving DataStore byte-table row addressing must use row numbers, not UID-style row options.
  - Added `getacl-locking-special-object-method-universe-doc`: 6 retained cases proving Locking SP `SPTemplates` and `MethodID` object rows use special object-method associations, not ordinary `Get`.
  - Added `locking-hotplug-reset-boundary-doc`: 7 cases proving HotPlug aborts sessions but does not fire PowerCycle-only `LockOnReset`.
  - Added `locking-reset-list-restrictions-no-mutation-doc`: 20 cases for unsupported reset_types lists and failed-Set non-mutation.
  - Added `locking-created-row-default-lockonreset-doc`: 12 cases for dynamically created Locking row defaults, reset behavior, failed `LockOnReset` Set, and DeleteRow/recreate defaults.
- Mismatches found:
  - DataStore accepted UID-shaped byte-table row options for Set/Get.
  - GetACL accepted ordinary `Get` associations for Locking SP `SPTemplates` / `MethodID` object rows.
  - HotPlug was not normalized as reset type 2, so stale-session and fresh-state behavior were wrong.
  - Reset-list and created-row batches found no new production bug; they are accepted regression coverage.
- How the algorithm was fixed:
  - Added raw-argument row-option validation for byte-table Set/Get.
  - Tightened Locking SP GetACL association existence for `SPTemplates_*` and `MethodID_*`.
  - Added HotPlug/HotPlugReset reset-type parsing and reset-event handling.
  - Added unit tests for the new parser, association, and reset repairs.
- How consensus handled it:
  - DataStore row-option: 3 reviewers, 12 accepted.
  - GetACL special-object: exact-status rows were removed because the docs prove only "not SUCCESS"; 6 retained rows accepted.
  - HotPlug: 3 reviewers, 7 accepted.
  - Reset-list/create-row: initial 2 disagreements were resolved by strengthening evidence and re-reviewing the exact rows. Final: 32 accepted, no new quarantine.
- Latest evidence snapshot:
  - Full sourced corpus: 2809 / 0 mismatches.
  - Consensus gate: 2727 accepted / 82 quarantined / 0 mismatches.
  - Synthetic corpus: 205 / 0 mismatches.
  - Unit tests: 863 passed.
  - Local evaluation: 100.00.
  - Doc graph: 1376 sections, 2867 entities, 28887 edges, 2809 test links.
  - Doc coverage: 470 / 1376 docs covered by sourced cases; 263 high-priority A/B docs still untriaged.
- Presentation angle:
  - This is the clearest audit-trail example so far: the system did not just generate cases, it detected overclaimed status certainty, used quarantine/re-review when reviewers disagreed, improved the evidence packets, and kept only rows that reached consensus.

## 2026-05-26 20:52 KST - Locking Geometry Nontransition Data Preservation

- What changed:
  - Added `locking-geometry-nontransition-data-doc`: 22 long host-I/O cases around Locking `RangeStart` / `RangeLength` changes.
  - Cases cover valid expansion, trims, atomic slides, repeated geometry moves, adjacent-row pressure, and failed-overlap non-mutation.
- Mismatches found:
  - None. The current rulebase already preserves same-row written data across nontransition geometry changes.
- How the algorithm was handled:
  - No production repair was made. The important engineering choice was evidence discipline: only the normative “SHALL NOT cause loss of data” rule for nontransition LBAs was accepted.
  - The informative “transitioned data may be lost” text was not turned into trusted FAIL cases.
- How consensus handled it:
  - Three reviewers independently labeled the same 22 rows.
  - All reviewers returned 11 PASS / 11 FAIL with no concerns.
  - Consensus accepted all 22; quarantine stayed at 82.
- Latest evidence snapshot:
  - Full sourced corpus: 2831 / 0 mismatches.
  - Consensus gate: 2749 accepted / 82 quarantined / 0 mismatches.
  - Synthetic corpus: 205 / 0 mismatches.
  - Unit tests: 863 passed.
  - Local evaluation: 100.00.
  - Doc graph: 1376 sections, 2889 entities, 29041 edges, 2831 test links.
  - Doc coverage: 470 / 1376 docs covered by sourced cases; 263 high-priority A/B docs still untriaged.
- Presentation angle:
  - This is a good story for “harder cases without overclaiming.” The loop created longer compositional trajectories, but still refused to promote ambiguous/informative text into trusted labels.

## 2026-05-26 21:05 KST - Cross-Range GenKey Media-Key Scope

- What changed:
  - Added `locking-crossing-genkey-media-doc`: 9 cases where host writes span multiple Locking ranges and a later `GenKey` changes only one range's media key.
  - Added regression tests for segment-specific invalidation.
- Mismatches found:
  - The model treated a cross-range host write as one whole-span remembered pattern tied to a fallback range.
  - That lost the distinction between the segment whose media key changed and the adjacent segment whose media key did not change.
- How the algorithm was fixed:
  - Host writes are now split into effective Locking range segments before being stored.
  - Reads over a multi-segment interval now reassemble remembered segments and detect stale media generations segment-by-segment.
  - A GenKey on Range1 invalidates old Range1 data without invalidating adjacent Range2 data; GlobalRange GenKey only invalidates uncovered GlobalRange segments.
- How consensus handled it:
  - Three reviewers independently labeled 9 rows.
  - All reviewers returned 5 PASS / 4 FAIL with no concerns.
  - Consensus accepted all 9; quarantine stayed at 82.
- Latest evidence snapshot:
  - Full sourced corpus: 2840 / 0 mismatches.
  - Consensus gate: 2758 accepted / 82 quarantined / 0 mismatches.
  - Synthetic corpus: 205 / 0 mismatches.
  - Unit tests: 865 passed.
  - Local evaluation: 100.00.
  - Doc graph: 1376 sections, 2898 entities, 29131 edges, 2840 test links.
  - Doc coverage: 470 / 1376 docs covered by sourced cases; 263 high-priority A/B docs still untriaged.
- Presentation angle:
  - This is one of the stronger “model actually improved” examples: the fix moved from whole-range memory to segment-level media-key tracking, which is a general rulebase improvement rather than a hard-coded answer.

## 2026-05-26 21:34 KST - UserMMMM AccessControl/ACE Generalization

- What changed:
  - Added `user-mmmm-accesscontrol-exact-doc`: 12 official-doc cases around User2 as an instantiation of Opal's UserMMMM rows.
  - The cases require exact `GetACL` return uidrefs and exact ACE `BooleanExpr`/`Columns` cells for `C_PIN_User2`, `Authority_User2`, `ACE_C_PIN_User2_Set_PIN`, and `ACE_User2_Set_CommonName`.
- Mismatches found:
  - The model was still too User1-shaped in several exact AccessControl/ACE paths.
  - It could accept `ACE_C_PIN_User1_Set_PIN` as the ACL for `C_PIN_User2/Set`.
  - It could accept `Admins OR User1` as the BooleanExpr for `ACE_C_PIN_User2_Set_PIN`.
  - It could accept `ACE_User1_Set_CommonName` for `Authority_User2/Set`.
- How the algorithm was fixed:
  - ACE name parsing and uidref canonicalization now recognize generic `UserN` ACE aliases.
  - Exact `GetACL` expectations now instantiate `C_PIN_UserN` and `Authority_UserN` associations from the UserMMMM pattern.
  - ACE preconfiguration cell checks now synthesize rows for `ACE_C_PIN_UserN_Set_PIN` and `ACE_UserN_Set_CommonName`.
  - Regression tests pin the behavior so future changes cannot quietly collapse User2 through User8 back to User1.
- How consensus handled it:
  - Three reviewers independently labeled 12 rows.
  - All reviewers returned 6 PASS / 6 FAIL with no concerns.
  - Consensus accepted all 12; quarantine stayed at 82.
- Latest evidence snapshot:
  - Full sourced corpus: 2852 / 0 mismatches.
  - Consensus gate: 2770 accepted / 82 quarantined / 0 mismatches.
  - Synthetic corpus: 205 / 0 mismatches.
  - Unit tests: 868 passed.
  - Local evaluation: 100.00.
  - Doc graph: 1376 sections, 2910 entities, 29275 edges, 2852 test links.
  - Doc coverage: 471 / 1376 docs covered by sourced cases; 262 high-priority A/B docs still untriaged.
- Presentation angle:
  - This is a clean example of the loop finding a hidden generalization bug: the earlier tests proved User1, but the official table was UserMMMM. The repaired model now follows the documented family rather than memorizing the first instance.

## 2026-05-26 21:45 KST - UserMMMM Long Authority/C_PIN Scope

- What changed:
  - Added `user-mmmm-authority-long-doc`: 10 long cases using `User8` as a non-User1 instantiation of Opal's mandatory UserMMMM rows.
  - The cases combine Admin setup, User8 enablement, User8 C_PIN assignment, ACE personalization, User8 authentication, C_PIN Set authorization, `GetACL`, and ACE cell reads.
- Mismatches found:
  - None in the current model. The previous UserMMMM generalization repair already carried through to this longer trajectory.
- How the algorithm was handled:
  - No new production repair was made.
  - The important check was conceptual: User8 may change only `C_PIN_User8.PIN` through `ACE_C_PIN_User8_Set_PIN`; it may not change `TryLimit`, and mixed `PIN + TryLimit` Set must fail as a whole.
- How consensus handled it:
  - First reviewer pass agreed on the labels but flagged evidence gaps.
  - We strengthened the evidence with the exact Core sections for ACE Columns, C_PIN column mapping, and Set all-or-nothing failure.
  - Laplace, Euler, and Wegener re-reviewed the strengthened batch and reported all 10 labels correct with no remaining concerns.
  - Consensus accepted all 10; quarantine stayed at 82.
- Latest evidence snapshot:
  - Full sourced corpus: 2862 / 0 mismatches.
  - Consensus gate: 2780 accepted / 82 quarantined / 0 mismatches.
  - Synthetic corpus: 205 / 0 mismatches.
  - Unit tests: 868 passed.
  - Local evaluation: 100.00.
  - Doc graph: 1376 sections, 2920 entities, 29475 edges, 2862 test links.
  - Doc coverage: 472 / 1376 docs covered by sourced cases; 261 high-priority A/B docs still untriaged.
- Presentation angle:
  - This is useful process evidence: the system did not blindly accept labels just because reviewers agreed. It caught under-evidenced reasoning, added the missing official sections, then promoted the cases only after a clean no-concern re-review.

## 2026-05-26 22:00 KST - UserMMMM TryLimit/Uses Long Counters

- What changed:
  - Added `user-mmmm-auth-tries-uses-long-doc`: 20 long cases using `User8` to combine C_PIN `TryLimit`/`Tries`, Authority `Limit`/`Uses`, explicit Proof authentication, session startup, and PIN modification.
- Mismatches found:
  - None. The earlier UserMMMM generalization already held for the longer authentication-counter state machine.
- How the algorithm was handled:
  - No production repair was made.
  - The key validation was conceptual: failed auth affects Tries only, successful auth resets Tries and increments Uses, PIN modification resets Tries without consuming Uses, and Tries reset does not lower Authority Uses.
- How consensus handled it:
  - Initial reviewers agreed with the labels but found two places where the case design could be more conservative.
  - We removed exact `StartSession` failure-status assertions after Limit lockout and switched to explicit `Authenticate must not return True`.
  - We changed the PIN Set reset cases so Admin PIN Set directly follows failed Proof, avoiding accidental reset by User8 login.
  - The revised batch was re-reviewed by three agents with no remaining concerns and all 20 cases were accepted.
- Latest evidence snapshot:
  - Full sourced corpus: 2882 / 0 mismatches.
  - Consensus gate: 2800 accepted / 82 quarantined / 0 mismatches.
  - Synthetic corpus: 205 / 0 mismatches.
  - Unit tests: 868 passed.
  - Local evaluation: 100.00.
  - Doc graph: 1376 sections, 2940 entities, 29835 edges, 2882 test links.
  - Doc coverage: 473 / 1376 docs covered by sourced cases; 260 high-priority A/B docs still untriaged.
- Presentation angle:
  - This is a strong example of the review loop improving case quality even without finding a solver bug: the agents caught over-specific status assumptions and a confounded trajectory, then the batch was revised into more defensible official-doc regressions.

## 2026-05-26 22:30 KST - RangeNNNN GetACL Generalization Bug

- What changed:
  - Added `getacl-rangennnn-alias-impossible-doc`: 10 official-doc cases around RangeNNNN exact AccessControl ACLs.
  - The batch targets wrong successful `GetACL` responses for `Locking_Range2/8`, `K_AES_128_Range2/8_Key`, and `K_AES_256_Range2/8_Key`.
- Mismatches found:
  - The model accepted `Range1` ACEs as if they applied to other RangeNNNN instances.
  - It accepted K_AES `Get` associations returning `GenKey` ACEs.
  - It accepted wrong AES-family ACEs, e.g. returning a `K_AES_128` GenKey ACE for a `K_AES_256` association.
- How the algorithm was fixed:
  - Generic RangeNNNN ACE aliases are now normalized in parsing, engine comparison, and semantic ACE-symbol handling.
  - Exact `GetACL` expectations synthesize Opal's documented RangeNNNN formulas instead of memorizing only GlobalRange and Range1.
  - A first repair exposed an important boundary: dynamically host-created Locking ranges have dynamic AccessControl rows and must not be forced into preconfigured RangeNNNN ACLs. The model now tracks `State.created_locking_ranges` and exempts those rows from the preconfigured exact-ACL rule.
- How consensus handled it:
  - Three agents first agreed on labels, but one raised a packaging concern: the blind source snippets did not expose every K_AES AccessControl row.
  - The review exporter was improved to include multiple relevant excerpts per long source section.
  - After re-review, `rangennnn_acl_{a,b,c}.jsonl` contains 30 no-concern reviews, all matching the author labels.
- Latest evidence snapshot:
  - Full sourced corpus: 2892 / 0 mismatches.
  - Consensus gate: 2810 accepted / 82 quarantined / 0 mismatches.
  - Synthetic corpus: 205 / 0 mismatches.
  - Unit tests: 871 passed.
  - Local evaluation: 100.00.
  - Doc graph: 1376 sections, 2950 entities, 29935 edges, 2892 test links.
  - Doc coverage: 473 / 1376 docs covered by sourced cases; 260 high-priority A/B docs still untriaged.
- Presentation angle:
  - This is a strong “model improved through edge cases” story. The failure was not one wrong answer; it was a missing formula-instantiation rule. The final repair also shows the loop preventing overgeneralization by separating preconfigured RangeNNNN rows from host-created dynamic ranges.

## 2026-05-26 22:39 KST - RangeNNNN ACE.Get Follow-Through

- What changed:
  - Added `ace-rangennnn-cells-impossible-doc`: 8 official-doc cases that test RangeNNNN ACE row `BooleanExpr` and `Columns` cells directly.
  - These cases deliberately use impossible-success labels so they remain valid whether an optional RangeNNNN row is absent or present.
- Mismatches found:
  - None. The previous RangeNNNN AccessControl repair already generalized to ACE row cell validation.
- How the algorithm was handled:
  - No production code change was needed for this slice.
  - The value is regression confidence: the model now rejects wrong ACE.Get cell payloads for Locking RangeNNNN and K_AES RangeNNNN GenKey ACE rows.
- How consensus handled it:
  - Three reviewers completed 24 labels with no concerns.
  - Consensus accepted all 8 new cases; quarantine stayed at 82.
- Latest evidence snapshot:
  - Full sourced corpus: 2900 / 0 mismatches.
  - Consensus gate: 2818 accepted / 82 quarantined / 0 mismatches.
  - Synthetic corpus: 205 / 0 mismatches.
  - Unit tests: 871 passed.
  - Local evaluation: 100.00.
  - Doc graph: 1376 sections, 2958 entities, 29975 edges, 2900 test links.
- Presentation angle:
  - This is a useful “repair generalization check” slide: after fixing exact GetACL aliasing, the loop immediately checked a neighboring observable surface and confirmed the repair was not too narrow.

## 2026-05-26 22:55 KST - Created RangeNNNN Long Reset Audit

- What changed:
  - Added `locking-created-row-long-reset-doc`: 10 official-doc cases for dynamically created Locking RangeNNNN rows.
  - The trajectories are deliberately long: create row, mutate geometry/lock cells/LockOnReset, cross one or more reset boundaries, reopen a session, then observe the final Get.
- Mismatches found:
  - None. The current rulebase already tracked this family correctly.
- How the algorithm was handled:
  - No production code change was made for this batch.
  - This was a stress and regression layer over the suspected high-value Locking state machine, not a narrow fix.
- How consensus handled it:
  - Three reviewers completed 30 labels with no concerns.
  - Consensus accepted all 10 new cases; quarantine stayed at 82.
- Latest evidence snapshot:
  - Full sourced corpus: 2910 / 0 mismatches.
  - Consensus gate: 2828 accepted / 82 quarantined / 0 mismatches.
  - Synthetic corpus: 205 / 0 mismatches.
  - Unit tests: 871 passed.
  - Local evaluation: 100.00.
  - Doc graph: 1376 sections, 2968 entities, 30145 edges, 2910 test links.
- Presentation angle:
  - This is a strong “we made the tests harder, not just bigger” example: the case checks that the model carries created-row state through multiple semantically different events and does not confuse ProtocolStackReset with Opal LockOnReset reset_types.

## 2026-05-26 23:02 KST - Failed Set Does Not Poison Later Reset

- What changed:
  - Added `locking-created-row-failed-set-reset-doc`: 10 official-doc cases where a created Locking row sees a failed Set, then a reset, then a Get.
  - This connects two concepts that are easy to handle separately but harder together: all-or-nothing Set semantics and reset-state recovery.
- Mismatches found:
  - None. The model already preserved pre-failure state through the later reset.
- How the algorithm was handled:
  - No production code change was needed.
  - This serves as a regression guard against partial-mutation fixes that would look locally correct but corrupt longer trajectories.
- How consensus handled it:
  - Three reviewers completed 30 labels with no concerns.
  - Consensus accepted all 10 new cases; quarantine stayed at 82.
- Latest evidence snapshot:
  - Full sourced corpus: 2920 / 0 mismatches.
  - Consensus gate: 2838 accepted / 82 quarantined / 0 mismatches.
  - Synthetic corpus: 205 / 0 mismatches.
  - Unit tests: 871 passed.
  - Local evaluation: 100.00.
  - Doc graph: 1376 sections, 2978 entities, 30345 edges, 2920 test links.
- Presentation angle:
  - This is a clean “contextual repair discipline” example: if a future mismatch appears here, the right fix is not a case-specific answer but the general invariant that failed Set cannot mutate the state consumed by later resets.

## 2026-05-26 23:22 KST - LogTo Bug Found, Fixed, Then Quarantined by Evidence Review

- What changed:
  - Added `accesscontrol-logto-default-doc`: 10 cases around direct `AccessControl.Get` of the `LogTo` column for issued Locking SP associations.
  - The local case generator paired empty/default `LogTo` responses against impossible non-empty `LogList` UID responses.
- Mismatches found:
  - The rulebase initially missed 5 impossible cases: it treated wrong non-empty `LogTo` cells as acceptable.
- How the algorithm was fixed:
  - `LogTo` is now a first-class AccessControl column constant.
  - The parser resolves named `LogTo` Cellblock bounds.
  - The expectation layer constrains known issued-row `LogTo` defaults during direct AccessControl `Get`.
  - Two regression tests were added for numeric and named Cellblock variants.
- How consensus handled it:
  - The three reviewers did not disagree about the local PASS/FAIL shape, but two reviewers raised source-grounding concerns.
  - The issue was not the `LogTo` default itself; it was that the packet evidence did not directly prove the concrete AccessControl row UID encodings used by the direct-Get calls.
  - Consensus left all 10 new cases quarantined. Accepted count stayed at 2838; quarantine moved to 92.
- Latest evidence snapshot:
  - Full sourced corpus: 2930 / 0 mismatches.
  - Consensus gate: 2838 accepted / 92 quarantined / 0 mismatches.
  - Synthetic corpus: 205 / 0 mismatches.
  - Unit tests: 873 passed.
  - Local evaluation: 100.00.
  - Doc graph: 1376 sections, 2988 entities, 30395 edges, 2930 test links.
  - Doc coverage: 475 / 1376 docs covered by sourced cases; 258 high-priority A/B docs still untriaged.
- Presentation angle:
  - This is a useful “safety valve” story: the generation loop found and repaired a real model blind spot, but the independent evidence loop prevented a weakly grounded UID-specific case from becoming part of the trusted benchmark.

## 2026-05-26 23:49 KST - MBR Shadow Reset Batch Accepted After Reviewer-Driven Rework

- What changed:
  - Added `mbr-shadow-reset-long-doc`: 10 long MBR shadowing cases that combine byte-table payload provenance, `MBRControl.Done`, `MBRDoneOnReset`, and reset event identity.
  - The trajectories deliberately distinguish PowerCycle, ProtocolStackReset, and enabled TPerReset/Programmatic reset.
- Mismatches found:
  - None. The current model already handled this official-doc slice.
- How the algorithm was handled:
  - No production rulebase change was needed.
  - The value is trusted coverage around an important hidden-score candidate: state must flow from MBR table writes into host reads only when shadowing is active after the correct reset semantics.
- How consensus handled it:
  - First review round flagged two cases because a failed multi-column Set made the evidence packet less crisp.
  - The generator revised those cases so `Enable` and `Done` are set successfully before a failed `DoneOnReset=[3]` update. That isolates the invalid reset-list rule.
  - Re-review accepted all 10 cases with no concerns.
- Latest evidence snapshot:
  - Full sourced corpus: 2940 / 0 mismatches.
  - Consensus gate: 2848 accepted / 92 quarantined / 0 mismatches.
  - Synthetic corpus: 205 / 0 mismatches.
  - Unit tests: 873 passed.
  - Local evaluation: 100.00.
  - Doc graph: 1376 sections, 2998 entities, 30535 edges, 2940 test links.
  - Doc coverage: 475 / 1376 docs covered by sourced cases; 258 high-priority A/B docs still untriaged.
- Presentation angle:
  - This is a clean example of the loop improving the test, not just the model: reviewers did not reject the concept, they found a weaker trajectory formulation, and the final accepted case became more defensible.

## 2026-05-26 23:57 KST - MBR Access Split Batch Accepted

- What changed:
  - Added `mbr-access-byte-state-doc`: 10 cases around MBR byte-table Get/Set access control and byte-state provenance.
  - The batch checks that unauthenticated sessions can read MBR bytes through `ACE_Anybody`, but cannot write because MBR Set is `ACE_Admin`.
- Mismatches found:
  - No final model mismatch.
  - The harness caught a generator mistake before consensus: a direct `MBR.Get` was attempted without reopening a session after replacing a host-read assertion.
- How the algorithm was handled:
  - No production code change was needed.
  - This was a robustness batch for byte-table authorization and nonmutation semantics.
- How consensus handled it:
  - The first packet had reviewer concerns over compact raw Get argument notation and host-read pattern shorthand.
  - The cases were revised to use explicit `Cellblock` row bounds for every final MBR byte observation.
  - Re-review accepted all 10 cases with no concerns.
- Latest evidence snapshot:
  - Full sourced corpus: 2950 / 0 mismatches.
  - Consensus gate: 2858 accepted / 92 quarantined / 0 mismatches.
  - Synthetic corpus: 205 / 0 mismatches.
  - Unit tests: 873 passed.
  - Local evaluation: 100.00.
  - Doc graph: 1376 sections, 3008 entities, 30635 edges, 2950 test links.
  - Doc coverage: 475 / 1376 docs covered by sourced cases; 258 high-priority A/B docs still untriaged.
- Presentation angle:
  - Another good quality-control example: the loop improved packet clarity, not just count. Trusted cases only entered after the evidence and trajectory were explicit enough for blind agreement.

## 2026-05-27 00:17 KST - ACE/K_AES Cross-Check Added With Conservative Quarantine

- What changed:
  - Added `ace-kaes-set-crosscheck-long-doc`: 24 cases combining ACE row cells, ACE `BooleanExpr` personalization, `GetACL`, and K_AES GenKey associations.
  - The goal was to prevent a model from confusing two nearby concepts:
    - setting an ACE object's `BooleanExpr` is authorized by `ACE_ACE_Set_BooleanExpression`;
    - invoking a K_AES key object's `GenKey` method is authorized by the corresponding K_AES GenKey ACE.
- Mismatches found:
  - None in the current rulebase.
- How the algorithm was handled:
  - No production model change was made.
  - The run still exercised the existing general mechanisms: ACE cell expectation tracking, successful ACE.Set state mutation, exact `GetACL` uidref list validation, and K_AES ACE canonicalization.
- How consensus handled it:
  - All three reviewers produced 24 labels with the expected 12 PASS / 12 FAIL split.
  - Accepted: 16 cases.
  - Quarantined: 8 cases.
  - Quarantine reason was evidence quality, not solver failure:
    - 4 cases used symbolic `User1` in a later ACE.Get return after setting numeric UID `0000000900030001`.
    - 4 cases relied on exact ACE-object Set or K_AES GenKey AccessControl rows that were summarized correctly but not fully visible in the extracted snippets.
- Latest evidence snapshot:
  - Full sourced corpus: 2974 / 0 mismatches.
  - Consensus gate: 2874 accepted / 100 quarantined / 0 mismatches.
  - Synthetic corpus: 205 / 0 mismatches.
  - Unit tests: 873 passed.
  - Local evaluation: 100.00.
  - Doc graph: 1376 sections, 3032 entities, 30947 edges, 2974 test links.
  - Doc coverage: 475 / 1376 docs covered by sourced cases; 258 high-priority A/B docs still untriaged.
- Presentation angle:
  - This is a good “reviewers are not rubber stamps” example.
  - The loop accepted the clear official-doc cases, rejected the weaker packet formulations, and preserved the reason for rejection so the next generation pass can target exactly the missing evidence.

## 2026-05-27 00:42 KST - ACE/K_AES Quarantine Reworked Into Trusted Cases

- What changed:
  - Added `ace-kaes-crosscheck-evidence-tight-doc`: 12 evidence-tight cases derived from the quarantined ACE/K_AES cross-check concerns.
  - The revised cases use numeric User1 UID `0000000900030001` in final ACE.Get observations and cite exact Opal rows for K_AES GenKey ACEs and AccessControl associations.
- Mismatches found:
  - None. The current rulebase already handled these once the cases were expressed with stronger evidence.
- How the algorithm was handled:
  - No production solver change was made.
  - The important process fix was conceptual and procedural: distinguish the ACE object's `Set` ACL from K_AES key-object `GenKey` ACLs, and require reviewer `concerns` to mean actual evidence ambiguity rather than ordinary FAIL rationale.
- How consensus handled it:
  - Initial re-review had protocol noise: one reviewer mislabeled a column-4-only CellBlock case and another filled `concerns` for normal negative cases.
  - After clarifying the review instruction, Dirac, Lorentz, and Bernoulli re-reviewed all 12 cases with no concerns.
  - Consensus accepted all 12; quarantine stayed at 100.
- Latest evidence snapshot:
  - Full sourced corpus: 2986 / 0 mismatches.
  - Consensus gate: 2886 accepted / 100 quarantined / 0 mismatches.
  - Synthetic corpus: 205 / 0 mismatches.
  - Unit tests: 873 passed.
  - Local evaluation: 100.00.
  - Doc graph: 1376 sections, 3044 entities, 31115 edges, 2986 test links.
  - Doc coverage: 475 / 1376 docs covered by sourced cases; 258 high-priority A/B docs still untriaged.
- Presentation angle:
  - This is exactly the loop we wanted to demonstrate: a first generation pass produced useful but partially under-evidenced cases, reviewers quarantined the weak ones, and the next pass turned the ambiguity into accepted official-doc tests without changing the model opportunistically.

## 2026-05-27 01:05 KST - Read-Only Session C_PIN Counter Batch Accepted

- What changed:
  - Added `cpin-readonly-auth-tries-long-doc`: 16 long cases tying `StartSession.Write=False`, explicit `Authenticate`, C_PIN `TryLimit/Tries`, and Authority `Limit/Uses`.
  - The key idea is that a read-only host session still allows the TPer to maintain authentication counters.
- Mismatches found:
  - None. The existing model already applied Authenticate side effects independent of host write permission.
- How the algorithm was handled:
  - No production repair was made.
  - The model behavior validated here is subtle: “read-only session” blocks host mutation methods, but failed/successful authentication still mutates TPer-maintained `Tries`/`Uses` state according to the spec.
- How consensus handled it:
  - Ampere, Mendel, and Plato each reviewed 16 blind packets.
  - All three produced 8 PASS / 8 FAIL, no concerns, and matching case order.
  - Consensus accepted all 16; quarantine remained at 100.
- Latest evidence snapshot:
  - Full sourced corpus: 3002 / 0 mismatches.
  - Consensus gate: 2902 accepted / 100 quarantined / 0 mismatches.
  - Synthetic corpus: 205 / 0 mismatches.
  - Unit tests: 873 passed.
  - Local evaluation: 100.00.
  - Doc graph: 1376 sections, 3060 entities, 31355 edges, 3002 test links.
  - Doc coverage: 476 / 1376 docs covered by sourced cases; 258 high-priority A/B docs still untriaged.
- Presentation angle:
  - This is a good example of concept composition rather than just harder single-rule cases: session mode, Authenticate result shape, C_PIN failed-attempt accounting, and Authority successful-use accounting all have to stay disentangled.

## 2026-05-27 10:49 KST - Read-Only Host Mutation Bug Found, Repaired, And Reworked Through Consensus

- What changed:
  - Added `readonly-explicit-nonpersistence-long-doc`: 8 cases checking that explicit host `Set` mutations in `Write=False` sessions do not persist.
  - Added `readonly-explicit-nonpersistence-tight-doc`: 4 direct-observation cases for ACE `BooleanExpr` and Authority `Uses` nonpersistence.
- Mismatches found:
  - The first local run found 8 solver mismatches. The model was treating successful context `Set` records as persistent even when the active session was read-only.
  - A follow-up direct ACE.Get case found a separate alias issue: `ACE_DataStore_Get_All` was not mapped to canonical row `ACE_0003FC00`, so known ACE row cell validation could be bypassed for the name-form object.
- How the algorithm was handled:
  - The transition model now blocks persistent effects from explicit host mutation methods in open read-only sessions.
  - The fix is concept-level: it covers Set/Create/Delete/AddACE/RemoveACE/SetACL/Activate/GenKey/Revert-style host mutations while preserving documented read-only exceptions like C_PIN authentication counters.
  - The parser now canonicalizes name-form DataStore ACE rows to the same UID-form keys used by Opal preconfiguration and state tracking.
- How consensus handled it:
  - First review accepted 6 of the 8 original cases and quarantined 2 because they were too indirect or too easy to misread.
  - Instead of pushing those through, the generator added direct ACE.Get and Authority.Get replacement cases.
  - Carson, Planck, and Mill reviewed the tight batch; all three produced 2 PASS / 2 FAIL with no concerns.
  - Final consensus: 3014 cases, 9597 review rows, 2912 accepted, 102 quarantined.
- Latest evidence snapshot:
  - Full sourced corpus: 3014 / 0 mismatches.
  - Consensus gate: 2912 accepted / 102 quarantined / 0 mismatches.
  - Synthetic corpus: 205 / 0 mismatches.
  - Unit tests: 880 passed.
  - Local evaluation: 100.00.
  - Doc graph: 1376 sections, 3072 entities, 31679 edges, 3014 test links.
  - Doc coverage: 478 / 1376 docs covered by sourced cases; 257 high-priority A/B docs still untriaged.
- Presentation angle:
  - This is a strong end-to-end story: official-doc concept composition found a real false positive, the repair changed a general state-transition rule, reviewers quarantined weak formulations, and the loop generated cleaner direct observations before adding the cases to the trusted corpus.

## 2026-05-27 12:42 KST - Private Regression Hypothesis Converted Into A Public-Doc Repair

- What changed:
  - Investigated the reported 87.5 -> 87.0 private-score dip without using private labels.
  - The leading suspect was AccessControl/GetACL, specifically the broad RangeNNNN/K_AES RangeNNNN exact ACL generalization.
  - Added `getacl-optional-range-existence-doc`, a 4-case official-doc diagnostic batch, after first fixing the solver.
- Mismatches found:
  - Local trusted cases had no mismatch, which is expected because the existing RangeNNNN sourced cases mostly checked wrong-alias impossibility.
  - New regression tests exposed the conceptual false positive: an unobserved optional `Locking_Range2` or `K_AES_256_Range8_Key` could previously return a perfect-looking exact ACL and be accepted.
- How the algorithm was handled:
  - The solver now distinguishes mandatory/known range-backed AccessControl objects from optional unobserved rows.
  - GlobalRange and Range1..MaxRanges stay valid; Range IDs beyond supported MaxRanges must be created/observed before exact GetACL success is accepted.
  - If MaxRanges is unobserved, the model uses Opal's minimum of 8 non-global ranges rather than treating every RangeNNNN string as real.
  - The repair is not case-specific: the same predicate gates Locking range objects and K_AES RangeNNNN key objects for GetACL/ACL association existence.
- How consensus handled it:
  - The first packet was revised after self-review because `MaxRanges=1` is weak in Opal, whose LockingInfo table requires a minimum of 8 ranges.
  - The final Range8/Range9 packet was reviewed independently by Aquinas, Darwin, and Cicero.
  - All three reviewers agreed: Range9 Locking/K_AES cases are FAIL, Range8 Locking/K_AES cases are PASS, no concerns.
  - Consensus now has 3018 cases, 9609 review rows, 2916 accepted, 102 quarantined.
- Latest evidence snapshot:
  - Unit tests: 884 passed.
  - New tag: `getacl-optional-range-existence-doc`, 4 / 0 mismatches.
  - Full sourced corpus: 3018 / 0 mismatches.
  - Consensus gate: 2916 accepted / 102 quarantined / 0 mismatches.
  - Synthetic corpus: 205 / 0 mismatches.
  - Local evaluation: 100.00.
- Presentation angle:
  - This is a useful “score-dip response” story: leaderboard feedback was used only to prioritize a suspicious public-doc area, then the actual repair was justified by official optional-row semantics and guarded by local trusted regression tests.

## 2026-05-27 14:34 KST - MaxRanges Consistency Added As A Bidirectional State Check

- What changed:
  - Added `lockinginfo-maxranges-consistency-doc`, a 4-case official-doc batch tying successful RangeNNNN/K_AES observations to later `LockingInfo.MaxRanges` reads.
  - The new cases check the inverse of the earlier GetACL range-boundary rule: if Range9 has already been observed as successful, a later `MaxRanges=8` success is impossible; Range8 remains valid.
- Mismatches found:
  - This gap was found by consistency inspection while extending the AccessControl/Locking range work, not by probing private labels.
  - The new regression tests cover the failure mode directly before the sourced batch is promoted.
- How the algorithm was handled:
  - The model now tracks the highest observed non-global Locking range id from created ranges and successful Locking/K_AES range observations.
  - `LockingInfo.Get` validates returned `MaxRanges` against that observed maximum before accepting `SUCCESS`.
  - This is a general state-machine repair: any higher observed range constrains later geometry, not only the four added examples.
- How consensus handled it:
  - Newton, Nietzsche, and Avicenna independently reviewed the blind packets.
  - All three produced the same labels: Range9 Locking/K_AES cases `FAIL`, Range8 Locking/K_AES cases `PASS`, no concerns.
  - Consensus now has 3022 cases, 9621 review rows, 2920 accepted, 102 quarantined.
- Latest evidence snapshot:
  - New tag: `lockinginfo-maxranges-consistency-doc`, 4 / 0 mismatches.
  - Full sourced corpus: 3022 / 0 mismatches.
  - Consensus gate: 2920 accepted / 102 quarantined / 0 mismatches.
  - Synthetic corpus: 205 / 0 mismatches.
  - Unit tests: 887 passed.
  - Local evaluation: 100.00.
  - Doc graph: 1376 sections, 3080 entities, 31747 edges, 3022 test links.
  - Doc coverage: 478 / 1376 docs covered by sourced cases; 257 high-priority A/B docs still untriaged.
- Presentation angle:
  - This is a clean example of the loop converting a concept into a bidirectional invariant: `MaxRanges` bounds range rows, and observed range rows bound later `MaxRanges` claims.

## 2026-05-27 16:00 KST - Optional Rows Became A Three-State Presence Model

- What changed:
  - Added `optional-range-direct-presence-doc`, a 7-case official-doc batch for direct optional Range9 operations.
  - It covers both sides: Range9 may be absent before support is observed, but Range9 success is invalid after `MaxRanges=8`.
- Mismatches found:
  - The rulebase had been treating many RangeNNNN name matches as if the row existed.
  - The new tests forced a better distinction between “known present,” “known absent,” and “not yet observed.”
- How the algorithm was handled:
  - Added `_range_id_support_state`, returning `True`, `False`, or `None` instead of a flat yes/no.
  - Direct Locking `Get`, Locking `Set`, K_AES `Get`, K_AES `GenKey`, and Locking `CreateRow` now consult that support state.
  - `CreateRow` responses are checked so a successful return of Range9 is rejected when `MaxRanges=8` has already been observed.
- How consensus handled it:
  - Kant, Wegener, and Helmholtz independently reviewed the blind packets.
  - All three agreed: 4 FAIL cases for Range9 success after `MaxRanges=8`, and 3 PASS cases for absent optional Range9 failures before `MaxRanges` is known.
  - Consensus now has 3029 cases, 9642 review rows, 2927 accepted, 102 quarantined.
- Latest evidence snapshot:
  - New tag: `optional-range-direct-presence-doc`, 7 / 0 mismatches.
  - Full sourced corpus: 3029 / 0 mismatches.
  - Consensus gate: 2927 accepted / 102 quarantined / 0 mismatches.
  - Synthetic corpus: 205 / 0 mismatches.
  - Unit tests: 894 passed.
  - Local evaluation: 100.00.
  - Doc graph: 1376 sections, 3087 entities, 31789 edges, 3029 test links.
  - Doc coverage: 478 / 1376 docs covered by sourced cases; 257 high-priority A/B docs still untriaged.
- Presentation angle:
  - This is a strong example for the talk: a naive binary concept (`Range9 exists?`) became a trajectory-sensitive state abstraction, which then unified GetACL behavior and direct method behavior.

## 2026-05-27 17:07 KST - Optional Row Presence Extended To Deletion

- What changed:
  - Added `optional-range-delete-presence-doc`, a 4-case official-doc batch for Range9 `DeleteRow` and direct `Delete`.
  - This extends the same optional-row support model from direct reads/writes/key generation to object lifecycle deletion.
- Mismatches found:
  - The range-support abstraction was not yet applied to deletion expectations.
  - Without that, a Range9 deletion could be treated too much like a concrete row just because the UID/name parsed cleanly.
- How the algorithm was handled:
  - `DeleteRow` and direct `Delete` now consult `_range_id_support_state`.
  - If `MaxRanges=8` has excluded Range9, deletion `SUCCESS` is forbidden.
  - If Range9 support has not been observed, deletion failure is accepted because the optional row may be absent.
- How consensus handled it:
  - James, Popper, and Carver independently reviewed the blind packets.
  - All three agreed: Range9 deletion success after `MaxRanges=8` is `FAIL`; unobserved Range9 deletion failure is `PASS`.
  - Consensus now has 3033 cases, 9654 review rows, 2931 accepted, 102 quarantined.
- Latest evidence snapshot:
  - New tag: `optional-range-delete-presence-doc`, 4 / 0 mismatches.
  - Full sourced corpus: 3033 / 0 mismatches.
  - Consensus gate: 2931 accepted / 102 quarantined / 0 mismatches.
  - Synthetic corpus: 205 / 0 mismatches.
  - Unit tests: 898 passed.
  - Local evaluation: 100.00.
  - Doc graph: 1376 sections, 3091 entities, 31809 edges, 3033 test links.
  - Doc coverage: 478 / 1376 docs covered by sourced cases; 257 high-priority A/B docs still untriaged.
- Presentation angle:
  - This is the cleanup step that makes the optional-row abstraction feel complete: not just access methods, but lifecycle methods now obey the same trajectory-sensitive presence model.

## 2026-05-27 17:40 KST - Positive Controls Prevented Optional-Row Overcorrection

- What changed:
  - Added `optional-range-supported-presence-doc`, a 7-case PASS batch for `MaxRanges=9` and Range9.
  - These are positive controls: they prove the model is not simply banning Range9.
- Mismatches found:
  - None. The three-state support model already handled these cases.
- How the algorithm was handled:
  - No production repair was needed.
  - The corpus now encodes both sides of the invariant: `MaxRanges=8` excludes Range9, while `MaxRanges=9` allows Range9 when the row/key is present.
- How consensus handled it:
  - Copernicus, Hilbert, and Euler independently reviewed the blind packets.
  - All three labeled all 7 cases PASS with no concerns.
  - Consensus now has 3040 cases, 9675 review rows, 2938 accepted, 102 quarantined.
- Latest evidence snapshot:
  - New tag: `optional-range-supported-presence-doc`, 7 / 0 mismatches.
  - Full sourced corpus: 3040 / 0 mismatches.
  - Consensus gate: 2938 accepted / 102 quarantined / 0 mismatches.
  - Synthetic corpus: 205 / 0 mismatches.
  - Unit tests: 903 passed.
  - Local evaluation: 100.00.
  - Doc graph: 1376 sections, 3098 entities, 31879 edges, 3040 test links.
  - Doc coverage: 478 / 1376 docs covered by sourced cases; 257 high-priority A/B docs still untriaged.
- Presentation angle:
  - This is a nice “scientific method” moment for the story: after adding negative cases, we added the opposite positive controls so the model learns the boundary, not just a slogan.

## 2026-05-27 20:46 KST - Optional GetACL Was Recalibrated Instead Of Over-Rejected

- What changed:
  - Added `datastore-empty-booleanexpr-doc` with 10 cases and `getacl-optional-range-unobserved-doc` with 6 cases.
  - The DataStore batch is a clean authority-state regression: if `BooleanExpr=[]` is accepted, the ACE always evaluates False; byte-table `Get` returns empty and `Set` fails without mutation.
  - The GetACL batch fixes a sharper scoring candidate: before `MaxRanges` is observed, Range9+ may be present or absent. A successful Range9 GetACL is not automatically wrong; it is wrong only if the ACL list is not the exact RangeNNNN/K_AES pattern, or if later `MaxRanges=8` contradicts the observation.
- Mismatches found:
  - New sourced GetACL cases exposed one solver mismatch: `K_AES_256_Range9_Key/GenKey` GetACL exact success was still rejected as an unknown association.
  - DataStore empty BooleanExpr produced no mismatch; existing expression evaluation already had the right semantics.
- How the algorithm was handled:
  - Range support stayed three-state: present / absent / unknown.
  - AccessControl association existence now preserves the unknown state instead of flattening it to absent.
  - Successful Range9 GetACL now updates observed range state, so later `LockingInfo.MaxRanges` cannot contradict it.
  - Exact ACL validation stayed strict on `SUCCESS`.
- How consensus handled it:
  - `datastore_empty_bool_{a,b,c}.jsonl`: 30 no-concern reviews, all 10 cases accepted.
  - `getacl_optional_unknown_{a,b,c}.jsonl`: 18 reviews. Four cases accepted; two optional-absence failure cases were quarantined because the docs justify failure but not a single exact failure status.
  - Consensus now has 3056 cases, 9723 review rows, 2952 accepted, 104 quarantined.
- Latest evidence snapshot:
  - Full sourced corpus: 3056 / 0 mismatches.
  - Consensus gate: 2952 accepted / 104 quarantined / 0 mismatches.
  - Synthetic corpus: 205 / 0 mismatches.
  - Unit tests: 910 passed.
  - Local evaluation: 100.00.
  - Doc graph: 1376 sections, 3114 entities, 32021 edges, 3056 test links.
  - Doc coverage: 478 / 1376 docs covered by sourced cases; 257 high-priority A/B docs still untriaged.
- Presentation angle:
  - This is a useful story beat: the process did not just make the model stricter. It found where strictness itself was the bug, then kept the exact-return constraints while relaxing only the unsupported assumption.

## 2026-05-29 00:31 KST - Wrapper Input Shapes Became First-Class Test Targets

- What changed:
  - A wrapper-focused subagent audited the high-level TCGstorageAPI parser and found concrete shape gaps in `checkPIN`, `setRange`, and `revertLockingSP`.
  - An AccessControl-focused audit found a separate direct-Get hole for documented pattern rows beyond the original concrete rows.
- Mismatches found:
  - Before repair, `checkPIN(params=["SID", "new"]) -> True` after a SID PIN update was predicted `FAIL` because `params` were ignored.
  - Before repair, positional `setRange("Admin1", 1, 80, 8, True, True, False, True)` could leave later `getRange` stale because range fields were dropped.
  - Before repair, `revertLockingSP("new", KeepGlobalRangeKey=True)` did not carry the keep-key option into low-level RevertSP logic.
  - Before repair, direct `AccessControl.Get` for `000000070003A802` and `000000070003B801` accepted wrong identity cells.
- How the algorithm was handled:
  - `checkPIN` now uses the shared high-level argument extractor, so `args`, `params`, and `parameters` encode the same authority/PIN pair.
  - `setRange` now maps the positional tail to the documented Locking columns while preserving explicit `authAs`.
  - `revertLockingSP` now forwards `KeepGlobalRangeKey`.
  - AccessControl direct Get now validates conservative documented pattern identities for User1..8 C_PIN Set rows and K_AES global/Range1..8 GenKey rows.
- How consensus handled it:
  - The wrapper cases are synthetic score-first smoke cases, not official consensus items.
  - The new official-doc-backed AccessControl tag has 4 cases and passes full sourced validation, but it is not yet in the accepted consensus matrix.
  - Existing accepted consensus remained stable: 3567 accepted cases, 0 mismatches.
- Latest evidence snapshot:
  - New/expanded wrapper synthetic: `tcgstorageapi-wrapper`, 30 / 0 mismatches.
  - New sourced tag: `accesscontrol-pattern-direct-identity-tight-doc`, 4 / 0 mismatches.
  - Full sourced corpus: 3696 / 0 mismatches.
  - Consensus gate: 3567 accepted / 0 mismatches.
  - Synthetic corpus: 235 / 0 mismatches.
  - Unit tests: 999 passed.
  - Local evaluation: 100.00.
  - Doc coverage: 519 / 1376 docs covered by sourced cases; 232 high-priority A/B docs still untriaged.
- Presentation angle:
  - This is a good “private-score realism” moment: after the formal document loop, a subagent checked whether the API wrapper could express the same semantics through different input shapes. The repair did not invent new protocol rules; it made the parser preserve already-known protocol meaning across realistic call encodings.

## 2026-05-30 KST - Wrapper Signature Re-read Found A Positional Order Bug

- What changed:
  - Re-reading the start prompt after the 88.00 submission found that `setRange` positional arguments use wrapper order, not low-level column order.
  - The previous repair made positional `setRange` non-dropping, but still ordered the four boolean fields as `ReadLockEnabled`, `WriteLockEnabled`, `ReadLocked`, `WriteLocked`.
  - The prompt's wrapper signature is `RangeStart, RangeLength, ReadLocked, WriteLocked, ReadLockEnabled, WriteLockEnabled, LockOnReset`.
- How the algorithm was handled:
  - The parser now translates wrapper positional arguments into semantic names before the existing Locking table model sees them.
  - Keyword arguments are unchanged, so the repair is scoped to the ambiguous positional wrapper path.
- Evidence snapshot:
  - `python3 -m unittest tests.test_solver_rules -q`: 1009 tests passed.
  - `python3 tools/run_synthetic_edges.py --tag tcgstorageapi-wrapper`: 30 cases, 0 mismatches.
  - `python3 tools/run_sourced_edges.py`: 3743 cases, 0 mismatches.
  - Local public evaluation: 100.00.
- Presentation angle:
  - This is a clean example of why the workflow keeps both official protocol semantics and assignment wrapper semantics. The protocol column mapping was right, but the wrapper API had its own positional signature that needed a translation layer.

## 2026-05-31 KST - Crypto Cellblocks Reused DataStore Access-Control State

- What changed:
  - The next A/B table-method pass targeted Crypto Template failure clauses around cellblock parameters.
  - The model already knew how DataStore Get/Set ACE personalization works, but crypto methods did not reuse that knowledge when `Input` or `BufferOut` explicitly pointed at a DataStore cellblock.
- Mismatches found:
  - New tests would previously allow impossible `SUCCESS` for crypto methods that read from or write to a DataStore cellblock after the corresponding DataStore ACE BooleanExpr had been set to empty.
- How the algorithm was handled:
  - Added a narrow explicit-cellblock detector.
  - Applied DataStore Get ACL to crypto input cellblocks and DataStore Set ACL to crypto BufferOut cellblocks.
  - Left direct byte payload shorthand untouched to avoid over-tightening existing valid crypto traces.
- Evidence snapshot:
  - New tag: `crypto-cellblock-accesscontrol-doc`, 4 / 0 mismatches.
  - Full sourced corpus: 3747 / 0 mismatches.
  - Consensus gate: 3591 accepted / 0 mismatches; new tag pending review.
  - Unit tests: 1011 passed.
  - Synthetic corpus: 235 / 0 mismatches.
  - Local public evaluation: 100.00.
  - Doc coverage: 594 / 1376, with 130 A/B priority docs still untriaged.
- Presentation angle:
  - This is a useful “concept reuse” example: once DataStore ACE semantics were trusted, a later subagent could compose that concept into Crypto Template cellblock rules instead of inventing a separate crypto-specific exception.

## 2026-05-31 KST - Metadata Tables: Tightened Only The Proven Impossible Success

- What changed:
  - The remaining coverage pass hit Core `Column` / `Type` metadata-table sections.
  - The solver did not yet treat fixed UIDs `0000000400000000` and `0000000500000000` as `ColumnTable` and `TypeTable`.
  - A probe found that `Type_HostDefined.Size` could be accepted as a successful host `Set`.
- How the algorithm was handled:
  - Added metadata-table identity mapping for Column/Type.
  - Added Column/Type to the system metadata AccessControl association limits.
  - Rejected host Set of `Type_*` column 0x04 only, because Core explicitly says `Size` is TPer-calculated and not host-modifiable.
  - Deliberately did not make broad Type-table `CreateRow` success assumptions because Opal marks Type as not required in Locking SP.
- Evidence snapshot:
  - New tag: `type-column-metadata-table-doc`, 6 / 0 mismatches.
  - Unit tests: 1013 passed.
- Presentation angle:
  - This is a good example of conservative repair discipline: when the document exposed a broad feature area, we patched only the part with a hard normative rule and left optional lifecycle behavior for later evidence.

## 2026-05-31 KST - Crypto Cellblock Rule Was Reused Across Method Families

- What changed:
  - The first crypto cellblock pass fixed the algorithm generally but only wrote `Encrypt` and `Sign` sourced examples.
  - The next pass expanded the evidence to `Decrypt`, `Hash`, and `HMAC` without changing production code.
- How the algorithm was handled:
  - The previous helper already looked for explicit DataStore cellblock references in input and output parameters.
  - New long-form cases confirmed the same Get/Set ACE gate applies across stream and non-stream crypto methods.
- Evidence snapshot:
  - `crypto-cellblock-accesscontrol-doc`: 10 / 0 mismatches after expansion.
- Presentation angle:
  - This is a clean “concept composition” story: DataStore ACE state plus crypto cellblock parameters plus method-stream state combine into one shared rule rather than many one-off cases.

## 2026-05-31 KST - AccessControl Logging Was Tightened Without Broad Reinterpretation

- What changed:
  - The coverage loop reached `core/5.7.3.8`, which says Locking object `Set` methods default to `LogAlways`.
  - A probe showed the solver accepted both empty Log and `LogAlways` for Locking Range Set AccessControl rows.
- How the algorithm was handled:
  - Added recognition for concrete Locking Set AccessControl row suffixes `0003F000..0003F7FF`.
  - Expected `LogAlways` only for those rows.
  - Left other issued rows alone because earlier private-score analysis warned against broad AccessControl reinterpretation.
- Evidence snapshot:
  - New tag: `locking-accesscontrol-logalways-doc`, 6 / 0 mismatches.
  - Full sourced: 3765 / 0.
  - Consensus gate: 3591 / 0.
  - Unit tests: 1014 passed.
  - Synthetic: 235 / 0.
  - Local evaluation: 100.00.
- Presentation angle:
  - This is a useful example of “conservative specificity”: the model learned one normative exception in AccessControl logging without overriding the rest of the issued-row preconfiguration model.

## 2026-05-31 KST - Clock Template Was Bounded Before Being Modeled

- What changed:
  - The next uncovered-high-priority cluster was Clock Template time-setting.
  - Rather than inventing a Clock state machine inside Opal, the pass first checked whether Opal Admin/Locking SPs expose those Clock methods at all.
- How the algorithm was handled:
  - No production code change was needed.
  - The existing supported-method boundary already rejects Clock Template methods in Opal Admin/Locking SP.
  - Added sourced cases to make that boundary explicit and documented.
- Evidence snapshot:
  - New tag: `opal-clock-template-unsupported-doc`, 14 / 0 mismatches.
  - Full sourced: 3779 / 0.
  - Unit tests: 1014 passed.
  - Doc coverage: 619 covered, 111 untriaged A/B.
- Presentation angle:
  - This is a useful “do not over-model optional templates” moment: the agent used official docs to separate Core optional capability from the fixed Opal method universe before making any broad changes.

## 2026-05-31 KST - Evidence Links Were Backfilled For Type References

- What changed:
  - Several Core type-reference shards were not new algorithm behavior, but they were real source support for existing cases.
  - The pass linked those documents into the relevant sourced tags instead of inventing redundant tests.
- Evidence snapshot:
  - Full sourced: 3779 / 0.
  - Doc coverage: 626 covered, 104 untriaged A/B.
- Presentation angle:
  - This is part of the “traceability layer”: not every document fragment requires a new rule, but each relevant fragment should point to the edge cases that already cover it.

## 2026-05-31 KST - VerifyMode Became A Typed Locking Enum

- What changed:
  - The coverage loop hit Core `verify_mode`, a small enum that is easy to miss because Locking `VerifyMode` is described as a boolean-like requirement in prose.
  - The actual type table says valid values are only `0` and `1`; `2-7` are reserved.
- How the algorithm was handled:
  - First probe showed reserved values were accepted in both `Set` and `Get`.
  - The repair was made at the type/column level: Locking column 0x0F is now validated as `verify_mode`, instead of adding a one-off trajectory exception.
- Evidence snapshot:
  - New tag: `locking-verify-mode-enum-doc`, 6 / 0 mismatches.
  - Full sourced: 3785 / 0.
  - Unit tests: 1017 passed.
  - Doc coverage: 628 covered, 103 untriaged A/B.
- Presentation angle:
  - This is a compact example of the “official-doc shard -> edge probe -> general rule repair” loop. One parsed text fragment exposed a hidden enum constraint, and the resulting model change now covers both future Set and Get trajectories.

## 2026-05-31 KST - RSA Padding Was Kept At The Credential Column Boundary

- What changed:
  - The coverage loop reached `padding_type`, whose obvious temptation is to patch Sign/Verify method arguments.
  - The stronger document anchor was actually C_RSA credential `Format`, because the RSA object tables explicitly type that column as `padding_type`.
- How the algorithm was handled:
  - Probes showed reserved C_RSA `Format` values and boolean coercion were accepted.
  - The solver repair validates C_RSA column 0x03 on Set and Get, but does not invent unsupported method-level padding semantics.
- Evidence snapshot:
  - New tag: `crsa-padding-type-enum-doc`, 8 / 0 mismatches.
  - Full sourced: 3793 / 0.
  - Unit tests: 1020 passed.
  - Doc coverage: 631 covered, 102 untriaged A/B.
- Presentation angle:
  - This is a good “stay at the right abstraction layer” example: the agent found an edge case from a type document, then attached it to the table column where the official schema actually uses that type.

## 2026-05-31 KST - KeysAvailableCfg Was Linked Conservatively

- What changed:
  - Core `KeysAvailableCfg` and Opal `AlignmentRequired` both touch LockingInfo column 0x07 in the parsed fragments.
  - The safe rule was host read-only behavior, not a broad reinterpretation of Get semantics.
- Evidence snapshot:
  - `lockinginfo-readonly-doc` expanded to 7 / 0 mismatches.
  - Doc coverage: 633 covered, 101 untriaged A/B.
- Presentation angle:
  - This is a useful “do not force a model update when the source boundary is ambiguous” example. The evidence was still captured, but the solver was not made more brittle.

## 2026-05-31 KST - Hash Protocol Became A Shared Credential Enum Rule

- What changed:
  - The `hash_protocol` type showed up across several credential tables.
  - Probes showed reserved and boolean values were accepted broadly.
- How the algorithm was handled:
  - Added one shared credential Hash-column detector rather than separate one-off checks per credential family.
  - The same validation now applies to Set inputs and Get outputs.
- Evidence snapshot:
  - New tag: `credential-hash-protocol-enum-doc`, 20 / 0 mismatches.
  - Full sourced: 3814 / 0.
  - Unit tests: 1023 passed.
  - Doc coverage: 638 covered, 100 untriaged A/B.
- Presentation angle:
  - This is the clearest “concept combination” example from this pass: one column type document plus multiple credential table schemas generated a family of edge cases and one general repair.

## 2026-05-31 KST - C_AES Mode Added A Second Credential-Type Repair Pattern

- What changed:
  - The coverage loop reached the AES credential type documents after the hash_protocol pass.
  - Core defines `symmetric_mode` separately from `symmetric_mode_media`: plain AES credentials allow values `0-11`, while `12-23` are reserved.
  - The C_AES object tables bind that type to the Mode column and bind `feedback_size` to the FeedbackSize column.
- How the algorithm was handled:
  - A probe confirmed the solver accepted reserved C_AES Mode values and boolean coercion.
  - The repair was made at the C_AES credential schema boundary, not as a single hard-coded trajectory.
  - FeedbackSize was handled conservatively: same-call CFB mode enforces `1..16`, while standalone FeedbackSize only enforces uinteger shape because prior Mode state may be unknown.
- Evidence snapshot:
  - New tag: `caes-mode-feedback-doc`, 18 / 0 mismatches.
  - Full sourced: 3832 / 0.
  - Unit tests: 1028 passed.
  - Doc coverage: 643 covered, 95 untriaged A/B.
- Presentation angle:
  - This is a useful follow-up to the hash_protocol story: the same schema-driven machinery can absorb another credential table type without broadening the solver into unsupported crypto-method behavior.

## 2026-05-31 KST - LockingInfo Enum Checks Stayed Narrow

- What changed:
  - The remaining coverage list exposed `enc_supported`.
  - LockingInfo column `0x03` uses that type, and private-style probes showed successful Get returns could claim reserved enum values.
- How the algorithm was handled:
  - The repair was intentionally read-side only. LockingInfo Set was already blocked as read-only, so the missing behavior was only validating returned object-table cell values.
  - This avoided changing LockingInfo geometry semantics while still enforcing the official schema.
- Evidence snapshot:
  - New tag: `lockinginfo-encryptsupport-enum-doc`, 4 / 0 mismatches.
  - Full sourced: 3836 / 0.
  - Unit tests: 1030 passed.
  - Doc coverage: 644 covered, 94 untriaged A/B.
- Presentation angle:
  - This is a small but clean example of model discipline: when a source fragment only justifies one column type check, the algorithm changes exactly that and leaves neighboring LockingInfo behavior untouched.

## 2026-05-31 KST - Lifecycle Types Were Validated Without Rewriting Lifecycle Semantics

- What changed:
  - The coverage loop reached Core `life_cycle_state` and Opal's modified lifecycle-state table.
  - Probes showed the solver accepted impossible SP table LifeCycleState Get returns such as reserved value `5` and boolean `True`.
- How the algorithm was handled:
  - The repair validates only the SP table LifeCycleState return cell.
  - It deliberately does not reinterpret disabled/frozen transition behavior, which is already covered by separate long lifecycle trajectories.
- Evidence snapshot:
  - New tag: `sp-lifecycle-state-enum-doc`, 6 / 0 mismatches.
  - Full sourced: 3842 / 0.
  - Unit tests: 1032 passed.
  - Doc coverage: 646 covered, 92 untriaged A/B.
- Presentation angle:
  - This is a good story for “contextual generalization”: the model was not patched for a single `5` value, but taught the Opal lifecycle enum boundary used by the SP table.

## 2026-05-31 KST - AES Credential Schema Now Covers Byte Sizes Too

- What changed:
  - After fixing C_AES enum columns, the next uncovered fragments were fixed byte-size types.
  - Probes showed C_AES Key and ResidualData cells accepted wrong byte lengths on both Set and Get.
- How the algorithm was handled:
  - The repair maps C_AES table columns to their declared `bytes_16` or `bytes_32` types.
  - It validates only cells that the trace claims were successfully written or returned; it does not assume protected key cells must always be readable.
- Evidence snapshot:
  - New tag: `caes-fixed-bytes-doc`, 14 / 0 mismatches.
  - Full sourced: 3856 / 0.
  - Unit tests: 1035 passed.
  - Doc coverage: 652 covered, 90 untriaged A/B.
- Presentation angle:
  - This is another clean “concept composition” example: column-type fragments plus C_AES table schemas produced a family of edge cases and one reusable typed-cell validation path.

## 2026-05-31 KST - Password Return Validation Avoided Access-Control Overreach

- What changed:
  - The `password` type fragment says C_PIN PIN values are max 32 bytes.
  - Probes showed returned PIN cells could claim impossible values.
- How the algorithm was handled:
  - The repair validates returned PIN cells only when they appear in the trace.
  - It leaves the protected-cell omission behavior untouched, so access-control semantics are not broadened.
- Evidence snapshot:
  - New tag: `cpin-password-return-type-doc`, 4 / 0 mismatches.
  - Full sourced: 3860 / 0.
  - Unit tests: 1037 passed.
  - Doc coverage: 653 covered, 89 untriaged A/B.
- Presentation angle:
  - This is a nice example of careful repair scope: type checking was improved without changing whether the C_PIN PIN cell should be readable.

## 2026-05-31 KST - Authority Operation Was Tightened Without Touching GetACL

- What changed:
  - The next score-relevant pass stayed in the Authority/Get area but avoided the risky GetACL association rules that previously lowered leaderboard score.
  - A probe showed Admin1/User1 Operation cells accepted impossible successful return values: other auth methods, reserved enum values, booleans, and arbitrary strings.
- How the algorithm was handled:
  - The repair combined the generic `auth_method` type fragment with concrete Opal Authority preconfiguration rows.
  - It was not patched to one bad answer: issued AdminN/UserN password-authority rows now have a reusable Password Operation expectation, while any Authority Operation cell also gets enum-boundary validation.
  - The high-level `getAuthority()` wrapper stayed on the `Enabled` boolean path, so table-cell Get validation did not break wrapper semantics.
- Evidence snapshot:
  - New tag: `authority-password-operation-doc`, 8 / 0 mismatches.
  - Full sourced: 3868 / 0.
  - Synthetic: 235 / 0.
  - Unit tests: 1039 passed.
  - Doc coverage: 654 covered, 88 untriaged A/B.
- Presentation angle:
  - This is a clean “concept mixing” example: `auth_method` enum boundaries plus Opal issued Authority rows generated longer-lasting tests than a single Admin1 bad-return case.

## 2026-05-31 KST - Existence Rules Were Applied Conservatively

- What changed:
  - Basic Get/Set fail fragments were still uncovered in the high-priority queue.
  - Probes showed null and all-ones InvokingIDs could still claim successful Get/Set results.
- How the algorithm was handled:
  - The model now rejects only definitely absent object UIDs when they do not resolve to any known symbol.
  - It deliberately does not reject every unknown-looking object name, because Opal has optional rows and private tests may use implementation-specific UIDs.
- Evidence snapshot:
  - New tag: `get-set-absent-object-doc`, 4 / 0 mismatches.
  - Full sourced: 3872 / 0.
  - Synthetic: 235 / 0.
  - Unit tests: 1040 passed.
  - Doc coverage: 654 covered, 88 untriaged A/B.
- Presentation angle:
  - This is a useful example of avoiding overrepair: the official rule was “object must exist,” but the implementation chose a narrow, high-confidence subset instead of guessing every optional object universe.

## 2026-05-31 KST - Enum Validators Stopped Treating Bool As Integer

- What changed:
  - After the Authority Operation repair, the same probe pattern exposed enum validators that parsed `True` as `1`.
  - That affected credential and media-key typed return cells, including padding_type, hash_protocol, and symmetric_mode_media.
- How the algorithm was handled:
  - The fix lives in shared enum validators, so it applies to future return-cell checks using those declared enum types.
  - It did not reinterpret valid numeric enum values; it only separates boolean from integer, matching the type system.
- Evidence snapshot:
  - New tag: `enum-bool-coercion-doc`, 12 / 0 mismatches.
  - Full sourced: 3884 / 0.
  - Synthetic: 235 / 0.
  - Unit tests: 1041 passed.
  - Doc coverage: 656 covered, 88 untriaged A/B.
- Presentation angle:
  - This is a concise example of model generalization: one discovered edge-case pattern became a reusable typed-cell invariant across multiple credential families.

## 2026-05-31 KST - Delete Absent Object Rule Was Captured As Evidence

- What changed:
  - The already-modeled Delete object-existence rule was turned into sourced coverage using the Basic Table Method Delete failure clause.
  - New trajectories cover NULL UID and all-ones UID Delete attempts under an otherwise valid Admin session.
- How the algorithm was handled:
  - No solver repair was needed; this was a coverage and audit-trail hardening step.
  - The unit regression was broadened so Get, Set, and Delete all reject definitely absent invoking objects.
- Evidence snapshot:
  - New tag: `delete-absent-object-doc`, 2 / 0 mismatches.
  - Full sourced: 3886 / 0.
  - Synthetic: 235 / 0.
  - Unit tests: 1041 passed.
  - Doc coverage: 657 covered, 87 untriaged A/B.
- Presentation angle:
  - Useful for showing that the process does not only patch failures; it also records officially grounded invariants that the model already handles.

## 2026-05-31 KST - SecretProtect ProtectMechanisms Got A Type Guard

- What changed:
  - The SecretProtect Get cases were extended from wrong Table/ColumnNumber returns to the `ProtectMechanisms` cell itself.
  - A successful response can no longer return boolean or out-of-range values for the `protect_types` column.
- How the algorithm was handled:
  - The repair added a reusable `protect_types` return validator rather than hard-coding one SecretProtect row.
  - It still preserves optional-row safety: the solver only validates the cell when the trace claims a concrete SecretProtect row was successfully returned.
- Evidence snapshot:
  - Expanded tag: `secretprotect-get-cells-tight-doc`, 8 / 0 mismatches.
  - Full sourced: 3890 / 0.
  - Synthetic: 235 / 0.
  - Unit tests: 1042 passed.
  - Doc coverage: 658 covered, 86 untriaged A/B.
- Presentation angle:
  - This is a good example of concept mixing from a type fragment plus an Opal preconfigured row: `protect_types` became an enforceable successful-Get invariant.

## 2026-05-31 KST - C_HMAC Key Lengths Were Brought Up To C_AES Strictness

- What changed:
  - C_HMAC Key columns now enforce their declared fixed byte lengths on both Set and successful Get.
  - The new coverage spans C_HMAC_160, C_HMAC_256, C_HMAC_384, and C_HMAC_512.
- How the algorithm was handled:
  - The repair generalizes through credential-family type mapping instead of enumerating one private-looking trace.
  - Engine return validation now understands bytes_20, bytes_48, and bytes_64, so future typed-return checks can reuse it.
- Evidence snapshot:
  - New tag: `chmac-fixed-bytes-doc`, 24 / 0 mismatches.
  - Full sourced: 3914 / 0.
  - Synthetic: 235 / 0.
  - Unit tests: 1044 passed.
  - Doc coverage: 663 covered, 83 untriaged A/B.
- Presentation angle:
  - This is a strong “pattern transfer” story: a known C_AES fixed-byte invariant was extended to the parallel C_HMAC credential family using official column-type tables.

## 2026-05-31 KST - H_SHA Object Returns Joined The Fixed-Bytes Family

- What changed:
  - H_SHA Proof and Accumulator successful Get responses now enforce bytes_20/32/48/64 according to the specific hash width.
- How the algorithm was handled:
  - The C_HMAC fixed-byte repair was reused rather than duplicated.
  - The change only constrains successful H_SHA Get return cells, so it does not alter crypto-stream state behavior.
- Evidence snapshot:
  - New tag: `hsha-fixed-bytes-doc`, 16 / 0 mismatches.
  - Full sourced: 3930 / 0.
  - Synthetic: 235 / 0.
  - Unit tests: 1045 passed.
  - Doc coverage: 667 covered, 83 untriaged A/B.
- Presentation angle:
  - This is another reusable-type-invariant example: once bytes_20/48/64 existed, adjacent crypto tables became cheaper and safer to cover.

## 2026-05-31 KST - Clock Template Boundary Was Extended To GetACL

- What changed:
  - The earlier Clock Template boundary only covered direct method invocation.
  - The same official-doc boundary is now exercised through `AccessControl.GetACL` associations for every Clock Template method in both Opal Admin and Locking SPs.
- How the algorithm was handled:
  - No production rule was loosened or widened.
  - The existing method-universe and AccessControl association model already rejected these impossible successful associations.
- Evidence snapshot:
  - Expanded tag: `opal-clock-template-unsupported-doc`, 28 / 0 mismatches.
  - Full sourced: 3944 / 0.
  - Synthetic: 235 / 0.
  - Unit tests: 1045 passed.
  - Doc coverage: 668 covered, 82 untriaged A/B.
- Presentation angle:
  - This is a good example of using a risky private-score surface, GetACL, in a conservative way: only associations for methods absent from the Opal method universe are rejected.

## 2026-05-31 KST - TPerInfo Readability Did Not Mean Untyped Returns

- What changed:
  - TPerInfo.Get is now constrained by the declared types of its returned cells.
  - GUDID must be bytes_12, metadata counters must be uinteger, and ProgrammaticResetEnable must be boolean when those cells appear in a successful response.
- How the algorithm was handled:
  - The repair did not change who can read TPerInfo.
  - It only validates the shape of successful return cells, using reusable `bytes_8`, `bytes_12`, and `boolean` type checks.
- Evidence snapshot:
  - New tag: `tperinfo-get-types-doc`, 10 / 0 mismatches.
  - Full sourced: 3954 / 0.
  - Synthetic: 235 / 0.
  - Unit tests: 1046 passed.
  - Doc coverage: 673 covered, 77 untriaged A/B.
- Presentation angle:
  - This is a clean “readable does not mean arbitrary” example: the access decision and typed response validation are separate model responsibilities.

## 2026-05-31 KST - Coverage Backfill Without Behavioral Churn

- What changed:
  - Core capability-discovery overview docs were linked to the existing Level 0 geometry feature cases.
  - The general Column Types overview was linked to the TPerInfo typed-return cases.
- How the algorithm was handled:
  - No solver behavior changed in this mini-pass.
  - The audit trail now better reflects which broad official sections are already being exercised by concrete edge cases.
- Evidence snapshot:
  - `level0-geometry-feature-doc`: 8 / 0 after source backfill.
  - `tperinfo-get-types-doc`: 4 / 0 after source backfill.
  - Doc coverage: 673 covered, 77 untriaged A/B.
- Presentation angle:
  - This is the bookkeeping side of the loop: not every uncovered shard deserves a new rule, but every relevant shard should be attached to the cases that already embody it.

## 2026-05-31 KST - SP Table Joined The Typed-Return Sweep

- What changed:
  - SP.Get on UID, Bytes, and Frozen now rejects malformed successful return cells.
- How the algorithm was handled:
  - This reused the shared bytes, uinteger, enum, and boolean validators rather than adding row-specific checks.
  - SP.Get now validates the basic typed columns it can safely constrain without modeling date/max-bytes vendor details.
- Evidence snapshot:
  - Expanded tag: `sp-frozen-get-type-doc`, 6 / 0 mismatches.
  - Full sourced: 3960 / 0.
  - Synthetic: 235 / 0.
  - Unit tests: 1047 passed.
  - Doc coverage: 673 covered, 77 untriaged A/B.
- Presentation angle:
  - Another tidy example of the loop finding an adjacent column after a typed-return repair and generalizing the invariant without touching access policy.

## 2026-05-31 KST - LockingInfo Types Were Tightened Around MaxRanges

- What changed:
  - LockingInfo.Get now rejects malformed UID, boolean-coerced MaxRanges, and negative MaxReEncryptions successful returns.
- How the algorithm was handled:
  - This did not change optional range presence logic.
  - It only validates the typed shape of successful configuration reads before those values influence later state.
- Evidence snapshot:
  - New tag: `lockinginfo-get-types-doc`, 6 / 0 mismatches.
  - Full sourced: 3966 / 0.
  - Synthetic: 235 / 0.
  - Unit tests: 1048 passed.
  - Doc coverage: 673 covered, 77 untriaged A/B.
- Presentation angle:
  - Useful score story: the model hardened a LockingInfo surface without guessing new optional-range semantics, so it reduces false accepts while preserving conservative behavior.

## 2026-05-31 KST - Three Broad Shards Were Attached To Existing Cases

- What changed:
  - Types Encoding, SP lifecycle overview, and Opal terminology docs were linked into already-running edge-case tags.
- How the algorithm was handled:
  - No solver behavior changed.
  - The evidence graph became more complete: broad prose sections now point to concrete RowValues, lifecycle, and data-removal trajectories.
- Evidence snapshot:
  - `set-rowvalues-doc`: 6 / 0.
  - `locking-feature-lifecycle-doc`: 6 / 0.
  - `data-removal-doc`: 6 / 0.
  - Doc coverage: 676 covered, 74 untriaged A/B.
- Presentation angle:
  - This is useful for explaining that the system distinguishes “new rule needed” from “existing rule needs better source attribution.”

## 2026-05-31 KST - boolean_ACE Was Linked To The Capacity Case

- What changed:
  - `core/5.1.3.11` now supports the existing `ace-booleanexpr-capacity-doc` cases.
- Evidence snapshot:
  - `ace-booleanexpr-capacity-doc`: 12 / 0.
  - Doc coverage: 677 covered, 73 untriaged A/B.
- Presentation angle:
  - The 23-entry OR trajectory now points directly to the operator type table it relies on.

## 2026-05-31 KST - Clock Internals Were Attached To The Opal Boundary

- What changed:
  - `clock_kind`, `clock_time`, and `lag` type shards now support the existing Clock Template unsupported-method cases.
- Evidence snapshot:
  - `opal-clock-template-unsupported-doc`: 28 / 0.
  - Doc coverage: 680 covered, 70 untriaged A/B.
- Presentation angle:
  - This reinforces the conservative modeling choice: Core defines rich Clock internals, but Opal Admin/Locking SPs do not expose those methods.

## 2026-05-31 KST - Lifecycle And Reference Shards Were Reconciled

- What changed:
  - Default Authority, Admin Template lifecycle exception, Manufactured SP, object-reference, LogList-reference, Template-reference, and byte-row-reference docs were linked to existing sourced edge cases.
- How the algorithm was handled:
  - No solver behavior changed in this pass.
  - The risky AccessControl/GetACL interpretation was not broadened; only the evidence graph was tightened around already-passing exact-ACL and byte-table trajectories.
- Evidence snapshot:
  - Authority default cells: 8 / 0.
  - Opal IssueSP unsupported: 4 / 0.
  - GetACL exact/reference tags: 112 total checked cases / 0 across the targeted set.
  - DataStore payload: 8 / 0.
  - Doc coverage: 692 covered, 58 untriaged A/B.
- Presentation angle:
  - This is a clean example of traceability work: the tests already existed, but now the report can point from a failed model decision back to the exact reference-type or lifecycle shard that justifies it.

## 2026-05-31 KST - A/B Priority Coverage Reached Zero Untriaged

- What changed:
  - Remaining B-priority type and lifecycle shards were either linked to existing sourced cases or manually triaged when they were only informative/duplicate section text.
- How the algorithm was handled:
  - No solver behavior changed.
  - This pass deliberately avoided risky AccessControl semantic changes after the prior private-score drop concern.
- Evidence snapshot:
  - Full sourced suite: 3966 / 0 mismatches.
  - Synthetic suite: 235 / 0 mismatches.
  - Unit suite: 1048 passed.
  - Doc coverage: 744 covered docs, 0 untriaged A/B.
- Presentation angle:
  - This gives a clean story boundary: the high-priority official-doc sweep is now auditable, with test-backed shards and explicit reasons for non-testable shards.

## 2026-05-31 KST - Session Startup Busy State Was Modeled

- What changed:
  - The solver now recognizes the official `SP_BUSY` response for overlapping StartSession attempts to the same SP when either the existing or requested session is read-write.
  - The old behavior was too blunt: any open reconstructed session caused a generic failure set. The new behavior follows the document distinction between same-SP RW overlap, same-SP RO overlap, and released sessions.
- How the algorithm was handled:
  - This was not patched to one fixture. The rule is keyed on reconstructed session state (`sp`, `write`, `open`) and the requested `StartSession.Write` value.
  - `EndSession` still releases the session, so the same request can later succeed.
- Evidence snapshot:
  - New tag: `startsession-sp-busy-doc`, 8 / 0 mismatches.
  - Full sourced: 3974 / 0.
  - Synthetic: 235 / 0.
  - Unit tests: 1048 passed.
  - Doc coverage: 754 covered docs, 0 untriaged A/B.
- Presentation angle:
  - Strong score-improvement story: a previously generic session-state approximation became a specific official status transition with source-backed positive and negative trajectories.

## 2026-05-31 KST - AdminSP RW Cross-SP Combination Was Blocked

- What changed:
  - The solver now rejects successful trajectories that combine a read-write AdminSP session with any session to another SP.
  - This covers both orders: AdminSP RW first, then LockingSP; or LockingSP first, then AdminSP RW.
- How the algorithm was handled:
  - The repair is based on reconstructed session state, not on individual case names.
  - `EndSession` remains the boundary that releases resources and permits a later AdminSP RW session.
- Evidence snapshot:
  - New tag: `adminsp-rw-session-combination-doc`, 6 / 0 mismatches.
  - Full sourced: 3980 / 0.
  - Synthetic: 235 / 0.
  - Unit tests: 1048 passed.
  - Doc coverage: 757 covered docs, 0 untriaged A/B.
- Presentation angle:
  - This is a useful “model got more semantic” example: the repair composes AdminSP session policy with StartSession.Write and EndSession resource release.

## 2026-05-31 KST - Important Coverage Queue Is Now Closed

- What changed:
  - A/B/C-priority untriaged official-doc shards are now zero.
  - Covered docs reached 811 out of 1376, with the remaining untriaged set limited to 349 D-priority shards.
- How the algorithm was handled:
  - No extra solver behavior was added during this closure pass.
  - Low-level packet/token/secure-message byte rules were explicitly deferred instead of being forced into decoded method cases.
  - Leaf UID/CommonName/Proof/status/type shards were tied to existing concrete cases or marked covered indirectly.
- Evidence snapshot:
  - Full sourced: 3980 / 0.
  - Synthetic: 235 / 0.
  - Unit tests: 1048 passed.
  - Coverage: A/B/C untriaged = 0; D untriaged = 349.
- Presentation angle:
  - This gives a clean progress milestone: the high and medium importance official-document surface is either tested, source-linked to tested behavior, or explicitly marked as needing a future fixture layer.

## 2026-05-31 KST - GetACL Log-Representation Hardening

- What changed:
  - AccessControl meta-methods now recognize more official-equivalent parameter encodings for the same InvokingID/MethodID association.
  - New sourced cases cover UID dictionaries, singleton wrappers, snake-case UID arguments, `TargetUID`, `object_uid`, and `method_uid` forms while still enforcing exact ACE uidref lists.
- How the algorithm was handled:
  - The solver did not broaden which AccessControl rows exist.
  - It only broadened input normalization before applying the same association-existence, meta-ACL, and exact-return rules.
  - This keeps the previous private-score risk area bounded: missing associations remain rejected, but equivalent representations of existing associations are no longer missed.
- Evidence snapshot:
  - New tag `getacl-representation-equivalence-doc`: 14 / 0 mismatches.
  - Full sourced: 3994 / 0.
  - Synthetic: 235 / 0.
  - Unit tests: 1048 passed.
  - Coverage: 811 / 1376 docs covered; A/B/C untriaged = 0; D untriaged = 349.
- Presentation angle:
  - This is a clear example of score-driven but principled repair: after the score plateau, the work targeted hidden-log representation variance while preserving the official AccessControl semantics.

## 2026-05-31 KST - TCGstorageAPI Lock Wrapper Alias Hardening

- What changed:
  - High-level `readLock`, `writeLock`, `readUnlock`, and `writeUnlock` traces are now mapped to Locking row `ReadLocked` / `WriteLocked` updates.
  - Wrapper arguments now accept extra private-log spellings such as `range_id`, `band_no`, `lockingRange`, and `auth_as`.
- How the algorithm was handled:
  - The repair reuses the existing Locking table Set/Get state machine.
  - No new Locking semantics were invented; wrapper calls are decoded into the same columns that raw `Set` and `setRange` already use.
- Evidence snapshot:
  - Wrapper smoke tag: 32 / 0 mismatches.
  - Full sourced: 3994 / 0.
  - Full synthetic: 237 / 0.
  - Unit tests: 1048 passed.
- Presentation angle:
  - Good hidden-score story: the public method-level suite stayed stable, while the API-shaped decoder learned another family of likely private trace forms.

## 2026-05-31 KST - TCGstorageAPI Wrapper Envelope Normalization

- What changed:
  - Wrapper decoding now accepts `name`, `function_name`, `functionName`, `operation_name`, and `operationName` envelopes.
  - The expectation helpers use the same function-name normalizer as the parser.
- How the algorithm was handled:
  - A fuzz case found a concrete stale-state false positive: `operationName=getRange` was parsed as a wrapper event, but stale `getRange` return fields were not checked because the expectation helper did not recognize the envelope.
  - The fix aligns parser and expectation recognition rather than changing Locking rules.
- Evidence snapshot:
  - Wrapper smoke tag: 34 / 0 mismatches.
  - Full sourced: 3994 / 0.
  - Full synthetic: 239 / 0.
  - Unit tests: 1048 passed.
- Presentation angle:
  - This is a neat “subagent fuzzing paid off” slide: alternate envelope forms exposed an actual model blind spot and the repair was localized to normalization.

## 2026-05-31 KST - TCGstorageAPI DataStore Offset Window Repair

- What changed:
  - High-level `writeData` now honors wrapper byte offsets such as `offset` / `startRow`.
  - High-level `readData` now honors wrapper windows such as `offset + length` and `startRow + endRow`.
  - Positional wrapper forms such as `writeData(auth, bytes, offset)` and `readData(auth, offset, length)` are handled as byte windows, not as malformed authority arguments.
  - Added wrapper checks for `hasLockedRange` envelope variants and DataStore partial-overwrite reads.
- How the algorithm was handled:
  - The repair did not invent new DataStore behavior.
  - Wrapper calls are decoded into the same byte-table offset semantics already used by raw DataStore Set/Get.
  - The discovered failure was contextual: an overwrite at offset 2 was being applied as if it began at row 0 because lower byte-table helpers inspected the raw wrapper input rather than the normalized wrapper intent.
- Evidence snapshot:
  - Full synthetic: 255 / 0.
  - Full sourced: 3994 / 0.
  - Unit tests: 1048 passed.
  - Coverage: 811 / 1376 docs covered; A/B/C untriaged = 0; D untriaged = 349.
- Presentation angle:
  - Strong example of “edge case generation became a model repair”: a longer wrapper trajectory exposed a real provenance bug, and the fix generalized to all wrapper byte windows.

## 2026-05-31 KST - TCGstorageAPI Wrapper Auth Alias Consistency

- What changed:
  - Wrapper calls now accept `auth_as` wherever the corresponding helper already accepted `authAs`.
  - Added authority-wrapper smoke cases proving snake-case credentials update and verify Authority.Enabled state correctly.
- How the algorithm was handled:
  - This is a log-representation repair, not a protocol semantic change.
  - The same credential tuple is normalized before existing authority/session/ACE rules run.
- Evidence snapshot:
  - Full synthetic: 265 / 0.
  - Wrapper synthetic tag: 60 / 0.
  - Full sourced: 3994 / 0.
  - Unit tests: 1048 passed.
- Presentation angle:
  - Useful “private-log robustness” example: hidden traces can differ in field naming, and the model should normalize spelling variance before applying official rules.

## 2026-05-31 KST - TCGstorageAPI Wrapper AuthAs Credential Guard

- What changed:
  - Wrapper operations now reject impossible `SUCCESS` when their explicit `authAs` credential mismatches the tracked authority credential.
  - `checkPIN`/`Authenticate` false-result semantics remain valid, and multi-auth wrapper lists still work.
- How the algorithm was handled:
  - The first attempt was too broad and broke two existing unit tests.
  - The final repair is scoped to implicit high-level wrapper method events, skips authentication-result wrappers, and avoids appending a synthetic authority pair when explicit authAs pairs already exist.
- Evidence snapshot:
  - Full synthetic: 280 / 0.
  - Full sourced: 3994 / 0.
  - Unit tests: 1048 passed.
  - Coverage: 811 / 1376 docs covered; A/B/C untriaged = 0; D untriaged = 349.
- Presentation angle:
  - This is a nice debugging story: generated edge cases exposed a real false positive, regression tests caught an overbroad fix, and the final repair was narrowed to the actual wrapper-auth boundary.

## 2026-05-31 KST - TCGstorageAPI Wrapper readData Scoped Auth

- What changed:
  - High-level `readData(authAs=...)` now evaluates DataStore read authorization using the wrapper-supplied authority, not whichever raw TCG session happened to be open in the reconstructed trace.
  - Added paired cases proving that User1 cannot receive an Admin-written DataStore payload without `readAccess`, while an empty-result unauthorized read remains acceptable.
- How the algorithm was handled:
  - The fix creates a scoped session only for wrapper DataStore read authorization.
  - It reuses the existing DataStore ACE/default authorization helpers, so the repair follows the same rulebase path as raw `DataStore.Get`.
  - Non-wrapper DataStore reads and existing raw session semantics were left alone.
- Evidence snapshot:
  - Full synthetic: 286 / 0.
  - Wrapper synthetic tag: 81 / 0.
  - Full sourced: 3994 / 0.
  - Unit tests: 1048 passed.
  - Coverage: 811 / 1376 docs covered; A/B/C untriaged = 0; D untriaged = 349.
- Presentation angle:
  - Strong example of concept mixing: `DataStore payload consistency` plus `AccessControl readAccess` plus `wrapper implicit authAs session` exposed a bug that single-concept tests would likely miss.

## 2026-05-31 KST - TCGstorageAPI Wrapper writeData Scoped Auth

- What changed:
  - High-level `writeData(authAs=...)` now checks DataStore Set authorization under the wrapper authority.
  - User1 can no longer mutate the DataStore just because an Admin1 raw session is already open in the reconstructed state.
- How the algorithm was handled:
  - The readData scoped-auth helper was generalized to `readData/writeData`.
  - The repair reuses existing DataStore ACE/default authorization logic with a temporary wrapper-scoped session.
  - Existing raw `DataStore.Set` semantics remain unchanged.
- Evidence snapshot:
  - Full synthetic: 288 / 0.
  - Wrapper synthetic tag: 83 / 0.
  - Full sourced: 3994 / 0.
  - Unit tests: 1048 passed.
  - Coverage: 811 / 1376 docs covered; A/B/C untriaged = 0; D untriaged = 349.
- Presentation angle:
  - This pairs nicely with the readData case: the same generated concept combination found both a confidentiality-style leak and an integrity-style mutation bug.

## 2026-05-31 KST - TCGstorageAPI Wrapper Scoped Auth Grant Regression Checks

- What changed:
  - Added positive-control wrapper trajectories for legitimate User1 DataStore read/write grants.
  - These prove scoped-auth does not simply reject all User wrapper access under an open Admin session.
- How the algorithm was handled:
  - No production code change was needed.
  - One initial expected result was corrected during audit: after `readAccess(User1)` personalizes the DataStore Get ACE, the payload should be checked through User1 readData rather than Admin readData.
- Evidence snapshot:
  - Full synthetic: 290 / 0.
  - Wrapper synthetic tag: 85 / 0.
  - Full sourced: 3994 / 0.
  - Unit tests: 1048 passed.
  - Coverage: 811 / 1376 docs covered; A/B/C untriaged = 0; D untriaged = 349.
- Presentation angle:
  - Useful process story: generated tests are not blindly accepted; when a new case contradicted an already-established ACE replacement rule, the case expectation was corrected instead of bending the model.

## 2026-05-31 KST - TCGstorageAPI Wrapper GenKey/Erase Scoped Auth

- What changed:
  - Wrapper `genKey` and `erase` no longer borrow unrelated privileged raw sessions for authority checks.
  - A correct User1 credential is now treated as correct-but-insufficient for K_AES GenKey and band Erase unless the relevant ACE/EraseMaster authority is actually satisfied by that wrapper authority.
- How the algorithm was handled:
  - Added a reusable wrapper-scoped state helper.
  - Applied it only to high-level wrapper `genKey` and `erase` authority checks, leaving raw method traces untouched.
- Evidence snapshot:
  - Full synthetic: 292 / 0.
  - Wrapper synthetic tag: 87 / 0.
  - Full sourced: 3994 / 0.
  - Unit tests: 1048 passed.
  - Coverage: 811 / 1376 docs covered; A/B/C untriaged = 0; D untriaged = 349.
- Presentation angle:
  - This shows the loop generalizing from one bug family: the first DataStore leak suggested a broader wrapper session-boundary hypothesis, and follow-up agents found the same pattern in GenKey and Erase.

## 2026-05-31 KST - TCGstorageAPI Wrapper Range Set Scoped Auth

- What changed:
  - Wrapper range mutations now respect the wrapper authority boundary.
  - User1 cannot use `setRange` or `readLock` to change Locking row state by piggybacking on an open Admin1 raw session.
- How the algorithm was handled:
  - The reusable wrapper-scoped authority helper was applied to range Set wrappers.
  - Only the authority checks were scoped; existing Locking row value validation and state-transition logic stayed intact.
- Evidence snapshot:
  - Full synthetic: 294 / 0.
  - Wrapper synthetic tag: 89 / 0.
  - Full sourced: 3994 / 0.
  - Unit tests: 1048 passed.
  - Coverage: 811 / 1376 docs covered; A/B/C untriaged = 0; D untriaged = 349.
- Presentation angle:
  - This extends the story from payload access to Locking state integrity: generated long wrapper trajectories found that the same session-boundary bug could alter lock state, not just return data.

## 2026-05-31 KST - TCGstorageAPI Wrapper PIN/Authority Set Scoped Auth

- What changed:
  - Wrapper PIN and authority mutations now use the wrapper-supplied authority for Set permission checks.
  - User1 cannot change SID's PIN, tighten SID's PIN policy, or enable User2 by inheriting an unrelated privileged raw session.
- How the algorithm was handled:
  - Reused the same scoped Set authority path introduced for range wrappers.
  - Added only wrappers whose semantics are clear protected Set mutations.
- Evidence snapshot:
  - Full synthetic: 297 / 0.
  - Wrapper synthetic tag: 92 / 0.
  - Full sourced: 3994 / 0.
  - Unit tests: 1048 passed.
  - Coverage: 811 / 1376 docs covered; A/B/C untriaged = 0; D untriaged = 349.
- Presentation angle:
  - This is a good “generalization without overfitting” example: one session-boundary hypothesis kept producing independent failures across DataStore, Locking, GenKey, Erase, PIN, and Authority wrappers.

## 2026-05-31 KST - TCGstorageAPI Wrapper Port/PSK Set Scoped Auth

- What changed:
  - Wrapper `setPort` and `setPskEntry` now use wrapper `authAs` for Set permission checks.
  - User1 cannot change AdminSP port or TLS PSK state by piggybacking on an open SID session.
- How the algorithm was handled:
  - Continued using the scoped Set authority helper.
  - The patch was intentionally limited to known mutation wrappers with clear Set semantics.
- Evidence snapshot:
  - Full synthetic: 299 / 0.
  - Wrapper synthetic tag: 94 / 0.
  - Full sourced: 3994 / 0.
  - Unit tests: 1048 passed.
  - Coverage: 811 / 1376 docs covered; A/B/C untriaged = 0; D untriaged = 349.
- Presentation angle:
  - This rounds out the wrapper mutation boundary story: after the first DataStore bug, the loop systematically checked every high-level mutation family and found the same issue across several surfaces.

## 2026-05-31 KST - TCGstorageAPI Wrapper Scoped Get Repairs

- What changed:
  - High-level `getAuthority`, `getPskEntry`, `getRange`, and `getMEK` now evaluate protected Get authorization under the wrapper `authAs` authority.
  - User1 can no longer borrow stale Admin/SID raw sessions to read Authority, TLS PSK, Locking range, or ActiveKey metadata.
- How the algorithm was handled:
  - The existing wrapper-scoped authority helper was applied only to protected wrapper Get families.
  - Positive controls were added for legitimate Admin/SID queries to avoid turning the repair into blanket rejection.
  - Existing tracked return-value comparisons, such as Authority.Enabled and ActiveKey UID matching, remain in force after authorization succeeds.
- Evidence snapshot:
  - Full synthetic after this family: 307 / 0.
  - Wrapper synthetic tag after this family: 102 / 0.
  - Full sourced: 3994 / 0.
  - Unit tests: 1048 passed.
  - Coverage: 811 / 1376 docs covered; A/B/C untriaged = 0; D untriaged = 349.
- Presentation angle:
  - This extends the session-boundary story from mutation bugs to confidentiality/metadata leaks: the same concept combination found protected reads that were accidentally using ambient raw sessions.

## 2026-05-31 KST - TCGstorageAPI Wrapper LockOnReset Latent Lock Audit

- What changed:
  - Added wrapper LockOnReset reset trajectories that observe later Locking state through `getRange`.
  - The final cases assert the spec-derived latent stored-lock behavior: a matching reset sets both stored locked cells when any lock side is enabled, while disabled host I/O remains ineffective until the enabled flag changes.
- How the algorithm was handled:
  - A speculative enabled-side-only solver patch was tried because it matched an intuitive host-I/O reading.
  - Sourced cases and unit tests rejected that interpretation, so the production patch was reverted and the synthetic oracle was corrected instead.
  - This is recorded as a quarantine/resolution example: the loop did not force the model to match a bad generated hypothesis.
- Evidence snapshot:
  - Full synthetic: 309 / 0.
  - Wrapper synthetic tag: 104 / 0.
  - Full sourced: 3994 / 0.
  - Unit tests: 1048 passed.
  - Coverage: 811 / 1376 docs covered; A/B/C untriaged = 0; D untriaged = 349.
- Presentation angle:
  - Strong process story for the presentation: generated edge cases are treated as hypotheses, and official-document/source-aligned tests can overrule the generator before production code is changed.

## 2026-05-31 KST - Score-First DataStore And AccessControl Sweep

- What changed:
  - Added DataStore raw/wrapper cross-observation cases so raw `DataStore.Set/Get` and high-level `readData/writeData` share the same byte-table state.
  - Added LockOnReset reset-type boundary cases for wrapper `setRange`: HardwareReset-only lists do not fire on PowerCycle, but do fire on HardwareReset.
  - Repaired direct `AccessControl.Get` handling when a request mixes readable metadata with the unreadable ACL column.
- How the algorithm was handled:
  - DataStore and LockOnReset additions were guardrails only; the current solver already followed those rules.
  - The AccessControl change is a real generalized repair: whole-request rejection is acceptable when ACL is requested directly, but successful metadata responses must still match and ACL leakage is still forbidden.
  - The repair was verified against sourced AccessControl/GetACL cases to avoid repeating the earlier score-drop risk from over-tightening this area.
- Evidence snapshot:
  - Full synthetic: 320 / 0.
  - Full sourced: 3994 / 0.
  - Unit tests: 1049 passed.
  - Coverage: 811 / 1376 docs covered; A/B/C untriaged = 0; D untriaged = 349.
- Presentation angle:
  - Good example of a mature loop: not every generated case forces a patch, but when a score-sensitive inconsistency is found, the model change is phrased as a protocol-level rule and backed by regression coverage.

## 2026-05-31 KST - Wrapper Authentication And Locking Long-Trajectory Expansion

- What changed:
  - Added long high-level `checkPIN` trajectories for TryLimit, Tries, Persistence, Authority.Uses, Authority.Limit, and later raw table observations.
  - Added a `changePIN` recovery trajectory showing a successful credential replacement after lockout clears `C_PIN.Tries`.
  - Added wrapper Locking latent-lock trajectories separating stored `ReadLocked/WriteLocked` cells from the effective `ReadLockEnabled/WriteLockEnabled` flags.
  - Added `hasLockedRange()` summary cases over the same latent-lock state.
- How the algorithm was handled:
  - These were guardrail/coverage expansions; the current solver already passed them.
  - The cases intentionally mix wrapper calls, raw table Gets, host I/O, reset behavior, and summary wrappers so a shallow one-step model cannot pass by matching only local return values.
- Evidence snapshot:
  - Full synthetic: 348 / 0.
  - Wrapper synthetic tag: 141 / 0.
  - Full sourced after the AccessControl repair: 3994 / 0.
  - Unit tests after the AccessControl repair: 1049 passed.
  - Coverage: 811 / 1376 docs covered; A/B untriaged = 0.
- Presentation angle:
  - This is the clearest “concept mixing” story so far: official C_PIN/Auth/Locking concepts were combined into longer API-shaped trajectories that test whether the model maintains state across wrapper calls, raw Gets, reset events, and host I/O.

## 2026-05-31 KST - Score-First Plan And P0/P1/P2 Execution

- What changed:
  - Wrote a score-first execution plan that prioritizes likely private-score axes before broad remaining document coverage.
  - Added AccessControl full-row direct `Get` guardrails: rejection is allowed, readable metadata/log cells are checked on success, and ACL leakage remains forbidden.
  - Added Range8 wrapper trajectories so optional-range state cannot collapse into Range1 or Range2.
  - Added DataStore User1 -> User2 authority churn with offset payload preservation, failed-write nonmutation, and later authorized User2 mutation.
- How the algorithm was handled:
  - No production solver change was made in this batch.
  - A generated AccessControl PASS case initially used an ambiguous `CommonName` cell that collided with MethodID parsing; it was corrected as a generated-case issue rather than forcing a solver patch.
  - This is an example of the loop validating generated edge cases before treating them as model failures.
- Evidence snapshot:
  - Full synthetic: 396 / 0.
  - Wrapper synthetic tag: 183 / 0.
  - AccessControl synthetic tag: 8 / 0.
  - Full sourced: 3994 / 0.
  - Unit tests: 1049 passed.
  - Coverage: 811 / 1376 docs covered; A/B untriaged = 0.
- Presentation angle:
  - Strong “process maturity” story: when the goal switched to score, the loop did not randomly add cases. It focused on suspected private-score concepts, mixed them into longer trajectories, and rejected an imprecise generated case without overfitting the solver.
