# Coverage Gap Summary

Generated from `python3 tools/doc_coverage.py`, `python3 tools/build_doc_inventory.py`, and `python3 tools/label_consensus.py report`.

## What Counts As Touched

The current official-document coverage tool counts a document as touched only when it appears in `Evidence.sources` for a case in `tools/run_sourced_edges.py`.

This means:

- Existing sourced cases are counted.
- Newly added sourced cases are counted.
- Unit tests and synthetic smoke tests are not counted as official-document coverage unless represented as sourced cases.
- Manual triage is not currently being used; `analysis/doc_inventory.jsonl` is the exhaustive shard ledger.

## Current Official-Document Coverage

- Official document files: 1376
- Sourced edge cases: 2276
- Consensus-accepted sourced cases: 2227
- Quarantined sourced cases: 49
- Documents referenced by sourced tests: 466
- Untriaged A/B priority documents: 265
- Exhaustive inventory rows: 1376
- Cartography pending A/B rows: 221

The source of truth for per-document coverage is `analysis/doc_coverage_report.md` and `analysis/doc_coverage_matrix.json`.

## Recent Coverage Movement

- Added `mbr-shadow-byte-payload-doc`: 9 accepted cases.
  - Extends MBR byte-table payload coverage from direct `MBR.Get` into active host MBR shadow reads.
  - The batch verifies that partial MBR byte-table overwrites and omitted-`Where` prefix rewrites are reflected by later host reads when `MBRControl.Enabled=True` and `Done=False`, while `Done=True` continues to expose prior user media until `DoneOnReset` clears `Done`.
  - This batch triggered a solver repair: MBR/DataStore byte-table state now recomputes the contiguous prefix after every successful offset write, so direct byte-table Gets and host shadow reads share the same canonical payload.
  - Coverage movement: sourced cases increased from 2267 to 2276 and accepted cases from 2218 to 2227. Referenced document shards stayed at 466 because this deepens already-covered MBR/byte-table sections.
- Added `accesscontrol-meta-self-association-doc`: 12 accepted cases.
  - Extends AccessControl meta-method coverage by proving that the AccessControl table's meta-ACL columns do not imply rows for the meta-methods themselves.
  - The batch verifies that `GetACL`, `AddACE`, `RemoveACE`, and `DeleteMethod` targeting `AccessControl.GetACL`/`AccessControl.AddACE`/`AccessControl.RemoveACE` self associations cannot succeed because the InvokingID/MethodID combination does not exist.
  - This batch triggered a solver repair: `_combo_exists_for_get_acl` now rejects AccessControl associations whose target MethodID is one of the documented meta-method columns rather than treating those columns as callable AccessControl rows.
- Added `syncsession-return-shape-doc`: 10 accepted cases.
  - Extends Session Manager startup coverage into returned parameter shape for `StartSession`/`SyncSession` and `StartTrustedSession`/`SyncTrustedSession`.
  - The batch verifies that successful startup returns both `HostSessionID` and `SPSessionID`, that `SPChallenge` is omitted unless the host signing authority is a direct signing credential, and that `SPResponse` is omitted unless the original StartSession carried a host challenge.
  - This batch triggered a solver repair: expected responses can now require or forbid named return parameters, and session state records whether startup included `HostChallenge`.
- Repaired `host-properties-response-reset-long-doc` against Opal SSC HostProperties support.
  - The original Core-only interpretation over-required optional Core HostProperties such as `MaxAggTokenSize` when an Opal response omitted them.
  - The current model now treats Opal mandatory HostProperties (`MaxComPacketSize`, `MaxPacketSize`, `MaxIndTokenSize`, `MaxPackets`, `MaxSubpackets`, `MaxMethods`) as required, while optional Core properties are validated only when returned or previously observed as supported.
  - This restored public eval from 95.00 to 100.00 while keeping all 18 HostProperties sourced cases at 0 mismatches.
- Added `adminexch-disabled-doc`: 3 accepted cases.
  - Extends Admin SP Authority/session-startup coverage around the Base Template `AdminExch` row.
  - The batch verifies that issued-disabled `AdminExch` cannot be used as `HostExchangeAuthority` to open a session, and explicit `Authenticate(AdminExch)` cannot return `SUCCESS True` or `NOT_AUTHORIZED`; the document-grounded behavior is `SUCCESS False`.
  - This batch triggered a solver repair: `AdminExch` is now modeled as disabled by default in Admin SP, and `StartSession` checks the Host Control Authority chosen from `HostSigningAuthority` or `HostExchangeAuthority` against `Authority.Enabled`. Two draft PASS packets with representation concerns were pruned before promotion.
  - Coverage movement: document shards referenced by sourced tests increased from 459 to 460, and pending A/B cartography rows decreased from 225 to 224.
- Added `session-manager-control-target-doc`: 9 accepted cases.
  - Extends Session Manager control-session coverage around the SMUID boundary and supported control-method universe.
  - The batch verifies that `Properties` on SMUID can succeed, while `Properties`/`StartSession` with non-SMUID InvokingID and SP methods such as `Get`, `Set`, `Authenticate`, and `Random` on SMUID cannot return normal `SUCCESS` as control-session method invocations.
  - This batch triggered a solver repair: `expected_status` now rejects explicit SMUID targets whose MethodID is not a supported Session Manager control method, instead of letting a generic SP-method expectation accept the response. During review, four draft cases with Packet.Session/trajectory-abstraction concerns were pruned before promotion, so the trusted set contains only no-concern packets.
  - Coverage movement: document shards referenced by sourced tests increased from 457 to 459, and pending A/B cartography rows decreased from 227 to 225.
- Added `tper-properties-response-constraints-doc`: 16 accepted cases.
  - Extends `Properties` coverage from HostProperties state into TPer `Properties` response constraints.
  - The batch verifies returned TPer property type/range constraints, `MaxPacketSize` and `MaxComPacketSize` minimum-or-zero semantics, nonnegative uinteger properties, boolean property typing, TPer `AckNak=True` requiring `SequenceNumbers=True`, and `Asynchronous=True` requiring `MaxMethods=0`.
  - This batch triggered a solver repair: `Properties` expectations now enable TPer property response validation; parsing extracts returned TPer `Properties` separately from `HostProperties`; and the engine rejects impossible known-property payloads while still tolerating omitted unsupported properties and vendor extension pairs.
  - Coverage movement: document shards referenced by sourced tests increased from 456 to 457; pending A/B cartography rows stayed at 227 because the remaining top `5.2.2.4.1` parent shard still includes low-level communication rules that are not directly representable as method-return trajectories.
- Added `host-properties-response-reset-long-doc`: 18 accepted cases.
  - Extends Session Manager `Properties` coverage from timeout-only return parsing into full `HostProperties` response/state validation.
  - The batch verifies Table 168 minimum coercion, all-supported-property response completeness, cumulative supersede/omitted-value preservation, `AckNak=True` with `SequenceNumbers=False` returning both false, and reset behavior for PowerCycle, HardwareReset, ProtocolStackReset, and non-resetting programmatic TPerReset.
  - This batch triggered a solver repair: `State.host_properties` now tracks cumulative HostProperties state; `Properties` expectations validate returned HostProperties; parsing canonicalizes known host-property names; and reset transitions reset or preserve the state according to the cited reset sections.
  - Coverage movement: document shards referenced by sourced tests increased from 451 to 456, and pending A/B cartography rows decreased from 229 to 227.
- Added `cpin-genkey-reset-reissue-long-doc`: 52 accepted cases.
  - Extends C_PIN/Auth coverage with long GenKey/reset/reissue trajectories: successful GenKey invalidates the previous PIN across resets and resets `Tries` without consuming `Authority.Uses`; failed GenKey leaves PIN and `Tries` unchanged; PowerCycle/HardwareReset affect nonpersistent `Tries` differently; and a later authorized C_PIN `PIN` Set can intentionally reissue the old byte value.
  - No solver repair was required. Existing GenKey mutation tracking, invalidated-PIN state, TryLimit/Tries accounting, reset persistence, PIN Set reissue, and Authority Uses tracking already matched the official semantics.
  - Coverage movement: document shards referenced by sourced tests stayed at 451 because this deepens already-covered C_PIN/Auth/GenKey sections; pending A/B cartography rows stayed at 229.
- Added `authenticate-proof-tries-uses-long-doc`: 26 accepted cases.
  - Extends authentication coverage by using `Authenticate` `Proof` rather than `Challenge` as the password credential surface, composed with `C_PIN.TryLimit/Tries` and `Authority.Limit/Uses`.
  - The batch verifies correct Proof `Success=True`, incorrect Proof `Success=False`, failed Proof incrementing Tries without Uses, successful Proof resetting Tries and incrementing Uses, TryLimit lockout false results, TryLimit zero behavior, host Tries reset, disabled authority false result, and final-use Authority Limit exhaustion.
  - No solver repair was required. Existing Proof parsing, Authenticate result-boolean validation, C_PIN counter transitions, and Authority Uses tracking already matched the official semantics.
  - Coverage movement: document shards referenced by sourced tests stayed at 451 because this deepens already-covered Auth/C_PIN/Authority sections; pending A/B cartography rows stayed at 229.
- Added `spinfo-addace-persistence-long-doc`: 21 accepted cases.
  - Extends AccessControl state coverage around Admin SP `SPInfo/Get`, where `AddACEACL` permits `AddACE` but `RemoveACEACL`, `GetACLACL`, and `DeleteMethodACL` are empty.
  - The batch verifies that successful `AddACE` persists across sessions and failed `RemoveACE`/`GetACL`/`DeleteMethod` attempts, duplicate detection follows the mutated ACL, failed duplicate/nonexistent AddACE attempts do not poison later valid additions, and failed meta-methods do not tombstone or undo the association.
  - No solver repair was required. Existing dynamic ACL addition/removal state, deleted-association state, and meta-ACL authorization already matched the official semantics.
  - Coverage movement: document shards referenced by sourced tests stayed at 451 because this deepens already-covered AccessControl/AddACE sections; pending A/B cartography rows stayed at 229.
- Added `locking-toggle-reenable-long-doc`: 34 accepted cases.
  - Extends Locking state-machine coverage by composing disabled `ReadLockEnabled`/`WriteLockEnabled`, stored `ReadLocked`/`WriteLocked` edits while disabled, later re-enable, matching PowerCycle `LockOnReset`, host I/O, and Level 0 `Locked`.
  - The batch verifies that disabled lock features make stored locked cells ineffective without erasing or freezing those stored cells; clearing or setting a locked cell while disabled becomes meaningful after re-enable, and disabled LockOnReset does not retroactively lock after re-enable unless the feature was re-enabled before the matching reset.
  - No solver repair was required. Existing RangeState Set transitions, disabled-lock host-I/O semantics, reset handling, and Level 0 Locked computation already matched the official semantics.
  - Coverage movement: document shards referenced by sourced tests stayed at 451 because this deepens already-covered Locking state-machine sections; pending A/B cartography rows stayed at 229.
- Added `cpin-genkey-tries-limit-long-doc`: 26 accepted cases.
  - Extends authentication/C_PIN coverage by composing `GenKey` credential rotation with `TryLimit`, observable `Tries`, `Authority.Uses`, old-PIN invalidation, explicit `Authenticate`, and `StartSession`.
  - The batch verifies that successful `GenKey` on `C_PIN_User1` resets `Tries` and invalidates the prior host-known PIN, but does not count as a successful authentication for `Authority.Uses`; later old-PIN attempts fail and update failure counters normally.
  - No solver repair was required. Existing C_PIN GenKey, invalidated-credential, Tries reset, failed-authentication, and Authority Uses tracking already matched the official semantics.
  - Coverage movement: document shards referenced by sourced tests stayed at 451 because this deepens already-covered C_PIN/Auth/GenKey sections; pending A/B cartography rows stayed at 229.
- Added `getacl-personalized-ace-invariant-doc`: 16 accepted cases.
  - Extends AccessControl/GetACL coverage by separating the AccessControl ACL column from the ACE row `BooleanExpr` column after personalization.
  - The batch verifies that personalizing DataStore Get/Set ACEs, C_PIN_User1 Set ACE, MBRControl Set ACE, Locking_Range1 Get ACE, or K_AES_Mode ACE does not cause `GetACL` to return authority names or modified BooleanExpr values; it must still return the association's ACE uidref list.
  - No solver repair was required. Existing exact GetACL return-list validation and ACE-row state tracking already kept ACL membership separate from ACE BooleanExpr changes.
  - Coverage movement: document shards referenced by sourced tests stayed at 451 because this deepens already-covered AccessControl/ACE sections; pending A/B cartography rows stayed at 229.
- Added `datastore-booleanexpr-and-offset-long-doc`: 32 accepted cases.
  - Extends DataStore byte-table coverage into AND/OR ACE BooleanExpr composition across separate Get and Set ACEs, explicit `Authenticate(User1)` inside an Admin session, failed Admin-only/User-only AND writes, and exact offset-preserving payload checks.
  - The batch verifies that `Admins AND User1` requires both authorities in the same session, `Admins OR User1` can grant only one side of DataStore access, and failed unauthorized writes do not mutate bytes visible to a later combined-authority read.
  - No solver repair was required. Existing ACE BooleanExpr evaluation, explicit authentication session-state tracking, separate DataStore Get/Set ACE state, and byte offset reconstruction already matched the official semantics.
  - Coverage movement: document shards referenced by sourced tests stayed at 451 because this deepens already-covered DataStore/ACE/Auth sections; pending A/B cartography rows stayed at 229.
- Added `locking-crossing-reset-long-doc`: 35 accepted cases.
  - Extends Locking state-machine coverage into `RangeCrossingBehavior` composed with `LockOnReset`, PowerCycle, TCGReset, enabled TPER_RESET, manual unlock, and Read/WriteLockEnabled gating.
  - The batch verifies that RangeCrossingBehavior=0 only permits crossing transfers when all addressed ranges are unlocked, RangeCrossingBehavior=1 still terminates otherwise-unlocked crossing transfers, and single-range transfers are not rejected merely because the bit is 1.
  - No solver repair was required. Existing range-crossing, reset, effective-range, and enabled-lock-cell logic already matched the official semantics.
  - Coverage movement: document shards referenced by sourced tests stayed at 451 because this deepens already-covered Locking/Opal SSC V2 sections; pending A/B cartography rows stayed at 229.
- Added `auth-disabled-reactivation-long-doc`: 18 accepted cases.
  - Extends authentication state-machine coverage across disabled/re-enabled `Authority.Enabled` transitions combined with `C_PIN.TryLimit/Tries`, `Authority.Limit/Uses`, explicit `Authenticate`, and `StartSession`.
  - The batch verifies that disabling an authority gates authenticatability without clearing independent C_PIN or Authority counters; after re-enable, preserved or explicitly reset counters still decide lockout and use-limit behavior.
  - No solver repair was required. Existing authentication state tracking already matched the official semantics for disabled authorities, TryLimit lockout, host Tries/PIN reset, Uses reset, and Limit exhaustion.
  - Coverage movement: document shards referenced by sourced tests stayed at 451 because this deepens already-covered Authority/C_PIN/Auth sections; pending A/B cartography rows stayed at 229.
- Added `getacl-admin-locking-remaining-exact-acl-long-doc`: 34 accepted cases.
  - Extends exact GetACL coverage into remaining issued Admin/Locking AccessControl associations: Admin descriptor-object Gets, SPTemplates row Gets, MethodID and ACE object Gets, Authority_Admin1 Get/Set, Locking Table_Locking descriptor Get, Locking MethodID object Gets, and Locking ACE object Set rows whose ACL is `ACE_ACE_Set_BooleanExpression`.
  - This batch triggered a solver repair: exact GetACL validation now generalizes Opal wildcard preconfiguration rows instead of validating only a small manually enumerated subset. Wrong-but-syntactic ACE uidref lists for these associations are now rejected.
  - Coverage movement: document shards referenced by sourced tests stayed at 451 because the batch deepens already-covered AccessControl/ACE/MethodID shards; pending A/B cartography rows stayed at 229.
- Added `datastore-split-ace-offset-granularity-long-doc`: 30 accepted cases.
  - Extends DataStore byte-table coverage into split Get/Set ACE authorization and offset/granularity composition: Set-only User1 writes are later visible to Admin, Get ACE replacement gives User1 reads while removing Admin reads, Set ACE revocation blocks User1 writes, structured row offsets, raw `startRow`, omitted `Where`, no-op Set, and aligned/unaligned attempts preserve exact payload state.
  - No solver repair was required. Existing DataStore ACE replacement, byte reconstruction, unauthorized-Get empty-result handling, failed-Set non-mutation, and mandatory-granularity validation already matched the official semantics under this longer trajectory.
  - Coverage movement: document shards referenced by sourced tests stayed at 451 because this intentionally deepened already-covered DataStore/ACE shards; pending A/B cartography rows stayed at 229.
- Added `ace-booleanexpr-long-doc`: 19 accepted cases.
  - Extends ACE/ACL coverage from exact `GetACL` payloads into actual BooleanExpr evaluation over authenticated authorities. The batch covers `Admins OR User1` C_PIN rotation and old-PIN invalidation, later `Admins`-only C_PIN restriction, DataStore Get/Set ACEs personalized to `Admins OR User1`, byte payload composition across Admin/User writes, `Admins AND User1` blocking either authority alone, and explicit `Authenticate(User1)` inside an Admin session satisfying the AND expression.
  - No solver repair was required. Existing ACE expression parsing/evaluation and session authentication state already handled OR/AND and explicit authentication in the same session.
  - Coverage movement: document shards referenced by sourced tests increased from 449 to 451, and pending A/B cartography rows decreased from 231 to 229.
- Added `protocol-stack-reset-long-doc`: 30 accepted cases.
  - Extends reset/session coverage into long Protocol Stack Reset trajectories: stale Locking/Admin sessions fail after `TCGReset`, `ProtocolStackReset`, and `StackReset`; fresh sessions observe preserved Locking, MBRControl, DataStore, and TPerInfo state; `TCGReset` does not apply Opal Programmatic `LockOnReset` or `MBRDoneOnReset`; later PowerCycle/TPER_RESET still apply their matching reset-type effects; and pending StartTrustedSession identifiers are invalidated by the reset.
  - No solver repair was required. Existing parser/transition logic already separates `PROTOCOL_STACK_RESET` from Opal reset_types 0/1/3, aborts the session/startup context, and returns before LockOnReset/MBRDoneOnReset mutation.
  - Coverage movement: document shards referenced by sourced tests increased from 445 to 449, and pending A/B cartography rows decreased from 233 to 231.
- Added `locking-disabled-disregard-long-doc`: 25 accepted cases.
  - Extends Locking state-machine coverage into disabled-feature trajectories: disabled read/write sides ignore stored lock cells for host I/O, disabled locked cells do not set Level 0 Locked, stored cells remain observable, re-enabling a feature makes the stored locked cell effective again, disabling it again restores effective unlock behavior, and matching LockOnReset is disregarded while both lock features are disabled.
  - This batch triggered a solver repair: reset handling now follows the S0 disabled-state transition and does not set `ReadLocked`/`WriteLocked` on a matching `LockOnReset` when both read and write locking are disabled. Existing one-side-enabled reset behavior remains covered by prior tests.
  - Coverage movement: document shards referenced by sourced tests increased from 442 to 445, and pending A/B cartography rows decreased from 235 to 233.
- Added `create-table-name-commonname-long-doc`: 21 accepted cases.
  - Extends `CreateTable` coverage into long Name/CommonName uniqueness trajectories: exact duplicate pair rejection, same-name/different-CommonName success, different-name/same-CommonName success, object/byte kind cross-conflicts on the same pair, failed invalid-kind/byte-MaxSize non-reservation, duplicate-failure non-poisoning, reopened-session persistence, and interleaved unique-chain duplicate rejection.
  - No solver repair was required. The existing created-table name tracking already records successful pairs per SP and ignores failed attempts.
  - Coverage movement: document shards referenced by sourced tests increased from 440 to 442, and pending A/B cartography rows decreased from 237 to 235.
- Added `accesscontrol-meta-acl-columns-long-doc`: 27 accepted cases.
  - Extends AccessControl coverage into row-column independence: `AddACEACL`, `RemoveACEACL`, `GetACLACL`, and `DeleteMethodACL` govern their corresponding meta-methods independently from the target `ACL` column. Successful `AddACE` mutates only ACL membership; it does not make empty GetACL/RemoveACE/DeleteMethod meta-ACL columns invocable.
  - No solver repair was required. The existing meta-ACL model already kept row-specific meta-method authorization separate from dynamic ACL additions/removals.
  - Coverage movement: document shards referenced by sourced tests increased from 437 to 440, and pending A/B cartography rows decreased from 240 to 237.
- Added `starttrusted-session-id-long-doc`: 16 accepted cases.
  - Extends the thin StartTrustedSession coverage into session-ID continuity: matching HostSessionID/SPSessionID success, mismatched HostSessionID failure, mismatched SPSessionID failure, both mismatched failure, non-default ID tracking, stale identifiers after a restarted session, failure after EndSession, failure before startup, non-SMUID target failure, and HostResponse not rescuing mismatched IDs.
  - This batch triggered a solver repair: successful StartSession now stores returned HostSessionID and SPSessionID on `Session`, and StartTrustedSession rejects mismatches against those stored IDs instead of accepting any open-session continuation.
  - Coverage movement: document shards referenced by sourced tests increased from 431 to 437, and pending A/B cartography rows decreased from 243 to 240.
- Added `session-startup-security-long-doc`: 32 accepted cases.
  - Extends session-startup coverage into long HostChallenge/SignedHash/Secure/ResponseExch trajectories: current SID password matching, missing/wrong HostChallenge rejection, latest `Secure=0` and `HashAndSign=0` observations overriding earlier required states, empty SignedHash rejection, role-mismatched startup authorities, credentialless exchange authorities, and C_PIN-as-inappropriate exchange credential.
  - This batch triggered a solver repair during independent review. A reviewer rejected the earlier non-null C_PIN exchange-credential success pair, correctly noting that Core requires an appropriate exchange credential for session-key encryption and C_PIN is a password credential. The model now tracks observed Authority Credential symbols and rejects C_PIN credentials for exchange-key satisfaction instead of treating any non-null credential as enough.
  - Coverage movement: document shards referenced by sourced tests increased from 428 to 431, and pending A/B cartography rows decreased from 246 to 243.
- Added `datastore-offset-stress-long-doc`: 34 accepted cases.
  - Extends DataStore byte-table coverage into long offset/provenance trajectories: overlapping writes, exact middle/prefix/suffix Gets, raw `startRow` Set syntax, omitted-Where leading overwrite, no-op Set, byte-table column-Values failure, explicit one-byte and interior Gets, and mandatory-granularity aligned/unaligned sequences.
  - No new solver repair was required; this batch validates existing byte reconstruction, failed Set non-mutation, no-op Set behavior, raw/structured offset parsing, and mandatory write-granularity enforcement.
  - Coverage movement: document shards referenced by sourced tests increased from 426 to 428, and pending A/B cartography rows decreased from 248 to 246.
- Added `created-table-association-scope-long-doc`: 28 accepted cases.
  - Extends created-table AccessControl coverage into long association-scoping trajectories across `TableUID.Get`, `TableUID.Set`, `TableUID.Next`, and table descriptor `Get`.
  - No new solver repair was required; this batch validates that dynamic `AddACE`/`RemoveACE`, duplicate checks, later `GetACL` observations, and `DeleteMethod` tombstones are keyed by the exact `InvokingID`/`MethodID` pair and do not leak to sibling associations.
- Added `auth-tries-uses-long-doc`: 22 accepted cases.
  - Extends authentication coverage into longer mixed C_PIN/Authority trajectories: failed explicit `Authenticate`, failed `StartSession`, successful explicit `Authenticate`, successful `StartSession`, host `Tries` reset, PIN rotation, host `Uses` reset, `TryLimit=0`, and nonzero Authority `Limit` exhaustion.
  - No new solver repair was required; this batch validates the existing model for separate `C_PIN.Tries` and `Authority.Uses` accounting, success-only use increments, TryLimit lockout, explicit host counter updates, and later Get/StartSession postconditions.
- Added `datastore-authority-churn-long-doc`: 26 accepted cases.
  - Extends DataStore byte-table coverage into longer authority/ACE churn trajectories: Admin base writes, Set-only User1 partial overwrites, Admin verification, Get ACE replacement, Admin read removal, Set ACE revocation, failed unauthorized writes, mandatory-granularity failures, aligned User1 overwrites, no-op Set, and exact subrange reads.
  - No new solver repair was required; this batch validates the existing DataStore model for offset-level byte tracking, independent Get/Set ACE replacement, unauthorized Get empty-result behavior, unauthorized/failed Set non-mutation, and mandatory write-granularity enforcement.
- Added `locking-multi-range-long-get-doc`: 20 accepted cases.
  - Extends Locking reset coverage into longer multi-range trajectories with three independent rows, PowerCycle, HardwareReset, enabled TPER_RESET/Programmatic reset, manual lock clearing, enabled-column changes, stored-cell `Get` observations, and Level 0 `Locked` checks.
  - No new solver repair was required; this batch validates that existing state reconstruction treats each range's `ReadLockEnabled`/`WriteLockEnabled`, `ReadLocked`/`WriteLocked`, and `LockOnReset` independently, and counts only enabled locked cells for Level 0 `Locked`.
- Added `created-row-delete-object-acl-doc`: 10 accepted cases.
  - Extends created-row lifecycle coverage from table-level `DeleteRow` into direct row-object `Delete`, using Core's rule that rows may be deleted either way and that object deletion removes associated AccessControl rows.
  - This batch triggered a solver repair: `_expected_delete` now accepts direct created-row `Delete` with an empty success result, and `_apply_delete_success` reuses created-row cleanup so stale row-object ACL state and unique-column occupancy are removed without touching sibling rows.
- Added `created-row-meta-acl-state-doc`: 12 accepted cases.
  - Extends created-row AccessControl coverage into row-object meta-ACL methods: `AddACE`, `RemoveACE`, `GetACL`, and `DeleteMethod`.
  - This batch triggered a solver repair: row-object meta-ACL authorization is now seeded from the creating session authority and dynamic ACL additions/removals/tombstones are honored for created row associations.
- Added `created-row-method-association-doc`: 11 accepted cases.
  - Extends created-row AccessControl coverage into per-method tombstone scoping for row `Delete` and row `Set` associations.
  - No new solver repair was required after the meta-ACL state patch; this batch verifies that tombstones are keyed by exact InvokingID/MethodID and do not delete sibling rows or unrelated row methods.
- Added `created-row-failed-meta-nonmutation-doc`: 9 accepted cases.
  - Extends created-row AccessControl coverage into failed meta-method non-mutation for `AddACE`, `RemoveACE`, and `DeleteMethod`.
  - No new solver repair was required; this batch verifies that only successful meta-method calls mutate dynamic ACL or tombstone state.
- Added `created-row-cleanup-acl-state-doc`: 8 accepted cases.
  - Extends created-row AccessControl coverage into cleanup after `DeleteRow` and direct row-object `Delete`.
  - No new solver repair was required; this batch verifies stale dynamic ACL/tombstone state is removed for deleted rows and isolated from sibling rows.
- Added `level0-range-crossing-locking-doc`: 11 accepted cases.
  - Extends Level 0 Opal SSC V2 coverage from descriptor-value validation into stateful host-I/O behavior across Locking range boundaries.
  - This batch triggered a solver repair: observed `RangeCrossingBehavior` is now stored and later constrains unlocked multi-range reads/writes. Behavior 0 processes the transfer; behavior 1 forbids normal success; locked-range protection still takes precedence.
- Added `getacl-admin-common-exact-acl-doc`: 30 accepted cases.
  - Extends exact Admin SP GetACL coverage to common table/SP method rows whose ACL is `ACE_Anybody`, `ACE_SP_SID`, or `ACE_SP_SID plus ACE_Admin`.
  - This batch triggered a solver repair: `_known_acl_return_refs` now covers the remaining common Admin SP preconfigured rows, and the Activate row is correctly modeled as `LockingSP.Activate`.
- Added `level0-geometry-feature-doc`: 8 accepted cases.
  - Extends Level 0 Geometry Reporting descriptor coverage to fixed descriptor fields and LockingInfo-derived geometry/alignment values.
  - This batch triggered a solver repair: successful Level 0 geometry discovery now validates returned logical block size, alignment granularity, lowest aligned LBA, and alignment-required state against reconstructed LockingInfo observations.
- Added `level0-opal-ssc-v2-feature-doc`: 12 accepted cases.
  - Extends Level 0 Opal SSC V2 descriptor coverage to fixed length/code fields, descriptor version minimum, ComID/admin/user authority minimum counts, and constrained enum-like values.
  - This batch triggered a solver repair: `ExpectedResponse.expected_return_allowed_values` now lets the engine reject reserved or impossible descriptor field values.
- Added `locking-reset-session-boundary-doc`: 14 accepted cases.
  - Extends Locking reset coverage to session-boundary behavior: stale open sessions after reset, protocol stack reset without Programmatic LockOnReset application, PowerCycle/TPER_RESET relocking, and disabled TPER_RESET non-mutation.
  - No new solver repair was required; the existing reset/session/LockOnReset state model passed all fourteen independently reviewed cases.
- Added `created-table-deletemethod-tombstone-doc`: 7 accepted cases.
  - Extends created-table AccessControl lifecycle coverage beyond one post-`DeleteMethod` `GetACL` check into a tombstone trajectory: later `GetACL`, `AddACE`, `RemoveACE`, and a second `DeleteMethod` on the same deleted association cannot succeed.
  - No new solver repair was required; the existing deleted-method association state model passed all seven independently reviewed cases.
- Added `ace-get-preconfig-cells-doc`: 16 cases, 13 accepted and 3 quarantined.
  - Extends ACE table coverage to authorized `ACE.Get` observations of preconfigured `BooleanExpr` and `Columns` cells across Admin SP and Locking SP rows.
  - This batch triggered solver repairs: ACE Get now validates returned `BooleanExpr`/`Columns`, successful `ACE.Set(BooleanExpr)` changes later observable BooleanExpr state, and official string forms like `Admins OR SID` and `Admins OR User1 *ACE1` parse into the normal authority/operator model.
  - Quarantine note: three otherwise-agreed cases are withheld because reviewers recorded representation concerns around the `*ACE1` annotation and UID-vs-symbolic rendering of `User1`.
- Added `reencrypt-status-enum-doc`: 8 cases, 6 accepted and 2 quarantined.
  - Extends re-encryption status coverage to reserved enum values in `LastReEncStat` and `GeneralStatus`.
  - This batch triggered a solver repair: returned `Locking.Get` cells for those columns now use enum validators, so reserved status values are rejected.
  - Quarantine note: one case used the named value `Success` instead of a numeric enum value, and one case touched the ambiguous `gen_status` state-range wording; both are withheld from the trusted corpus despite mostly agreeing labels.
- Added `reencrypt-progress-status-postcondition-doc`: 6 accepted cases.
  - Extends re-encryption progress/status coverage to `GeneralStatus` and `LastReEncryptLBA` values after successful requests.
  - This batch triggered a solver repair: `PAUSE_req` now records the correct pause-origin `GeneralStatus`, `START_req` initializes `LastReEncryptLBA` to the all-ones sentinel, and later `Locking.Get` validates these known cells.
- Added `reencrypt-request-postcondition-doc`: 10 accepted cases.
  - Extends re-encryption state-machine coverage from isolated request success/failure into longer traces where a later `Locking.Get(ReEncryptState)` must reflect the successful request transition.
  - No production solver repair was required; this locks in the existing state-transition model under independent consensus.
- Added `data-removal-interrupted-bit-doc`: 8 cases, 7 accepted and 1 quarantined.
  - Extends Level 0 Supported Data Removal Mechanism descriptor coverage to the Data Removal Operation Interrupted bit in fresh/no-interruption and post-successful-`GenKey` trajectories.
  - This batch triggered a solver repair: explicit returned `DataRemovalOperationInterrupted=1` is now rejected when no interrupted operation has been observed or after successful completion.
  - Quarantine note: one otherwise-correct PASS case used the shortened spelling `OperationInterrupted`; reviewers flagged that the packet did not prove this alias is protocol-compliant, so it stays out of the trusted corpus.
- Added `activekey-advkey-state-doc`: 12 accepted cases.
  - Extends Locking `ActiveKey`/`NextKey` state coverage through direct Set, `PENDING`/`ACTIVE` blocking for `NextKey`, and `ADVKEY_req` from `COMPLETED`/`PAUSED`.
  - This batch triggered a solver repair: `ActiveKey`/`NextKey` are now tracked as known state, later `Locking.Get` cells are validated, and media-key references are canonicalized across symbolic names and UIDs.
- Added `getacl-admin-exact-acl-doc`: 16 accepted cases.
  - Extends exact AccessControl/GetACL coverage into Admin SP preconfigured rows for Authority, C_PIN, TPerInfo, and DataRemovalMechanism.
  - This batch triggered a solver repair: `_known_acl_return_refs` and ACE canonicalization now cover Admin SP exact ACL returns instead of accepting wrong-but-syntactic ACE lists.
- Added `getacl-global-kaes-exact-acl-doc`: 16 accepted cases.
  - Extends exact AccessControl/GetACL coverage into Locking_GlobalRange and K_AES_128/K_AES_256 GlobalRange/Range1 Get/GenKey rows.
  - This batch triggered a solver repair: ACE canonicalization and `_known_acl_return_refs` now distinguish GlobalRange vs Range1 and K_AES_128 vs K_AES_256 GenKey ACEs instead of only modeling the K_AES Mode/Get case.
- Added `auth-tries-uses-composite-doc`: 10 accepted cases.
  - Combines C_PIN `TryLimit`/`Tries` with Authority `Limit`/`Uses` in longer authentication trajectories.
  - This batch triggered a solver repair: successful Authority Set of columns `0x0F`/`0x10` now updates reconstructed `Limit`/`Uses` state even when those are the only Authority columns written, so later Get/Auth/StartSession checks use the updated values.
- Added `getacl-expanded-exact-acl-doc`: 10 accepted cases.
  - Expands exact AccessControl/GetACL coverage beyond DataStore, MBRControl, and C_PIN into Locking_Range1 Get/Set, K_AES_256_Range1_Key Get, and Authority_User1 Set.
  - This batch triggered a solver repair: exact GetACL uidref comparison is now equality-based, additional ACE aliases are canonicalized, and `_known_acl_return_refs` covers the new Opal preconfigured rows.
- Added `datastore-ace-replacement-doc`: 8 accepted cases.
  - Covers the score-relevant rule that setting `ACE_DataStore_Get_All` or `ACE_DataStore_Set_All` BooleanExpr to User1 replaces the prior Admins expression instead of leaving Admins implicitly authorized.
  - This batch triggered a solver repair: DataStore Get/Set authorization now follows configured DataStore ACE BooleanExpr state, while unauthorized byte-table Get remains `SUCCESS` with an empty result list.
- Added `datastore-sparse-rework-doc`: 4 accepted cases.
  - Reworks the sparse-fill ambiguity by separating final User1 reads after Get ACE personalization from final Admin reads where Get ACE personalization has not occurred.
  - No additional solver repair was required after the DataStore ACE replacement fix.
- Updated `datastore-sparse-fill-doc`: 10 cases, 8 accepted and 2 quarantined.
  - Extends DataStore byte-table coverage into sparse writes and gap filling: Admin writes at noncontiguous offsets, later row-ordered `Get`, overlapping partial overwrite, Set-only User1 mutations, later Get ACE personalization, and unauthorized Set attempts that must not mutate bytes.
  - Quarantine note: two Admin-session final Get cases after Get ACE personalization remain held out because one reviewer did not apply the ACE replacement interpretation used by two other reviewers. The direct accepted `datastore-ace-replacement-doc` batch is the trusted source for that rule.
- Added `locking-reset-long-trajectory-doc`: 10 accepted cases.
  - Extends the LockOnReset state machine into longer trajectories: reset-induced locks, later disabled lock-enable columns, Level 0 Locked consistency, manual clearing after reset, nonmatching HardwareReset preservation, enabled Programmatic reset relocking, and split read/write host I/O behavior.
  - No new solver repair was required; existing Locking reset, host I/O, and Level 0 descriptor logic passed all ten consensus-accepted trajectories.
- Added `created-table-delete-object-doc`: 4 accepted cases.
  - Covers `Delete` invoked directly on a created Table descriptor object: success must return an empty list, and the deletion removes AccessControl associations for both the created table and its descriptor.
  - This batch triggered a solver repair: `_expected_delete` now recognizes created Table descriptors as valid Delete targets, and `_apply_delete_success` routes descriptor-object deletion through the unified created-table cleanup path.
- Added `created-table-delete-acl-doc`: 5 cases, 4 accepted and 1 quarantined.
  - Accepted cases cover table-deletion side effects: after successful `DeleteRow` of a created table descriptor, `GetACL` for both the deleted table UID and deleted descriptor UID must return `NOT_AUTHORIZED`, not stale `SUCCESS` with an ACL list.
  - This batch triggered a solver repair: descriptor deletion now removes the created table lifecycle object, including descriptor mapping, rows, size/allocation state, stored `GetSetACL`, dynamic ACL mutations, and stale method-association state.
  - Quarantine note: the same-name `CreateTable` reuse case was held out because reviewers wanted an explicit source for `NewTableName`/`CommonName` reuse after deletion rather than relying on inference from descriptor deletion.
- Added `created-table-meta-acl-doc`: 6 accepted cases.
  - Covers AccessControl rows created as a side effect of `CreateTable`, especially `TableUID.Get`/`DeleteMethod` meta-method behavior controlled by the `GetSetACL` parameter.
  - This batch triggered a solver repair: newly created table AccessControl associations are now recognized, their `GetSetACL` is tracked, empty `GetSetACL` blocks meta-method success, `ACE_Anybody` permits it, and successful `DeleteMethod` removes the association for later `GetACL`.
- Added `datastore-long-trajectory-doc`: 6 accepted cases.
  - Extends DataStore coverage into longer hidden-score-like traces: interleaved Admin/User partial overwrites, Set-only User1 write with empty User1 Get, later Admin verification, later Get ACE personalization, and failed unauthorized Set attempts that must not mutate bytes.
  - No new solver repair was required; existing DataStore offset/payload and ACE-state logic passed all six consensus-accepted trajectories.
- Added `genkey-reencrypt-state-doc`: 5 accepted cases.
  - Reworks the earlier `genkey-doc` ReEncryptState quarantines by using symbolic `ReEncryptState` values and explicit `ReEncryptState`/K_AES evidence instead of raw column/value inference.
  - Covers `K_AES_256_Range1_Key.GenKey` for `PENDING`, `ACTIVE`, `COMPLETED`, and `PAUSED`, plus `K_AES_256_GlobalRange_Key.GenKey` for global `PENDING`, all as impossible `SUCCESS` responses.
  - No new solver repair was required; this validates the existing GenKey/ReEncryptState gate with stronger official-document evidence.
- Added `addace-acl-state-doc`: 5 cases, 4 accepted and 1 quarantined.
  - Covers Admin SP `SPInfo/Get` `AddACE` statefulness: adding `ACE_Admin` can succeed, adding preexisting `ACE_Anybody` cannot succeed, and a second add of the same ACE cannot succeed even when the second call uses a numeric uidref spelling.
  - This batch triggered a solver repair: successful `AddACE` now mutates reconstructed AccessControl ACL state, and later `AddACE` checks that state for duplicates.
  - Quarantine note: the arbitrary nonexistent ACE UID case was held out because reviewers noted that the supplied preconfiguration table does not universally rule out vendor extension ACE rows.
- Added `locking-host-io-impossible-doc`: 4 accepted cases.
  - Reworks earlier `locking-doc` quarantine items by avoiding exact Data Protection Error status-code claims.
  - Covers explicit MBR-disabled enabled ReadLocked/WriteLocked host I/O and mixed boundary crossings as impossible `SUCCESS` responses.
  - No new solver repair was required; this is an evidence/assertion tightening of existing host I/O lock behavior.
- Added `data-removal-feature-doc`: 12 accepted cases.
  - Covers Opal Level 0 Data Removal Feature descriptor fixed version/length fields, processing bit default, and supported mechanism/operation bit masks.
  - This batch triggered a solver repair: `ExpectedResponse` can now express required/cleared bit masks, and raw Level 0 Data Removal Feature responses are checked semantically rather than by status alone.
- Added `meta-acl-preconfig-empty-doc`: 8 accepted cases.
  - Covers broad Opal preconfigured AccessControl rows where `AddACEACL`, `RemoveACEACL`, or `DeleteMethodACL` are empty even in Admin sessions.
  - This batch triggered a solver repair: `_known_meta_acl_authorization` now routes known preconfigured rows through their row-specific meta-ACL columns instead of a broad permissive default.
- Added `locking-feature-reset-doc`, `locking-feature-mbr-reset-doc`, and `mbrcontrol-reset-get-doc`: 24 accepted cases.
  - Covers reset-driven Locking Feature descriptor bits, MBRControl `DoneOnReset` effects, and later observable `MBRControl.Get` state after PowerCycle, HardwareReset, and enabled Programmatic/TPer reset.
  - Review correction: one MBR reset packet was archived under `analysis/label_reviews/superseded/2026-05-24-locking-feature-mbr-reset-evidence-refresh/` until explicit reset mapping evidence was added.
- Added `datastore-cross-authority-doc`: 8 accepted cases.
  - Covers cross-authority byte-table provenance: User1 with Set-only DataStore ACE can mutate bytes but cannot read them, and a later Admin Get must observe the current payload including partial overwrites.
  - No new production repair was required beyond the existing DataStore offset/payload state model; these are high-value longer-trajectory regressions.
- Added `getacl-exact-acl-doc`: 12 accepted cases.
  - Covers exact `GetACL` return contents for DataStore Get/Set, MBRControl Get/Set, and C_PIN_User1 Set AccessControl associations.
  - This batch triggered a solver repair: `GetACL` success now validates exact expected ACE uidrefs, not merely that the return payload is a syntactic uidref list.
  - Review correction: the first packet was archived under `analysis/label_reviews/superseded/2026-05-24-getacl-exact-acl-order-refresh/` because a reviewer flagged ACE-list order ambiguity. The regenerated packet matches table order and passed three-reviewer consensus with no concerns.
- Added `locking-feature-descriptor-doc`: 10 accepted cases.
  - Covers Level 0 Locking Feature descriptor bits `LockingEnabled`, `Locked`, `MBREnabled`, and `MBRDone` against reconstructed Locking SP lifecycle, enabled locked range cells, and MBRControl Enable/Done state.
  - This batch triggered a solver repair: high-level `hasLockedRange` and raw `Level0Discovery` Locking Feature responses are now checked against the same official state predicates instead of being accepted as generic host-helper outputs.
- Added `locking-feature-lifecycle-doc`: 6 accepted cases.
  - Extends the same descriptor bits through longer RevertSP trajectories: successful Locking SP RevertSP returns the Locking Feature descriptor to disabled/unlocked, while a failed locked-global-range KeepGlobalRangeKey RevertSP preserves enabled/locked state.
- Added `cpin-user-ace-booleanexpr-doc`: 5 accepted cases.
  - Covers `ACE_C_PIN_User1_Set_PIN` supported BooleanExpr values (`Admins`, `Admins OR User1`) and their downstream effect on whether User1 can change `C_PIN_User1.PIN`.
  - Review correction: two draft `User1`-only BooleanExpr cases were archived under `analysis/label_reviews/superseded/2026-05-24-cpin-user-ace-user1-only-ambiguity/` because the Opal text guarantees support for `Admins` and `Admins OR UserMMMM` but does not cleanly forbid every vendor extension.
- Added `acl-revertsp-meta-doc`: 9 accepted cases.
  - Covers the Locking SP `ThisSP/RevertSP` AccessControl row: `GetACLACL=ACE_Admin`, while `AddACEACL`, `RemoveACEACL`, and `DeleteMethodACL` are empty.
  - This batch triggered a solver repair: row-specific meta-ACL authorization now recognizes Locking SP `ThisSP/RevertSP`, so unauthenticated `GetACL` is rejected and empty Add/Remove/Delete meta-ACL columns reject success even in an Admin session.
- Added `datastore-offset-payload-doc`: 8 accepted cases.
  - Covers DataStore byte-table subrange `Get`, nonzero-offset `Set`, and partial overwrite behavior where later `Get` must return only the currently stored bytes in the requested row interval.
  - This batch triggered a solver repair: DataStore payload state now tracks byte offsets rather than only the latest whole-table payload string.
- Added `locking-reset-state-machine-doc`: 13 accepted cases.
  - Covers LockOnReset matching/nonmatching reset recovery for Power Cycle, Hardware Reset, and Programmatic/TPER_RESET; empty LockOnReset preserving locked and unlocked states; disabled lock features being disregarded for host write; and PowerCycle aborting an open Locking SP session before a later method.
  - The first review round was superseded after reviewers asked for more explicit source support for `TPerReset`/Programmatic mapping and PowerCycle session abort. The accepted round added `opal/3.2.3`, `opal/4.2.3.1`, and `core/3.3.7.1.5`, then all 13 labels passed no-concern review.
- Added `deletesp-lifecycle-doc`: 5 accepted cases.
  - Covers DeleteSP empty-result shape, deletion after successful session close, disabled-SP DeleteSP consequences, and AdminSP non-deletability.
- Added `admin-revert-sid-doc`: 7 accepted cases.
  - Covers AdminSP Revert read-write requirement, empty-result shape, immediate session abort, SID reset-to-MSID behavior when the Opal SSC V2 revert behavior field is `0x00`, invalidation of the pre-revert SID PIN, and active-LockingSP user-data removal.
- Added `table-lifecycle-doc`: 7 accepted cases.
  - Covers CreateTable duplicate Name/CommonName rejection, created object-table CreateRow/DeleteRow lifecycle, DeleteRow empty-result shape, byte-table CreateRow/DeleteRow rejection, AccessControl system-table DeleteRow rejection, and Delete empty-result shape on Locking objects.
- Added `meta-acl-doc`: 6 accepted cases.
  - Covers row-specific AddACEACL/RemoveACEACL/GetACLACL/DeleteMethodACL behavior, empty meta-ACL NOT_AUTHORIZED failures, AddACE empty-result shape, and GetACL via ACE_Anybody on a Locking C_PIN_User1/Set association.
- Added `meta-acl-empty-doc`: 6 accepted cases.
  - Covers the Admin SP `SPInfo/Get` AccessControl row where the base ACL is `ACE_Anybody` but `RemoveACEACL`, `GetACLACL`, and `DeleteMethodACL` are empty, so those meta-methods fail with `NOT_AUTHORIZED`.
- Added `set-where-values-doc`: 8 accepted cases.
  - Covers `Set` `Where`/`Values` parameter-shape rules across object, object-table, and byte-table invocation forms; `Values` omission as success/no-op; and empty-list success return shape.
- Added `log-clear-flush-doc`: 6 accepted cases.
  - Covers `ClearLog`/`FlushLog` Log table target rules, empty-list success results, and non-Log target rejection using direct Log and C_PIN table evidence.
- Added `log-createlog-doc`: 7 accepted cases.
  - Covers `CreateLog` LogList target rules, required parameters, unsigned `MinSize`, duplicate log-table names, and the three-field success result shape.
- Added `random-doc`: 6 accepted cases.
  - Covers `Random` Count byte-length matching, unsigned Count rejection, `BufferOut` empty-result behavior, and unsupported-parameter `INVALID_PARAMETER` failure.
- Added `package-doc`: 7 accepted cases.
  - Covers `GetPackage`/`SetPackage` impossible-success cases for missing required parameters, invalid credential uidrefs, non-credential targets, and `SetPackage` empty result shape.
- Added `table-query-doc`: 7 accepted cases.
  - Covers `GetFreeSpace` result shape and SP-method target rules, plus `GetFreeRows` result shape on object tables.
- Added `secretprotect-doc`: 3 accepted cases.
  - Covers host non-modifiability of the SecretProtect `Table`, `ColumnNumber`, and `ProtectMechanisms` columns.
- Added `table-kind-doc`: 8 accepted cases.
  - Covers `table_kind` values `1=Object` and `2=Byte`, reserved/out-of-range kind rejection, and `CreateTable` success result arity (`UID`, `Rows`).
- Added `get-cellblock-doc`: 8 accepted cases.
  - Covers `Get` `Cellblock` context rules for byte-table, object-table, and object invocations, including row-bounds byte-table reads and invalid `Table`/row/column component combinations.
- Added `next-doc`: 6 accepted cases.
  - Covers `Next` on object tables, byte-table rejection, `Count` unsignedness, and successful result type as a list of UID column values.
- Added `kaes-get-doc`: 8 accepted cases.
  - Covers K_AES Mode `Get` through `ACE_K_AES_Mode`, valid `symmetric_mode_media` return values, omission of protected K_AES Key material, direct Key-column rejection, and unknown-column rejection.
- Added `log-createlog-params-doc`: 4 accepted cases.
  - Covers `CreateLog` required `HighSecurity`, boolean range validation, optional `HintSize` unsignedness, and a valid `HighSecurity=True` success case.
- Added `loglist-readonly-doc`: 2 accepted cases.
  - Covers host non-modifiability of LogList `Log` and `Serial` columns. A direct Log table delete case was discarded after reviewers noted wording ambiguity.
- Added `reencrypt-column-types-doc`: 2 accepted cases.
  - Covers Locking `ActiveKey` rejecting non-media-key C_PIN references and successful `ReEncryptRequest` `Get` returning no value. Several broader candidate cases were discarded after reviewers flagged UID/state/reserved-value ambiguity.
- Added `cpin-charset-doc`: 1 accepted case.
  - Covers C_PIN `CharSet` column `0x04` rejecting a C_PIN object UID because `CharSet` has `byte_table_ref` type. A symbolic `CharSet` column variant was discarded after one reviewer flagged the name-to-column inference.
- Added `genkey-public-exponent-doc`: 2 accepted cases.
  - Covers `PublicExponent` rejection on non-C_RSA GenKey targets using C_PIN and K_AES_256 examples.
- Added `cpin-column-types-doc`: 2 accepted cases.
  - Covers C_PIN `TryLimit` rejecting a negative `uinteger_4` value and C_PIN `Persistence` rejecting boolean value `2`.
  - The first review round was discarded because a reviewer noted that the docs prove impossible `SUCCESS` but not the exact alternate status; the accepted round explicitly asserts only impossible success.
- Added `loglist-highsecurity-doc`: 1 accepted case.
  - Covers LogList `HighSecurity` column `0x05` rejecting boolean value `2`.
  - The first review round was discarded because reviewers put exact-status caveats in `concerns`; the accepted round explicitly limited concerns to PASS/FAIL ambiguity.
- Added `log-row-readonly-doc`: 2 accepted cases.
  - Covers host non-modifiability of Log table entry row `MonotonicTime` and `Data` cells.
  - This batch triggered a solver repair: Log table rows are now rejected as direct host `Set` targets and Log column names are parsed for read-only checks.
- Added `advkeymode-doc`: 1 accepted case.
  - Covers Locking `AdvKeyMode` rejecting reserved enum value `2`.
  - This batch triggered a solver repair: Locking `Set` now validates `AdvKeyMode` against the sourced `adv_key_mode` enum values `0` and `1`.
- Added `reencrypt-state-values-doc`: 2 accepted cases.
  - Covers ReEncryptState reserved enum value `6` in successful `Get` payloads and stale `COMPLETED` state after successful `ADVKEY_req`.
  - No production solver repair was needed; existing return-cell comparison and re-encryption transition tracking already rejected both.
- Added `meta-acl-locking-status-doc`: 2 accepted cases.
  - Covers exact `NOT_AUTHORIZED` status for Locking SP `C_PIN_User1/Set` `RemoveACE` and `DeleteMethod` attempts when the corresponding meta-ACL columns are empty.
  - No production solver repair was needed; this fills PASS counterparts for existing impossible-success meta-ACL cases.
- Added `lockinginfo-readonly-doc`: 6 accepted cases.
  - Covers host non-modifiability of LockingInfo `UID`, `Name`, `Version`, `EncryptSupport`, `MaxRanges`, and `MaxReEncryptions`.
  - No production solver repair was needed; existing LockingInfo Set rejection already covered the behavior.
- Added `log-entry-readonly-expanded-doc`: 12 accepted cases.
  - Expands Log entry row read-only coverage from `MonotonicTime`/`Data` to all remaining Log row columns.
  - No production solver repair was needed; the earlier Log row Set rejection generalized correctly.
- Added `loglist-initial-row-doc`: 4 accepted cases.
  - Covers the initial LogList row UID `0000000A02000001`, `Name=Log`, and fresh `HighSecurity=false`.
  - This batch triggered a solver repair: initial LogList default return cells are now checked, while a prior successful host `HighSecurity` Set updates later Get expectations.
- Added `mbrcontrol-readonly-doc`: 1 accepted case.
  - Covers host non-modifiability of the MBRControl `UID` column.
  - No production solver repair was needed; existing MBRControl read-only checks already rejected the impossible-success case.
- Added `mbrcontrol-defaults-doc`: 8 accepted cases.
  - Covers Opal MBRControl preconfigured defaults `Enable=false`, `Done=false`, `DoneOnReset=PowerCycle`, plus later `Get` reflecting a successful Admins `Set`.
  - This batch triggered a solver repair: MBRControl `Get` return cells are now checked against preconfiguration and tracked `Set` state.
- Added `data-removal-reserved-doc`: 6 accepted cases.
  - Covers reserved `ActiveDataRemovalMechanism` enum values `3`, `6`, and `7` failing with `INVALID_PARAMETER` and not succeeding.
  - No production solver repair was needed; existing DataRemovalMechanism enum validation already generalized beyond value `4`.
- Added `methodid-locking-preconfig-doc`: 16 accepted cases.
  - Covers Locking SP MethodID preconfigured row names for `Next`, `GenKey`, `RevertSP`, `Get`, `Set`, `Authenticate`, and `Random`, plus host non-modifiability of issued MethodID `UID` and `Name`.
  - This batch triggered a solver repair: successful MethodID `Get` responses now check the returned `Name` cell against the invoked MethodID UID.
- Added `methodid-locking-extra-readonly-doc`: 14 accepted cases.
  - Covers host non-modifiability of issued MethodID `CommonName` and `TemplateID` columns for the same Locking SP MethodID rows.
  - No production solver repair was needed; existing MethodID read-only `Set` rejection already covered columns 2 and 3.
- Added `cpin-issued-readonly-doc`: 15 accepted cases.
  - Covers host non-modifiability of issued C_PIN `UID`, `Name`, and `CommonName` columns across Admin SP `C_PIN_SID`, `C_PIN_MSID`, `C_PIN_Admin1`, and Locking SP `C_PIN_Admin1`/`C_PIN_User1`.
  - No production solver repair was needed; existing C_PIN identity-column read-only validation already covered the behavior.
- Added `authority-issued-readonly-doc`: 21 accepted cases.
  - Covers host non-modifiability of issued Authority `UID`, `Name`, and `CommonName` columns across Admin SP and Locking SP preconfigured authority rows.
  - This batch triggered a solver repair: issued Authority `CommonName` is now rejected as a host `Set` target, matching the same issued-row identity-column rule already applied to `UID`/`Name`.
- Added `ace-issued-readonly-doc`: 30 accepted cases.
  - Covers host non-modifiability of issued ACE `UID`, `Name`, and `CommonName` columns across Admin SP and Locking SP preconfigured ACE rows.
  - This batch triggered a solver repair: issued ACE `CommonName` is now rejected as a host `Set` target, and the issued ACE UID range helper was extended to cover the Opal preconfigured ACE rows used by the test cases.
- Added `spinfo-readonly-doc`: 10 accepted cases.
  - Covers host non-modifiability of SPInfo `UID`, `SPID`, `Name`, `Size`, and `SizeInUse` in both Admin SP and Locking SP preconfigured SPInfo rows.
  - No production solver repair was needed; existing SPInfo `Set` validation already rejected these read-only columns.
- Added `table-descriptor-readonly-doc`: 44 accepted cases.
  - Covers host non-modifiability of issued Table descriptor columns `UID`, `Name`, `CommonName`, `TemplateID`, `Kind`, `Column`, `NumColumns`, `Rows`, `RowsFree`, `RowBytes`, and `LastID` across representative Admin SP and Locking SP table descriptors.
  - No production solver repair was needed; existing issued Table descriptor `Set` validation already rejected these read-only columns.
- Added `sptemplates-readonly-doc`: 16 accepted cases.
  - Covers host non-modifiability of SPTemplates `UID`, `TemplateID`, `Name`, and `Version` in Admin SP Base/Admin and Locking SP Base/Locking template rows.
  - No production solver repair was needed; existing SPTemplates `Set` validation already rejected these read-only columns.
- Added `template-readonly-doc`: 15 accepted cases.
  - Covers host non-modifiability of Admin SP Template `UID`, `Name`, `RevisionNumber`, `Instances`, and `MaxInstances` across Base/Admin/Locking preconfigured template rows.
  - No production solver repair was needed; existing Template `Set` validation already rejected these read-only columns.
- Added `sp-table-readonly-doc`: 14 accepted cases.
  - Covers host non-modifiability of Admin SP SP-table `UID`, `Name`, `ORG`, `EffectiveAuth`, `DateOfIssue`, `Bytes`, and `LifeCycleState` across Admin and Locking SP rows.
  - No production solver repair was needed; `Frozen` is deliberately excluded and remains separately modeled.
- Added `tperinfo-readonly-doc`: 8 accepted cases.
  - Covers host non-modifiability of TPerInfo Core columns `UID`, `Bytes`, `GUDID`, `Generation`, `FirmwareVersion`, `ProtocolVersion`, `SpaceForIssuance`, and `SSC`.
  - No production solver repair was needed; Opal `ProgrammaticResetEnable` column `0x08` is deliberately excluded and remains SID-modifiable.
- Added `methodid-admin-preconfig-doc`: 48 accepted cases.
  - Covers Admin SP MethodID preconfigured names for `Next`, `GetACL`, `Get`, `Set`, `Authenticate`, `Revert`, `Activate`, and `Random`, plus host non-modifiability of issued MethodID `UID`, `Name`, `CommonName`, and `TemplateID`.
  - No production solver repair was needed; the earlier MethodID return-cell and read-only validation generalized to Admin SP rows.
- Added `acl-method-params-doc`: 18 accepted cases.
  - Covers `GetACL`, `AddACE`, `RemoveACE`, and `DeleteMethod` AccessControl meta-method required parameters, AccessControl-table target validation, empty success result shape for mutation/delete meta-methods, and `GetACL` result shape as a list of ACE uidrefs.
  - This batch triggered a solver repair: successful `GetACL` responses now require a UID-list return payload instead of accepting scalar ACE references.
- Added `authenticate-result-doc`: 7 accepted cases.
  - Covers `Authenticate` success-result boolean shape for Password/SID and Anybody authorities: correct SID Proof after a prior C_PIN Set and Anybody UID must return `SUCCESS True`, wrong SID Proof returns `SUCCESS False`, and successful responses cannot omit the required boolean result.
  - This batch triggered solver repairs: `Authenticate` now accepts `Proof` as the password credential input, `Anybody` success requires a true result, known correct Password authentication requires true, and known incorrect Password authentication requires false.
- Added `trylimit-tries-get-doc`: 14 accepted cases.
  - Covers long C_PIN TryLimit/Tries state trajectories where failed `Authenticate`, `TryLimit=0`, successful `Authenticate`, successful PIN `Set`, `PowerCycle`, `HardwareReset`, and `TryLimit` `Set` are observed through later `C_PIN_User1` `Get` return cells.
  - This batch triggered a solver repair: successful C_PIN non-PIN `Get` responses now validate known `TryLimit`, `Tries`, and `Persistence` cells against tracked state instead of accepting any returned value.
- Added `byte-table-descriptor-rows-doc`: 12 accepted cases.
  - Covers Opal Locking SP `Table_MBR` and `Table_DataStore` descriptor `Get` payloads for `Kind=Byte`, MBR/DataStore minimum `Rows`, and composite named/numeric return-cell forms.
  - This batch triggered solver repairs: Table descriptor named-column returns are parsed, and successful descriptor `Get` responses now reject Rows values below the documented minimums.
- Added `byte-table-granularity-doc`: 16 accepted cases.
  - Covers Opal-added Table descriptor granularity columns `0x0D`/`0x0E`, object-table zero granularity, byte-table mandatory/recommended bounds, read-only descriptor cells, and DataStore `Set` alignment after an observed mandatory granularity.
  - This batch triggered solver repairs: byte-table mandatory granularity is recorded from descriptor `Get`, and later byte-table `Set` rejects unaligned start offsets or payload lengths.
- Added `create-table-row-allocation-doc`: 14 accepted cases.
  - Covers `CreateTable` `Rows` result bounds from `MinSize`/`MaxSize`, named and positional result forms, byte-table empty `Columns`, and byte-table `MaxSize`/`HintSize` `INVALID_PARAMETER` failures.
  - This batch triggered solver repairs: successful method results can now be checked by named/positional selectors, `CreateTable` validates `Rows` against `MinSize`/`MaxSize`, and ambiguous object-table `HintSize < MinSize` failure behavior was removed from the trusted corpus.
- Added `create-row-unique-columns-doc`: 10 accepted cases.
  - Covers host-created object table unique-column schemas, duplicate unique combinations, missing/undeclared row-data columns, no-unique duplicate allowance, and exact one-row UID-list result shape.
  - This batch triggered solver repairs: created table schemas and row values are tracked, and `CreateRow` validates declared columns, unique combinations, and UID-list result length.
- Added `table-descriptor-size-set-doc`: 13 accepted cases.
  - Covers created Table descriptor `MinSize`/`MaxSize` `Set` behavior, descriptor-row addressing through `Where`, zero `MaxSize`, lowered `MinSize` rejection, `MaxSize` below `MinSize`/current `Rows`, and size-state carryover after successful `Set` and `CreateRow`.
  - This batch triggered solver repairs: created table descriptor UIDs and size metadata are tracked, descriptor size `Set` updates state, and later `MaxSize` checks use the current row count.
- Added `delete-row-created-table-doc`: 5 accepted cases.
  - Covers created-table `DeleteRow` row lifecycle, unique-value reuse after deleting the matching row, multi-row deletion, and empty success-result shape. An exact omitted-`Rows` status draft was removed after review because only impossible success was sourced.
  - This batch triggered solver repairs: `CreateRow` result UIDs now index tracked created-table row values, and successful `DeleteRow` removes deleted rows from later unique-conflict checks.
- Coverage now references 466 official document sections through 2267 sourced cases, with 2218 consensus-accepted cases in the trusted corpus. The latest MBR/DataStore byte-table batches added method-universe coverage plus direct MBR byte-payload postconditions.

## Existing Sourced Case Review Status

All 2267 sourced cases are visible to `label_consensus.py`, but only cases with three independent agreeing reviews and no concerns are accepted.

- Accepted: 2218
- Quarantined: 49
- Needs review: 0

Notable accepted tags:

| Tag | Accepted | Quarantined |
|---|---:|---:|
| `created-table-deletemethod-tombstone-doc` | 7 | 0 |
| `ace-get-preconfig-cells-doc` | 13 | 3 |
| `admin-revert-sid-doc` | 7 | 0 |
| `advkeymode-doc` | 1 | 0 |
| `ace-issued-readonly-doc` | 30 | 0 |
| `acl-method-params-doc` | 18 | 0 |
| `auth-tries-uses-composite-doc` | 10 | 0 |
| `authenticate-result-doc` | 7 | 0 |
| `authority-issued-readonly-doc` | 21 | 0 |
| `byte-table-descriptor-rows-doc` | 12 | 0 |
| `byte-table-granularity-doc` | 16 | 0 |
| `cpin-charset-doc` | 1 | 0 |
| `cpin-column-types-doc` | 2 | 0 |
| `cpin-genkey-reset-reissue-long-doc` | 52 | 0 |
| `cpin-issued-readonly-doc` | 15 | 0 |
| `create-row-unique-columns-doc` | 10 | 0 |
| `create-table-row-allocation-doc` | 14 | 0 |
| `created-row-accesscontrol-doc` | 10 | 0 |
| `created-row-cleanup-acl-state-doc` | 8 | 0 |
| `created-row-delete-object-acl-doc` | 10 | 0 |
| `created-row-failed-meta-nonmutation-doc` | 9 | 0 |
| `created-row-meta-acl-state-doc` | 12 | 0 |
| `created-row-method-association-doc` | 11 | 0 |
| `created-table-dynamic-getacl-doc` | 10 | 0 |
| `data-removal-doc` | 6 | 0 |
| `data-removal-reserved-doc` | 6 | 0 |
| `datastore-payload-doc` | 6 | 0 |
| `datastore-user-payload-doc` | 8 | 0 |
| `delete-row-created-table-doc` | 5 | 0 |
| `deletesp-lifecycle-doc` | 5 | 0 |
| `genkey-public-exponent-doc` | 2 | 0 |
| `get-cellblock-doc` | 8 | 0 |
| `getacl-global-kaes-exact-acl-doc` | 16 | 0 |
| `kaes-get-doc` | 8 | 0 |
| `locking-composite-get-doc` | 8 | 0 |
| `locking-lockonreset-get-doc` | 8 | 0 |
| `locking-range-get-doc` | 12 | 0 |
| `lockinginfo-readonly-doc` | 6 | 0 |
| `lockonreset-get-doc` | 8 | 0 |
| `log-clear-flush-doc` | 6 | 0 |
| `log-createlog-doc` | 7 | 0 |
| `log-createlog-params-doc` | 4 | 0 |
| `log-entry-readonly-expanded-doc` | 12 | 0 |
| `log-row-readonly-doc` | 2 | 0 |
| `loglist-highsecurity-doc` | 1 | 0 |
| `loglist-initial-row-doc` | 4 | 0 |
| `loglist-readonly-doc` | 2 | 0 |
| `mbrcontrol-defaults-doc` | 8 | 0 |
| `mbrcontrol-readonly-doc` | 1 | 0 |
| `methodid-admin-preconfig-doc` | 48 | 0 |
| `methodid-locking-extra-readonly-doc` | 14 | 0 |
| `methodid-locking-preconfig-doc` | 16 | 0 |
| `meta-acl-doc` | 6 | 0 |
| `meta-acl-empty-doc` | 6 | 0 |
| `meta-acl-locking-status-doc` | 2 | 0 |
| `next-doc` | 6 | 0 |
| `package-doc` | 7 | 0 |
| `random-doc` | 6 | 0 |
| `reencrypt-column-types-doc` | 2 | 0 |
| `reencrypt-state-values-doc` | 2 | 0 |
| `revertsp-lifecycle-doc` | 11 | 0 |
| `secretprotect-doc` | 3 | 0 |
| `set-where-values-doc` | 8 | 0 |
| `sp-table-readonly-doc` | 14 | 0 |
| `spinfo-readonly-doc` | 10 | 0 |
| `sptemplates-readonly-doc` | 16 | 0 |
| `table-descriptor-readonly-doc` | 44 | 0 |
| `table-descriptor-size-set-doc` | 13 | 0 |
| `table-kind-doc` | 8 | 0 |
| `table-lifecycle-doc` | 7 | 0 |
| `table-query-doc` | 7 | 0 |
| `template-readonly-doc` | 15 | 0 |
| `tperinfo-readonly-doc` | 8 | 0 |
| `trylimit-authenticate-result-doc` | 11 | 0 |
| `trylimit-tries-get-doc` | 14 | 0 |

Pending review: none.

Latest accepted batch:

- `syncsession-trans-credit-doc`: 15 sourced cases, all accepted by three independent reviewers with no concerns. This batch validates optional `SyncSession` `TransTimeout` and `InitialCredit` return values against StartSession requests and observed Properties bounds.
- `datastore-byte-table-method-universe-doc`: 20 sourced cases, all accepted by three independent reviewers with no concerns. This batch verifies `DataStore` is a byte table with Get/Set AccessControl associations only; direct `CreateRow`/`DeleteRow` success and meta-method success for `DataStore.CreateRow`/`DataStore.DeleteRow` are impossible.
- `mbr-byte-table-method-universe-doc`: 20 sourced cases, all accepted by three independent reviewers with no concerns. This mirrors the byte-table method-universe check for `MBR`, preventing object-table row-management assumptions from leaking onto the MBR byte table.
- `mbr-byte-payload-doc`: 8 sourced cases, all accepted by three independent reviewers with no concerns. This batch triggered a solver repair: direct MBR byte-table `Get` now validates returned bytes against prior `Set` writes, including nonzero row offsets and omitted-`Where` prefix writes.
- `cpin-genkey-reset-reissue-long-doc`: 52 sourced cases, all accepted by three independent reviewers with no concerns. This batch verifies successful/failed C_PIN `GenKey` behavior across PowerCycle and HardwareReset, old-PIN invalidation, nonpersistent `Tries`, `Authority.Uses`, and explicit PIN reissue by later authorized `Set`.
- `system-table-row-mutation-long-doc`: 8 sourced cases, all accepted by three independent reviewers with no concerns. This batch verifies direct `CreateRow`/`DeleteRow` success is impossible for MethodID and AccessControl system tables in both Admin SP and Locking SP sessions; AccessControl rows must arise from side effects or DeleteMethod, and MethodID rows are not host-created/deleted.
- `datastore-read-window-authority-churn-long-doc`: 33 sourced cases, all accepted by three independent reviewers with no concerns. This batch verifies DataStore read-window behavior under repeated Get/Set ACE replacement: unauthorized byte-table `Get` stays `SUCCESS` with empty results across explicit and omitted-endRow windows, authorized omitted-endRow `Get` is not a short exact read, Set/Get ACEs remain independent, failed unauthorized Admin `Set` calls do not mutate bytes, and later Admins/User1/OR Get ACE changes expose only the currently authorized windows.
- `authenticate-proof-tries-uses-long-doc`: 26 sourced cases, all accepted by three independent reviewers with no concerns. This batch verifies that `Authenticate` `Proof` drives the same C_PIN Tries and Authority Uses state machine as password authentication, including lockout, reset, disabled, and Limit interactions.
- `spinfo-addace-persistence-long-doc`: 21 sourced cases, all accepted by three independent reviewers with no concerns. This batch verifies that `SPInfo/Get` `AddACE` state persists across sessions and failed meta-method attempts, while empty `RemoveACEACL`/`GetACLACL`/`DeleteMethodACL` columns stay empty and non-mutating.
- `locking-toggle-reenable-long-doc`: 34 sourced cases, all accepted by three independent reviewers with no concerns. This batch verifies long Locking enable/disable trajectories: stored locked cells can be changed while ineffective, re-enable makes the current stored value effective, and LockOnReset only locks after a matching reset when the feature is enabled before the reset.
- `cpin-genkey-tries-limit-long-doc`: 26 sourced cases, all accepted by three independent reviewers with no concerns. This batch verifies C_PIN GenKey credential rotation against C_PIN.TryLimit/Tries and Authority.Uses/Limit state: GenKey resets Tries and invalidates the old PIN without consuming an Authority use, and subsequent old-PIN attempts fail through the normal authentication path.
- `created-table-deletemethod-tombstone-doc`: 7 new sourced cases, all accepted by three independent reviewers with no concerns. This batch validates the deleted AccessControl association tombstone behavior after `DeleteMethod`.
- `ace-get-preconfig-cells-doc`: 16 new sourced cases, 13 accepted and 3 quarantined with representation concerns. This batch repairs and verifies ACE `Get` return-cell validation for preconfigured `BooleanExpr`/`Columns` and personalization-aware `BooleanExpr` observations.
- `activekey-advkey-state-doc`: 12 new sourced cases, all accepted by three independent reviewers with no concerns. This batch repairs and verifies Locking `ActiveKey`/`NextKey` postconditions after direct Set and `ADVKEY_req`.
- `getacl-admin-exact-acl-doc`: 16 sourced cases, all accepted by three independent reviewers with no concerns. This batch extends exact GetACL return checking to Admin SP C_PIN, Authority, TPerInfo, and DataRemovalMechanism preconfigured ACL rows.
- `getacl-admin-common-exact-acl-doc`: 30 sourced cases, all accepted by three independent reviewers with no concerns. This batch extends Admin SP exact GetACL return checking to common table/SP rows including `AdminSP.Revert` and `LockingSP.Activate`.
- `level0-range-crossing-locking-doc`: 11 sourced cases, all accepted by three independent reviewers with no concerns. This batch stores the observed Opal SSC V2 `RangeCrossingBehavior` bit and applies it to later unlocked multi-range host I/O.
- `getacl-locking-common-ace-exact-acl-doc`: 46 sourced cases, all accepted by three independent reviewers with no concerns. This batch extends Locking SP exact GetACL return checking to empty-ACL `CommonName` traps, ACE object `Get`/`Set`, Authority, C_PIN, SecretProtect, LockingInfo, and MBR rows.
- `getacl-locking-table-next-exact-acl-doc`: 6 sourced cases, 4 accepted and 2 quarantined. The quarantined pair concerns `LockingTable.Next`; reviewers agreed with labels but recorded that the blind packet source snippet was truncated before the exact Opal row, so those two are retained for evidence-packet rework.
- `locking-failed-set-no-mutation-doc`: 12 sourced cases, all accepted by three independent reviewers with no concerns. This batch checks long Locking trajectories where failed overlap/alignment/duplicate-column Set attempts must not mutate later observable RangeStart, RangeLength, lock-state, or LockOnReset cells.
- `created-table-addace-removeace-state-doc`: 9 sourced cases, 7 accepted and 2 quarantined. Accepted cases cover created-table `GetSetACL` authorization, `AddACE` empty-result shape, duplicate runtime `AddACE` rejection, successful `RemoveACE` clearing a runtime addition, and empty `GetSetACL` `AddACE` denial. The quarantined cases preserve reviewer concerns around numeric ACE alias evidence and failed-method no-mutation inference.
- `created-table-removeace-failure-doc`: 6 sourced cases, 3 accepted and 3 quarantined. Accepted cases cover `RemoveACE` empty-result shape and empty-`GetSetACL` `NOT_AUTHORIZED`; quarantined cases record insufficient evidence for exact nonexistent-ACE status and absent-from-target-ACL semantics.
- `locking-set-state-transition-doc`: 16 sourced cases, 14 accepted and 2 quarantined. Accepted cases cover Set-driven preservation of `Locked` vs `LockOnReset`, disabled lock-feature host I/O behavior, observable stored locked cells after disabling, and a longer independent-field Set sequence. Quarantined cases need clearer reset type evidence for PowerCycle value `[0]`.
- `locking-lifecycle-disabled-frozen-doc`: 32 sourced cases, 26 accepted and 6 quarantined. Accepted cases cover exact `SP_FROZEN` startup failures, exact `SP_DISABLED` disabled-SP method failures, disabled session startup allowance, re-enable `SPInfo.Enabled=True`, `DeleteSP`, and control-session exceptions. Quarantined cases preserve evidence-packet concerns around frozen state observed via `Get`, failure payload shape, and ambiguous already-disabled `Enabled=False` wording.
- `locking-lifecycle-disabled-frozen-clean-doc`: 8 sourced rework cases, 6 accepted and 2 quarantined. Accepted cases keep the same disabled/frozen lifecycle status semantics but avoid unsourced failure payloads; quarantined cases note that `GetFreeRows` success payload content was not independently established.
- `admin-revert-sid-doc`: now 11 sourced cases, 6 accepted and 5 quarantined after re-review. Accepted cases still cover Admin SP `Revert` empty result, read-write requirement, session abort, and behavior `0x00` SID-to-MSID reset. The new behavior `0xFF` cases were label-agreed but quarantined because the exact vendor-unique replacement SID value is not observable in the packet; one older user-data-removal case also moved to quarantine due to a lifecycle-state evidence concern.
- `admin-revert-locking-clean-doc`: 4 sourced rework cases, 3 accepted and 1 quarantined. Accepted cases explicitly observe Locking SP `LifeCycle=Manufactured` after `Activate`, then validate that Admin SP `Revert` returns Locking to Manufactured-Inactive/OFS and reports `LockingEnabled=0`. The quarantined case keeps a reviewer caveat that the cited text proves session refusal but not the exact failure status code.
- `locking-multi-range-reset-clean-doc`: 22 sourced clean cases, 18 accepted and 4 quarantined. The accepted cases repair and verify the stored-cell semantics of `LockOnReset`: matching resets set both stored `ReadLocked` and `WriteLocked` true per row, while enabled columns decide host I/O and Level 0 `Locked`. The quarantined cases are retained for host-write success wording concerns rather than stored-cell disagreement.
- `datastore-failed-mutation-defaults-doc`: 19 sourced cases, all accepted by three independent reviewers with no concerns. This batch verifies DataStore failed-Set non-mutation, no-`Values` Set no-op success, mandatory-granularity failure non-mutation, later aligned overwrites, and the raw byte-table `Get` distinction between explicit `endRow` and omitted `endRow`.
- `trylimit-authenticate-result-doc`: 11 sourced cases, all accepted by three independent reviewers with no concerns. This batch verifies explicit `Authenticate` result-boolean behavior under C_PIN TryLimit lockout, Tries saturation, host Tries reset, and TryLimit zero behavior.
- `created-table-dynamic-getacl-doc`: 10 sourced cases, all accepted by three independent reviewers with no concerns after evidence refresh. This batch verifies that created-table `AddACE`/`RemoveACE` mutations are reflected by later `GetACL`, and records a useful process example where the first review quarantined one numeric uidref case until `opal/4.2.1.6.txt` was added to prove the `ACE_Admin` UID mapping.
- `created-row-accesscontrol-doc`: 10 sourced cases, all accepted by three independent reviewers with no concerns after rework. This batch verifies `CreateRow` row-object AccessControl creation, non-empty `GetACL` uidref payloads, stale-success rejection after `DeleteRow`, sibling-row preservation, and the new strict uidref-list validation that rejects arbitrary strings.
- `created-row-delete-object-acl-doc`: 10 sourced cases, all accepted by three independent reviewers with no concerns. This batch verifies direct `Delete` on a created row object, empty success result shape, stale row `GetACL`/second-delete rejection, sibling preservation, and unique-value release scoped to the deleted row.
- `created-row-meta-acl-state-doc`: 12 sourced cases, all accepted by three independent reviewers with no concerns after rework. This batch verifies created-row `AddACE`/`RemoveACE` state, duplicate/re-add behavior, `DeleteMethod` tombstones, and the new created-row meta-ACL authority tracking.
- `created-row-method-association-doc`: 11 sourced cases, all accepted by three independent reviewers with no concerns. This batch verifies exact row-object method tombstones for `Delete` and `Set`, direct Delete blocking, sibling preservation, and independent method association behavior.
- `created-row-failed-meta-nonmutation-doc`: 9 sourced cases, all accepted by three independent reviewers with no concerns after rework. This batch verifies failed row-object `AddACE`/`RemoveACE`/`DeleteMethod` attempts do not mutate dynamic ACL or tombstone state.
- `created-row-cleanup-acl-state-doc`: 8 sourced cases, all accepted by three independent reviewers with no concerns after rework. This batch verifies row-level dynamic ACL/tombstone cleanup after `DeleteRow` and direct row-object `Delete`, plus sibling isolation.
- `locking-multi-range-long-get-doc`: 20 sourced cases, all accepted by three independent reviewers with no concerns. This batch verifies hidden-score-like long Locking traces across multiple ranges, nonmatching reset preservation, Programmatic-only relocking, manual clearing, disabled read/write enable semantics, and Level 0 `Locked` consistency.
- `datastore-authority-churn-long-doc`: 26 sourced cases, all accepted by three independent reviewers with no concerns. This batch verifies hidden-score-like DataStore payload trajectories across authority replacement, independent Get/Set ACEs, Set-only writes, later Get authorization, failed writes, mandatory granularity, and byte-slice postconditions.

Important:

- Quarantined cases should not be treated as trusted regression data.
- Concerns are preserved in `analysis/label_consensus_report.md`.
- A document is not considered fully handled until it has a concrete pipeline state in `analysis/doc_inventory.jsonl`, not merely because it is absent from coverage.

## Next Best Untouched Slices

1. Remaining ACL/ACE docs
   - Deeper ACE BooleanExpr combinations, deleted association side effects beyond the current DeleteMethod model, missing ACE rows, and exact AddACE/RemoveACE failure conditions where status is sourced.
   - Authentication-state coverage now includes TryLimit explicit `Authenticate` lockout semantics; future auth work should favor less-covered Authority operation/session-key-exchange combinations rather than repeating basic TryLimit flows.

2. Remaining table method docs
   - Broader `Get`, malformed parameters, CreateTable space/row-limit failures, and byte-table payload/provenance semantics. Basic `Set` `Where`/`Values` parameter shape is now covered.

3. Remaining re-encryption/data-removal docs
   - Data removal operation processing/interruption and deeper progress/status cases.

4. Remaining lifecycle/revert docs
   - PSID Revert variants, issued-SP deletion details, and exact post-revert personalization reset behavior where evidence can prove the target assertion.
   - Locking SP Disabled/Frozen basics now have trusted sourced coverage; future lifecycle work should favor deeper revert/delete/freeze interactions and avoid treating quarantined payload-shape cases as trusted.

5. MBR/DataStore byte-table provenance variants
   - DataStore now has accepted payload-provenance and personalized User1 ACE cases.
   - DataStore failed-mutation/default cases now also cover invalid byte-table `Set`, no-op `Set`, mandatory-granularity failures, and raw `Get` `endRow` omission semantics.
   - Important correction: unauthorized DataStore byte-table `Get` is modeled as `SUCCESS` with an empty result list, following `core/5.3.4.2.2`, not as a method-level `NOT_AUTHORIZED`.
   - Keep new payload-specific cases only when the trajectory writes known table bytes first. Avoid exact error-code assertions unless a source maps the status code.

6. Session timeout expiration side effects
   - Bounds are covered; actual timer-expiry session termination remains out of model unless a trajectory event can express elapsed time.
