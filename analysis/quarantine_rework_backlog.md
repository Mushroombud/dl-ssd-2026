# Quarantine Rework Backlog

Quarantine is not a trash bin. It is the list of candidate edge cases that are not trusted enough to enter the regression corpus yet.

The rework loop is:

1. Read `analysis/quarantined_sourced_cases.json`.
2. Group cases by failure reason.
3. Decide whether the case can be regenerated with stronger evidence, narrower assertion, or cross-document support.
4. Add a new sourced case only if the ambiguity is removed.
5. Keep the old quarantined case as history; do not silently promote it.
6. Run three fresh blind reviewers on the regenerated case.

Current state from `python3 tools/label_consensus.py report`:

- Total quarantined: 16
- `locking-doc`: 5
- `mbr-doc`: 1
- `mbr-table-doc`: 2
- `reset-doc`: 2
- `genkey-doc`: 2
- `addace-acl-state-doc`: 1
- `created-table-delete-acl-doc`: 1
- `datastore-sparse-fill-doc`: 2

Resolved rework:

- `auth-missing-doc`: initial no-authority Authenticate candidates had one reviewer concern because the Awaiting Challenge state was implicit. Reworked candidates now include a preceding successful `Authenticate(Anybody)` step and passed three fresh reviewers with no concerns.
- `mbr-table-doc`: the old payload-provenance concern was reworked by writing known bytes to the MBR table before enabling shadowing. Four reworked cases passed independent consensus. Two adjacent assertions stayed quarantined because they still required stronger evidence.
- `locking-host-io-impossible-doc`: earlier `locking-doc` exact-status cases were regenerated as impossible-`SUCCESS` cases with explicit MBRControl inactive context. Four regenerated cases passed independent consensus with no concerns.
- `genkey-reencrypt-state-doc`: earlier `genkey-doc` raw-column ReEncryptState cases were regenerated with symbolic `ReEncryptState` values and explicit `core/5.7.2.2.13` evidence. Five regenerated impossible-`SUCCESS` cases passed independent consensus with no concerns.

## Rework Groups

### Q1. Locking Data Protection Error Status

Cases:

- `locking-doc-b851c105a8`
- `locking-doc-d50b5ce5c2`
- `locking-doc-0a2dedce7e`
- `locking-doc-da4c2809f3`
- `locking-doc-baeee0d5e5`

Problem:

- The source says Data Protection Error, but the packet used `INVALID_PARAMETER` as the concrete status.
- One reviewer also wanted explicit MBRControl state for some read-lock cases.

Rework strategy:

- Do not create exact-status PASS cases unless a source maps Data Protection Error to the concrete status code.
- Prefer `SUCCESS` impossible FAIL cases where the document only proves that normal success is not allowed.
- Add explicit MBRControl Enable/Done context when the rule depends on the MBR rows.

### Q2. MBR Table Payload Provenance

Case:

- `mbr-doc-6de85002a7`

Problem:

- The packet did not prove the exact MBR table bytes, so reviewers could not trust a payload-specific FAIL.

Rework strategy:

- First write known bytes into the MBR table or use a documented default payload.
- Then make the read assertion about those exact bytes.
- If exact bytes cannot be proven, only assert non-user-data behavior, not a concrete payload.

Partial rework result:

- `mbr-table-doc` now contains accepted active-shadowing exact-payload cases where the trajectory first writes known MBR bytes.
- The original quarantined case remains as history and should not be promoted silently.
- Avoid future post-`Done=true` exact-payload assertions unless the trajectory and source prove the underlying media source.

### Q3. LockOnReset Reset-Type Evidence

Cases:

- `reset-doc-a3a6b1f205`
- `reset-doc-38a4d44f44`

Problem:

- The packet did not prove reset type value `0` maps to `PowerCycle`.
- The exact locked-write failure status was not independently proven.

Rework strategy:

- Use a named reset helper or add source evidence that decodes the reset type.
- Avoid exact locked-write status unless a source proves it.
- Prefer impossible-success assertions for locked writes after reset.

### Q4. GenKey ReEncryptState Evidence

Cases:

- `genkey-doc-b719388487`
- `genkey-doc-4df1b343af`

Problem:

- The packet used raw `Locking` column `12` and numeric state value `2` without source evidence that decodes them.

Rework strategy:

- Regenerate with `core/5.7.2.2.13.txt` as evidence for `ReEncryptState`.
- Use symbolic state values such as `PENDING`, not raw numeric `2`, in the trajectory.
- Prefer an impossible-success assertion unless the source proves the exact error status.

Rework result:

- Added `genkey-reencrypt-state-doc` with five accepted impossible-`SUCCESS` cases.
- Covered `PENDING`, `ACTIVE`, `COMPLETED`, and `PAUSED` for `K_AES_256_Range1_Key.GenKey`, plus global `PENDING` for `K_AES_256_GlobalRange_Key.GenKey`.
- Three independent reviewers accepted all five with no concerns.
- The original two `genkey-doc` cases remain quarantined as historical records and are not part of the trusted corpus.

### Q5. MBR Table Adjacent Exactness

Cases:

- `mbr-table-doc-16a62ffe0e`
- `mbr-table-doc-f330655a4b`

Problem:

- Reviewers agreed with the labels but recorded concerns, so the cases are not trusted.
- The `Done=true` case proves shadowing is inactive, but one reviewer noted the snippets do not explicitly prove the exact post-Done read source.
- The unauthenticated MBR `Set` correct-status case proves `SUCCESS` is not allowed, but one reviewer noted the snippet does not map the failure to the exact `NOT_AUTHORIZED` status.

Rework strategy:

- Keep `mbr-table-doc-d746e634fa` as the trusted impossible-success unauthenticated `Set` case.
- Rework the `Done=true` payload case only if the packet adds a stronger source/table row that proves ordinary user-media readback after inactive shadowing.
- Rework exact unauthenticated status only if a source maps the access-control failure to `NOT_AUTHORIZED`; otherwise use only impossible-success assertions.

### Q6. AddACE Arbitrary Nonexistent ACE UID

Case:

- `addace-acl-state-doc` arbitrary UID `0000000800FFFFFF`

Problem:

- Reviewers agreed with the intended FAIL label but two recorded concerns.
- The packet proves the Admin SP preconfigured ACE rows used by the case, but does not fully prove that no vendor extension ACE row could ever use the arbitrary UID.

Rework strategy:

- Keep the trusted accepted `AddACE` duplicate/existing-ACE cases.
- Avoid arbitrary nonexistent UID assertions unless the packet includes a stronger source that bounds the full ACE table namespace.
- Prefer duplicate-ACE assertions because they depend only on the target ACL state, not on global nonexistence of a vendor extension row.

### Q7. Created Table Name Reuse After Descriptor Deletion

Case:

- `created-table-delete-acl-doc-e1be4004ed`

Problem:

- Reviewers agreed with the PASS label but two recorded concerns.
- The packet proves that deleting a Table descriptor deletes the table, descriptor, and associated AccessControl rows, but it does not explicitly state the policy for reusing the same `NewTableName`/`CommonName` afterward.
- The intended label relies on the inference that uniqueness is checked against rows currently present in the Table table.

Rework strategy:

- Do not treat the current case as trusted regression data.
- Rework only if the packet can cite the Name/CommonName uniqueness rule and enough deletion semantics to prove the prior descriptor row is no longer present in the Table table.
- Keep the accepted AccessControl deletion side-effect cases from the same batch; those do not depend on name reuse.

### Q8. DataStore Sparse Fill After Get ACE Personalization

Case:

- `datastore-sparse-fill-doc-25d98e253f`
- `datastore-sparse-fill-doc-1f3d6b78ca`

Problem:

- Reviewers disagreed on whether Admin remains authorized after `ACE_DataStore_Get_All` is personalized to User1.
- Two reviewers applied ACE replacement semantics: the final Admin-session byte-table Get is unauthorized and should return `SUCCESS` with an empty result list.
- One reviewer focused on the later Admin `Set` filling the sparse gap and treated the final Admin `Get` as authorized.

Rework strategy:

- Do not treat the current case as trusted regression data.
- Prefer the accepted `datastore-ace-replacement-doc` batch for the replacement rule.
- Prefer the accepted `datastore-sparse-rework-doc` batch for sparse-fill payload checks with explicit final authority.
- Keep the eight accepted sparse-fill cases; they cover row-order payload reconstruction, partial overwrite, Set-only User mutation, and unauthorized Set non-mutation without the disputed final Admin read.

Rework result:

- Added `datastore-ace-replacement-doc` with 8 accepted cases and no reviewer concerns.
- Added `datastore-sparse-rework-doc` with 4 accepted cases and no reviewer concerns.
- Fixed the solver so DataStore Get/Set no longer hard-code Admin authorization after a DataStore ACE BooleanExpr has been personalized.
