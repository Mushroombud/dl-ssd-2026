# UCT-16 Revert Admin SP using PSID, with Locking SP in Manufactured state

- 1) Opal 2.01
- 2) Opal 2.02
- 3) Opalite 1.00
- 4) Pyrite 2.00
- 5) Pyrite 2.01
- 6) Ruby 1.00 If the PSID Feature Set is implemented this test case also applies to Opal 1.00 and Opal 2.00.
- 1) The PIN column of C_PIN_SID is set to <SID_PASSWORD>
- 2) Locking SP is in the Manufactured state
- 3) For ZNS device, reset Write Pointer
- 1) Write the MAGIC_PATTERN over 64 logical blocks beginning at LBA 0
- 2) For ZNS device, read Write Pointer and Zone State
- 3) Invoke the StartSession method with SPID = Admin SP UID, HostSigningAuthority = PSID authority UID, and HostChallenge = PSID authority’s credential obtained from the VU PSID delivery mechanism
- 4) Invoke the Revert method on Admin SP object
- 5) If the “Behavior of C_PIN_SID Pin upon TPer Revert” from the return of Level 0 Discovery = 0 then
Invoke the StartSession method with SPID = Admin SP UID, HostSigningAuthority = SID authority UID, and HostChallenge = C_PIN_MSID PIN column value
Else Invoke the StartSession method with SPID = Admin SP UID, HostSigningAuthority = SID authority UID, and HostChallenge = C_PIN_SID VU PIN column value
- 6) CLOSE_SESSION
- 7) Invoke the StartSession method with SPID = Locking SP UID
- 8) Read 64 logical blocks beginning at LBA 0
- 9) For ZNS device, read Write Pointer and Zone State
- 1) Steps #1-5 SUCCEED
- 2) The StartSession method in step #7 results in a SyncSession method with a status code of INVALID_PARAMETER
- 3) The Read command in step #8 responds in one of the following ways:
- 4) For ZNS device in step #9, a. If Key Change Zone Behavior bit is set to one, Write Pointer = 0 and Zone State = Empty
b. If Key Change Zone Behavior bit is cleared to zero, Write Pointer and Zone State should be the same as those read in step #2
