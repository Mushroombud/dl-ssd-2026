# UCT-15 Revert Admin SP using Admin1, with Locking SP in Manufactured state

This test case applies to Opal 2.00, 2.01 and 2.02 with no exceptions. This test case only applies to all other SSCs supported by this specification if the Admin1 authority in the Authority table of the AdminSP is implemented.
- 1) Locking SP is in the Manufactured state
- 2) Admin1 authority is enabled
- 3) For ZNS device, reset Write Pointer
- 1) Write the MAGIC_PATTERN over 64 logical blocks beginning at LBA 0
- 2) For ZNS device, read Write Pointer and Zone State
- 3) Invoke the StartSession method with SPID = Admin SP UID and HostSigningAuthority = Admin1 authority UID
- 4) Invoke the Revert method on Admin SP object
- 5) If the “Behavior of C_PIN_SID Pin upon TPer Revert” from the return of Level 0 Discovery = 0 then
- 6) CLOSE_SESSION
- 7) Invoke the StartSession method with SPID = Locking SP UID
- 8) Read 64 logical blocks beginning at LBA 0
- 9) For ZNS device, read Write Pointer and Zone State
- 1) Steps #1-6 SUCCEED
- 2) The StartSession method in step #6 results in a SyncSession method with a status code of INVALID_PARAMETER
- 3) For all SSCs supported by this specification other than Pyrite 1.00, the Read command in step #8 responds in one of the following ways:
- a. The Read command fails without returning data;
- b. The Read command fails and returns data that does not match the MAGIC_PATTERN; or
- c. The Read command succeeds and returns data that does not match the MAGIC_PATTERN
- a. If Key Change Zone Behavior bit is set to one, Write Pointer = 0 and Zone State = Empty; or
- b. If Key Change Zone Behavior bit is cleared to zero, Write Pointer and Zone State should be kept same as the one read in step #2
