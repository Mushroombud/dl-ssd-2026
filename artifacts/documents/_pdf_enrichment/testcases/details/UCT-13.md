# UCT-13 Revert the Admin SP using SID, with Locking SP in ManufacturedInactive state

- 1) Write the MAGIC_PATTERN over 64 logical blocks beginning at LBA 0
- 2) For ZNS device, read Write Pointer and Zone State
- 3) Invoke the StartSession method with SPID = Admin SP UID and HostSigningAuthority = SID authority UID
- 4) Invoke the Revert method on Admin SP object
- 5) If the “Behavior of C_PIN_SID Pin upon TPer Revert” from the return of Level 0 Discovery = 0 then
- 6) CLOSE_SESSION
- 7) Invoke the StartSession method with SPID = Locking SP
- 8) Read 64 logical blocks beginning at LBA 0
- 9) For ZNS device, read Write Pointer and Zone State
- 2) The StartSession method in step #7 results in a SyncSession method with a status code of INVALID_PARAMETER
- 3) The Read command in step #8 returns data that matches the MAGIC_PATTERN
- 4) For ZNS device in step #9, Write Pointer and Zone State should be the same as those read in step #2
