# UCT-14 Revert the Admin SP using SID, with Locking SP in Manufactured state

- 1) SID’s PIN column value is set to <SID_PASSWORD> value in the SID’s C_PIN credential PIN column
- 2) Locking SP is in the Manufactured state
- 3) Determining support for the Revert feature: a. Invoke the StartSession method with SPID = Admin SP UID b. Invoke the Get method on UID 00 00 00 06 00 00 02 02 to determine support
- 4) For ZNS device, reset Write Pointer
- 1) Write the MAGIC_PATTERN over 64 logical blocks beginning at LBA 0
- 2) For ZNS device, read Write Pointer and Zone State
- 3) Invoke the StartSession method with SPID = Admin SP UID and HostSigningAuthority = SID authority UID
- 4) Invoke the Revert method on Admin SP object
- 5) If the “Behavior of C_PIN_SID Pin upon TPer Revert” from the return of Level 0 Discovery = 0 then
- 6) CLOSE_SESSION
- 7) Invoke the StartSession method with SPID = Locking SP UID
- 8) Read 64 logical blocks beginning at LBA 0
- 9) For ZNS device, read Write Pointer and Zone State
- 1) Steps #1-6 SUCCEED
- 2) The StartSession method in step #6 results in a SyncSession method with a status code of INVALID_PARAMETER
- 3) For all SSCs supported by this specification other than Pyrite 1.00, The Read command in step #8 responds in one of the following ways:
- 4) For ZNS device in step #9, a. If Key Change Zone Behavior bit is set to one, Write Pointer = 0 and Zone State = Empty; or
b. If Key Change Zone Behavior bit is cleared to zero, Write Pointer and Zone State should be the same as those read in step #2
