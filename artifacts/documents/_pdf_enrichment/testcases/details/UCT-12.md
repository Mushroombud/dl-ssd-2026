# UCT-12 Revert the Locking SP using SID, with Locking SP in Manufactured state

- 1) Write the MAGIC_PATTERN over 64 logical blocks beginning at LBA 0
- 2) For ZNS device, read Write Pointer and Zone State
- 3) Invoke the StartSession method with SPID = Admin SP UID and HostSigningAuthority = SID authority UID
- 4) Invoke the Revert method on Locking SP object
- 5) CLOSE_SESSION
- 6) Invoke the StartSession method with SPID = Locking SP UID
- 7) This test step varies based on the SSC version:
- 8) For ZNS device, read Write Pointer and Zone State
- 1) Steps #1-5 SUCCEED
- 2) The StartSession method in step #5 results in a SyncSession method with a status code of INVALID_PARAMETER
- 3) For all SSCs supported by this specification other than Pyrite 1.00, the Read command in step #6 responds in one of the following ways:
- 4) For ZNS device in step #8,
- a) If Key Change Zone Behavior bit is set to one, Write Pointer = 0 and Zone State = Empty; or
- b) If Key Change Zone Behavior bit is cleared to zero, Write Pointer and Zone State should be kept same as the ones read in step #2.
