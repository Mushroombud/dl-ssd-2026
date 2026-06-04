# SPF-08 RevertSP

See [2] for support requirements on RevertSP and KeepGlobalRangeKey/KeepData. There are three tests in this test case. Each must be performed.
- 1) Write the MAGIC_PATTERN over 64 logical blocks beginning at LBA 0
- 2) Invoke the StartSession method with SPID = Locking SP UID and HostSigningAuthority = Admin1 authority UID
- 3) Invoke the RevertSP method with the KeepGlobalRangeKey/KeepData omitted
- 4) Invoke the StartSession method with SPID = Locking SP UID
- 5) This test step varies based on the SSC version: a. For all SSCs supported by this specification other than Pyrite 1.00, read 64 logical blocks beginning at LBA 0 b. For Pyrite 1.00, do nothing for this step
- 1) Steps #1-3 SUCCEED
- 2) The StartSession method in step #4 results in a SyncSession method with a status code of INVALID_PARAMETER
- 3) For all SSCs supported by this specification other than Pyrite 1.00, the Read command in step #5 responds in one of the following ways:
a. The Read command fails without returning data; b. The Read command fails and returns data that does not match the MAGIC_PATTERN; or c. The Read command succeeds and returns data that does not match the MAGIC_PATTERN
- 1) Write the MAGIC_PATTERN over 64 logical blocks beginning at LBA 0
- 2) Invoke the StartSession method with SPID = Locking SP UID and HostSigningAuthority = Admin1 authority UID
- 3) Invoke the RevertSP method with the KeepGlobalRangeKey/KeepData present and set to FALSE
- 4) Invoke the StartSession method with SPID = Locking SP UID
- 5) Read 64 logical blocks beginning at LBA 0
- 1) Steps #1-3 SUCCEED
- 2) The StartSession method in step #4 results in a SyncSession method with a status code of INVALID_PARAMETER
- 3) The Read command in step #5 responds in one of the following ways: a. The Read command fails without returning data; b. The Read command fails and returns data that does not match the MAGIC_PATTERN; or c. The Read command succeeds and returns data that does not match the MAGIC_PATTERN
- 1) Locking_GlobalRange ReadLockEnabled, WriteLockEnabled, ReadLocked and WriteLocked column values = FALSE
- 2) If non-Global Locking Range objects are implemented, then all non-Global Locking Range objects’ ReadLockEnabled, WriteLockEnabled, ReadLocked and WriteLocked column values = FALSE and RangeStart and RangeLength columns = 0
- 1) Write the MAGIC_PATTERN over 64 logical blocks beginning at LBA 0
- 2) Invoke the StartSession method with SPID = Locking SP UID and HostSigningAuthority = Admin1 authority UID
- 3) Invoke the RevertSP method with the KeepGlobalRangeKey/KeepData present and set to TRUE
- 4) Invoke the StartSession method with SPID = Locking SP UID
- 5) Read 64 logical blocks beginning at LBA 0
- 1) Steps #1-3 SUCCEED
- 2) The StartSession method in step #4 results in a SyncSession method with a status code of INVALID_PARAMETER
- 3) The Read command in step #5 returns data that matches the MAGIC_PATTERN
