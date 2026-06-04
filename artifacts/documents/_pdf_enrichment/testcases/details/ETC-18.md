# ETC-18 RevertSP – GlobalRange Locked

- 1) Invoke the StartSession method with SPID = Locking SP UID and HostSigningAuthority = Admin1 authority UID
- 2) Invoke the Set method on GlobalRange with the following conditions: a. ReadLockedEnabled = TRUE b. WriteLockedEnabled = TRUE c. ReadLocked = TRUE d. WriteLocked = TRUE
- 3) Invoke the RevertSP method on the Locking SP with KeepGlobalRangeKey/KeepData = TRUE
- 4) CLOSE_SESSION
- 1) Steps #1-2 SUCCEED
- 2) Step #3 RevertSP method returns a status code of FAIL
- 3) Step #4 SUCCEEDS
- ETC-19: Activate / ATA Security Interaction Notes Start of informative comment See[8] End of informative comment
- ETC-20: StartSession on Inactive Locking SP
1) The StartSession method in step #1 results in a SyncSession method with a status code of INVALID_PARAMETER
