# UCT-06 Configuring Locking Objects (Locking Ranges)

- 1) Invoke the StartSession method with SPID = Locking SP UID and HostSigningAuthority = Admin1 authority UID
- 2) This test step varies based on the SSC version:
- a. For Opal, invoke the Set method on LAST_REQUIRED_RANGE. Configure the locking range as follows:
- b. For all SSCs supported by this specification other than Opal, invoke the Set method on Locking_GlobalRange. Configure the locking range as follows:
- i. ReadLockEnabled = TRUE
- ii. WriteLockEnabled = TRUE
- iii. ReadLocked = FALSE
- iv. WriteLocked = FALSE
- v. LockOnReset = {0}
- 3) Invoke the Set method on the BooleanExpr column of the LAST_REQUIRED_RANGE_RDLOCKED_ACE ACE object to set the UIDs of the User1 and LAST_REQUIRED_USER Authority objects
- 4) Invoke the Set method on the BooleanExpr column of the LAST_REQUIRED_RANGE_WRLOCKED_ACE ACE object to set the UIDs of the User1 and LAST_REQUIRED_USER Authority objects
- 5) CLOSE_SESSION
- 6) This test step varies based on the SSC version:
- 7) This test step varies based on the SSC version:
- 8) Power cycle the SD
- 9) This test step varies based on the SSC version:
- 10) This test step varies based on the SSC version: a. For Opal, Write the MAGIC_PATTERN over the entire LAST_REQUIRED_RANGE
b. For all SSCs supported by this specification other than Opal, Write the MAGIC_PATTERN over an ARBITRARILY_VARYING_LBA_RANGE
- 1) Steps #1-8 SUCCEED
- 2) The value returned from the Read command in step #7 is the MAGIC_PATTERN
- 3) Steps #9-10 return Data Protection Error
