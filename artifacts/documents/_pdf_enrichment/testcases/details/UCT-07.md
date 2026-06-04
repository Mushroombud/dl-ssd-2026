# UCT-07 Unlocking Ranges

- 1) Invoke the StartSession method with SPID = Locking SP UID and HostSigningAuthority = User1 authority UID
- 2) Invoke the Set method on the ReadLocked and WriteLocked columns of the LAST_REQUIRED_RANGE Locking object with a value of FALSE
- 3) CLOSE_SESSION
- 4) This test step varies based on the SSC version:
- a. For Opal, Read the entire LAST_REQUIRED_RANGE
- b. For all SSCs supported by this specification other than Opal, Read an ARBITRARILY_VARYING_LBA_RANGE
