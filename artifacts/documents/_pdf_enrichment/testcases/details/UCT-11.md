# UCT-11 MBR Done

This test case applies to all SSCs supported by this specification with the following exception for Pyrite 1.00, Pyrite 2.00, and Ruby 1.00:
This test case only applies to Pyrite 1.00, 2.00, 2.01 and Ruby 1.00 if the MBR Shadowing feature is supported.
- 1) Invoke the StartSession method with SPID = Locking SP UID and HostSigningAuthority = LAST_REQUIRED_USER authority UID
- 2) Invoke the Set method on the ReadLocked and WriteLocked columns of the LAST_REQUIRED_RANGE Locking object with a value of FALSE
- 3) Invoke the Set method on the Done column of the MBRControl table with a value of TRUE
- 4) CLOSE_SESSION
- 5) This test step varies based on SSC version: a. For Opal, Read the entire LAST_REQUIRED_RANGE
b. For all SSCs supported by this specification other than Opal, Read the entire range from LBA 0 to SIZE_OF_MBR_TABLE_DESCRIPTOR_IN_LOGICAL_BLOCKS + 10
- 1) Steps #1-5 SUCCEED
- 2) The value returned from the Read command in step #5 = 1s
