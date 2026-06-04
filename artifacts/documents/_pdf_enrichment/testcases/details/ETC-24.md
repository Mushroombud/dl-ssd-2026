# ETC-24 Read Locked and Write Locked Error Responses

#### ETC-24: Read Locked and Write Locked Error Responses
1) Opal 1.00 2) Opal 2.00 3) Opal 2.01 4) Opal 2.02 5) All other SSCs supported by this specification, if Locking_Range1 is implemented
- 1) Locking_GlobalRange ReadLockEnabled, WriteLockEnabled, ReadLocked and WriteLocked column values = TRUE
- 2) If non-Global Locking Range objects are implemented, then all non-Global Locking Range objects ReadLockEnabled, WriteLockEnabled, ReadLocked and WriteLocked column values = FALSE and RangeStart and RangeLength columns values = 0
- 3) For Pyrite 1.00, 2.00 and 2.01, and Ruby 1.00, if the MBR Shadowing feature is supported, then the Enable column value of the MBRControl table = FALSE
- 4) For Opal 1.00, 2.00, 2.01 and 2.02, and Opalite 1.00, the Enable column value of the MBRControl table = FALSE
The Read command and the Write command (as identified by [2]) issued in this test sequence are the commands that are supported by the SD and by the Test Suite. The LBA range of the Read command and the Write command is defined in the ARBITRARILY_VARYING_LBA_RANGE. If other parameters are required for a supported command, use ARBITRARILY_VARYING_COMMAND_PARAMETERS. Refer to section 3.6.
- 1) Invoke the StartSession method with SPID = Locking SP UID and HostSigningAuthority = Admin1 authority UID
- 2) Invoke the Set method on Locking_Range1. Configure the locking range as follows: a. RangeStart = 0 b. RangeLength = 1024
- 3) Invoke the Set method to configure Locking_Range1 ReadLockEnabled and WriteLockEnabled column values
- 4) Issue a Read command in Locking_Range1
- 5) Issue a Write command in Locking_Range1
- 6) Invoke the Set method to configure Locking_Range1 ReadLockEnabled and WriteLockEnabled column values
- 7) Issue a Read command in Locking_Range1
- 8) Issue a Write command in Locking_Range1
- 9) Invoke the Set method to configure Locking_Range1 ReadLockEnabled and WriteLockEnabled column values
- 10) Issue a Read command in Locking_Range1
- 11) Issue a Write command in Locking_Range1
- 1) Steps #1-3 SUCCEED
- 2) The commands issued in Step #4 SUCCEED. The commands issued in Step #5 FAIL
- 3) Step #6 SUCCEEDs
- 4) The commands issued in Step #7 FAIL. The commands issued in Step #8 SUCCEED
- 5) Step #9 SUCCEEDs
- 6) The commands issued in Step #10 and Step #11 all FAIL
- 7) For all supported Write commands in step #5, #8, and #11 and all supported Read commands in step #4, #7, and #10, the SD SHALL: a. For Read command, transfer no data b. Return a Data Protection Error, (See [2])
