# ETC-01 Native Protocol Read/Write Locked Error Responses

#### ETC-01: Native Protocol Read/Write Locked Error Responses
- 1) Locking_GlobalRange ReadLockEnabled, WriteLockEnabled, ReadLocked and WriteLocked column values = TRUE
- 2) If non-Global Locking Range objects are implemented, then all non-Global Locking Range objects ReadLockEnabled, WriteLockEnabled, ReadLocked and WriteLocked column values = FALSE and RangeStart and RangeLength columns values = 0
- 3) For Pyrite 1.00, 2.00 and 2.01, and Ruby 1.00, if the MBR Shadowing feature is supported, then the Enable column value of the MBRControl table = FALSE
- 4) For Opal 1.00, 2.00, 2.01 and 2.02, and Opalite 1.00, the Enable column value of the MBRControl table = FALSE
- 1) Issue each of the Write commands (as identified by [2]) that are supported by the SD and the Test Suite. If an LBA range is required for a supported command, write to an ARBITRARILY_VARYING_LBA_RANGE. If other parameters are required for a supported command, use ARBITRARILY_VARYING_COMMAND_PARAMETERS. Refer to section 3.6
- 2) Issue each of the Read commands (as identified by [2]) that are supported by the SD and the Test Suite. If an LBA range is required for a supported command, read from an ARBITRARILY_VARYING_LBA_RANGE. If other parameters are required for a supported command, use ARBITRARILY_VARYING_COMMAND_PARAMETERS. Refer to section 3.6
- 1) Each of the issued commands in Steps #1-2 FAIL
- 2) For all supported Write commands in step #1 and all supported Read commands in step #2, the SD SHALL:
- a. Transfer no data
- b. Return a Data Protection Error, (See [2])
