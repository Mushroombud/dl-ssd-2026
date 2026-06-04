# UCT-10 Enable MBR Shadowing

This test case applies to all SSCs supported by this specification with the following exception for Pyrite 1.00, 2.00 and 2.01, and Ruby 1.00:
This test case only applies to Pyrite 1.00, 2.00 and 2.01, and Ruby 1.00 if the MBR Shadowing feature is supported.
- 1) Invoke the StartSession method with SPID = Locking SP UID and HostSigningAuthority = Admin1 authority UID
- 2) Invoke the Set method on the BooleanExpr column of the ACE_MBRCONTROL_SET_DONE ACE object to include the UIDs of the User1 and LAST_REQUIRED_USER Authority objects
- 3) Invoke the Get method on the Rows column of the MBR Table Descriptor Object
- 4) This test step varies based on the SSC version:
- 5) This test step varies based on the SSC version:
- a. For Opal, write 1s over the entire LAST_REQUIRED_RANGE
- b. For all SSCs supported by this specification other than Opal, write 1s over the range from LBA 0 to SIZE_OF_MBR_TABLE_DESCRIPTOR_IN_LOGICAL_BLOCKS + 10
- 6) This test step varies based on the SSC version: a. For Opal 1.00 invoke the Set method to write the entire MBR table with the MAGIC_PATTERN
- 7) Invoke the Set method on the Enable column of the MBRControl table with a value of TRUE
- 8) CLOSE_SESSION
- 9) Power cycle the SD
- 10) This test step varies based on the SSC version: a. For Opal, Write the MAGIC_PATTERN over the entire LAST_REQUIRED_RANGE
- 11) Read from LBA 0 to the size of the MBR Table
- 12) This test step varies based on the SSC version: a. For Opal 1.00 Read 10 LBAs starting immediately following the end of the MBR
b. For all SSCs supported by this specification other than Opal 1.00, Read 10 LBAs or an appropriate value adhering to the Range Alignment requirements, starting immediately following the end of the MBR Shadowing
- 1) Steps #1-9 SUCCEED
- 2) Step #10 returns Data Protection Error
- 3) The value returned from the Read command in step #11 matches the MAGIC_PATTERN
- 4) The value returned from the Read command in step #12 = 0s
