# SPF-01 Transaction

- 1. Case 1 attempts to write an entire table with the MAGIC_PATTERN.
- 2. Case 2 attempts to write an entire table with 0s, and then close the session without committing the Transaction.
In most cases, the MBR table is used for these tests but for SSCs where the MBR shadowing feature is optional, the MBR table is only used when the MBR shadowing feature is supported, otherwise the DataStore table is used.
Since Session Timeout is VU, test results may be NA if session timeout occurs or if the transaction cannot be committed.
- 1) For Opal 1.00, 2.00, 2.01 and 2.02, and Opalite 1.00, knowledge of the MBR table size
- 2) For Opal 2.00, 2.01 and 2.02, and Opalite 1.00, knowledge of the MandatoryWriteGranularity Column value for the MBR table
- 3) For Pyrite 1.00, 2.00 and 2.01, and Ruby 1.00, if the MBR Shadowing feature is supported, then knowledge of the MBR table size, otherwise knowledge of the DataStore table size
- 4) For Pyrite 1.00, 2.00 and 2.01, and Ruby 1.00, if the MBR Shadowing feature is supported, then knowledge of the MandatoryWriteGranularity Column value for the MBR table, otherwise knowledge of the MandatoryWriteGranularity Column value for the DataStore table
- 1) Invoke the StartSession method with SPID = Locking SP UID and HostSigningAuthority = Admin1 authority UID
- 2) This test step varies based on SSC version:
- 3) CLOSE_SESSION if the write is successful, or if the session aborts due to a timeout, exit the test and record result as NA
- 4) Invoke the StartSession method with SPID = Locking SP UID and HostSigningAuthority = Admin1 authority UID
- 5) Send a subpacket that contains a StartTransaction token with a status code of 0x00
- 6) This test step varies based on SSC version:
- 7) Send a subpacket that contains an End Transaction token with a status code of 0x00
- 8) CLOSE_SESSION if the SD responds with an End Transaction token with a status code of 0x00, or if the session aborts due to a timeout exit the test and record result as NA
- 9) Invoke the StartSession method with SPID = Locking SP UID and HostSigningAuthority = Admin1 authority UID
- 10) This test step varies based on SSC version:
- a. For Opal 1.00, 2.00, 2.01 and 2.02, and Opalite1.00, invoke the Get method on the MBR table to read the data from the table
- b. For Pyrite 1.00, 2.00 and 2.01, and Ruby 1.00, if the MBR Shadowing feature is supported, invoke the Get method on the MBR table to read the data from the table
- c. For Pyrite 1.00, 2.00 and 2.01, and Ruby 1.00, if the MBR Shadowing feature is not supported, invoke the Get method on the DataStore table to read the data from the table
- 1) Steps #1-11 SUCCEED
- 2) The Get in step #10 returns the MAGIC_PATTERN
- 3) If the session is aborted on step #3 or step #8, the result of this test is NA
- 1) Invoke the StartSession method with SPID = Locking SP UID and HostSigningAuthority = Admin1 authority UID
- 2) Send a subpacket that contains a StartTransaction token with a status code of 0x00
- 3) This test step varies based on SSC version:
- 4) CLOSE_SESSION if the write is successful, or if the session aborts due to a timeout exit the test and record result as NA
- 5) Invoke the StartSession method with SPID = Locking SP UID and HostSigningAuthority = Admin1 authority UID
- 6) This test step varies based on SSC version:
- 7) CLOSE_SESSION
- 2) The Get method in step #6 returns the MAGIC_PATTERN
- 3) If the session is aborted on step #4, the result of this test is NA
