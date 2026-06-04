# SPF-06 Next

Start of informative comment Testing of the Next method to verify that the method works correctly in multiple conditions. This test contains two different tests, but only one test is required per SSC, as specified by the SSC applicability section of each test. End of informative comment
- 1) Invoke the StartSession method with SPID = Locking SP UID
- 2) Invoke the Get method on the LockingInfo table’s MaxRanges Column
- 3) Invoke the Next method on the Locking table with an empty parameter list
- 4) Invoke the Next method on the Locking table with the Where parameter set to the first UID from the list of UIDs returned in step #3, and the Count parameter set to 1
- 5) CLOSE_SESSION
- 1) Steps #1-5 SUCCEED
- 2) Step #3 a. returns a list of UIDs where the number of values = the MaxRanges value + 1, and b. the first four bytes of each UID returned are 0x00000802
- 3) Step #4 returns a list that contains only the UID that was second in the list of UIDs returned in Step #3
- 1) Invoke the StartSession method with SPID = Locking SP UID
- 2) Invoke the Next method on the MethodID table with an empty parameter list
- 3) Invoke the Next method on the MethodID table with the Where parameter set to the first UID from the list of UIDs returned in step #3 and the Count parameter set to 1
- 4) CLOSE_SESSION
- 1) Steps #1-4 SUCCEED
- 2) Step #2 a. returns a list of UIDs where the number of values >= 7, and b. the first four bytes of each UID returned are 0x00000006
- 3) Step #3 returns a list that contains only the second UID from the list of UIDs returned in Step #2
