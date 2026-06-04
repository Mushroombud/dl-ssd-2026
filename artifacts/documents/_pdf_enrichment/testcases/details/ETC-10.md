# ETC-10 Invalid Invoking ID - Get

The LockingInfo table is a single row table. The UID used in the following test refers to row 5, a nonexistent row of the LockingInfo table.
Unless otherwise noted in a method's description, this status code (NOT_AUTHORIZED) SHALL be returned whenever there is no row in the AccessControl table to represent the InvokingID/MethodID combination, or when there is a row but the ACL for the InvokingID/MethodID combination has not been satisfied.
- 1) Invoke the StartSession method with SPID = Locking SP UID and HostSigningAuthority = Admin1 authority UID
- 2) Invoke the Get method on Invoking UID of 00 00 08 01 AA BB CC DD
- 3) CLOSE_SESSION
Step #1 SUCCEEDS The Get method in step #2 returns a status code of NOT_AUTHORIZED Step #3 SUCCEEDS
This test validates correct behavior when the Get method is invoked on a Byte table and the authority does not have access to retrieve contents from the byte table.
This test case tests the following requirement from [1]: If the currently authenticated authorities do not satisfy the access control restrictions for invoking the Get method on a byte table, the method SHALL return an empty results list. End of informative comment
- 1) Invoke the StartSession method with SPID = Locking SP UID and HostSigningAuthority = Anybody authority UID
- 2) Invoke the Get method on Invoking UID of 00 00 10 01 00 00 00 00 (DataStore table)
- 3) CLOSE_SESSION
Steps #1 SUCCEEDS The Get method in step #2 returns a status code of NOT_AUTHORIZED or SUCCESS and an empty results list Step #3 SUCCEEDS
This test validates correct behavior when the Get method is invoked on an Object table and the authority does not have access to retrieve contents from the Object table.
This test case tests the following requirement from [1]: When the Get method is invoked on a table or object, only the values that are readable based on currently authenticated authorities and their associated ACE restrictions for the method SHALL be returned.
Cell values that have been requested but are not permitted to be read by the currently authenticated authorities are not returned. Since the return value of the method for non-byte tables is a list of namevalue pairs, cells to which the host invoking the Get method does not have access are omitted from the return result. If a column is known to exist but not returned with a value, then the host is able to discern that it did not have permission to invoke the Get method on that cell. It is not an error to request columns that are not permitted to be retrieved.
- 1) Invoke the StartSession method with SPID = Locking SP UID and HostSigningAuthority = Admin1 authority UID
- 2) Invoke the Get method on the InvokingID 00 00 00 0B 00 01 00 01 (C_PIN_Admin1) to get the PIN, CharSet, TryLimit, and Tries columns.
- 3) CLOSE_SESSION
Steps #1 SUCCEEDS The Get method in step #2 returns a status code of SUCCESS and only returns the CharSet, TryLimit, and Tries column values. Step #3 SUCCEEDS
Start of informative comment This test validates correct behavior when the Get method is invoked on a non-table UID. This test case is similar to Test Case 1, but instead this test case tests with a valid InvokingUID but there is no row in the ACL table that matches the InvokingID/MethodID combination. This test case tests the following requirement from [1]:
“Unless otherwise noted in a method's description, this status code (NOT_AUTHORIZED) SHALL be returned whenever there is no row in the AccessControl table to represent the InvokingID/MethodID combination, or when there is a row but the ACL for the InvokingID/MethodID combination has not been satisfied.”
- 1) Invoke the StartSession method with SPID = Locking SP UID and HostSigningAuthority = Anybody authority UID
- 2) Invoke the Get method on the InvokingID 00 00 00 00 00 00 00 01 (ThisSP)
- 3) CLOSE_SESSION
Steps #1 SUCCEEDS The Get method in step #2 returns a status code of NOT_AUTHORIZED and an empty results list Step #3 SUCCEEDS
- ETC-11: Invalid Invoking ID – Non-Get Notes Start of informative comment The LockingInfo table is a single row table. The UID used in the following test refers to row 5, a non-existing row of the LockingInfo table. This test uses Set method to represent all non-Get methods. End of informative comment
- ETC-12: Authorization
- 1) Invoke the StartSession method with SPID = Locking SP UID
- 2) Invoke the Set method on the Enabled column of the User1 Authority
- 3) CLOSE_SESSION
- 1) Steps #1 SUCCEEDS
- 2) The Set method in step #2 returns a status code of NOT_AUTHORIZED
- 3) Step #3 SUCCEEDS
