# UCT-09 Using the DataStore Table

- 1) Invoke the StartSession method with SPID = Locking SP UID and HostSigningAuthority = Admin1 authority UID
- 2) Invoke the Set method on the BooleanExpr column of the ACE_DataStore_Set_All ACE object to include the UID of the User1 Authority object
- 3) Invoke the Set method on the BooleanExpr column of the ACE_DataStore_Get_All ACE object to include the UID of the User1 Authority object
- 4) CLOSE_SESSION
- 5) Invoke the StartSession method with SPID = Locking SP UID and HostSigningAuthority = User1 authority UID
- 6) Invoke the Set method to write the entire DataStore table with the MAGIC_PATTERN
- 7) CLOSE_SESSION
- 8) Invoke the StartSession method with SPID = Locking SP UID and HostSigningAuthority = User1 authority UID
- 9) Invoke the Get method on the DataStore table to read the data of the DataStore table
- 10) CLOSE_SESSION
- 1) Steps #1-10 SUCCEED
- 2) The Get method in step #9 returns the MAGIC_PATTERN
