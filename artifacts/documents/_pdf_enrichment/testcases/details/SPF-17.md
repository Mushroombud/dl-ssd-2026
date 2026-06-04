# SPF-17 Additional DataStore Tables

Only one of the following tests is performed based on the value of the Maximum Number of DataStore tables field in the DataStore table Feature Descriptor.
- 4) All other SSCs supported by this specification, if the Additional DataStore Tables Feature Set is implemented
- 1) In the DataStore table Feature Descriptor, the Maximum Number of DataStore Tables field value = 1
- 2) Locking SP is in the Manufacture-Inactive State
- 1) Issue Level 0 Discovery command to retrieve the DataStore Table Size Alignment field
- 2) Invoke the StartSession method with SPID = Admin SP UID and HostSigningAuthority = SID authority UID
- 3) Invoke the Activate method on the Locking SP with a DataStoreTableSize parameter value = the value of the DataStore Table Size Alignment field of the Level 0 Discovery Feature Descriptor
- 4) CLOSE_SESSION
- 5) Invoke the StartSession method with SPID = Locking SP UID and HostSigningAuthority = Admin1 authority UID
- 6) Invoke the Get method to retrieve the DataStore table’s Rows column value from the Table table
- 7) CLOSE_SESSION
- 2) The Get method in step #6 returns a value = the DataStoreTableSize parameter value in step #3
1) Opal 2.00 2) Opal 2.01 3) Opal 2.02 4) All other SSCs supported by this specification, if the Additional DataStore Tables Feature Set is implemented
- 1) In the DataStore Table Feature Descriptor, the Maximum Number of DataStore tables field value > 1
- 2) Locking SP is in the Manufactured-Inactive State
- 2) Invoke the StartSession method with SPID = Admin SP UID and HostSigningAuthority = SID authority UID
- 3) Invoke the Activate method with a DataStoreTableSize parameter value containing a number of items = the Maximum Number of DataStore Tables field, with values = the value of the DataStore Table Size Alignment field of the Level 0 Discovery Feature Descriptor
- 4) CLOSE_SESSION
- 5) Invoke the StartSession method with SPID = Locking SP UID and HostSigningAuthority = Admin1 authority UID
- 6) Invoke the Get method to retrieve each DataStore table’s Rows column value from the Table table
- 7) CLOSE_SESSION
- 1) Steps #1-5 SUCCEED
- 2) For each DataStore table, the Get method in step #6 returns a value = the DataStoreTableSize parameter value in step #3
