# ETC-23 Data Removal Mechanism – Set Unsupported Value

Test the Set method on the ActiveDataRemovalMechanism column in the Data Removal Mechanism table with an invalid value to make sure a proper error is returned
- 1) Pyrite 2.00
- 2) Pyrite 2.01
- 3) All other SSCs supported by this specification, if the Data Removal Mechanism feature is implemented
1) If DUT is other than Opal 2.02, knowledge of supported Data Removal Mechanisms from Supported Data Removal Mechanisms Feature Descriptor in Level 0 Discovery
- 1) Invoke the StartSession method with SPID = Admin SP UID and HostSigningAuthority = SID authority UID
- 2) Invoke the Set method on the ActiveDataRemovalMechanism column of the DataRemovalMechanism table,
- 3) CLOSE_SESSION
- 1) Steps #1-3 SUCCEED
- 2) The Set method in Step #2 returns INVALID_PARAMETER
