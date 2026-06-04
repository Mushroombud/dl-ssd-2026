# SPF-20 Data Removal Mechanism Start of informative comment

Test the Set method and the Get method on the ActiveDataRemovalMechanism column in the Data Removal Mechanism table to make sure this table is functional
- 1) Pyrite 2.00
- 2) Pyrite 2.01
- 3) Opal 2.02
- 4) All other SSCs supported by this specification, if the Data Removal Mechanism feature is implemented
1) If DUT is other than Opal v2.02, knowledge of supported Data Removal Mechanisms from Supported Data Removal Mechanisms Feature Descriptor in Level 0 Discovery
- 1) Invoke the StartSession method with SPID = Admin SP UID and HostSigningAuthority = SID authority UID.
- 2) Invoke the Get method on the ActiveDataRemovalMechanism column of the DataRemovalMechanism table
- 3) Invoke the Set method on the ActiveDataRemovalMechanism column of the DataRemovalMechanism table,
- 4) CLOSE_SESSION
- 5) Invoke the StartSession method with SPID = Admin SP UID and HostSigningAuthority = Anybody authority UID.
- 6) Invoke the Get method on the ActiveDataRemovalMechanism column of the DataRemovalMechanism table
- 7) CLOSE_SESSION
- 1) Steps #1-7 SUCCEED
- 2) The value returned from the Get method in Step #2 matches is equal to one of the bits set in the Supported Data Removal Mechanisms returned in Level 0 Discovery
- 3) The value returned from the Get method in Step #6 matches the value that was set in Step #3
