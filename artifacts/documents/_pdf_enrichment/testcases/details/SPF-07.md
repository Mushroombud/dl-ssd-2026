# SPF-07 Host Session Number (HSN)

Test the Host Session Number to verify that the SD responses with the corresponding Host Session Number provided by the host.
- 1) Invoke the StartSession method with HostSessionID = ARBITRARILY_VARYING HSN, SPID = Admin SP UID, and HostSigningAuthority = SID authority UID
- 2) Invoke the Get method on MSID C_PIN credential’s PIN Column
- 3) CLOSE_SESSION
- 1) Steps #1-3 SUCCEED
- 2) The StartSession method in step #1 results in a SyncSession method with the same HSN as parameterized in the StartSession method
- 3) The Packet received in step #2 that contains the Get method response has the same HSN as parameterized in the StartSession method
