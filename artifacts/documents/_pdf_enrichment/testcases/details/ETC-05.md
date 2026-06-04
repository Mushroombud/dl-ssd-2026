# ETC-05 Unexpected Token Outside of Method – Regular Session Notes Start of informative comment

- This test verifies the condition corresponding to [1], Section 3.2.2.4.2 item 2. The reason for the expected response #2 of “All Response(s) returned - no further data” is that the device is in the “Awaiting IF_SEND” state, see [1], Section 3.3.10.5 End of informative comment
- This test verifies the condition corresponding to [1], Section 3.2.2.4.2 item 3.
- 1) Invoke the StartSession method with SPID = Locking SP UID and HostSigningAuthority = Admin1 authority UID
- 2) Invoke the Set method on the Enabled Column of User1 Authority with a value of FALSE and an EndList Token immediately after the Call Token
- 3) CLOSE_SESSION
- 1) Step #1 SUCCEEDS
- 2) Step #2 Set method returns NOT_AUTHORIZED, or returns a ComPacket with a CloseSession method.
- 3) Step #3 SUCCEEDS if step #2 returns NOT_AUTHORIZED
