# SPF-02 IF-RECV Behavior Tests

Start of informative comment There are two tests performed relating to IF-RECV Behavior:
- Case 1 attempts to issue an IF-RECV command while the SD is in an Awaiting IF-SEND state
- Case 2 attempts to issue an IF-RECV command with an Insufficient Transfer Length End of informative comment
- 1) Steps #1 SUCCEEDS
- 2) IF-RECV in step #1 has a ComPacket header value of “All Response(s) returned - no further data”, (See [1])
- 1) Invoke the StartSession method with SPID = Locking SP UID and HostSigningAuthority = Admin1 authority UID
- 2) Invoke the Get method on the DataStore table to retrieve 1024 Rows. For the IF-RECV command issued by the Host to retrieve the result, the IF-RECV command has a transfer length of 1
- 3) Issue IF-RECV command to retrieve the result with the transfer length based on the MinTransfer value in the IFRECV response to step #2
- 4) CLOSE_SESSION
- 1) Step #1-4 SUCCEED
- 2) IF-RECV in step #2 has a ComPacket header value of “Response ready, insufficient transfer length request”, see [1]
