# ETC-07 Unexpected Token Outside of Method – Control Session

- 1) Invoke the StartSession method with SPID = Locking SP UID and an EndList Token before the Call Token
- 2) Invoke the StartSession method with SPID = Locking SP UID
- 1) IF-RECV in step #1 has a ComPacket header value of “All Response(s) returned - no further data”, (See [1])
- 2) Steps #2 SUCCEEDS
- ETC-08: Unexpected Token in the Method Parameter List – Control Session Notes Start of informative comment This test verifies the condition corresponding to [1], Section 3.2.2.4.2 items 1 and 4. The reason for the expected response #1a of “All Response(s) returned - no further data” is the description in [1], Section 3.3.7.1.5: “The Host or TPer is free at any time to end a session in which it is participating, but only the host SHALL end the session successfully.” End of informative comment
- ETC-09: Exceeding Transaction Limit
- 1) Invoke the Properties method to identify MaxTransactionLimit
- 2) Invoke the StartSession method with SPID = Locking SP UID and HostSigningAuthority = Admin1 authority UID
- 3) Send a subpacket that contains MaxTransactionLimit + 1 StartTransaction Tokens
- 4) Invoke the StartSession method with SPID = Locking SP UID and HostSigningAuthority = Admin1 authority UID
- 1) Steps #1-2 SUCCEED
- 2) IF-RECV in step #3 has a ComPacket header value of “All Response(s) returned - no further data” (See [1]), or returns a ComPacket with a CloseSession method.
- 3) Steps #4-5 SUCCEED
