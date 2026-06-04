# ETC-02 General – IF-SEND/IF-RECV Synchronous Protocol

#### ETC-02: General – IF-SEND/IF-RECV Synchronous Protocol
- 1) Invoke the Properties method within an IF-SEND using a valid ComID and do not retrieve the response with an IF-RECV
- 2) Invoke the Properties method using the ComID from the previous step
- 1) Step #1 SUCCEEDS
- 2) Step #2 FAILS. The IF-SEND command returns Synchronous Protocol Violation error
- ETC-03: Invalid IF-SEND Transfer Length Notes Start of informative comment None End of informative comment
- ETC-04: Invalid SessionID - Regular Session
- 1) Invoke the StartSession method with SPID = Admin SP UID
- 2) Invoke the Get method on MSID’s credential object in C_PIN table with a Packet SessionID value <> the current SessionID value
- 3) CLOSE_SESSION
- 1) Steps #1-3 SUCCEED
- 2) IF-RECV in step #2 has a ComPacket header value of “All Response(s) returned - no further data”, (See [1])
