# ETC-14 Exceed TPer Properties – Regular Session

This test verifies the condition corresponding to [1], Section 5.2.2.4.1.1. The reason for the expected response #1a of “All Response(s) returned - no further data” is the description in [1], Section 3.3.7.1.5: “The Host or TPer is free at any time to end a session in which it is participating, but only the host SHALL end the session successfully.”
- 1) Invoke the Properties method to identify the MaxSubPackets
- 2) Invoke the StartSession method with SPID = Locking SP UID and HostSigningAuthority = Admin1 authority UID
- 3) Send a packet with MaxSubPackets +1 SubPackets. Each SubPacket contains an invocation of the Set method on the DataStore table
- 4) Invoke the StartSession method with SPID = Locking SP UID and HostSigningAuthority = Admin1 authority UID
- 5) CLOSE_SESSION
- 1) Steps #1-2 SUCCEED
- 2) IF-RECV in step #3 has a ComPacket header value of “All Response(s) returned - no further data” (See [1]), or returns a ComPacket with a CloseSession method.
- 3) Steps #4-5 SUCCEED
- ETC-15: Exceed TPer Properties – Control Session Notes Start of informative comment Tests for MaxSubPackets exceeded. End of informative comment
- ETC-16: Overlapping Locking Ranges
- 1) Opal 1.00, 2.00 and 2.01
- 2) All other SSCs supported by this specification, if the MaxRanges column value in the LockingInfo table is > 1
- 1) Invoke the StartSession method with SPID = Locking SP UID and HostSigningAuthority = Admin1 authority UID
- 2) Invoke the Set method on Locking_Range1. Configure the locking range as follows: a. RangeStart = 0 b. RangeLength = 64
- 3) Invoke the Set method on Locking_Range2. Configure the locking range as follows: a. RangeStart = 0 b. RangeLength = 64
- 4) CLOSE_SESSION
- 1) Steps #1-2 SUCCEED
- 2) The Set method in step #3 returns a status code of INVALID_PARAMETER
- 3) Step #4 SUCCEEDS
