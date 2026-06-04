# ETC-13 Malformed ComPacket Header – Regular Session

This tests a malformed Length field in the ComPacket header whereas TRANSFER LENGTH field in IF-SEND CDB has a correct value. If it is not possible to invoke a Set method that exceeds the TPer’s MaxComPacketSize, then this test cannot be performed and the result should be marked as NA.
- 1) Invoke the Properties method to identify the MaxComPacketSize
- 2) Invoke the StartSession method with SPID = Locking SP UID and HostSigningAuthority = Admin1 authority UID
- 3) This test step varies based on SSC version:
- 4) Issue IF-RECV
Steps #1-2 SUCCEED The IF_SEND in step #3: a. SUCCEEDS; or b. FAILS with a result of “Invalid Transfer Length parameter on IF-SEND” The IF-RECV in step #4 returns a ComPacket header with a value of “All Response(s) returned - no further data” (See [1]), or returns a ComPacket with a CloseSession method.
