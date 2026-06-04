# SPF-04 Tries Reset

Start of informative comment The following test verifies that the value of Tries is reset upon successful authentication. End of informative comment
- 1) If Persistence=FALSE, continue; if Persistence=TRUE, exit the test sequence
- 2) Invoke the StartSession method with SPID = Admin SP UID and HostSigningAuthority = SID authority UID
- 3) Invoke the Get method on SID’s C_PIN Object to retrieve the TryLimit Column’s value
- 4) CLOSE_SESSION
- 5) Invoke the StartSession method with SPID = Locking SP UID and HostSigningAuthority = Admin1 authority UID
- 6) Invoke the Get method on Admin1’s C_PIN Object to retrieve the TryLimit Column’s value
- 7) Invoke the Get method on User1’s C_PIN Object to retrieve the TryLimit Column’s value
- 8) CLOSE_SESSION
- 9) If SID C_PIN Object has a TryLimit Column value > 1, then
- 10) If Admin1 C_PIN Object has a TryLimit Column value > 1, then
- 11) If User1 C_PIN Object has a TryLimit Column value >1, then
- a. Invoke the StartSession method with SPID = Locking SP UID, HostSigningAuthority = User1 authority UID, and HostChallenge = a value that does not match the current User1 C_PIN object’s PIN column value, until User1 C_PIN object’s Tries value = User1 C_PIN object’s TryLimit value -1
- b. Invoke the StartSession method with SPID = Locking SP UID and HostSigningAuthority = User1 authority UID.
- c. CLOSE_SESSION
- d. Invoke the StartSession method with SPID = Locking SP UID and HostSigningAuthority = Admin1 authority UID
- e. Invoke the Get method on the Tries Column of the User1 Authority’s C_PIN Object
- f. CLOSE_SESSION
- 1) Step #1, FAIL if Persistence=TRUE
- 2) Steps #2-11 SUCCEED
- 3) For each Authority with a TryLimit column value > 1, that Authority’s C_PIN Tries column value = 0 on steps #8c, #9c, and #10e
