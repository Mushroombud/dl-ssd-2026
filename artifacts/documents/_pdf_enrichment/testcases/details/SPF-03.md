# SPF-03 TryLimit

- 1) Invoke the StartSession method with SPID = Locking SP UID and HostSigningAuthority = Admin1 authority UID
- 2) Invoke the Get method on Admin1’s C_PIN Object to retrieve the TryLimit Column’s value
- 3) Invoke the Get method on User1’s C_PIN Object to retrieve the TryLimit Column’s value
- 4) CLOSE_SESSION
- 5) Invoke the StartSession method with SPID = Admin SP UID and HostSigningAuthority = SID authority UID
- 6) Invoke the Get method on SID’s C_PIN Object to retrieve the TryLimit Column’s value
- 7) CLOSE_SESSION
- 8) If SID C_PIN Object has a TryLimit Column value >0, then
- 9) If Admin1 C_PIN Object has a TryLimit Column value >0, then
- a. Invoke the StartSession method with SPID = Locking SP UID, HostSigningAuthority = Admin1 authority UID, and HostChallenge = a value that does not match the current Admin1 C_PIN object’s PIN column value, until Admin1 C_PIN object’s Tries value = Admin1 C_PIN object’s TryLimit value
- b. Invoke the StartSession method with SPID = Locking SP UID and HostSigningAuthority = Admin1 authority UID
Else do not perform this test step and the Test Suite SHALL mark the result of this step as NA
- 10) If User1 C_PIN Object has a TryLimit Column value >0, then
- a. Invoke the StartSession method with SPID = Locking SP UID, HostSigningAuthority = User1 authority UID, and HostChallenge = a value that does not match the current User1 C_PIN object’s PIN column value, until User1 C_PIN object’s Tries value = User1 C_PIN object’s TryLimit value
- b. Invoke the StartSession method with SPID = Locking SP UID and HostSigningAuthority = User1 authority UID
Else do not perform this test step and the Test Suite SHALL mark the result of this step as NA
- 1) Steps #1-7 SUCCEED
- 2) Steps #8-10 FAIL for any Authority with a TryLimit value >0.
- 3) Every StartSession method in steps #8a, #9a, and #10a results in a SyncSession method with a status code of NOT_AUTHORIZED
- 4) The StartSession method with the correct HostChallenge value in steps #8b, #9b, and #10b results in a SyncSession method with a status code of AUTHORITY_LOCKED_OUT
