# SPF-05 Tries Reset on Power Cycle

Start of informative comment The following test verifies that the value of Tries is reset upon power cycle. End of informative comment
- 1) Invoke the StartSession method with SPID = Admin SP UID and HostSigningAuthority = SID authority UID.
- 2) Invoke the Get method on SID’s C_PIN Object to retrieve the TryLimit Column’s value
- 3) CLOSE_SESSION
- 4) Invoke the StartSession method with SPID = Locking SP UID and HostSigningAuthority = Admin1 authority UID
- 5) Invoke the Get method on Admin1’s C_PIN Object to retrieve the TryLimit Column’s value
- 6) Invoke the Get method on User1’s C_PIN Object to retrieve the TryLimit Column’s value
- 7) CLOSE_SESSION
- 8) If SID C_PIN Object has a TryLimit Column value >0, then
- 9) If Admin1 C_PIN Object has a TryLimit Column value >0, then
- 10) If User1 C_PIN Object has a TryLimit Column value >0, then
- 11) Power cycle the SD
- 12) If SID C_PIN Object has a TryLimit Column value >0, then
- 13) If Admin1 C_PIN Object has a TryLimit Column value >0, then
- a. Invoke the StartSession method with SPID = Locking SP UID and HostSigningAuthority = Admin1 authority UID
- b. Invoke the Get method on Admin1 Authority’s C_PIN Tries Column
- c. CLOSE_SESSION
- 14) If User1 C_PIN Object has a TryLimit Column value >0, then
- a. Invoke the StartSession method with SPID = Locking SP UID and HostSigningAuthority = Admin1 authority UID
- b. Invoke the Get method on User1 Authority’s C_PIN Tries Column
- c. CLOSE_SESSION
- 1) Steps #1-7 and steps #11-14 SUCCEED
- 2) Every StartSession method in steps #8, #9, and #10 results in a SyncSession method with a status code of NOT_AUTHORIZED
- 3) For test step #12, if SID C_PIN TryLimit Column value > 0, then a. Admin SP session opens successfully b. The Get method on SID Authority’s C_PIN Tries Column returns 0
- 4) For test step #13, if Admin1 C_PIN TryLimit Column value > 0, then a. Locking SP session opens successfully b. The Get method on Admin1 Authority’s C_PIN Tries Column returns 0
- 5) For test step #14, if User1 C_PIN TryLimit Column value > 0, then a. Locking SP session opens successfully b. The Get method on User1 Authority’s C_PIN Tries Column returns 0
