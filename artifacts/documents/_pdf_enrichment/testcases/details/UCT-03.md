# UCT-03 Taking Ownership of an SD

The following test is to establish that an SD can be controlled by host software. Taking ownership is a key step in managing an SD.
- 1) If Opal 1.00; or if any other SSC supported by this specification and the Initial C_PIN_SID PIN Indicator value = 0, then
- a. Invoke the StartSession method with SPID = Admin SP UID
- b. Invoke the Get method to retrieve MSID’s PIN column value from the C_PIN table
- c. CLOSE_SESSION
- d. Invoke the StartSession method with SPID = Admin SP UID and HostSigningAuthority = SID authority UID
- e. SET_PASSWORD_FOR SID to <SID_PASSWORD>
- f. CLOSE_SESSION
- 2) If any SSC supported by this specification other than Opal 1.00 and the Initial C_PIN_SID PIN Indicator value <> 0, then obtain SID VU PIN value from the SD vendor
- 3) If Opal 2.00, 2.01 or 2.02
- a. Invoke the StartSession method with SPID = Admin SP UID, HostSigningAuthority = SID authority UID, and HostChallenge = <SID_PASSWORD>
- b. SET_PASSWORD_FOR Admin1 to <AdminSP_Admin1_ PASSWORD>
- c. ENABLE Admin1
- d. CLOSE_SESSION
- If Opal 1.00, or if any other SSC supported by this specification and the Initial C_PIN_SID PIN Indicator value =
- If Opal 2.00, 2.01 or 2.02 then step #3 SUCCEEDS
