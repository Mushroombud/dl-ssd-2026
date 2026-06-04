# UCT-04 Activate Locking SP when in Manufactured-Inactive State

#### UCT-04: Activate Locking SP when in Manufactured-Inactive State
- 1) Invoke the StartSession method with SPID = Admin SP UID and HostSigningAuthority = SID authority UID
- 2) Invoke the Activate method on Locking SP object
- 3) CLOSE_SESSION
- 4) Invoke the StartSession method with SPID = Locking SP UID and HostSigningAuthority = Admin1 authority UID
- 5) CLOSE_SESSION
