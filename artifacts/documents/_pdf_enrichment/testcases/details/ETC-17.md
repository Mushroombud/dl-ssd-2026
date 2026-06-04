# ETC-17 Invalid Type

- 1) Invoke the StartSession method with SPID = Locking SP UID and HostSigningAuthority = Admin1 authority UID
- 2) Invoke the Set method on the Enabled column of the User1 Authority to value of 0xAAAA
- 3) CLOSE_SESSION
- 1) Steps #1 SUCCEEDS
- 2) The Set method in step #2 returns a status code of INVALID_PARAMETER
- 3) Step #3 SUCCEEDS
