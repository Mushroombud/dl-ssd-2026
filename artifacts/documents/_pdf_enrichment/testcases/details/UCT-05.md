# UCT-05 Configuring Authorities

The following sections describe the sequences of steps for setting the PIN Credential value for one or more Admin authorities, and enabling and setting the PIN Credential value for multiple User authorities.
- 1) Invoke the StartSession method with SPID = Locking SP UID and HostSigningAuthority = Admin1 authority UID
- 2) SET_PASSWORD_FOR Admin1 to <Admin1_PASSWORD>
- 3) ENABLE User1
- 4) SET_PASSWORD_FOR User1 to <User1_PASSWORD>
- 5) Enable LAST_REQUIRED_USER
- 6) SET_PASSWORD_FOR LAST_REQUIRED_USER to <LAST_REQUIRED_USER_PASSWORD>
- 7) CLOSE_SESSION
- 8) Invoke the StartSession method with SPID = Locking SP UID and HostSigningAuthority = Admin1 authority UID
- 9) CLOSE_SESSION
- 10) Invoke the StartSession method with SPID = Locking SP UID and HostSigningAuthority = User1 authority UID
- 11) CLOSE_SESSION
- 12) Invoke the StartSession method with SPID = Locking SP UID and HostSigningAuthority = LAST_REQUIRED_USER authority UID
- 13) CLOSE_SESSION
