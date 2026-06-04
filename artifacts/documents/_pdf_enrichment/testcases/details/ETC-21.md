# ETC-21 StartSession with Incorrect HostChallenge Notes Start of informative comment None End of informative comment

#### ETC-21: StartSession with Incorrect HostChallenge Notes Start of informative comment None End of informative comment
1) The C_PIN credential associated with Admin1 has a TryLimit column value of 0; or a Tries column value < the TryLimit column value
1) Invoke the StartSession method with SPID = Locking SP UID, HostSigningAuthority = Admin1 authority UID, and HostChallenge = a value that is different from the C_PIN_Admin1 PIN column value
The StartSession method in step #1 results in a SyncSession method with a status code of NOT_AUTHORIZED
