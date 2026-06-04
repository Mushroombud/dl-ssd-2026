# ETC-22 Multiple Sessions

Start of informative comment There are two tests performed regarding multiple sessions: Case 1 attempts to start two Read-Write sessions with the Locking SP Case 2 attempts to start MaxSessions + 1 Read-Only sessions with the Locking SP End of informative comment
2) Invoke the StartSession method with SPID = Locking SP UID and Write = TRUE 3) Invoke the StartSession method with SPID = Locking SP UID and Write = TRUE
- 1) Step #1-2 SUCCEEDS
- 2) The StartSession method in step #3 results in a SyncSession method with a status code of: a) If MaxSessions = 1: SP_BUSY or NO_SESSIONS_AVAILABLE b) If MaxSession <> 1: SP_BUSY
- 1) Invoke the Properties method to identify the MaxSessions and MaxReadSessions. If MaxSessions = 0 or MaxReadSessions = 0 or MaxReadSessions is omitted, do not perform this test and the Test Suite SHALL mark the result as NA
- 2) Invoke the StartSession method with SPID = Locking SP UID and Write = FALSE up to the lesser of MaxSessions or MaxReadSessions
- 3) Invoke the StartSession method with SPID = Locking SP UID and Write = FALSE
- 1) Step #1 SUCCEEDS
- 2) Every StartSession method invoked in step #2 results in a SyncSession method with a status code of SUCCESS
- 3) The StartSession method in step #3 results in a SyncSession method with a status code of NO_SESSIONS_AVAILABLE
