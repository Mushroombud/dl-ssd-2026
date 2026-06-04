# UCT-01 Level 0 Discovery

This test includes the sequence of operations required to determine if the SD supports any SSC supported by this specification.
1) Issue an IF-RECV Level 0 Discovery with the following conditions:
- a. Security Protocol = 1
- b. Security Protocol Specific = 0x0001
- c. Transfer Length is a value large enough to retrieve the entire response data of Level 0 Discovery
- 1) Step #1 SUCCEEDS
- 2) The SD returns the following values for Level 0 Discovery:
- i. Feature Code = 0x0002
- ii. For Opal 1.00, Opal 2.00, Opal 2.01, Opal 2.02, Opalite 1.00, and Ruby 1.00, Media Encryption = 1
- iii. For Pyrite 1.00, Pyrite 2.00 and Pyrite 2.01, Media Encryption = 0
- iv. Locking Supported = 1
- 3) The SD returns the following values for Opal 1.00: a. Opal 1.00 Feature
- 4) The SD returns the following values for Opal 2.00, 2.01 or 2.02:
- 5) The SD returns the following values for Opalite 1.00:
- 6) The SD returns the following values for Pyrite 1.00:
- 7) The SD returns the following values for Pyrite 2.00:
- 8) The SD returns the following values for Ruby 1.00:
