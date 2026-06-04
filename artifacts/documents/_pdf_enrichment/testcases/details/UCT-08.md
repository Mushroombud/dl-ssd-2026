# UCT-08 Erasing Ranges

- 1) This test step varies based on the SSC version:
- 2) Invoke the StartSession method with SPID = Locking SP UID and HostSigningAuthority = Admin1 authority UID
- 3) Invoke the Get method on the LAST_REQUIRED_RANGE to retrieve the ActiveKey column’s value
- 4) Invoke the GenKey method on the UID retrieved from the LAST_REQUIRED_RANGE’s ActiveKey column
- 5) CLOSE_SESSION
- 6) This test step varies based on the SSC version: a. For Opal, attempt to read the entire LAST_REQUIRED_RANGE
b. For all SSCs supported by this specification other than Opal, attempt to read the entire ARBITRARILY_VARYING_LBA_RANGE that was written to in test step #1
- 1) Steps #1-5 SUCCEED
- 2) The Read command in step #6 responds in one of the following ways:
- a. The Read command fails without returning data;
- b. The Read command fails and returns data that does not match the MAGIC_PATTERN; or
- c. The Read command succeeds and returns data that does not match the MAGIC_PATTERN
