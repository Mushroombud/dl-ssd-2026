# SPF-09 Range Alignment Verification

This test case only applies to Opal 2.00, 2.01 and 2.02, and Ruby 1.00 if the AlignmentRequired column value in the LockingInfo table = TRUE.
1) Confirm the AlignmentRequired column value in the LockingInfo table = TRUE. If AlignmentRequired = FALSE do not perform the test and the Test Suite SHALL mark the result as NA.
- 1) Invoke the StartSession method with SPID = Locking SP UID and HostSigningAuthority = Admin1 authority UID
- 2) Invoke the Get method on the LockingInfo table to retrieve the LogicalBlockSize, AlignmentGranularity and LowestAlignedLBA column values
- 3) If AlignmentGranularity is > 1, then invoke the Set method on RangeLength and RangeStart columns with RangeStart and RangeLength values satisfying the conditions:
- 1) If AlignmentGranularity is = 1 then mark the test NA
- 2) If AlignmentGranularity is > 1, steps #1-4 SUCCEED
