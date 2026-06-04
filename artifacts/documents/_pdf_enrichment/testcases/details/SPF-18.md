# SPF-18 Range Crossing Behavior

Start of informative comment Test that the range crossing behavior is as specified by the returned value for range crossing. Determine support for feature via Level 0 Discovery. End of informative comment
- 1) Opal 1.00
- 2) Opal 2.00
- 3) Opal 2.01
- 4) Opal 2.02
- 5) All other SSCs supported by this specification, if Locking_Range1 is implemented
- 1) Locking_Range1 length is non-zero and does not span the entire SD
- 2) Locking_GlobalRange and Locking_Range1 are unlocked
- 1) Issue a Write command with the MAGIC_PATTERN, with a beginning LBA in Locking_Range1 and ending LBA in Locking_GlobalRange. For ZNS device, if Zone Capacity is less than Zone Size, skip this step.
- 2) Issue a Read command, with a beginning LBA in Locking_Range1 and ending LBA in Locking_GlobalRange. For ZNS device, if Read Across Zone Boundaries is cleared to zero, skip this step.
- 1) If Range Crossing is supported and if step #1 or #2 is not skipped, then steps #1-2 SUCCEED
- 2) If Range Crossing is not supported and if step #1 or #2 is not skipped, then steps #1-2 FAIL. The Write command in step #1 and the Read command in step #2 return Other Invalid Command Parameter
