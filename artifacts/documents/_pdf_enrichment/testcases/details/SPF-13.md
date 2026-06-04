# SPF-13 Authenticate

This test case only applies to the following SSCs:
- 1) Opal 2.00
- 2) Opal 2.01
- 3) Opal 2.02
- 4) Opalite 1.00
- 5) Pyrite 1.00
- 6) Pyrite 2.00
- 7) Pyrite 2.01
- 8) Ruby 1.00
- 1) Invoke the StartSession method with SPID = Admin SP UID
- 2) Invoke the Authenticate method with Authority = SID Authority UID and Proof = C_PIN_SID PIN column value
- 3) Invoke the Get method on UID Column of SID C_PIN
- 4) CLOSE_SESSION
- 1) Steps #1-4 SUCCEED
- 2) The Get method in step #3 returns the C_PIN_SID PIN object’s UID column value
- SPF-14: Session Abort (Deprecated) This test case has been removed due to similar functionality being tested elsewhere. This section MAY be removed in a future version of this specification.
- SPF-15: Random Notes Start of informative comment This test is not intended to guarantee the quality of the RNG. End of informative comment
- SPF-16: CommonName
This test case only applies to the following SSCs:
- 1) Admin1 is enabled
- 2) The values returned from the Get methods in steps #4-5 are the same as the values previously Set in steps #23
