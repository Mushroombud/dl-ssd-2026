# Public Dataset Profile

Generated with:

```bash
PYTHONDONTWRITEBYTECODE=1 python -B -m src.ssd_verifier.dataset_scan dataset/testcases --labels dataset/label.jsonl --top-k 30
```

```text
total trajectories: 20
label distribution: {'pass': 10, 'fail': 10}

method distribution:
- StartSession: 109
- EndSession: 93
- Get: 68
- Set: 34
- Activate: 12
- GenKey: 4
- Read: 4
- Properties: 2
- Write: 2

object distribution:
- SessionManager: 111
- tcg_method: 93
- LockingSP: 23
- C_PIN_MSID: 18
- C_PIN_SID: 18
- MBRControl: 16
- Locking_GlobalRange: 12
- LockingInfo: 10
- Locking_Range1: 10
- host_io: 6
- Authority_User1: 4
- K_AES_256_Range1_Key: 4
- C_PIN_User1: 2
- UnknownSP_0000010500000004: 1

status distribution:
- SUCCESS: 315
- None: 6
- INVALID_PARAMETER: 3
- NOT_AUTHORIZED: 3
- FAIL: 1

target distribution:
- StartSession / SessionManager / pass: 4
- StartSession / SessionManager / fail: 3
- Properties / SessionManager / pass: 1
- Get / C_PIN_MSID / pass: 1
- Set / Authority_User1 / pass: 1
- Get / Locking_GlobalRange / pass: 1
- Get / MBRControl / pass: 1
- Read / host_io / pass: 1
- Properties / SessionManager / fail: 1
- Get / C_PIN_MSID / fail: 1
- Activate / UnknownSP_0000010500000004 / fail: 1
- Set / Authority_User1 / fail: 1
- Get / Locking_GlobalRange / fail: 1
- Get / MBRControl / fail: 1
- Read / host_io / fail: 1

target status distribution:
- SUCCESS: 11
- INVALID_PARAMETER: 3
- NOT_AUTHORIZED: 3
- None: 2
- FAIL: 1

Set object/column distribution:
- C_PIN_SID column 3: 18
- Authority_User1 column 5: 4
- Locking_Range1 column 5: 4
- Locking_Range1 column 6: 4
- Locking_Range1 column 7: 4
- Locking_Range1 column 8: 4
- C_PIN_User1 column 3: 2
- MBRControl column 2: 2
- MBRControl column 1: 2
- Locking_Range1 column 3: 2
- Locking_Range1 column 4: 2

GenKey cases: ['tc10.json', 'tc20.json']
Host I/O cases: ['tc10.json', 'tc20.json']
```
