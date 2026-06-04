# Edge-Case Test Generation Plan

이 문서는 SSD verifier의 private 성능을 올리기 위해, TCG/Opal 공식 문서를 근거로 edge-case 테스트 데이터를 체계적으로 만드는 계획이다.

핵심 목표는 단순히 테스트 개수를 늘리는 것이 아니라, 각 테스트가 다음 세 가지를 갖도록 만드는 것이다.

1. 공식 문서 근거
2. 독립적인 기대 라벨
3. solver mismatch가 났을 때 바로 고칠 수 있는 최소 재현 로그

## 0. 현재 원칙

### 라벨링 원칙

테스트 라벨은 반드시 공식 문서에서 온다.

허용되는 근거:

- `artifacts/documents/core/*.txt`
- `artifacts/documents/opal/*.txt`
- 과제 PDF가 직접 정의한 평가 규칙
- skeleton README가 직접 정의한 입력/출력 형식

주의:

- 기존 solver 코드가 그렇게 동작한다고 해서 라벨 근거로 삼지 않는다.
- 기존 unit test가 그렇게 되어 있다고 해서 라벨 근거로 삼지 않는다.
- LLM/사람 직감만으로 PASS/FAIL을 붙인 테스트는 `unsourced smoke test`로 따로 둔다.

### PASS/FAIL 원칙

이 과제의 PASS/FAIL은 마지막 응답의 protocol compliance다.

예:

```text
마지막 응답이 SUCCESS다
```

라는 사실만으로 PASS가 아니다.

스펙상 성공해야 하는 상황에서 SUCCESS면 PASS이고, 스펙상 거절해야 하는 상황에서 SUCCESS면 FAIL이다.

반대로:

```text
마지막 응답이 INVALID_PARAMETER / NOT_AUTHORIZED / data protection error다
```

라도, 그 에러가 스펙상 맞는 응답이면 PASS다.

### 상태 전이 원칙

대부분의 context step은 성공한 경우에만 상태를 바꾼다.

하지만 예외가 있다.

예:

- 인증 실패는 `Tries`를 증가시킬 수 있다.
- 특정 reset은 `LockOnReset`, `MBRDoneOnReset`, `Tries/Persistence` 등에 영향을 줄 수 있다.
- `EndSession`은 열린 session state를 닫는다.

따라서 edge case는 항상:

```text
context step들이 어떤 상태를 만들었는가?
마지막 target step에서 스펙상 어떤 응답이 맞는가?
```

로 쪼개서 봐야 한다.

## 1. Test Case 단위

각 sourced test case는 다음 정보를 가져야 한다.

```python
Case(
    name="짧고 구체적인 이름",
    trajectory=[...],
    expected="PASS" or "FAIL",
    evidence=Evidence(
        sources=(...),
        rule="문서에서 온 규칙을 한 문장으로 요약",
    ),
    tag="큰 분류"
)
```

### 좋은 테스트 이름

좋은 이름:

```text
MBR active outside read-locked range returns zeroes
TryLimit two blocks after two failed attempts
ReadLocked ignored when ReadLockEnabled is false
PinLength on non-C_PIN GenKey is invalid
```

나쁜 이름:

```text
test1
weird case
private maybe
```

### 좋은 evidence

좋은 evidence:

```text
source:
  artifacts/documents/core/5.7.3.2.txt
rule:
  Table 230 says that when MBR is active, outside-MBR read with
  ReadLockEnabled=True and ReadLocked=True returns all zeroes.
```

나쁜 evidence:

```text
대충 locking 관련
solver가 그렇게 되어 있음
전에 본 것 같음
```

## 2. 생성 루프

앞으로 edge-case 생성은 아래 순서로 한다.

### Step 1. 문서 조항을 고른다

예:

```text
core/5.7.3.2.txt
Table 230 Interface Read Command Access
```

### Step 2. 조항을 rule card로 바꾼다

예:

```text
Rule:
  If MBRControl.Enable=True and MBRControl.Done=False,
  and read starts inside MBR but ends outside MBR,
  then the device transfers no data and terminates with Data Protection Error.
```

### Step 3. 최소 context를 만든다

예:

```text
AdminSP ownership
Activate LockingSP
Set MBRControl.Enable=True
Set MBRControl.Done=False
```

### Step 4. target response 쌍을 만든다

Positive:

```text
Read 262143~262144 -> INVALID_PARAMETER
expected PASS
```

Negative:

```text
Read 262143~262144 -> SUCCESS / returns data
expected FAIL
```

### Step 5. solver mismatch를 본다

```bash
python tools/run_sourced_edges.py
```

Mismatch가 있으면:

```text
1. 문서 근거가 정말 맞는지 다시 확인
2. 테스트 context가 그 상태를 정확히 만들었는지 확인
3. solver expected reason을 확인
4. 최소 수정
5. 기존 unit/public/sourced 모두 재실행
```

### Step 6. 회귀 테스트로 남긴다

고친 버그는 반드시 sourced test에 남긴다.

그래야 나중에 다른 수정으로 다시 깨지는 것을 막을 수 있다.

## 3. 큰 분류

전체 edge-case 공간은 다음 축으로 쪼갠다.

우선순위는 A, B, C, D 순서다.

## 4. A축: Host I/O, Locking Range, MBR

이 축은 private 점수에 가장 직접적으로 영향을 줄 가능성이 높다.

이유:

- 과제 PDF의 TC-20이 이미 host Read/Write와 GenKey를 강조한다.
- final target이 host I/O일 때 PASS/FAIL 차이가 분명하다.
- 문서 `core/5.7.3.2.txt`가 read/write 행동을 표로 직접 준다.

### 주요 문서

- `artifacts/documents/core/5.7.2.2.txt`: Locking table column 목록
- `artifacts/documents/core/5.7.2.2.4.txt`: RangeStart
- `artifacts/documents/core/5.7.2.2.5.txt`: RangeLength
- `artifacts/documents/core/5.7.2.2.6.txt`: ReadLockEnabled
- `artifacts/documents/core/5.7.2.2.7.txt`: WriteLockEnabled
- `artifacts/documents/core/5.7.2.2.8.txt`: ReadLocked
- `artifacts/documents/core/5.7.2.2.9.txt`: WriteLocked
- `artifacts/documents/core/5.7.2.2.10.txt`: LockOnReset
- `artifacts/documents/core/5.7.2.5.txt`: MBRControl table
- `artifacts/documents/core/5.7.2.5.2.txt`: MBRControl Enable
- `artifacts/documents/core/5.7.2.5.3.txt`: MBRControl Done
- `artifacts/documents/core/5.7.3.2.txt`: Interface Read/Write Command Access
- `artifacts/documents/core/5.7.3.3.txt`: Creating Locking Ranges
- `artifacts/documents/core/5.7.3.4.txt`: Zero Length Locking Ranges
- `artifacts/documents/core/5.7.3.5.txt`: Changing RangeStart and RangeLength
- `artifacts/documents/core/5.7.3.6.txt`: MBR Table

### 하위 개념

1. `ReadLockEnabled`
2. `ReadLocked`
3. `WriteLockEnabled`
4. `WriteLocked`
5. `RangeStart`
6. `RangeLength`
7. `GlobalRange`
8. Non-global range
9. Range crossing
10. MBR shadow active
11. MBR shadow done
12. MBR boundary crossing
13. Zero length range
14. Alignment and granularity
15. LockOnReset

### 테스트 생성 매트릭스

Read 테스트:

```text
MBR active?     True / False
MBR done?       True / False
start in MBR?   True / False
end in MBR?     True / False
read enabled?   True / False
read locked?    True / False
cross ranges?   True / False
```

Write 테스트:

```text
MBR active?      True / False
MBR done?        True / False
start in MBR?    True / False
end in MBR?      True / False
write enabled?   True / False
write locked?    True / False
cross ranges?    True / False
```

### 우선 만들 edge cases

1. ReadLockEnabled=False이면 ReadLocked=True여도 user data 반환
2. ReadLockEnabled=True, ReadLocked=True이면 data protection error
3. WriteLockEnabled=False이면 WriteLocked=True여도 write 가능
4. WriteLockEnabled=True, WriteLocked=True이면 data protection error
5. MBR Enable=True, Done=False, read fully inside MBR이면 MBR table data 반환
6. MBR Enable=True, Done=False, read start inside/end outside면 data protection error
7. MBR Enable=True, Done=False, read outside MBR but read-locked이면 zeroes 반환
8. MBR Enable=True, Done=True, read-locked이면 data protection error
9. MBR Enable=True, Done=False, write starting inside MBR이면 data protection error
10. MBR Enable=True, Done=False, write outside MBR and unlocked이면 write 가능
11. Mixed range crossing read는 data protection error
12. Mixed range crossing write는 data protection error
13. LockOnReset empty set은 reset 후 locked 상태를 바꾸지 않음
14. LockOnReset에 해당 reset type이 있으면 reset 후 ReadLocked/WriteLocked가 True

### 특히 조심할 점

`core/5.7.3.2.txt` Table 230에서:

```text
MBR active, outside MBR, ReadLockEnabled=True, ReadLocked=True
```

일 때 read behavior는 일반 locked read와 다르다.

일반적으로는 data protection error지만, MBR active 상태의 해당 표 row는 `Return all zeroes`다.

이런 식의 표 우선순위가 private에서 중요할 수 있다.

## 5. A축: GenKey, Media Key, Re-encryption

이 축도 우선순위가 높다.

이유:

- 과제 PDF의 TC-20이 GenKey 후 old plaintext가 그대로 읽히면 FAIL이라고 한다.
- 공식 문서에서 `ReEncryptState`가 `GenKey` 가능 여부를 직접 제약한다.
- host I/O 결과와 TCG method 결과가 연결된다.

### 주요 문서

- `artifacts/documents/core/5.3.3.16.txt`: GenKey method
- `artifacts/documents/core/5.3.3.16.2.txt`: PinLength
- `artifacts/documents/core/5.3.3.16.3.txt`: GenKey Result
- `artifacts/documents/core/5.3.3.16.4.txt`: GenKey Fails
- `artifacts/documents/core/5.3.4.1.1.1.txt`: GenKey on C_PIN
- `artifacts/documents/core/5.7.2.2.11.txt`: ActiveKey
- `artifacts/documents/core/5.7.2.2.12.txt`: NextKey
- `artifacts/documents/core/5.7.2.2.13.txt`: ReEncryptState
- `artifacts/documents/core/5.7.2.2.14.txt`: ReEncryptRequest
- `artifacts/documents/core/5.7.3.7.txt`: Re-encryption
- `artifacts/documents/core/5.7.3.7.1.txt`: Re-encryption State Descriptions
- `artifacts/documents/core/5.7.3.7.2.txt`: ActiveKey Column Modifications
- `artifacts/documents/core/5.7.3.7.3.txt`: ReEncryptState Column Values
- `artifacts/documents/core/5.7.3.7.4.txt`: ReEncryption Request Attempts

### 하위 개념

1. C_PIN GenKey
2. K_AES GenKey
3. PinLength allowed only on C_PIN
4. PublicExponent allowed only on C_RSA
5. PinLength max 32
6. ReEncryptState IDLE vs non-IDLE
7. NextKey writable only when IDLE
8. GenKey blocked when re-encryption busy
9. Old plaintext invalidation after media key change
10. ActiveKey/NextKey transition

### 우선 만들 edge cases

1. C_PIN GenKey with PinLength=32 succeeds
2. C_PIN GenKey with PinLength=33 fails
3. K_AES GenKey with PinLength fails
4. C_PIN GenKey with PublicExponent fails
5. K_AES GenKey from wrong SP fails
6. K_AES GenKey without Admins authority fails
7. K_AES GenKey while ReEncryptState != IDLE fails
8. Write pattern before GenKey, read before GenKey returns old pattern
9. Write pattern before GenKey, read after GenKey must not return old pattern
10. ReEncryptRequest invalid transition fails

### 주의점

GenKey 관련 테스트는 두 종류로 나누어야 한다.

```text
method-level correctness:
  GenKey 응답 status가 맞는가?

media-level correctness:
  GenKey 이후 host Read 결과가 맞는가?
```

둘을 한 테스트에 섞으면 원인 분석이 어려워진다.

## 6. A축: Authentication, C_PIN, TryLimit

이 축은 상태 전이가 많고 private에서 꼬기 쉽다.

### 주요 문서

- `artifacts/documents/core/5.3.2.12.txt`: C_PIN object table
- `artifacts/documents/core/5.3.2.12.4.txt`: PIN
- `artifacts/documents/core/5.3.2.12.6.txt`: TryLimit
- `artifacts/documents/core/5.3.2.12.7.txt`: Tries
- `artifacts/documents/core/5.3.2.12.8.txt`: Persistence
- `artifacts/documents/core/5.3.4.1.1.2.txt`: Authentication attempt limits
- `artifacts/documents/core/5.3.4.1.2.txt`: Authorities
- `artifacts/documents/core/5.3.4.1.2.1.txt`: Anybody
- `artifacts/documents/core/5.3.4.1.2.3.txt`: SID
- `artifacts/documents/core/5.3.4.1.4.txt`: Disabled Authorities
- `artifacts/documents/core/5.3.4.1.5.txt`: Session Startup
- `artifacts/documents/core/5.3.4.1.10.txt`: Session Startup Authorities
- `artifacts/documents/core/5.3.4.1.14.txt`: Authenticate Method
- `artifacts/documents/core/5.3.4.1.14.1.txt`: Authenticate Failures

### 하위 개념

1. HostSigningAuthority
2. HostChallenge
3. Anybody authority
4. SID authority
5. Admin authority
6. User authority
7. Authority Enabled column
8. Disabled authority
9. PIN update
10. Failed PIN update no side effect
11. TryLimit
12. Tries
13. Persistence
14. PowerCycle vs HardwareReset effects on Tries
15. Authenticate method vs implicit StartSession auth

### 우선 만들 edge cases

1. Anybody StartSession succeeds without HostChallenge
2. Individual authority StartSession without HostChallenge fails
3. Wrong PIN increments Tries
4. Correct PIN resets Tries to 0
5. TryLimit=0 means unlimited attempts and Tries remains 0
6. TryLimit=N locks after N failed attempts
7. Successful Set of PIN resets Tries
8. Failed Set of PIN does not reset Tries
9. Persistence=False resets Tries after PowerCycle
10. Persistence=False does not reset Tries after HardwareReset
11. Disabled authority cannot authenticate even with correct PIN
12. Re-enabled authority can authenticate

### 주의점

문서상 인증 실패는 read-only session에서도 TPer가 Tries를 바꿀 수 있다.

즉:

```text
host가 read-only session에서 Set은 못 하지만,
TPer 내부적으로 failed auth 때문에 Tries를 올릴 수는 있다.
```

이런 차이를 테스트해야 한다.

## 7. B축: Table Get/Set/Create/Delete

이 축은 parser와 semantics가 같이 걸린다.

### 주요 문서

- `artifacts/documents/core/5.3.3.2.txt`: CreateTable
- `artifacts/documents/core/5.3.3.3.txt`: Delete
- `artifacts/documents/core/5.3.3.4.txt`: CreateRow
- `artifacts/documents/core/5.3.3.5.txt`: DeleteRow
- `artifacts/documents/core/5.3.3.6.txt`: Get
- `artifacts/documents/core/5.3.3.7.txt`: Set
- `artifacts/documents/core/5.3.3.8.txt`: Next
- `artifacts/documents/core/5.3.3.9.txt`: GetFreeSpace
- `artifacts/documents/core/5.3.3.10.txt`: GetFreeRows
- `artifacts/documents/core/5.3.4.2.txt`: Table Management
- `artifacts/documents/core/5.3.4.2.2.txt`: Retrieving Table Data
- `artifacts/documents/core/5.3.4.2.3.txt`: Creating Table Rows
- `artifacts/documents/core/5.3.4.2.4.txt`: Deleting Table Rows
- `artifacts/documents/core/5.3.4.2.5.txt`: Deleting Tables
- `artifacts/documents/core/5.3.4.2.6.txt`: Modifying Tables

### 하위 개념

1. Object method vs table method
2. `Where` required for table Set
3. `Where` invalid for object Set
4. `CellBlock`
5. RowValues
6. Bytes
7. Byte table vs object table
8. Missing required arguments
9. Invalid column
10. Unknown UID
11. Created row side effects
12. Deleted row side effects
13. Get return payload length/type

### 우선 만들 edge cases

1. Object.Set with Where fails
2. Table.Set without Where fails
3. Table.Set with Where row outside table fails
4. Byte table Set accepts byte payload
5. Object table Set rejects byte payload
6. Get CellBlock with invalid column range fails
7. DeleteRow on non-table fails
8. Delete on non-deletable manufactured object fails
9. CreateRow in Locking table creates range state
10. DeleteRow removes range state and later host I/O changes behavior

### 주의점

이 축은 “status가 맞는가”뿐 아니라 “context state가 다음 target에 반영되는가”를 봐야 한다.

예:

```text
CreateRow success
-> 새 locking range가 생김
-> 다음 host Read/Write가 그 range 기준으로 판단됨
```

## 8. B축: Access Control, ACL, ACE

이 축은 private에서 어려운 문제를 만들기 좋은 영역이다.

### 주요 문서

- `artifacts/documents/core/5.3.3.11.txt`: DeleteMethod
- `artifacts/documents/core/5.3.3.12.txt`: Authenticate
- `artifacts/documents/core/5.3.3.13.txt`: GetACL
- `artifacts/documents/core/5.3.3.14.txt`: AddACE
- `artifacts/documents/core/5.3.3.15.txt`: RemoveACE
- `artifacts/documents/core/5.3.4.3.txt`: Access Control
- `artifacts/documents/core/5.3.4.3.1.txt`: Meta-ACLs
- `artifacts/documents/core/5.3.4.3.2.txt`: BooleanExpr Column Format
- `artifacts/documents/core/5.3.4.3.3.txt`: Modifying BooleanExpr

### 하위 개념

1. ACE BooleanExpr
2. OR authority expression
3. AND authority expression
4. class authority vs individual authority
5. Admins class
6. Users class
7. DeleteMethod association removal
8. AddACE
9. RemoveACE
10. SetACL
11. AccessControl row references
12. ACL effects on later Set/Get/GenKey

### 우선 만들 edge cases

1. User1 cannot Set range without ACE grant
2. User1 can Set range after ACE grant
3. Removing ACE revokes permission
4. DeleteMethod removes method association and later method fails
5. GetACL unknown association fails
6. BooleanExpr malformed fails
7. BooleanExpr with unsupported AND fails if profile only allows OR
8. Admins class satisfies Admin1
9. Users class satisfies User1
10. Class authority should not be used as HostSigningAuthority in StartSession

### 주의점

ACL 테스트는 context가 길어지기 쉽다.

그래서 반드시 두 단계로 만든다.

```text
1. ACL setup 자체가 성공/실패하는지 테스트
2. ACL setup이 성공한 뒤 실제 protected operation이 바뀌는지 테스트
```

## 9. B축: SP Lifecycle, Revert, RevertSP, DeleteSP

이 축은 상태 초기화가 커서 private에서 틀리기 쉽다.

### 주요 문서

- `artifacts/documents/core/5.3.3.1.txt`: DeleteSP
- `artifacts/documents/core/5.3.3.20*.txt`가 있으면 Revert 관련 검색 필요
- `artifacts/documents/core/5.3.4.4.txt`: Deleting the SP
- `artifacts/documents/core/5.3.5.txt`: Life Cycle
- `artifacts/documents/core/5.4.5.txt`: Admin lifecycle
- `artifacts/documents/core/5.7.4.txt`: Locking lifecycle
- `artifacts/documents/opal/*.txt`: Opal SSC-specific Revert/RevertSP/Data Removal

### 하위 개념

1. AdminSP lifecycle
2. LockingSP activation
3. SP Frozen
4. SP Enabled
5. DeleteSP
6. pending deletion until EndSession
7. Revert
8. RevertSP
9. PSID authority
10. SID authority
11. factory reset state
12. credential reset after revert
13. locking ranges reset after revert
14. media data after revert/genkey/data removal

### 우선 만들 edge cases

1. LockingSP cannot open before Activate
2. Failed Activate has no side effect
3. Successful Activate enables LockingSP
4. Frozen SP rejects new sessions
5. DeleteSP success does not fully remove active session before EndSession if spec says pending
6. DeleteSP effect after EndSession
7. RevertSP requires correct authority
8. RevertSP resets LockingSP state
9. Revert with PSID resets ownership
10. Revert invalidates old credentials

### 주의점

Lifecycle 쪽은 Opal SSC-specific 문서가 core보다 더 구체적일 수 있다.

따라서 이 축은 반드시 `opal/` 문서 검색을 같이 해야 한다.

## 10. C축: Package, Crypto, Attestation, Random

이 축은 상대적으로 빈도가 낮을 수 있지만 private hidden에서 한두 개 나오면 점수를 갉아먹을 수 있다.

### 주요 문서

- `artifacts/documents/core/5.3.3.17.txt`: GetPackage
- `artifacts/documents/core/5.3.3.18.txt`: SetPackage
- `artifacts/documents/core/5.3.4.5.txt`: SetPackage operation
- `artifacts/documents/core/5.6.*.txt`: Crypto template
- `artifacts/documents/core/5.6.4.1.txt`: Random
- `artifacts/documents/core/5.6.4.9.txt`: Sign
- `artifacts/documents/core/5.6.4.10.txt`: Verify

### 하위 개념

1. GetPackage required Purpose
2. WrappingKey references credential
3. SigningKey references credential
4. SetPackage requires Value
5. SetPackage modifies credential and resets Tries if applicable
6. Random count and returned length
7. Sign input length
8. FirmwareAttestation target object

### 우선 만들 edge cases

1. GetPackage without Purpose fails
2. GetPackage with non-credential WrappingKey fails
3. SetPackage without Value fails
4. SetPackage with correct package changes later auth
5. Random Count=N returns N bytes
6. Sign with too-long input fails if wrapper/spec imposes size
7. FirmwareAttestation target mismatch fails

## 11. C축: Parser and Log-Shape Robustness

이 축은 TCG semantic이라기보다 과제 dataset/log representation에 대한 축이다.

### 근거

- 과제 skeleton README
- public testcase schema
- TCG method representation examples
- TCGstorageAPI wrapper logs if provided

### 하위 개념

1. UID string vs int
2. Symbolic name vs UID
3. method name vs method UID
4. status in `output.status_codes`
5. status in `output.args.result`
6. status in wrapper `return`
7. `None` return as failure
8. tuple/list/dict argument variants
9. top-level `type: Read`
10. high-level `function`
11. high-level `operation`
12. `kwargs.authAs`

### 우선 만들 edge cases

1. Same semantic command in canonical JSON form
2. Same semantic command with integer UID
3. Same semantic command with symbolic name only
4. Same semantic command with method UID only
5. Same semantic command through high-level wrapper
6. Status encoded in alternate field
7. Boolean return maps to SUCCESS/FAIL correctly

### 주의점

Parser tests should not pretend to be official TCG semantics if the only source is skeleton/log schema.

따라서 evidence에는 TCG spec이 아니라 skeleton README/public schema 근거를 넣는다.

## 12. D축: Report/Modeling Support Tests

이 축은 직접 점수보다는 보고서와 안정성용이다.

### 목적

- solver가 어떤 rule coverage를 갖는지 설명
- sourced vs unsourced test를 분리
- hidden score 개선 과정을 윤리적으로 설명

### 만들 수 있는 것

1. source coverage table
2. rule card count
3. tag별 sourced case count
4. mismatch history
5. before/after bug fix note
6. public score unchanged verification log

## 13. 우선순위 로드맵

### Phase 1. Host I/O and Locking Tables

목표:

- `core/5.7.3.2.txt` Table 230/231을 거의 전부 테스트화한다.

작업:

1. Read table rows를 rule card로 분해
2. Write table rows를 rule card로 분해
3. MBR active/done/in/out/cross 조합 생성
4. ReadLock/WriteLock enabled/locked 조합 생성
5. Mixed range boundary 조합 생성

완료 기준:

```text
run_sourced_edges.py --tag host-io-doc
mismatches: 0
```

### Phase 2. C_PIN and Authentication

목표:

- TryLimit, Tries, Persistence, disabled authority, session startup authority를 공식 문서 기준으로 커버한다.

작업:

1. TryLimit=0/N
2. failed auth count
3. successful auth reset
4. Set/GenKey/SetPackage reset
5. Persistence and reset type
6. disabled authority

### Phase 3. GenKey and Re-encryption

목표:

- GenKey method-level failure와 media-level stale plaintext를 분리해서 커버한다.

작업:

1. PinLength/PublicExponent matrix
2. SP and authority matrix
3. ReEncryptState matrix
4. host Read after key generation

### Phase 4. Table Semantics

목표:

- Get/Set/CreateRow/DeleteRow의 object/table/Where/CellBlock 차이를 커버한다.

작업:

1. Object.Set vs Table.Set
2. invalid Where
3. invalid columns
4. Byte table vs object table
5. row creation side effects

### Phase 5. ACL/ACE

목표:

- 권한 부여/회수와 later operation의 변화를 커버한다.

작업:

1. BooleanExpr parser
2. class authority
3. User grant/revoke
4. DeleteMethod

### Phase 6. Lifecycle/Revert

목표:

- 큰 상태 초기화가 제대로 되는지 확인한다.

작업:

1. Activate
2. Frozen/Enabled
3. DeleteSP
4. RevertSP
5. Revert/PSID

## 14. 테스트 생성 방식

### 손으로 먼저 만든다

처음부터 랜덤 generator로 가지 않는다.

먼저 문서 row 하나당 손으로 1~3개씩 만든다.

이유:

- 라벨 실수를 줄인다.
- context가 최소인지 확인한다.
- solver mismatch의 원인을 바로 알 수 있다.

### 그 다음 generator화한다

반복되는 축이 안정되면 generator로 만든다.

예:

```python
for mbr_enable in [0, 1]:
    for mbr_done in [0, 1]:
        for read_enabled in [0, 1]:
            for read_locked in [0, 1]:
                ...
```

하지만 generator도 반드시 rule table을 기준으로 해야 한다.

### Pair test를 기본으로 한다

각 규칙은 가능하면 두 개씩 만든다.

```text
correct response -> expected PASS
wrong response   -> expected FAIL
```

예:

```text
Read locked range -> INVALID_PARAMETER => PASS
Read locked range -> returns data      => FAIL
```

이렇게 해야 solver가 너무 관대하거나 너무 엄격한 경우를 둘 다 잡는다.

## 15. Mismatch 분석 규칙

Mismatch가 나오면 바로 solver를 고치지 않는다.

먼저 다음 순서로 확인한다.

1. evidence 문서가 정말 그 상황을 말하는가?
2. 테스트 context가 그 상황을 정확히 만들었는가?
3. final target만 평가하고 있는가?
4. 이전 실패 step의 side effect를 잘못 가정하지 않았는가?
5. status와 return payload를 혼동하지 않았는가?
6. TCG core 규칙과 Opal SSC-specific 규칙이 충돌하지 않는가?
7. solver의 reason이 어느 branch에서 나오는가?

그다음 고친다.

## 16. 로컬 작업 가능성

결론:

```text
이 프로젝트는 내 컴에서도 충분히 작업 가능하다.
```

이유:

- solver는 거의 순수 Python이다.
- public dataset이 작다.
- 공식 문서 txt 파일도 작다.
- `/workspace/seungmin/sm` 전체가 약 12MB 수준이다.
- `artifacts/documents`도 약 5.7MB 수준이다.
- 테스트 실행에는 `pytest` 정도만 필요하다.

### 로컬 작업의 장점

1. VS Code/Codex가 공유 서버 계정 설정에 덜 꼬인다.
2. SSH 접속 끊김 문제를 피할 수 있다.
3. 로컬에서 문서 읽기, 검색, 수정이 빠르다.
4. 내 Codex 계정/환경으로 안전하게 작업할 수 있다.
5. 서버에는 검증/제출 직전에만 올리면 된다.

### 로컬 작업의 단점

1. dashboard `submit`은 서버에서 해야 한다.
2. 서버의 정확한 evaluation 환경과 100% 같지는 않다.
3. 팀원이 서버에서 수정한 내용과 동기화 충돌 가능성이 있다.
4. `.git`이 없는 복사본이라 변경 추적을 따로 해야 한다.

### 추천 방식

추천은 hybrid다.

```text
로컬:
  문서 읽기
  sourced test 작성
  solver 수정
  unit/sourced/public local eval

서버:
  최종 rsync
  서버에서 unit/sourced/public 재실행
  팀 합의 후 submit
```

### 로컬로 가져오기

로컬에서:

```bash
mkdir -p ~/ssd-project
rsync -avz \
  --exclude .venv \
  --exclude .pytest_cache \
  --exclude '__pycache__' \
  --exclude predictions.jsonl \
  --exclude scores.json \
  -e "ssh -p 2225" \
  student@147.46.78.20:/workspace/seungmin/sm/ \
  ~/ssd-project/sm/
```

### 로컬 환경 만들기

```bash
cd ~/ssd-project/sm
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -U pip pytest
```

만약 `uv`를 쓰고 싶으면:

```bash
cd ~/ssd-project/sm
uv run --with pytest python -m pytest tests/test_solver_rules.py -q
```

### 로컬에서 돌릴 명령

```bash
cd ~/ssd-project/sm
python tools/run_sourced_edges.py
python tools/run_synthetic_edges.py
python -m pytest tests/test_solver_rules.py -q
DATASET_DIR=dataset LABEL_PATH=dataset/label.jsonl python evaluate.py
```

주의:

로컬 복사본의 `dataset/`이 없거나 오래됐으면 서버에서 같이 받아와야 한다.

### 서버로 다시 올리기

로컬에서:

```bash
rsync -avz \
  --exclude .venv \
  --exclude .pytest_cache \
  --exclude '__pycache__' \
  --exclude predictions.jsonl \
  --exclude scores.json \
  -e "ssh -p 2225" \
  ~/ssd-project/sm/ \
  student@147.46.78.20:/workspace/seungmin/sm/
```

서버에서 최종 확인:

```bash
cd /workspace/seungmin/sm
uv run --with pytest python -m pytest tests/test_solver_rules.py -q
python tools/run_sourced_edges.py
python tools/run_synthetic_edges.py
DATASET_DIR=/dl2026/dataset LABEL_PATH=/dl2026/dataset/label.jsonl python evaluate.py
```

## 17. Git 없는 상태에서 변경 추적

현재 `/workspace/seungmin/sm`은 `.git`이 없다.

그래서 최소한 다음 중 하나가 필요하다.

### 옵션 A. 로컬에서 새 git repo 만들기

추천.

```bash
cd ~/ssd-project/sm
git init
git add .
git commit -m "baseline"
```

이건 팀원 GitHub와 무관한 내 로컬 기록이다.

장점:

- 내가 뭘 바꿨는지 볼 수 있다.
- 실수했을 때 내 변경만 되돌릴 수 있다.
- 서버 공유 계정 git 설정을 건드리지 않는다.

주의:

- remote를 붙이지 않아도 된다.
- 팀원 repo에 push하지 않는다.

### 옵션 B. 서버에서 patch 백업

서버에서:

```bash
cd /workspace/seungmin/sm
diff -ruN /workspace/ssd-checker-dl /workspace/seungmin/sm > analysis/seungmin_changes.patch
```

다만 원본이 계속 변하면 관리가 어렵다.

## 18. 다음 실제 작업 순서

가장 좋은 다음 작업은 Phase 1이다.

### 다음 목표

`core/5.7.3.2.txt`의 Table 230/231을 거의 전부 sourced test로 옮긴다.

### 왜 이것부터인가

1. 공식 표가 명확하다.
2. host Read/Write는 final target으로 만들기 쉽다.
3. public에는 적게 나오고 private에는 꼬아서 나올 가능성이 있다.
4. 이미 하나의 실제 solver bug를 여기서 찾았다.

### 구체적 체크리스트

1. Table 230 row를 전부 rule card로 적는다.
2. 각 row마다 PASS case를 만든다.
3. 각 row마다 반대 FAIL case를 만든다.
4. MBR boundary를 0, last MBR LBA, last+1로 테스트한다.
5. Locking boundary를 range start-1/start/end/end+1로 테스트한다.
6. Mixed range crossing을 따로 테스트한다.
7. `run_sourced_edges.py --tag host-io-doc`로 묶는다.
8. mismatch가 나오면 문서와 context를 재확인한다.

## 19. 하지 말아야 할 것

1. leaderboard score를 보고 private 분포를 추측해서 테스트를 만들지 않는다.
2. submit 반복으로 black-box optimization하지 않는다.
3. 근거 없는 라벨을 sourced test에 넣지 않는다.
4. 모든 문제를 랜덤 fuzzing으로 해결하려 하지 않는다.
5. solver가 통과한다고 문서 규칙이 맞다고 착각하지 않는다.
6. 문서 규칙을 확인하지 않은 채 private 점수 원인을 단정하지 않는다.

## 20. 요약

앞으로의 핵심 구조:

```text
공식 문서 조항
-> rule card
-> minimal context
-> PASS/FAIL pair
-> sourced test
-> solver mismatch
-> 문서 재확인
-> 알고리즘 수정
-> regression
```

현재 가장 유망한 집중 영역:

```text
1. Host I/O + Locking + MBR
2. C_PIN + TryLimit + Authentication
3. GenKey + ReEncrypt + Media Key
4. Table Get/Set/Create/Delete
5. ACL/ACE
6. Lifecycle/Revert/DeleteSP
```

로컬 작업은 충분히 가능하고, 오히려 추천한다.

다만 최종 제출 전에는 반드시 서버에서 같은 테스트를 다시 돌린다.

## 21. 공식 문서 Coverage 장치

공식 문서의 어느 부분을 놓치고 있는지 계속 보이게 하기 위해 `tools/doc_coverage.py`를 둔다.

이 도구는 다음 세 가지를 한다.

1. `artifacts/documents/core`와 `artifacts/documents/opal`의 모든 `.txt` 문서를 스캔한다.
2. `tools/run_sourced_edges.py`의 `Evidence.sources`를 읽어 어떤 문서가 테스트 근거로 쓰였는지 매칭한다.
3. 아직 테스트 근거로 쓰이지 않았고, triage도 안 된 고위험 문서를 리포트 맨 위에 올린다.

### 실행

```bash
cd /workspace/seungmin/sm
python tools/doc_coverage.py
```

생성되는 파일:

```text
analysis/doc_coverage_report.md
analysis/doc_coverage_matrix.json
analysis/doc_coverage_triage.json
```

### 리포트 읽는 법

`analysis/doc_coverage_report.md`에서 가장 중요한 숫자는 다음이다.

```text
Official document files
Sourced edge cases
Documents referenced by sourced tests
Untriaged normative documents
Untriaged A/B priority documents
```

여기서 `Untriaged A/B priority documents`가 줄어드는 것이 우리의 coverage 개선 지표다.

이 숫자는 다음 둘 중 하나를 해야 줄어든다.

1. 해당 문서를 근거로 sourced test를 추가한다.
2. 해당 문서가 진짜로 informative/out-of-scope/duplicate라면 `analysis/doc_coverage_triage.json`에 이유를 적는다.

### Priority 의미

`A`:

```text
private 점수에 직접 영향을 줄 가능성이 큰 영역.
Host I/O, Locking, MBR, Authentication, C_PIN, GenKey, ReEncrypt 등.
```

`B`:

```text
Table methods, ACL/ACE, lifecycle/revert처럼 중요하지만 context가 길거나 간접적인 영역.
```

`C`:

```text
Package/Crypto/Session protocol/Opal SSC-specific detail 등.
```

`D`:

```text
정의, 용어, informative 문서일 가능성이 높은 영역.
```

### Triage 규칙

문서를 테스트하지 않고 triage할 때는 반드시 이유가 있어야 한다.

예:

```json
{
  "manual": {
    "core/1.4.1.txt": {
      "status": "informative",
      "reason": "Terminology section; no direct final-response rule."
    },
    "core/5.7.2.2.txt": {
      "status": "covered_indirectly",
      "reason": "Column table is covered through column-specific files 5.7.2.2.6-5.7.2.2.10."
    }
  }
}
```

좋은 triage status:

```text
informative
out_of_scope
duplicate
covered_indirectly
deferred
```

나쁜 triage reason:

```text
안 중요해 보임
귀찮음
solver가 이미 맞을 듯
```

### Strict 모드

나중에 coverage가 충분히 좋아졌을 때는 다음을 쓸 수 있다.

```bash
python tools/doc_coverage.py --strict
```

이 모드는 아직 untriaged A/B 문서가 남아 있으면 실패한다.

지금 당장은 실패하는 게 정상이다. 아직 backlog를 보여주는 단계이기 때문이다.

### 현재 baseline

처음 생성한 baseline은 대략 다음 상태다.

```text
Official document files: 1376
Sourced edge cases: 30
Documents referenced by sourced tests: 12
Untriaged normative documents: 1068
Untriaged A/B priority documents: about 550
```

이 숫자가 의미하는 것:

```text
아직 공식 문서 coverage는 극히 초기 상태다.
따라서 private 75점의 원인을 찾으려면 sourced test를 더 많이 만들 여지가 크다.
```

### Coverage 기반 작업 순서

앞으로는 다음 순서로 작업한다.

1. `python tools/doc_coverage.py` 실행
2. `analysis/doc_coverage_report.md`의 `Highest Priority Uncovered Documents`에서 하나 고름
3. 그 문서에서 rule card 추출
4. `tools/run_sourced_edges.py`에 PASS/FAIL pair 추가
5. `python tools/run_sourced_edges.py` 실행
6. mismatch가 있으면 문서/context 재확인 후 solver 수정
7. `python tools/doc_coverage.py` 다시 실행
8. report 숫자가 줄었는지 확인

이 장치의 목적은 완벽한 자동 증명이 아니다.

목적은:

```text
우리가 아직 보지 않은 공식 문서를 계속 눈앞에 세워두는 것
```

이다.

## 22. 독립 라벨 Consensus 장치

공식 문서를 근거로 sourced test를 만들더라도, 한 작성자가 문서를 잘못 읽었을 가능성은 남는다.

따라서 각 sourced case는 다음 흐름을 거친다.

```text
author label
-> blind review packet
-> multiple independent reviewer labels
-> consensus matrix
-> accepted or quarantine
```

### 핵심 파일

```text
tools/label_consensus.py
analysis/label_reviews/
analysis/label_consensus_report.md
analysis/label_consensus_matrix.json
analysis/quarantined_sourced_cases.json
analysis/accepted_sourced_cases.json
```

### Blind export

리뷰어에게 줄 파일은 다음처럼 만든다.

```bash
cd /workspace/seungmin/sm
python tools/label_consensus.py export --reviewer agent_alpha --tag mbr-doc --no-raw
```

생성 파일:

```text
analysis/label_reviews/agent_alpha.todo.jsonl
```

기본 export는 다음을 숨긴다.

```text
author_expected
case_name
```

이유:

기존 case 이름에 `impossible success`, `should not`, `correct status` 같은 표현이 들어가면 reviewer에게 답이 새어나간다.

따라서 reviewer는 기본적으로 다음만 본다.

```text
case_id
tag
official evidence/source snippets
compact trajectory
target response
```

### Completed review format

리뷰어는 `.todo.jsonl`을 보고 다음 형식의 `.jsonl`을 만든다.

```json
{"reviewer":"agent_alpha","case_id":"mbr-doc-a7a13ffff0","label":"PASS","confidence":0.92,"rationale":"Table 230 says this combination returns all zeroes.","concerns":"","source_refs":["core/5.7.3.2.txt"]}
```

완성 파일 위치:

```text
analysis/label_reviews/agent_alpha.jsonl
```

### Consensus report

```bash
python tools/label_consensus.py report
```

현재 policy:

```text
minimum independent reviewers: 3
minimum confidence: 0.75
author label is not counted as a review
```

accepted 조건:

```text
리뷰어가 3명 이상
모든 리뷰어 label이 서로 같음
리뷰어 consensus가 author label과 같음
모든 confidence >= 0.75
concerns가 비어 있음
```

quarantine 조건:

```text
리뷰어 부족
리뷰어 간 label disagreement
리뷰어 consensus와 author label disagreement
confidence 낮음
concerns 존재
```

즉 조금이라도 찝찝하면 accepted dataset에 안 들어간다.

### Consensus-gated sourced tests

리뷰 consensus를 통과한 case만 돌릴 수 있다.

```bash
python tools/run_sourced_edges.py --consensus-gate
```

현재는 실제 independent review가 없으므로 accepted case가 0개인 것이 정상이다.

```text
accepted=0
quarantined=30
```

이건 실패가 아니라 안전장치다.

### reviewer로 쓸 수 있는 주체

가능한 reviewer:

```text
1. 다른 LLM agent
2. 다른 모델 계열, 예: Claude/GPT/Gemini
3. 팀원
4. 나중의 우리 자신, 단 author label을 보지 않는 blind 상태
```

좋은 구성:

```text
agent_alpha: 공식 문서 literal reading 담당
agent_beta: 상태 전이/context consistency 담당
agent_gamma: adversarial reviewer, author label에 반례 찾기
```

### 중요한 운영 규칙

1. 같은 agent가 author와 reviewer를 겸하면 독립 review로 치지 않는다.
2. reviewer에게 solver verdict를 보여주지 않는다.
3. reviewer에게 author label을 보여주지 않는다.
4. reviewer에게 편향적인 case name을 보여주지 않는다.
5. disagreement가 생기면 solver를 고치기 전에 문서와 context를 다시 확인한다.
6. accepted된 case만 regression-quality sourced dataset으로 취급한다.

### 현재 baseline

초기 상태:

```text
sourced cases: 30
completed independent reviews: 0
accepted: 0
quarantined: 30
```

이 말은:

```text
기존 sourced case는 공식 문서 evidence가 붙어 있지만,
아직 independent label consensus는 통과하지 않았다.
```

라는 뜻이다.

따라서 지금부터는 case를 추가할 때마다 최소 3개 reviewer label을 모아서 accepted로 승격시키는 방향으로 운영한다.
