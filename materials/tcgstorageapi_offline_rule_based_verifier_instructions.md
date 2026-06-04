# TCGstorageAPI 기반 Offline Rule-Based SSD Protocol Verifier 구현 지시서

## 0. 목적

이 문서는 Codex에게 전달하기 위한 구현 지시서이다.

우리가 만들고자 하는 것은 **Deep Learning 모델이 아니라, Seagate/TCGstorageAPI 오픈소스 구현을 참조하여 만든 offline rule-based verifier**이다. 과제의 입력은 실제 SSD device가 아니라, 이미 수집된 **SSD command-response trajectory JSON**이다. 따라서 TCGstorageAPI를 그대로 실행해서 실제 드라이브에 명령을 보내는 것이 아니라, TCGstorageAPI 안의 Opal/TCG operation 구현, UID/table/column mapping, authority handling, method invocation pattern을 추출하여 **로그 기반 protocol oracle**로 재구성해야 한다.

최종 목표는 다음 함수다.

```python
def predict_trajectory(trajectory: list[dict]) -> str:
    """
    Input: one SSD command-response trajectory.
    The last record is the target command-response pair.
    Output: "PASS" or "FAIL".
    """
```

여기서 PASS/FAIL의 의미는 다음과 같다.

```text
PASS = 마지막 SSD response가 이전 command-response history로부터 추론한 protocol state 하에서 규격상 허용되는 응답이다.
FAIL = 마지막 SSD response가 이전 command-response history로부터 추론한 protocol state 하에서 규격을 위반한다.
```

중요한 점은 다음이다.

```text
PASS != output.status_codes == "Success"
FAIL != output.status_codes != "Success"
```

예를 들어 인증 없이 protected object를 수정했는데 SSD가 `NOT_AUTHORIZED`를 반환했다면, 이것은 error response이지만 protocol상 올바른 응답이므로 PASS이다. 반대로 인증 없이 protected object를 수정했는데 SSD가 `Success`를 반환했다면, 성공 응답처럼 보이지만 protocol 위반이므로 FAIL이다.

---

## 1. 전체 구현 전략

기존에 고려했던 “summary 생성 + DL model 추론” 방식 대신, 이번 구현은 다음 방향으로 간다.

```text
Public/private trajectory JSON
  ↓
Canonical Event Parser
  ↓
Offline Protocol State Tracker
  ↓
TCGstorageAPI-derived Rule Engine
  ↓
Expected Final Response / Expected Side Effect
  ↓
Actual Final Response 비교
  ↓
PASS / FAIL
```

핵심은 **TCGstorageAPI를 online host-side library에서 offline verifier로 바꾸는 것**이다.

TCGstorageAPI의 기존 구조는 대략 다음과 같다.

```text
high-level operation
  → pysed.invoke(object, method, args, authAs, sp, ...)
  → 실제 SED device에 IF-SEND/IF-RECV 전송
  → 실제 SSD response 수신
  → status == Success 여부 반환
```

우리가 필요한 구조는 반대다.

```text
recorded command-response log
  → command 의미 정규화
  → 이전 response가 성공이면 state update
  → 마지막 command의 expected response 계산
  → recorded final response와 비교
```

따라서 TCGstorageAPI 코드를 그대로 import하여 device를 열거나 `pysed.Sed(...)`를 생성하면 안 된다. 대신 다음 요소를 재사용/이식한다.

```text
- operation name → TCG method/object mapping
- tokens_table / locking_table / portlocking_table 같은 column mapping
- changePIN, setRange, gen_key, get_MEK, enable_range_access 등의 operation semantics
- authAs normalization logic
- default authority / required authority 흐름
- Opalv2-specific object/table naming convention
```

---

## 2. 참고 대상 Repository

기준 repo:

```text
https://github.com/Seagate/TCGstorageAPI
```

우선적으로 분석할 파일:

```text
TCGstorageAPI/tcgapi.py
TCGstorageAPI/tcgSupport.py
TCGstorageAPI/pysedSupport.py
sed_cli/sed_cli.py
sed_cli/README.md
```

특히 `tcgapi.py`의 다음 method들을 우선 분석한다.

```text
_getAuthAs
getRange
setRange
enable_range_access
get_MEK
gen_key
changePIN
setMinPINLength
checkPIN
writeaccess
readaccess
writeData
readData
revert
activate
takeownership / ownership-related flow가 sed_cli에 있으면 함께 분석
```

`tcgSupport.py`에서는 다음 mapping이 중요하다.

```python
tokens_table = {
    "PIN": [3],
    "RangeStart": [3],
    "RangeLength": [4],
    "ReadLockEnabled": [5],
    "WriteLockEnabled": [6],
    "ReadLocked": [7],
    "WriteLocked": [8],
    "LockOnReset": [9, 2],
    "Enabled": [5, 3],
    "PSK": [4],
    "PortLocked": [3],
    "CipherSuite": [5],
    "_MinPINLength": [0xFFFF0001],
}

locking_table = {
    "UID": 0,
    "Name": 1,
    "CommonName": 2,
    "RangeStart": 3,
    "RangeLength": 4,
    "ReadLockEnabled": 5,
    "WriteLockEnabled": 6,
    "ReadLocked": 7,
    "WriteLocked": 8,
    "LockOnReset": 9,
}
```

이 mapping은 과제 JSON의 `Set(... optional Values ...)`를 semantic field로 복원하는 데 사용한다.

---

## 3. Non-goals

이번 구현에서 하지 말아야 할 것:

1. **실제 SSD device 접근 금지**
   - `/dev/sdX`, `/dev/nvmeX`, `/sys/module/libata/parameters/allow_tpm`, privileged Docker 전제 금지.
   - 평가 환경에서는 command-response log만 주어진다.

2. **TCGstorageAPI의 transport layer 사용 금지**
   - `pysed.Sed(...)`, `opensea-transport`, 실제 IF-SEND/IF-RECV 전송 의존성을 제거한다.

3. **전체 TCG/Opal spec 완전 구현을 목표로 하지 말 것**
   - public dataset에서 실제 등장하는 operation/object/status universe를 먼저 분석하고, 그 subset부터 구현한다.
   - private set 일반화를 위해 TCGstorageAPI와 spec 기반으로 규칙을 확장하되, 처음부터 모든 table/method를 구현하려 하지 않는다.

4. **마지막 response pattern만 보는 shortcut 금지**
   - `Success면 PASS`, `NOT_AUTHORIZED면 FAIL` 같은 rule은 명백히 잘못된 접근이다.
   - 반드시 이전 records로부터 state를 update한 뒤 target response를 판정해야 한다.

---

## 4. 프로젝트 산출물 구조

권장 파일 구조:

```text
src/
  solver.py
  ssd_verifier/
    __init__.py
    predictor.py
    parser.py
    canonical.py
    state.py
    status.py
    uid_map.py
    rule_engine.py
    operations/
      __init__.py
      session.py
      auth.py
      credential.py
      locking.py
      genkey.py
      io.py
      sp_lifecycle.py
      acl.py
      datastore.py
    tcgstorageapi_refs/
      __init__.py
      mappings.py
      opal_objects.py
      tcg_tokens.py
    diagnostics.py
    dataset_scan.py
tests/
  test_parser.py
  test_state_transitions.py
  test_tc3_credential_update.py
  test_tc20_genkey.py
setup.sh
pyproject.toml
uv.lock
```

평가 entrypoint는 과제 repo의 evaluator 형식에 맞추되, 내부적으로는 `src/ssd_verifier/predictor.py`의 `predict_trajectory()`를 호출하게 만든다.

---

## 5. 핵심 데이터 모델

### 5.1 CanonicalEvent

원본 JSON record는 형식이 불규칙할 수 있으므로, 먼저 의미 단위 event로 변환한다.

```python
from dataclasses import dataclass, field
from typing import Any, Optional

@dataclass
class CanonicalEvent:
    index: int

    # raw record
    raw: dict

    # command family
    kind: str  # "tcg_method", "host_io", "unknown"

    # TCG method fields
    method_name: Optional[str] = None       # StartSession, Get, Set, Authenticate, Activate, GenKey, ...
    invoking_uid: Optional[str] = None
    invoking_name: Optional[str] = None     # C_PIN, Locking, K_AES_256, AdminSP, LockingSP, ...
    invoking_symbol: Optional[str] = None   # canonicalized symbolic object id

    # session/auth fields
    sp: Optional[str] = None                # AdminSP, LockingSP, ...
    authority: Optional[str] = None         # Anybody, SID, Admin1, User1, ...
    write_session: Optional[bool] = None

    # arguments
    required_args: dict[str, Any] = field(default_factory=dict)
    optional_args: dict[str, Any] = field(default_factory=dict)
    values: dict[str, Any] = field(default_factory=dict)

    # output
    status: Optional[str] = None            # normalized: SUCCESS, NOT_AUTHORIZED, INVALID_PARAMETER, ...
    return_values: list[Any] = field(default_factory=list)

    # host IO fields
    io_command: Optional[str] = None        # Read / Write
    lba_range: Optional[tuple[int, int]] = None
    pattern: Optional[str] = None
    read_result: Optional[str] = None

    # metadata
    is_success: bool = False
```

### 5.2 VerifierState

State는 완벽한 SSD internal state가 아니라, PASS/FAIL 판정에 필요한 protocol state만 추적한다.

```python
@dataclass
class SessionState:
    open: bool = False
    sp: Optional[str] = None
    host_session_id: Optional[str] = None
    sp_session_id: Optional[str] = None
    write: bool = False
    authenticated: set[str] = field(default_factory=set)

@dataclass
class LockingRangeState:
    range_id: str
    range_start: Optional[int] = None
    range_length: Optional[int] = None
    read_lock_enabled: bool = False
    write_lock_enabled: bool = False
    read_locked: bool = False
    write_locked: bool = False
    lock_on_reset: bool = False
    media_key_generation: int = 0

@dataclass
class VerifierState:
    session: SessionState = field(default_factory=SessionState)

    admin_sp_active: bool = True
    locking_sp_activated: bool = False

    # credentials
    pins: dict[str, str] = field(default_factory=dict)      # SID/Admin1/UserN symbolic value
    pin_known_aliases: dict[str, str] = field(default_factory=dict)

    # authority state
    authority_enabled: dict[str, bool] = field(default_factory=dict)

    # locking ranges
    ranges: dict[str, LockingRangeState] = field(default_factory=dict)

    # LBA model
    lba_patterns: dict[tuple[int, int], str] = field(default_factory=dict)
    lba_key_generation: dict[tuple[int, int], int] = field(default_factory=dict)

    # recent events / diagnostics
    successful_genkeys: list[dict] = field(default_factory=list)
    successful_sets: list[dict] = field(default_factory=list)
    failed_auth_attempts: list[dict] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
```

---

## 6. Parser / Canonicalizer 구현 요구사항

### 6.1 Status normalization

다음 status 표현들을 하나로 normalize한다.

```text
"Success", "SUCCESS", "success" → "SUCCESS"
"NotAuthorized", "NOT_AUTHORIZED", "NOT AUTHORIZED" → "NOT_AUTHORIZED"
"InvalidParameter", "INVALID_PARAMETER", "INVALID PARAMETER" → "INVALID_PARAMETER"
```

`output.status_codes`가 없고 host IO result만 있는 경우는 TCG method status가 아니라 host IO result로 처리한다.

### 6.2 Symbolic object normalization

과제 JSON에는 다음이 섞여 나올 수 있다.

```text
invoking_id.name
invoking_id.uid
method.uid
raw byte UID
symbolic names
```

가능한 경우 다음 canonical symbol로 변환한다.

```text
AdminSP
LockingSP
SID
Anybody
Admin1
User1, User2, ...
C_PIN
C_PIN_SID
C_PIN_MSID
C_PIN_Admin1
C_PIN_User1
Locking
Locking_GlobalRange
Locking_Range1
K_AES_256
K_AES_256_Range1_Key
ACE_*
Authority_*
MBRControl
DataStore
```

최초 구현에서는 exact mapping이 부족해도 된다. 대신 `invoking_id.name`이 있으면 그것을 우선 사용하고, UID-only case는 `uid_map.py`에 점진적으로 추가한다.

### 6.3 Values decoding

TCGstorageAPI의 `tokens_table`을 사용해 `Set` optional values를 semantic field로 바꾼다.

예:

```json
"optional": {
  "Values": [
    {"0x03": "..."}
  ]
}
```

`C_PIN` object에서 column `0x03`은 PIN field로 해석한다.

Locking object에서 column mapping은 다음을 따른다.

```text
3 → RangeStart
4 → RangeLength
5 → ReadLockEnabled
6 → WriteLockEnabled
7 → ReadLocked
8 → WriteLocked
9 → LockOnReset
```

---

## 7. State Transition 원칙

### 7.1 마지막 record는 state update하지 말 것

Trajectory의 마지막 record는 target이다. 이전 record들로 state를 만든 뒤, 마지막 record는 expected response와 비교하는 데만 사용한다.

```python
for record in trajectory[:-1]:
    event = parse(record)
    apply_transition(state, event)

target = parse(trajectory[-1])
verdict = judge_target(state, target)
```

### 7.2 성공한 operation만 state를 바꾼다

가장 중요한 원칙이다.

```python
if event.is_success:
    apply_success_effect(state, event)
else:
    apply_failure_effect_if_needed(state, event)
```

기본적으로 실패한 command의 intended side effect는 반영하지 않는다.

예:

```text
Set(C_PIN_SID, PIN=new_pin) -> NOT_AUTHORIZED
```

이면 SID PIN은 바뀌면 안 된다.

```text
GenKey(K_AES_256_Range1_Key) -> NOT_AUTHORIZED
```

이면 media key generation은 증가하면 안 된다.

### 7.3 실제 response를 그대로 믿되, compliance 여부는 target에서만 판단한다

이전 records는 “device가 그렇게 응답했다”는 로그이다. 이전 record가 spec 위반처럼 보여도, 기본 구현에서는 state reconstruction을 위해 성공 response의 side effect를 반영한다. 단, diagnostics에는 suspicious event로 기록한다.

과제 label은 마지막 response만 평가한다.

---

## 8. Operation별 구현 계획

### 8.1 Session lifecycle

대상:

```text
StartSession
EndSession
CloseSession
SyncSession
```

State update:

```text
StartSession(...)->SUCCESS:
  session.open = True
  session.sp = AdminSP / LockingSP
  session.write = Write parameter
  session.authenticated = {authority} if HostChallenge authentication succeeded
  session ids 저장

EndSession/CloseSession->SUCCESS:
  session.open = False
  session.sp = None
  session.write = False
  session.authenticated.clear()
```

Target judgment examples:

```text
StartSession with correct credential -> SUCCESS expected
StartSession with wrong credential -> NOT_AUTHORIZED expected
StartSession to inactive LockingSP -> error expected
```

처음에는 credential correctness를 완전히 알기 어렵다. 이전 `Get(C_PIN_MSID)` / `Set(C_PIN_*)` / known alias를 통해 추적 가능한 범위부터 구현한다.

### 8.2 Authentication / authority

대상:

```text
Authenticate
StartSession with HostChallenge
```

State update:

```text
Authenticate(Admin1)->SUCCESS:
  state.session.authenticated.add("Admin1")
```

Failure:

```text
Authenticate(...)->NOT_AUTHORIZED:
  authenticated set에 추가하지 않음
  failed_auth_attempts에 기록
```

Required authority check는 operation-specific rule에서 사용한다.

### 8.3 Credential update

대상:

```text
Set(C_PIN_*)
changePIN-equivalent flow
setMinPINLength
```

TCGstorageAPI reference:

```text
changePIN(auth, pin, authAs=None, obj=None)
  → obj = auth if obj is None else obj
  → token {"PIN": pin}
  → invoke(obj, "Set", ...)
```

Offline rule:

```text
Set(C_PIN_SID, PIN=new)->SUCCESS:
  if current auth is allowed to modify C_PIN_SID:
      state.pins["SID"] = new
  else:
      target이라면 SUCCESS는 FAIL
```

판정:

```text
- PIN update가 성공했으면 이후 new PIN으로 StartSession 가능해야 한다.
- PIN update가 실패했으면 이후 new PIN으로 StartSession이 SUCCESS인 것은 suspicious/FAIL target일 수 있다.
```

### 8.4 Locking range configuration

대상:

```text
Set(Locking::Range*)
Set(Locking_GlobalRange)
setRange-equivalent flow
```

TCGstorageAPI reference:

```text
setRange(... RangeStart, RangeLength, ReadLocked, WriteLocked, ReadLockEnabled, WriteLockEnabled, LockOnReset)
```

State update:

```text
Set(LockingRange, RangeStart=x, RangeLength=y, ReadLockEnabled=True, ...)->SUCCESS:
  update range config

Set(LockingRange, ReadLocked=True)->SUCCESS:
  state.ranges[range].read_locked = True
```

Target judgment:

```text
- Write session required for Set.
- Required authority must be authenticated.
- Invalid range/alignment can imply INVALID_PARAMETER if known.
```

초기 구현에서는 권한/세션/activated 여부 중심으로 판단하고, alignment/range crossing은 dataset에서 필요한 경우 추가한다.

### 8.5 LockingSP lifecycle

대상:

```text
Activate
Revert
RevertSP
PSID Revert
```

State update:

```text
Activate(LockingSP)->SUCCESS:
  state.locking_sp_activated = True
  Admin1 credential may become copied/initialized from SID depending on flow.
```

`Revert` / `RevertSP`:

```text
- credentials reset
- locking range reset
- media keys/data removed if applicable
```

초기 구현에서는 다음만 반드시 구현한다.

```text
LockingSP가 activate되기 전에는 LockingSP protected operations가 제한될 수 있다.
Revert/RevertSP 성공 후 기존 credential/range/key state는 reset되어야 한다.
```

### 8.6 GenKey / media key

대상:

```text
GenKey(K_AES_256*)
get_MEK
```

TCGstorageAPI reference:

```text
get_MEK(rangeNo, ...)
  → Get locking table column 0x0A to retrieve range key UID

gen_key(range_key, ...)
  → invoke(range_key, "GenKey")
```

State update:

```text
GenKey(range_key)->SUCCESS:
  corresponding range.media_key_generation += 1
  record successful_genkeys
```

Host I/O side effect:

```text
If old data was written under generation g,
and GenKey increments to generation g+1,
then reading same LBA should not return the old plaintext pattern.
```

Target judgment example:

```text
Write LBA 80-87 pattern 8E -> pass/SUCCESS
Read LBA 80-87 -> 8E
GenKey(K_AES_256_RangeKey)->SUCCESS
Target Read LBA 80-87 -> 8E
=> FAIL
```

### 8.7 Host Data I/O

대상:

```text
Read
Write
```

These are not TCG methods but can be target records.

State update:

```text
Write(LBA range, pattern)->success/pass:
  if write allowed by locking state:
      store lba_patterns[range] = pattern
      store lba_key_generation[range] = current range key generation
```

Read judgment:

```text
If read_locked for matching range:
  expected read failure / no pattern
If not locked and no key generation mismatch:
  expected previous pattern if known
If key generation changed after write:
  expected not equal to old pattern
```

### 8.8 Generic Get / Next / GetACL

대상:

```text
Get
Next
GetACL
```

State update:

```text
Get(C_PIN_MSID, col=3)->SUCCESS with value:
  store observed value as alias for current/default credential where applicable

Get(LockingRange)->SUCCESS:
  update observed range state if return values include columns

GetACL->SUCCESS:
  optionally store ACL info
```

처음에는 `Get` return value parsing이 어려울 수 있으므로, public dataset에서 실제 format을 보고 필요한 subset부터 구현한다.

### 8.9 ACL / ACE personalization

대상:

```text
Set(ACE_*)
GetACL
AccessControl table updates
```

이 영역은 full implementation이 어렵다. 초기 구현에서는 다음으로 제한한다.

```text
- known object/method별 coarse required authority table 사용
- Set(ACE_*)가 SUCCESS이면 해당 object/method rule override 가능성을 기록
- target이 ACL personalization 자체인 경우, write session + Admin authority 여부 중심으로 판단
```

추후 public 실패 케이스 분석 후 rule 확장.

### 8.10 DataStore / MBR / Port locking / TLS

낮은 우선순위로 구현한다. public dataset에 많이 나오면 추가한다.

```text
DataStore: readData/writeData flow
MBRControl: Enabled/Done state
Port locking: PortLocked, LockOnReset
TLS/PSK: 대부분 과제 핵심이 아니면 ignore
```

---

## 9. Rule Engine 설계

### 9.1 ExpectedResponse

`judge_target()`는 단순 문자열이 아니라 expected response constraints를 반환하게 한다.

```python
@dataclass
class ExpectedResponse:
    allowed_statuses: set[str]
    forbidden_statuses: set[str] = field(default_factory=set)
    expected_read_result: Optional[str] = None
    forbidden_read_result: Optional[str] = None
    reason: str = ""
    confidence: str = "medium"  # high / medium / low
```

예:

```python
ExpectedResponse(
    allowed_statuses={"NOT_AUTHORIZED"},
    reason="Protected Set requires authenticated Admin1/SID authority",
    confidence="high",
)
```

Host IO read case:

```python
ExpectedResponse(
    allowed_statuses=set(),
    forbidden_read_result="8E",
    reason="GenKey succeeded after this pattern was written; old plaintext should not still be readable",
    confidence="high",
)
```

### 9.2 Comparison logic

```python
def compare_expected_actual(expected: ExpectedResponse, target: CanonicalEvent) -> str:
    if target.kind == "host_io" and target.io_command == "Read":
        if expected.forbidden_read_result is not None:
            return "FAIL" if target.read_result == expected.forbidden_read_result else "PASS"
        if expected.expected_read_result is not None:
            return "PASS" if target.read_result == expected.expected_read_result else "FAIL"

    if target.status in expected.allowed_statuses:
        return "PASS"
    if target.status in expected.forbidden_statuses:
        return "FAIL"

    # Unknown/low-confidence fallback
    return heuristic_or_default(target, expected)
```

---

## 10. Dataset Scanner 먼저 구현

Rule engine을 만들기 전에 public dataset 전체를 스캔하는 도구를 먼저 구현한다.

`src/ssd_verifier/dataset_scan.py`

출력해야 할 것:

```text
- 총 trajectory 수
- label 분포
- method.name 분포
- invoking_id.name 분포
- invoking_id.uid 분포 top-K
- output.status_codes 분포
- target method 분포
- target status 분포
- TCG method vs Host IO 비율
- Set 대상 object/column 분포
- GenKey 등장 케이스 목록
- Read/Write target 케이스 목록
- unknown/unparsed field examples
```

Codex는 먼저 scanner를 구현하고, public dataset을 돌려서 `analysis/public_dataset_profile.md`를 생성하라.

이 profile을 바탕으로 rule coverage 우선순위를 정한다.

---

## 11. 우선순위별 구현 Milestones

### Milestone 1: Skeleton

- `predict_trajectory()` 구현
- JSON parser / canonicalizer
- status normalization
- target 분리
- baseline heuristic:
  - 알 수 없는 경우 majority label 또는 conservative fallback

### Milestone 2: Session/Auth/Credential

- StartSession / EndSession
- Authenticate
- Set(C_PIN)
- TC-3 credential update case 통과

### Milestone 3: Locking Range

- Set(LockingRange)
- ReadLocked / WriteLocked / enabled flags
- Read/Write allowed/denied 판단

### Milestone 4: GenKey + Host IO

- Write pattern tracking
- Read pattern tracking
- GenKey success 후 old pattern invalidation
- TC-20 case 통과

### Milestone 5: SP Lifecycle

- Activate
- Revert / RevertSP
- LockingSP activated state

### Milestone 6: ACL / DataStore / Misc

- ACE/ACL coarse handling
- DataStore
- MBRControl
- PortLocking if public dataset에서 등장할 경우

### Milestone 7: Validation and fallback

- unknown target에 대한 fallback heuristic 정리
- diagnostics logging
- public dataset error analysis 기반 rule 추가

---

## 12. TCGstorageAPI를 어떻게 변형할 것인가

### 12.1 직접 import하지 말고 mapping/semantics를 추출하라

TCGstorageAPI는 실제 drive access와 C++/transport dependency가 붙어 있다. 평가 환경에서 불필요하고 위험하다.

따라서 다음처럼 한다.

```text
TCGstorageAPI/tcgSupport.py
  → tcgstorageapi_refs/tcg_tokens.py 로 mapping 이식

TCGstorageAPI/tcgapi.py high-level methods
  → operations/*.py 에 offline transition rule로 재작성

sed_cli operation list
  → test scenario / operation coverage checklist로 사용
```

### 12.2 pysed.invoke를 offline expectation으로 치환

기존:

```python
status, rv, kwrv = self.__pysed.invoke(obj, "Set", arg, authAs=..., ...)
if status != StatusCode.Success:
    return self.fail(rv, status)
return True
```

변환 후:

```python
def judge_set_operation(state: VerifierState, event: CanonicalEvent) -> ExpectedResponse:
    if not state.session.open:
        return ExpectedResponse({"NOT_AUTHORIZED", "INVALID_PARAMETER"}, reason="No valid session")

    if not state.session.write:
        return ExpectedResponse({"NOT_AUTHORIZED"}, reason="Set requires write session")

    required = required_authority_for_set(event.invoking_symbol, event.values)
    if not has_authority(state, required):
        return ExpectedResponse({"NOT_AUTHORIZED"}, reason=f"Set requires {required}")

    return ExpectedResponse({"SUCCESS"}, reason="Authorized Set is allowed")
```

### 12.3 operation method를 transition + judge로 분리

각 operation module은 두 종류의 함수가 있어야 한다.

```python
def apply_transition(state: VerifierState, event: CanonicalEvent) -> None:
    """
    For context records only.
    Use actual response to update state.
    """

def judge_target(state: VerifierState, target: CanonicalEvent) -> ExpectedResponse:
    """
    For final target record.
    Compute protocol-expected response/effect.
    """
```

---

## 13. Required Authority Table 초안

초기 rough rule table은 다음처럼 시작한다. 정확한 ACL은 dataset/profile을 보고 보정한다.

```python
REQUIRED_AUTHORITY = {
    ("Set", "C_PIN_SID"): {"SID"},
    ("Set", "C_PIN_Admin1"): {"Admin1", "SID"},
    ("Set", "C_PIN_User"): {"Admin1", "SID"},
    ("Set", "LockingRange"): {"Admin1", "SID"},
    ("GenKey", "K_AES_256"): {"Admin1", "SID"},
    ("Activate", "LockingSP"): {"SID"},
    ("RevertSP", "LockingSP"): {"SID", "Admin1"},
    ("Get", "C_PIN_MSID"): {"Anybody", "SID", "Admin1"},
}
```

주의: 이 table은 출발점일 뿐이다. TCG/Opal ACL은 object/table/column별로 다를 수 있으므로, public dataset error analysis로 수정한다.

---

## 14. Diagnostics

모든 예측은 reason을 남겨야 한다.

```python
@dataclass
class Prediction:
    verdict: str
    confidence: str
    reason: str
    target: CanonicalEvent
    state_snapshot: dict
    expected: ExpectedResponse
```

평가 출력에는 PASS/FAIL만 내보내되, 로컬 debug mode에서는 다음 파일을 저장한다.

```text
debug_predictions.jsonl
```

각 줄:

```json
{
  "case_id": "...",
  "prediction": "FAIL",
  "reason": "GenKey succeeded after LBA pattern write; target Read returned old pattern",
  "target_method": "Read",
  "target_status": null,
  "target_read_result": "8E",
  "confidence": "high"
}
```

---

## 15. Unit Test 요구사항

최소한 다음 테스트를 만든다.

### 15.1 Credential update TC-3 style

```text
StartSession(AdminSP, Anybody, Write=1) -> SUCCESS
Get(C_PIN_MSID, col=3) -> SUCCESS
EndSession -> SUCCESS
StartSession(AdminSP, SID, old_pin, Write=1) -> SUCCESS
Set(C_PIN_SID, PIN=new_pin) -> SUCCESS
EndSession -> SUCCESS
Target: StartSession(AdminSP, SID, new_pin, Write=1) -> SUCCESS
Expected: PASS
```

변형:

```text
Set(C_PIN_SID, PIN=new_pin) -> NOT_AUTHORIZED
Target: StartSession(AdminSP, SID, new_pin) -> SUCCESS
Expected: FAIL
```

### 15.2 Unauthenticated protected Set

```text
StartSession(LockingSP, Anybody, Write=1) -> SUCCESS
Target: Set(LockingRange, WriteLocked=True) -> SUCCESS
Expected: FAIL
```

변형:

```text
StartSession(LockingSP, Anybody, Write=1) -> SUCCESS
Target: Set(LockingRange, WriteLocked=True) -> NOT_AUTHORIZED
Expected: PASS
```

### 15.3 GenKey TC-20 style

```text
Write(LBA=80-87, pattern=8E) -> pass
Read(LBA=80-87) -> 8E
GenKey(K_AES_256_RangeKey) -> SUCCESS
Target: Read(LBA=80-87) -> 8E
Expected: FAIL
```

변형:

```text
GenKey(K_AES_256_RangeKey) -> NOT_AUTHORIZED
Target: Read(LBA=80-87) -> 8E
Expected: PASS
```

---

## 16. Codex 작업 지시

Codex는 다음 순서로 작업하라.

### Step 1. Repo 분석

- 현재 프로젝트 repo와 Seagate/TCGstorageAPI repo를 모두 열어라.
- `TCGstorageAPI/tcgapi.py`, `tcgSupport.py`, `sed_cli/README.md`를 읽고 operation mapping을 정리하라.
- `pysed` / transport dependency를 직접 쓰지 말고, offline verifier에 필요한 mapping과 semantics만 가져오라.
- Apache 2.0 license notice를 보존해야 할 코드 조각이 있으면 명확히 분리하고 주석을 남겨라.

### Step 2. Dataset schema 분석

- `/dl2026/dataset` 또는 현재 public dataset 경로에서 JSON schema를 확인하라.
- `dataset_scan.py`를 구현해 command universe를 출력하라.
- target command distribution과 Set 대상 object/column distribution을 반드시 확인하라.

### Step 3. Core skeleton 구현

- `CanonicalEvent`
- `VerifierState`
- `ExpectedResponse`
- `predict_trajectory`
- parser/canonicalizer/status normalizer

### Step 4. High-priority rules 구현

- Session lifecycle
- Authentication
- Credential update
- Locking range Set
- GenKey
- Host Read/Write

### Step 5. Public examples 통과

- TC-3 credential update PASS
- TC-20 GenKey failure FAIL
- unauthenticated protected Set PASS/FAIL pair

### Step 6. Error analysis loop

- public validation split에서 틀린 케이스를 `debug_predictions.jsonl`로 저장하라.
- 틀린 target method/object/status 조합을 그룹화하라.
- 가장 많이 틀리는 operation부터 rule을 추가하라.

### Step 7. Submission compatibility

- `setup.sh`, `pyproject.toml`, `uv.lock`가 평가 서버에서 동작하도록 정리하라.
- network access 없는 evaluation phase에서 동작해야 하므로 외부 download 의존성을 제거하라.
- 실제 device access, root permission, privileged Docker 요구가 있으면 안 된다.

---

## 17. 구현상 중요한 판단 기준

1. **과제의 target은 마지막 response 하나다.**
   - 이전 record들은 context/state reconstruction용이다.

2. **이전 record의 response가 SUCCESS인 경우에만 side effect를 반영한다.**
   - 실패한 Set, 실패한 GenKey, 실패한 Authenticate는 state를 바꾸면 안 된다.

3. **TCG command는 non-TCG host IO에 영향을 줄 수 있다.**
   - GenKey 이후 Read 결과가 대표적이다.

4. **operation name만으로 판단하지 말 것.**
   - `Set`은 object/column에 따라 완전히 다른 operation이다.

5. **unknown case에서는 deterministic하게 fallback하라.**
   - 예측은 반드시 PASS/FAIL 중 하나여야 한다.
   - fallback rule은 별도 함수로 분리하고 diagnostics에 기록한다.

---

## 18. 최종 기대 결과

최종적으로 다음이 가능해야 한다.

```bash
cd /workspace/project
bash setup.sh
python evaluate.py
```

그리고 내부 solver는 각 test trajectory에 대해 다음 흐름으로 예측한다.

```python
from ssd_verifier.predictor import predict_trajectory

label = predict_trajectory(trajectory)
assert label in {"PASS", "FAIL"}
```

보고서에는 다음처럼 설명할 수 있어야 한다.

```text
We implemented an offline symbolic verifier for TCG/Opal SSD protocol compliance.
Instead of treating the task as simple sequence classification, our verifier parses each
command-response record into a canonical protocol event, reconstructs session,
authentication, credential, locking-range, media-key, and LBA-pattern states from the
context trajectory, and checks whether the final response is compliant under the inferred
state. We used Seagate/TCGstorageAPI as a reference implementation for Opal operation
semantics, object/table/column mappings, authority normalization, and high-level operation
flows, but removed all live device transport dependencies to make the verifier operate
entirely on offline JSON logs.
```

---

## 19. Appendix: Initial operation coverage checklist

우선 구현할 operation coverage:

```text
[Core]
- StartSession
- EndSession / CloseSession
- Authenticate
- Get
- Set
- Activate
- Revert / RevertSP
- GenKey

[Objects]
- AdminSP
- LockingSP
- SID
- Admin1
- Anybody
- C_PIN
- C_PIN_MSID
- C_PIN_SID
- C_PIN_Admin1
- Locking
- Locking_GlobalRange
- Locking_RangeN
- K_AES_256
- K_AES_256_RangeN_Key

[Host IO]
- Write(LBA, pattern)
- Read(LBA, result)

[States]
- session open/closed
- current SP
- write session
- authenticated authorities
- credential updates
- LockingSP activated
- range start/length
- read/write lock enabled
- read/write locked
- media key generation
- LBA pattern and key generation at write time
```

이 checklist에서 public dataset에 등장하지 않는 것은 낮은 우선순위로 미루고, public/private 일반화에 중요해 보이는 것부터 구현한다.
