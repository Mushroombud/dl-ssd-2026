# ABCD Priority Guide and D-Slice Candidate Plan

이 문서는 공식 문서 조각을 A/B/C/D로 나눈 기준을 팀원이 처음 봐도 이해할 수 있게 설명하고, D 조각 중에서도 실제로 파볼 만한 후보를 선별하기 위한 작업 노트다.

현재 기준 파일은 `analysis/doc_coverage_matrix.json`이다.

## Current Coverage Snapshot

| Priority | Total document slices | Covered by cases | Triaged without cases | Untriaged | Case references |
|---|---:|---:|---:|---:|---:|
| A | 169 | 162 | 7 | 0 | 14349 |
| B | 393 | 344 | 49 | 0 | 21216 |
| C | 409 | 257 | 152 | 0 | 8429 |
| D | 405 | 80 | 325 | 0 | 1553 |

이 표에서 `covered by cases`는 해당 문서 조각을 근거로 만든 테스트가 하나라도 있다는 뜻이다. `triaged without cases`는 테스트는 없지만 정보성, 중복, 현재 JSON 입력에서 관찰 불가능 등의 이유로 처리 완료했다는 뜻이다. `untriaged`는 아직 테스트도 triage도 안 된 조각이다.

## What A/B/C/D Mean

| Priority | 느낌 | 대표 주제 | 점수 기대값 |
|---|---|---|---|
| A | 마지막 PASS/FAIL을 직접 뒤집는 핵심 규칙 | Locking range 상태, PIN/authentication, RevertSP, GenKey, GetACL exactness, CreateRow/DeleteRow state | 가장 큼 |
| B | 핵심 상태와 연결되지만 한 단계 간접적인 규칙 | table/method access, byte table bounds, session return shape, issued object read-only cells, optional range support | 큼 |
| C | 맞으면 좋지만 hidden에서 자주 나오지는 않을 수 있는 주변 규칙 | wrapper envelope variants, uncommon getter/setter aliases, logging details, feature descriptors, rare table metadata | 중간 |
| D | 문서에는 있지만 현재 JSON 로그에 직접 드러나기 어렵거나 너무 일반적인 규칙 | terminology, architecture overview, packet/token encoding, reserved fields, abstract data types, broad template overview | 낮음 |

중요한 점은 D가 “쓸모없음”은 아니라는 것이다. D는 보통 다음 중 하나다.

- raw TCG packet/token 계층이라, 과제 입력 JSON에는 이미 고수준 method call로 가공되어 있을 가능성이 큼
- 배경 설명이나 용어 정의라, 하나의 구체적 마지막 응답 rule로 바꾸기 어려움
- 더 구체적인 A/B/C 조각에서 이미 사실상 커버됨
- optional/implementation-defined 성격이 강해 잘못 건드리면 hidden valid 로그를 FAIL로 만들 위험이 큼

## D Slice Inventory

D 전체는 405개다. 2026-06-08 최종 sweep 이후 D도 모두 covered 또는 triaged 상태로 닫혔다.

| Status | Count |
|---|---:|
| covered | 80 |
| triaged without cases | 325 |
| untriaged | 0 |

D untriaged normative-looking 조각은 현재 0개다. 아래 표는 sweep 중간에 우선 탐색 대상으로 삼았던 과거 분포이며, 지금은 전부 테스트 또는 triage로 처리됐다.

| Category | Untriaged normative D count |
|---|---:|
| other | 80 |
| package-crypto | 22 |
| opal-ssc | 11 |
| protocol-session | 6 |

## D Candidates Worth Exploring

아래는 D 중에서도 JSON 로그에 흔적이 남을 수 있어, 테스트 생성 후보로 남길 만한 그룹이다.

### D1. Session And Properties Surface

이 그룹은 D지만 실제 high-level JSON에 `StartSession`, `SyncSession`, `Properties`, session id, status code 형태로 나타날 가능성이 있다.

| Path | Title | Why it may matter |
|---|---|---|
| `opal/4.1.1.3.txt` | SyncSession (M) | Opal이 `HostSessionID`, `SPSessionID` 파라미터를 지원해야 한다는 규칙. SyncSession wrapper/return-shape 케이스로 변환 가능 |
| `core/5.2.2.1.1.txt` | HostProperties | Properties method의 host property list. 현재 parser가 Properties/HostProperties 계열을 다루므로 output shape나 unknown property handling 후보 |
| `core/5.1.5.4.txt` | SP_FAILED | SP lifecycle failed state에서 session open 실패 status. 상태를 만들 수 있다면 StartSession negative case 후보 |
| `core/5.1.5.7.txt` | NO_SESSIONS_AVAILABLE | session capacity 초과 status. 다만 capacity가 로그에 명시되지 않으면 테스트 신뢰도 낮음 |
| `core/3.3.4.6.txt` | Session Layer | regular session requirement. raw transport보다 high-level session handling 쪽으로 제한적으로만 사용 가능 |

추천: `opal/4.1.1.3.txt`와 `core/5.2.2.1.1.txt`부터 본다. 이 둘은 실제 JSON wrapper로 나타날 가능성이 상대적으로 높다.

### D2. Packet, Token, And Reserved Field Handling

이 그룹은 raw TCG encoding 계층이다. 원칙상 중요하지만, 과제 입력이 이미 parsed JSON이라면 점수 기여가 낮을 수 있다.

| Path | Title | Why it may matter |
|---|---|---|
| `core/3.2.2.3.4.txt` | Out of Order Control Tokens | out-of-order control token이면 session abort. JSON에 token-level trace가 있으면 유효 |
| `core/3.2.2.4.txt` | Invalid and Unexpected Tokens | invalid token handling. raw token evidence가 없다면 triage 가능 |
| `core/3.2.3.2.1.1.txt` | ComPacket Reserved | reserved field should be zero and ignored. ignored semantics가 JSON에 남으면 PASS/FAIL 가능 |
| `core/3.2.3.3.1.3.txt` | Packet Reserved | reserved field ignored. packet-level 로그가 없으면 낮은 가치 |
| `core/3.2.3.5.2.3.txt` | Message Authentication Code (MAC) | secure packet MAC coverage. cryptographic correctness까지 가면 위험, shape-level만 가능 |

추천: 우선은 triage 성격으로 본다. 실제 dataset/profile에서 `token`, `ComPacket`, `Packet`, `Reserved`, `MAC` 같은 key가 거의 없으면 D 유지/triage가 맞다.

### D3. Crypto Object Metadata And Read-Only Columns

이 그룹은 D로 분류되어 있지만 hidden 로그에 `Get`/`Set` table cell 형태로 나오면 꽤 쓸 수 있다. 다만 일부는 이미 A/B/C의 table read-only 규칙과 겹친다.

| Path | Title | Why it may matter |
|---|---|---|
| `core/5.1.4.2.11.txt` | name | name has implicit 32-byte restriction. CreateTable/CommonName boundary와 연결 가능 |
| `core/5.3.2.4.2.txt` | Column Name | issued column metadata name is not host-modifiable. table metadata Set rejection 후보 |
| `core/5.3.2.4.4.txt` | Column Type | column type is not host-modifiable. table metadata Set rejection 후보 |
| `core/5.3.2.5.2.txt` | Type Name | type row name read-only. table metadata Set rejection 후보 |
| `core/5.3.2.5.4.txt` | Type Format | type format read-only. table metadata Set rejection 후보 |
| `core/5.3.2.15.6.txt` | FeedbackSize | ignored except CFB mode. 암호 모드까지 모델링해야 해서 위험도 있음 |
| `core/5.3.2.26.5.txt` | HMAC Hash | ignored for host-invoked HMAC operations. HMAC operation semantics 후보이지만 crypto correctness까지 가면 위험 |

추천: `Column/Type metadata read-only` 계열은 이미 solver의 table metadata 모델과 맞닿아 있으므로 안전 후보다. `FeedbackSize`나 `HMAC Hash ignored`는 더 조심스럽다.

### D4. Opal SSC Overview Pieces

이 그룹은 Opal의 큰 구조를 설명한다. D인 이유는 대부분 하위 조각에서 더 구체적으로 다루기 때문이다.

| Path | Title | Why it may matter |
|---|---|---|
| `opal/2.2.txt` | Security Providers (SPs) | Admin SP와 Locking SP 지원. 이미 기본 state model에 들어감 |
| `opal/2.8.txt` | Issuance | issuance/preconfigured object defaults와 연결 가능하지만 너무 넓음 |
| `opal/3.1.1.1.txt` | Level 0 Discovery Header | feature descriptor shape 후보 |
| `opal/4.3.5.2.1.txt` | Geometry Reporting Feature Behavior | geometry feature와 LockingInfo alignment 쪽으로 연결 가능 |

추천: `opal/4.3.5.2.1.txt`는 이미 LockingInfo geometry와 맞닿아 있어 후보. `opal/2.2.txt`는 배경 설명으로 triage 가능성이 높다.

### D5. Logging Defaults

Logging은 hidden에서 AccessControl Log cell로 나올 수 있으면 유효하지만, 너무 넓게 적용하면 과매칭 위험이 있다.

| Path | Title | Why it may matter |
|---|---|---|
| `core/5.4.4.5.txt` | Admin Template Default Logging Settings | Admin SP method logging default |
| `core/5.5.5.9.txt` | Clock Template Default Logging Settings | Clock template method logging default |
| `core/5.6.5.9.txt` | Cryptographic Template Default Logging Settings | crypto template logging default |
| `core/5.8.4.6.txt` | Log Template Default Logging Settings | Log template method logging default |

추천: 기존 solver가 Locking/DataStore/AccessControl logging 일부를 다루므로, Log cell exactness가 dataset에 보이면 소량 테스트 가능. 전체 template에 무리하게 일반화하면 위험하다.

## Recommended Next Work

1. D1 `SyncSession` / `HostProperties`에서 JSON-visible wrapper key가 있는지 public/profile/score-probe queue를 검색한다.
2. D3 `Column/Type metadata read-only`를 기존 table metadata model과 비교해 이미 커버된 것과 빠진 것을 나눈다.
3. D2 packet/token/reserved 조각은 public/profile에 raw packet key가 없다면 triage로 닫는다.
4. D4 `Geometry Reporting Feature Behavior`는 `LockingInfo`/feature descriptor 쪽 existing tests와 중복 여부를 확인한다.
5. D5 logging defaults는 `AccessControl.Get(Log)` 형태로만 제한해 후보를 만든다.

## 2026-06-08 D Sweep Result

Subagent를 D1/D2/D3/D4-D5 네 갈래로 나눠 조사했다.

- D1 Session/Properties:
  `SyncSession`과 `HostProperties`는 이미 상당히 커버되어 있다. `SP_FAILED` lifecycle observation은 실제 구멍으로 확인되어 보강했다. successful `SP.Get(LifeCycleState)`에서 `4=Issued-Failed`, `13=Manufactured-Failed`, `Issued-Failed`, `Manufactured-Failed`를 관측하면 해당 SP의 later `StartSession SUCCESS`를 금지하고 `SP_FAILED`/generic failure 계열을 허용한다. 이후 `Properties` 응답에서 `MaxSessions=1`이 JSON-visible하게 관측되는 경우도 실제 구멍으로 확인되어 보강했다. 한 개의 open session이 있으면 두 번째 `StartSession SUCCESS`는 금지하고 `NO_SESSIONS_AVAILABLE`/generic failure 계열을 허용한다.
- D2 Packet/Token/Reserved:
  현재 과제 JSON은 decoded method/table trajectory라 raw `ComPacket`, packet reserved field, token ordering, secure packet MAC field가 거의 직접 보이지 않는다. 이쪽은 triage가 맞고, HMAC method/HostProperties처럼 이미 decoded된 표면만 건드린다.
- D3 Crypto/Table Metadata:
  실제 구멍이 확인됐다. `Type_*` row의 UID/Name/CommonName/Format/Size Set 성공과 `Column_*` row의 UID/Type/IsUnique/ColumnNumber/Transactional/Next/AttributeFlags Set 성공을 solver가 받아들이고 있었다. 공식 Core `5.3.2.4.*`, `5.3.2.5.*` 근거로 direct Set success를 FAIL 처리하도록 보강했다. `Column.Name/CommonName`은 "tables created during issuance" 조건이 붙어 있어 이번 patch에서는 일부러 일반화하지 않았다.
- D3 Crypto Named Columns:
  numeric column validation은 있었지만 named payload `{"Mode": 12}`, `{"FeedbackSize": 17}`, `{"Hash": 9}`, `{"Key": ...}`가 validation을 우회했다. `C_RSA_*`, `C_AES_*`, `C_HMAC_*`의 official column names를 numeric columns로 낮춰 기존 validator를 재사용하게 했다. 추가로 `C_AES_*`의 `Mode=CFB`가 이전 successful Set에서 관측된 뒤, 나중에 `FeedbackSize=17`만 따로 Set되는 경우를 놓치고 있었다. `caes_modes` 상태를 추적해서 current Mode가 CFB이면 later FeedbackSize도 1..16 범위를 강제하도록 보강했다.
- D4/D5 Geometry/Logging:
  `LockingInfo`, Level 0 geometry descriptor, Opal SSC V2 descriptor, AccessControl logging, Log/LogList는 이미 test/sourced coverage가 충분하다. 추가 후보는 있지만 broad template logging default 일반화는 위험하므로 보류한다.
- D4/D5 Follow-up Check:
  Geometry Reporting Feature Behavior는 `RangeStart`/`RangeLength` alignment formula와 Level 0 Geometry descriptor까지 이미 sourced coverage가 있다. LogEntry read-only columns도 expanded test로 커버되어 있어 신규 패치 후보가 아니었다.

검증 결과:

- `python3 -m unittest discover -s tests -q`: 1297 tests OK
- `DATASET_DIR=dataset LABEL_PATH=dataset/label.jsonl python3 evaluate.py`: score 100.00
- `python3 tools/run_synthetic_edges.py`: 7349 cases, 0 mismatches
- `python3 tools/run_sourced_edges.py`: 4212 cases, 0 mismatches
- Server `/workspace/seungmin/sm` update complete, targeted SP_FAILED/MaxSessions/C_AES tests OK, server public evaluation score 100.00.

## Candidate Acceptance Rule

D에서 새 테스트를 만들 때는 다음 조건을 모두 만족해야 solver 수정 후보로 승격한다.

- 공식 문서 문장과 JSON 로그 필드 사이의 연결이 명확해야 한다.
- 마지막 응답 PASS/FAIL이 하나로 정해져야 한다.
- optional/implementation-defined behavior를 정답으로 강제하지 않아야 한다.
- 기존 88점 안정판에서 false positive나 false negative가 실제로 드러나야 한다.
- 여러 wrapper alias를 넓히는 경우, hidden valid 로그를 과하게 FAIL 처리할 위험이 낮아야 한다.

즉 D는 넓게 파기보다 “JSON-visible하고 기존 solver 모델과 연결 가능한 작은 조각”만 뽑아야 한다.
