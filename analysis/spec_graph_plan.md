# Spec Graph Construction Plan

이 문서는 TCG/Opal 공식 문서를 신뢰도 있게 구조화하기 위한 spec graph 계획이다.

목표는 일반적인 문서 QA용 knowledge graph가 아니다.

목표는 다음이다.

```text
공식 문서 조항
-> 구조화된 Rule
-> 조건/상태 변수/예상 응답
-> sourced edge-case 후보
-> reviewer consensus
-> solver regression
```

## 1. 왜 그래프가 필요한가

현재 `doc_coverage.py`는 어느 문서 파일이 sourced test 근거로 쓰였는지 추적한다.

하지만 이것만으로는 부족하다.

예:

```text
core/5.7.3.2.txt를 evidence로 썼다
```

라는 사실은 알 수 있지만,

```text
Table 230의 14개 row 중 몇 개를 실제로 테스트했는가?
Table 231의 write behavior row는 커버됐는가?
MBR active + read locked + outside MBR -> zeroes row를 커버했는가?
```

는 알기 어렵다.

그래서 문서 파일보다 더 작은 단위인 `Rule`을 만들어야 한다.

## 2. 신뢰도 원칙

그래프 extraction은 세 등급으로 나눈다.

### Tier 1: deterministic

규칙이 표/명시적 구조로 되어 있고, 코드가 직접 파싱한다.

예:

```text
core/5.7.3.2.txt Table 230/231
```

이 경우 LLM이 해석하지 않는다.

표 row를 그대로 condition/expected_behavior로 매핑한다.

### Tier 2: assisted

LLM이 rule 후보를 추출하지만, source span과 reviewer consensus가 붙기 전까지는 accepted rule이 아니다.

예:

```text
긴 자연어 문단
복잡한 RevertSP 효과
ACL BooleanExpr 설명
```

### Tier 3: inferred

문서 여러 곳을 합쳐야만 나오는 규칙이다.

예:

```text
CreateRow로 range 생성
-> 이후 host Write behavior 변화
```

이건 반드시 human/agent review가 필요하다.

## 3. JSONL 파일 구조

그래프는 가볍게 JSONL로 관리한다.

```text
analysis/spec_graph/
  sections.jsonl
  entities.jsonl
  rules.jsonl
  edges.jsonl
  test_links.jsonl
  graph_report.md
```

### sections.jsonl

공식 문서 섹션 단위.

```json
{
  "node_id": "section:core/5.7.3.2",
  "kind": "Section",
  "path": "core/5.7.3.2.txt",
  "title": "5.7.3.2 Reading/Writing User Data",
  "family": "core",
  "chars": 8724,
  "words": 804,
  "sha1": "..."
}
```

### entities.jsonl

규칙에서 쓰이는 개념.

예:

```json
{
  "node_id": "entity:StateVariable:MBRControl.Enable",
  "kind": "StateVariable",
  "name": "MBRControl.Enable"
}
```

주요 kind:

```text
Method
Table
Column
StateVariable
Operation
ExpectedBehavior
Status
Rule
TestCase
```

### rules.jsonl

핵심.

예:

```json
{
  "rule_id": "core-5.7.3.2-table230-row05",
  "node_id": "rule:core-5.7.3.2-table230-row05",
  "kind": "Rule",
  "source": {
    "path": "core/5.7.3.2.txt",
    "table": "Table 230 Interface Read Command Access",
    "row_index": 5,
    "row_text": "| True | False | False | False | True | True | Return all zeroes |"
  },
  "operation": "HostRead",
  "conditions": {
    "MBRControl.Enable": true,
    "MBRControl.Done": false,
    "LBA.StartWithinMBR": false,
    "LBA.EndWithinMBR": false,
    "Locking.ReadLockEnabled": true,
    "Locking.ReadLocked": true
  },
  "expected_behavior": {
    "type": "read_returns",
    "value": "all_zeroes"
  },
  "extraction": {
    "method": "deterministic_markdown_table_parser",
    "trust_tier": "T1",
    "confidence": 1.0,
    "review_status": "needs_review"
  }
}
```

### edges.jsonl

그래프 연결.

예:

```json
{"src":"section:core/5.7.3.2","rel":"CONTAINS_RULE","dst":"rule:core-5.7.3.2-table230-row05"}
{"src":"rule:core-5.7.3.2-table230-row05","rel":"HAS_CONDITION","dst":"entity:StateVariable:MBRControl.Enable","value":true}
{"src":"rule:core-5.7.3.2-table230-row05","rel":"EXPECTS","dst":"entity:ExpectedBehavior:read_returns:all_zeroes"}
```

### test_links.jsonl

sourced test와 graph rule의 연결 후보.

처음에는 conservative하게 간다.

```json
{
  "test_id": "mbr-doc-a7a13ffff0",
  "case_name": "MBR active outside read-locked range returns zeroes",
  "evidence_sources": ["core/5.7.3.2.txt"],
  "candidate_rules": [
    {
      "rule_id": "core-5.7.3.2-table230-row05",
      "score": 0.83,
      "link_status": "candidate_unreviewed"
    }
  ]
}
```

즉 자동 연결은 처음부터 확정 coverage로 보지 않는다.

확정하려면 나중에 review를 붙인다.

## 4. 첫 구축 범위

첫 버전은 `core/5.7.3.2.txt`만 rule graph로 만든다.

이유:

1. 문서가 table 형태라 deterministic parsing이 가능하다.
2. Host Read/Write behavior는 final target과 직접 연결된다.
3. 이미 여기서 solver bug를 하나 찾았다.
4. Table 230/231은 edge-case matrix의 핵심이다.

## 5. 확장 계획

### Phase 1

```text
core/5.7.3.2 Table 230/231
```

### Phase 2

```text
core/5.3.4.1.1.2 Authentication Attempt Limits
core/5.3.3.16 GenKey
core/5.7.2.2.12 NextKey/ReEncryptState
```

### Phase 3

```text
Table Get/Set/CreateRow/DeleteRow
ACL/ACE
Revert/RevertSP
```

### Phase 4

LLM-assisted rule extraction with review.

이 단계에서도 LLM output은 바로 accepted graph가 아니다.

## 6. 사용 명령

그래프 빌드:

```bash
cd /Users/seungmin/ssd-project/sm
source .venv/bin/activate
python tools/build_spec_graph.py
```

출력:

```text
analysis/spec_graph/sections.jsonl
analysis/spec_graph/entities.jsonl
analysis/spec_graph/rules.jsonl
analysis/spec_graph/edges.jsonl
analysis/spec_graph/test_links.jsonl
analysis/spec_graph/graph_report.md
```

## 7. 중요한 제한

이 그래프는 oracle이 아니다.

그래프는 다음을 도와준다.

```text
1. 공식 문서 rule 단위 coverage 추적
2. edge-case 후보 생성
3. reviewer에게 줄 근거 packet 생성
4. solver mismatch 원인 분석
```

하지만 그래프 자체도 extraction artifact다.

따라서:

```text
rule extraction도 review 대상이다.
test label도 review 대상이다.
solver patch도 review 대상이다.
```

이 세 겹을 분리해야 한다.
