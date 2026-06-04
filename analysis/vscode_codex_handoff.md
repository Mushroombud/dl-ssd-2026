# VS Code Codex Handoff

이 문서는 VS Code Codex에서 이 프로젝트를 이어서 작업하기 위한 인계 문서다.

로컬 프로젝트 위치:

```bash
/Users/seungmin/ssd-project/sm
```

VS Code에서 열 폴더:

```bash
code /Users/seungmin/ssd-project/sm
```

## 1. 프로젝트 목표

Intro to Deep Learning term project의 SSD security protocol verifier를 개선한다.

입력은 SSD command-response log trajectory이고, 마지막 응답이 protocol/spec에 맞는지 판단한다.

출력은:

```text
PASS / FAIL
```

중요:

```text
PASS == 마지막 응답이 스펙상 맞다
FAIL == 마지막 응답이 스펙상 틀리다
```

`SUCCESS` 응답이라고 무조건 PASS가 아니다.  
스펙상 거절되어야 하는 상황에서 `SUCCESS`면 FAIL이다.

## 2. 현재 작업 원칙

이제부터는 감으로 edge case를 만들지 않는다.

공식 문서 기반 sourced test만 solver 개선 근거로 삼는다.

허용되는 근거:

```text
artifacts/documents/core/*.txt
artifacts/documents/opal/*.txt
materials/project.pdf
skeleton README / dataset schema
```

금지:

```text
기존 solver가 그렇게 동작하니까 라벨링
기존 unit test가 그렇게 되어 있으니까 라벨링
LLM이 보기엔 그럴 듯하니까 라벨링
leaderboard/private 점수 추측으로 black-box optimization
```

## 3. 현재 구현 상태

### 기존 solver 구조

메인 facade:

```text
src/solver.py
```

실제 구현:

```text
src/solver_components/constants.py
src/solver_components/models.py
src/solver_components/parsing.py
src/solver_components/semantics.py
src/solver_components/transitions.py
src/solver_components/expectations.py
src/solver_components/engine.py
```

핵심 흐름:

```text
trajectory[:-1]를 parse_event + apply_transition으로 상태 추적
trajectory[-1]를 expected_status로 판단
actual final response와 비교해서 PASS/FAIL
```

### 내가 추가한 개발 도구

공식 문서 기반 테스트:

```text
tools/run_sourced_edges.py
```

비공식 smoke test:

```text
tools/run_synthetic_edges.py
```

공식 문서 coverage 리포터:

```text
tools/doc_coverage.py
```

독립 라벨 consensus / quarantine 장치:

```text
tools/label_consensus.py
```

전략 문서:

```text
analysis/edge_case_generation_plan.md
```

coverage 리포트:

```text
analysis/doc_coverage_report.md
analysis/doc_coverage_matrix.json
analysis/doc_coverage_triage.json
```

label consensus 리포트:

```text
analysis/label_consensus_report.md
analysis/label_consensus_matrix.json
analysis/quarantined_sourced_cases.json
analysis/accepted_sourced_cases.json
analysis/label_reviews/
```

spec graph 빌더:

```text
tools/build_spec_graph.py
analysis/spec_graph/
```

## 4. 이미 발견해서 고친 버그

공식 문서 기반 테스트를 만들다가 실제 solver bug를 하나 찾고 고쳤다.

근거 문서:

```text
artifacts/documents/core/5.7.3.2.txt
artifacts/documents/core/5.7.2.5.2.txt
artifacts/documents/core/5.7.2.5.3.txt
```

내용:

```text
MBR shadowing active
MBRControl.Enable=True
MBRControl.Done=False
target LBA is outside MBR region
ReadLockEnabled=True
ReadLocked=True
```

이 경우 일반 read-locked data protection error가 아니라, Table 230 기준으로 `Return all zeroes`가 맞다.

수정한 파일:

```text
src/solver_components/models.py
src/solver_components/engine.py
src/solver_components/expectations.py
```

수정 내용:

- `ExpectedResponse.expected_zero_read_result` 추가
- read result가 all-zero인지 검사하는 comparator 추가
- MBR active + outside read-locked range branch 수정

## 5. 현재 검증 결과

로컬에서 확인 완료:

```text
491 unit tests passed
sourced edge cases: 52, mismatches: 0
synthetic smoke tests: 205, mismatches: 0
public eval score: 100.00
doc coverage report 생성 OK
label consensus report 생성 OK
spec graph 생성 OK
```

실행 명령:

```bash
cd /Users/seungmin/ssd-project/sm
source .venv/bin/activate

python -m pytest tests/test_solver_rules.py -q
python tools/run_sourced_edges.py
python tools/run_synthetic_edges.py
DATASET_DIR=dataset LABEL_PATH=dataset/label.jsonl python evaluate.py
python tools/doc_coverage.py
python tools/label_consensus.py report
python tools/build_spec_graph.py
```

## 6. 중요한 현재 상태

### Sourced tests

현재 sourced test는 52개다.

```bash
python tools/run_sourced_edges.py
```

결과:

```text
sourced edge cases: 52
mismatches: 0
```

이 중 일부만 independent reviewer consensus를 통과했다.

### Label consensus

현재 completed independent review는 93개다.

```bash
python tools/label_consensus.py report
```

결과:

```text
cases=52
reviews=93
accepted=30
quarantined=22
```

accepted 30개만 consensus gate에서 regression-quality sourced test로 취급된다.

```bash
python tools/run_sourced_edges.py --consensus-gate
```

이 장치는 “검증 안 된 라벨은 regression-quality dataset에 넣지 않는다”는 안전장치다.

## 7. Spec Graph 상태

공식 문서를 rule 단위로 구조화하는 첫 버전이 있다.

빌드:

```bash
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

현재 결과:

```text
sections=1376
entities=110
rules=27
edges=503
test_links=52
```

중요:

```text
rules.jsonl의 rule은 공식 표에서 deterministic하게 뽑은 것이지만 review_status=needs_review다.
test_links.jsonl의 연결은 candidate_unreviewed다.
즉 그래프는 oracle이 아니라, coverage와 review queue를 만드는 장치다.
```

현재 deterministic rule 범위:

```text
artifacts/documents/core/5.7.3.2.txt
Table 230 Interface Read Command Access
Table 231 Interface Write Command Access
```

현재 `graph_report.md` 기준, Table 230/231의 27개 row 중 21개가 sourced test 후보와 연결되고 6개 row가 아직 비어 있다.

## 8. Coverage 상태

공식 문서 coverage baseline:

```bash
python tools/doc_coverage.py
```

현재 대략:

```text
Official document files: 1376
Sourced edge cases: 52
Documents referenced by sourced tests: 12
Untriaged A/B priority documents: 550
```

즉 아직 공식 문서 coverage는 초기 상태다.

리포트:

```text
analysis/doc_coverage_report.md
```

다음 작업은 여기서 `Highest Priority Uncovered Documents`를 보고 하나씩 처리하는 것이다.

## 9. 다음 작업 로드맵

가장 먼저 할 일:

```text
analysis/spec_graph/graph_report.md의 uncovered deterministic rules 6개를 sourced test로 채우기
```

왜 이것부터?

1. Host Read/Write final target은 채점에 직접적이다.
2. 공식 문서가 table 형태라 라벨 근거가 명확하다.
3. 이미 여기서 solver bug를 하나 찾았다.

작업 루프:

```text
1. python tools/doc_coverage.py
2. analysis/doc_coverage_report.md에서 고위험 미커버 문서 하나 선택
3. 공식 문서에서 rule card 추출
4. tools/run_sourced_edges.py에 PASS/FAIL pair 추가
5. python tools/run_sourced_edges.py
6. mismatch 발생 시 문서/context 재확인
7. 필요하면 solver 수정
8. python -m pytest tests/test_solver_rules.py -q
9. DATASET_DIR=dataset LABEL_PATH=dataset/label.jsonl python evaluate.py
10. python tools/doc_coverage.py 재실행
```

## 10. Sourced Test 작성 규칙

`tools/run_sourced_edges.py`에 추가한다.

형식:

```python
evidence = source(
    "core/5.7.3.2.txt",
    rule="Table 230 says ...",
)

cases.append(
    case(
        "short precise name",
        context + [target],
        "PASS",
        evidence,
        "host-io-doc",
    )
)
```

가능하면 pair로 만든다.

```text
correct response -> expected PASS
wrong response   -> expected FAIL
```

주의:

- case 이름에 `impossible success`, `should not` 같은 편향 표현을 쓰면 reviewer에게 라벨이 유출된다.
- 새로 만드는 case는 가능하면 중립적 이름을 쓰는 게 좋다.
- 기존 case 이름은 이미 편향적인 것이 있어서 blind export에서는 case name을 숨긴다.

## 11. Label Consensus Workflow

리뷰용 blind packet 생성:

```bash
python tools/label_consensus.py export --reviewer agent_alpha --tag mbr-doc --no-raw
```

생성:

```text
analysis/label_reviews/agent_alpha.todo.jsonl
```

reviewer는 author label과 case name을 보지 않고, evidence와 trajectory만 보고 label을 작성한다.

완성 파일 예:

```text
analysis/label_reviews/agent_alpha.jsonl
```

형식:

```json
{"reviewer":"agent_alpha","case_id":"mbr-doc-a7a13ffff0","label":"PASS","confidence":0.92,"rationale":"Table 230 says this combination returns all zeroes.","concerns":"","source_refs":["core/5.7.3.2.txt"]}
```

리포트 생성:

```bash
python tools/label_consensus.py report
```

accepted 조건:

```text
최소 reviewer 3명
모든 reviewer label 동일
reviewer consensus가 author label과 동일
모든 confidence >= 0.75
concerns 비어 있음
```

그 외는 quarantine.

## 12. 로컬/서버 작업 방식

기본 작업은 로컬에서 한다.

```bash
cd /Users/seungmin/ssd-project/sm
source .venv/bin/activate
code .
```

서버는 최종 검증/submit용이다.

서버 경로:

```text
/workspace/seungmin/sm
```

서버로 올릴 때:

```bash
cd /Users/seungmin/ssd-project/sm
tar --exclude=.venv --exclude=.pytest_cache --exclude='__pycache__' --exclude='*.pyc' \
  -czf - . | ssh -p 2225 student@147.46.78.20 'cd /workspace/seungmin/sm && tar -xzf -'
```

서버에서 최종 확인:

```bash
cd /workspace/seungmin/sm
python tools/run_sourced_edges.py
python tools/doc_coverage.py
python tools/label_consensus.py report
uv run --with pytest python -m pytest tests/test_solver_rules.py -q
DATASET_DIR=/dl2026/dataset LABEL_PATH=/dl2026/dataset/label.jsonl python evaluate.py
```

주의:

- 서버 shared account의 VS Code Codex 설정은 꼬일 수 있다.
- 가능하면 로컬 VS Code Codex로 작업하고, 서버는 업로드/검증에만 쓴다.

## 13. Git 권장

현재 이 폴더는 `.git` 없는 복사본일 가능성이 높다.

로컬에서 개인 git을 시작하는 것을 권장한다.

```bash
cd /Users/seungmin/ssd-project/sm
git init
git add .
git commit -m "local baseline"
```

주의:

- 팀원 repo에 push하지 않는다.
- remote를 붙이지 않아도 된다.
- 이건 내 변경 추적용이다.

## 14. Codex에게 특히 강조할 것

다음 원칙을 반드시 지켜라.

1. 공식 문서 근거 없는 라벨은 sourced test에 넣지 말 것.
2. sourced test 추가 전후로 `doc_coverage.py`를 돌릴 것.
3. mismatch가 나오면 solver를 바로 고치지 말고 evidence/context를 먼저 재확인할 것.
4. reviewer consensus가 없는 case는 accepted regression dataset으로 취급하지 말 것.
5. public score 100은 private correctness를 보장하지 않는다고 볼 것.
6. leaderboard/private submit 반복으로 black-box optimization하지 말 것.
7. 서버 작업은 최소화하고 로컬에서 작업할 것.

## 15. 빠른 시작

VS Code Codex가 처음 할 일:

```bash
cd /Users/seungmin/ssd-project/sm
source .venv/bin/activate
python tools/doc_coverage.py
python tools/run_sourced_edges.py
python tools/label_consensus.py report
python tools/build_spec_graph.py
```

그 다음:

```text
analysis/spec_graph/graph_report.md를 읽고,
Table 230/231의 uncovered deterministic rule을 하나 골라
공식 문서 근거 기반 PASS/FAIL pair를 tools/run_sourced_edges.py에 추가한다.
```

가장 추천하는 시작점:

```text
analysis/spec_graph/graph_report.md
Uncovered Deterministic Rules
```

이미 일부 케이스가 있으므로, table row coverage가 빠진 조합을 채우는 방향으로 시작하면 된다.
