# Prompt To Give VS Code Codex

아래 내용을 VS Code Codex 새 작업에 붙여넣으면 된다.

```text
You are continuing work on the SSD verifier project in /Users/seungmin/ssd-project/sm.

First read:
- analysis/vscode_codex_handoff.md
- analysis/edge_case_generation_plan.md
- analysis/doc_coverage_report.md
- analysis/label_consensus_report.md

Project goal:
Improve the rule-based SSD security protocol verifier. The model reads a command-response trajectory and predicts whether the final response is protocol-compliant: PASS or FAIL.

Important policy:
- Do not label sourced edge cases by intuition.
- Every sourced case must cite official documents in artifacts/documents/core or artifacts/documents/opal, or project/skeleton schema docs.
- Existing solver behavior and existing unit tests are not valid label sources.
- Do not do leaderboard/private black-box optimization.
- If a sourced test mismatch appears, re-check the official document and test context before changing solver code.
- Label consensus is required before treating sourced cases as accepted regression data.

Current local commands:
cd /Users/seungmin/ssd-project/sm
source .venv/bin/activate
python tools/run_sourced_edges.py
python tools/doc_coverage.py
python tools/label_consensus.py report
python -m pytest tests/test_solver_rules.py -q
DATASET_DIR=dataset LABEL_PATH=dataset/label.jsonl python evaluate.py

Current state:
- Unit tests pass: 491 passed.
- Public eval score: 100.00.
- Sourced edge cases: 30, mismatches: 0.
- Synthetic smoke tests: 205, mismatches: 0.
- Document coverage is still very incomplete: about 550 untriaged A/B priority docs.
- Label consensus currently has 0 accepted cases because no independent reviews have been completed yet.

Main next task:
Use analysis/doc_coverage_report.md to drive coverage. Start with host I/O / Locking / MBR, especially artifacts/documents/core/5.7.3.2.txt Table 230 and Table 231. Convert missing table rows into official-document-sourced PASS/FAIL pairs in tools/run_sourced_edges.py.

Workflow:
1. Run python tools/doc_coverage.py.
2. Pick a high-priority uncovered official document.
3. Read the official source text.
4. Extract one rule card.
5. Add minimal PASS/FAIL pair to tools/run_sourced_edges.py with Evidence.sources and rule summary.
6. Run python tools/run_sourced_edges.py.
7. If mismatch, verify source/context first.
8. If solver bug is confirmed, patch solver narrowly.
9. Run unit tests and public eval.
10. Regenerate doc coverage and label consensus reports.

Be careful:
- Case names should be neutral when possible; blind label review hides case names by default, but new cases should avoid leaking labels anyway.
- Do not trust author labels until independent consensus reviews agree.
- Keep changes focused and document why each sourced case exists.
```
