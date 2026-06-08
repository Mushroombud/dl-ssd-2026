---
name: ssd-spec-auditor
description: Audit the SSD Opal rule-based evaluator against official spec evidence with minimal token usage. Use when validating score_probe_loop labels, finding missing spec exceptions, creating Ralph-loop batches, deciding local vs GPU execution for Qwen RAG, or reviewing verifier correctness beyond public testset pass rate.
---

# SSD Spec Auditor

Use this skill for two risks:

1. `score_probe_loop.py` probes may have wrong labels because they were generated without RAG/spec grounding.
2. The evaluator may still miss spec exceptions not represented by existing probes.

Do not paste large trajectories or spec excerpts into chat. Generate JSONL packets and inspect only the highest-risk records.

## Runtime Assumption

Assume a GPU environment with local Qwen3 embedding and reranker weights available under `artifacts/models/`.
Do not spend tokens choosing samples. The default probe audit is a full reranked sweep over every `score_probe_loop.py` probe.

For local placement checks, run:

```bash
python3 tools/spec_audit_rag.py profile
```

Default profile does not load Qwen models. Only intentionally benchmark local model execution with `--run-models`; if it starts rebuilding embeddings, stop and move dense/reranker work to GPU.

## Track A: Probe Oracle Audit

On the GPU server, create blind review packets for every generated probe:

```bash
.venv/bin/python tools/spec_audit_rag.py probe-sweep
```

This writes:

- `analysis/spec_audit/probe_sweep_packets.jsonl`
- `analysis/spec_audit/probe_sweep_summary.json`

Use `probe-packets --family <name> --dense --reranker --include-text` only for debugging a narrow family.

Review labels:

- `oracle_confirmed`: direct spec evidence supports the author label.
- `oracle_wrong`: evidence contradicts the author label.
- `oracle_ambiguous`: evidence is insufficient to choose PASS/FAIL.
- `oracle_unsupported`: retrieved evidence does not support this as a spec test.

Only repair evaluator code after accepted evidence supports the test label.

## Track B: Missing Exception Audit

Mine candidate spec obligations and link them to current probe-family coverage:

```bash
.venv/bin/python tools/spec_audit_rag.py obligation-packets --limit 50 --dense --reranker --include-text
```

Review labels:

- `covered`: existing probe families directly cover the obligation.
- `partial`: coverage exists but misses a precondition, payload shape, state transition, or failure side.
- `missing`: no meaningful probe coverage.
- `ambiguous`: candidate text needs cross-section evidence.
- `out_of_scope`: not testable in this evaluator contract.

For `partial` and `missing`, create a narrowed sourced/probe case before changing evaluator behavior.

## Token Discipline

- Do not ask an LLM to choose probes. Run `probe-sweep` once on GPU and work from the JSONL queue.
- Use `--path-contains <section>` only for suspected obligation areas.
- Keep hit text short. The default sweep stores 700 chars per hit.
- Never relabel a probe without retrieved source evidence in the packet.

## Execution Placement

- GPU server: `probe-sweep`, full obligation sweep, embedding rebuilds, and all reranked production packets.
- Local: syntax checks, `profile` without `--run-models`, and lexical debugging only.
