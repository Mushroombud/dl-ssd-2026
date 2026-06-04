# Independent Label Review Protocol

This folder is for blind reviews of `tools/run_sourced_edges.py` labels.

The point is to avoid trusting one author's interpretation of TCG/Opal rules.

## Files

- `*.todo.jsonl`: packets to give to a reviewer/agent.
- `*.jsonl`: completed reviewer labels.
- Do not count the original author label as a reviewer label.

## Reviewer Rules

Each reviewer should:

1. Read only the packet evidence and trajectory.
2. Ignore solver output.
3. Ignore the original author's expected label.
4. Return exactly `PASS` or `FAIL`.
5. Give confidence from `0.0` to `1.0`.
6. Put any ambiguity in `concerns`.

The default export hides case names and author labels because many case names
contain words like `impossible success`, which leak the intended answer.

## Completed Review Format

Each completed line should look like:

```json
{"reviewer":"agent_alpha","case_id":"mbr-doc-a7a13ffff0","label":"PASS","confidence":0.92,"rationale":"Table 230 says this combination returns all zeroes.","concerns":"","source_refs":["core/5.7.3.2.txt"]}
```

## Commands

Generate a blind packet:

```bash
cd /workspace/seungmin/sm
python tools/label_consensus.py export --reviewer agent_alpha --tag mbr-doc --no-raw
```

After the reviewer creates `analysis/label_reviews/agent_alpha.jsonl`:

```bash
python tools/label_consensus.py report
```

Only accepted cases can be run with:

```bash
python tools/run_sourced_edges.py --consensus-gate
```

Current policy:

- minimum reviewers: 3
- minimum confidence: 0.75
- any disagreement, low confidence, or concerns => quarantine
