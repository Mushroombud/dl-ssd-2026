# Cartography Queue

This queue is regenerated from `analysis/doc_inventory.jsonl`.
Each batch is small enough for one cartographer agent to inspect without relying on conversation memory.
A/B priority shards stay in this queue even when the keyword heuristic gives them score 0; those batches should either produce a rule slice or get explicit manual triage.

- Pending A/B documents: 0
- Suggested batch size: 20
