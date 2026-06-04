#!/usr/bin/env python3
"""Continuous verification runner for sourced edge-case work.

This script does not invent new cases. It keeps the mechanical part of the
edge-case loop moving: consensus refresh, accepted-case gate, full sourced
run, synthetic run, unit tests, public eval, and document coverage inventory.
Each pass appends a compact JSONL record so interrupted Codex sessions can
resume from the last known state instead of rediscovering it.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import time
from datetime import datetime
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LOG = ROOT / "analysis" / "continuous_edge_loop.jsonl"
DEFAULT_STATUS = ROOT / "analysis" / "continuous_edge_loop_status.md"
MATRIX = ROOT / "analysis" / "label_consensus_matrix.json"


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def run_step(name: str, cmd: list[str], *, timeout: int, env: dict[str, str] | None = None) -> dict[str, Any]:
    started = time.time()
    step_env = os.environ.copy()
    if env:
        step_env.update(env)
    try:
        completed = subprocess.run(
            cmd,
            cwd=ROOT,
            env=step_env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            check=False,
        )
        output = completed.stdout[-6000:]
        return {
            "name": name,
            "cmd": cmd,
            "returncode": completed.returncode,
            "seconds": round(time.time() - started, 2),
            "output_tail": output,
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "name": name,
            "cmd": cmd,
            "returncode": 124,
            "seconds": round(time.time() - started, 2),
            "output_tail": (exc.stdout or "")[-6000:] if isinstance(exc.stdout, str) else "",
            "timeout": timeout,
        }


def matrix_counts() -> dict[str, Any]:
    if not MATRIX.exists():
        return {}
    rows = json.loads(MATRIX.read_text(encoding="utf-8"))
    status_counts: dict[str, int] = {}
    accepted_by_tag: dict[str, int] = {}
    needs_review_by_tag: dict[str, int] = {}
    for row in rows:
        status = str(row.get("status", "unknown"))
        tag = str(row.get("tag", "unknown"))
        status_counts[status] = status_counts.get(status, 0) + 1
        if status == "accepted":
            accepted_by_tag[tag] = accepted_by_tag.get(tag, 0) + 1
        if status == "needs_review":
            needs_review_by_tag[tag] = needs_review_by_tag.get(tag, 0) + 1
    return {
        "total": len(rows),
        "status_counts": status_counts,
        "accepted_by_tag": dict(sorted(accepted_by_tag.items())),
        "needs_review_by_tag": dict(sorted(needs_review_by_tag.items())),
    }


def append_jsonl(path: Path, row: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def write_status(path: Path, record: dict[str, Any]) -> None:
    lines = [
        "# Continuous Edge Loop Status",
        "",
        f"- updated: {record['finished_at']}",
        f"- pass: {record['pass_index']}",
        f"- overall_ok: {record['overall_ok']}",
        "",
        "## Consensus",
        "",
        "```json",
        json.dumps(record.get("matrix_counts", {}), ensure_ascii=False, indent=2, sort_keys=True),
        "```",
        "",
        "## Steps",
        "",
    ]
    for step in record["steps"]:
        lines.append(f"- {step['name']}: rc={step['returncode']} seconds={step['seconds']}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def default_steps(include_slow: bool) -> list[tuple[str, list[str], int, dict[str, str] | None]]:
    py = "python3"
    public_eval_env = {
        "DATASET_DIR": "dataset",
        "LABEL_PATH": "dataset/label.jsonl",
    }
    steps: list[tuple[str, list[str], int, dict[str, str] | None]] = [
        ("consensus-report", [py, "tools/label_consensus.py", "report"], 180, None),
        ("consensus-gate", [py, "tools/run_sourced_edges.py", "--consensus-gate"], 240, None),
        ("sourced-all", [py, "tools/run_sourced_edges.py"], 240, None),
        ("synthetic", [py, "tools/run_synthetic_edges.py"], 180, None),
        ("public-eval", [".venv/bin/python", "evaluate.py"], 240, public_eval_env),
        ("doc-coverage", [py, "tools/doc_coverage.py"], 240, None),
        ("doc-inventory", [py, "tools/build_doc_inventory.py"], 240, None),
    ]
    if include_slow:
        steps.insert(4, ("unit-tests", [".venv/bin/python", "-m", "pytest", "tests/test_solver_rules.py", "-q"], 420, None))
    return steps


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=int, default=1, help="Number of passes. Use 0 for endless.")
    parser.add_argument("--sleep", type=int, default=600, help="Seconds between passes.")
    parser.add_argument("--include-slow", action="store_true", help="Run unit tests on each pass.")
    parser.add_argument("--log", type=Path, default=DEFAULT_LOG)
    parser.add_argument("--status", type=Path, default=DEFAULT_STATUS)
    args = parser.parse_args()

    pass_index = 0
    while args.iterations == 0 or pass_index < args.iterations:
        pass_index += 1
        record: dict[str, Any] = {
            "pass_index": pass_index,
            "started_at": now_iso(),
            "steps": [],
        }
        for name, cmd, timeout, env in default_steps(args.include_slow):
            step = run_step(name, cmd, timeout=timeout, env=env)
            record["steps"].append(step)
        record["matrix_counts"] = matrix_counts()
        record["finished_at"] = now_iso()
        record["overall_ok"] = all(step["returncode"] == 0 for step in record["steps"])
        append_jsonl(args.log, record)
        write_status(args.status, record)
        if not record["overall_ok"]:
            return 1
        if args.iterations != 0 and pass_index >= args.iterations:
            break
        time.sleep(args.sleep)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
