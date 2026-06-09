#!/usr/bin/env python3
"""Summarize spec-audit probe sweep packets without assigning oracle labels."""

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


DEFAULT_IN = Path("analysis/spec_audit/probe_sweep_packets.jsonl")
DEFAULT_OUT = Path("analysis/spec_audit/probe_sweep_triage.json")


def load_packets(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.exists():
        return rows
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                rows.append(json.loads(line))
    return rows


def is_authoritative_hit(hit: dict[str, Any]) -> bool:
    path = str(hit.get("path", ""))
    return path.startswith("core/") or path.startswith("opal/") or path.startswith("_pdf_enrichment/")


def packet_review_flags(packet: dict[str, Any]) -> tuple[int, list[str]]:
    reasons: list[str] = []
    if packet.get("author_expected") != packet.get("current_solver_label"):
        reasons.append("author_current_mismatch")
    hits = packet.get("retrieval", {}).get("hits", [])
    if not hits:
        reasons.append("no_hits")
    elif not any(is_authoritative_hit(hit) for hit in hits):
        reasons.append("no_authoritative_hit")
    if packet.get("author_expected") == "PASS" and packet.get("target_event", {}).get("status") not in {None, "SUCCESS", "PASS"}:
        reasons.append("pass_with_non_success_status")
    if packet.get("author_expected") == "FAIL" and packet.get("target_event", {}).get("status") in {"SUCCESS", "PASS"}:
        reasons.append("impossible_success_fail")
    return len(reasons), reasons


def summarize(rows: list[dict[str, Any]], limit: int) -> dict[str, Any]:
    by_family = Counter(row.get("family", "") for row in rows)
    by_expected = Counter(row.get("author_expected", "") for row in rows)
    current_mismatches = [
        row
        for row in rows
        if row.get("author_expected") != row.get("current_solver_label")
    ]
    flagged_rows = []
    for row in rows:
        flag_count, reasons = packet_review_flags(row)
        if flag_count:
            hits = row.get("retrieval", {}).get("hits", [])
            flagged_rows.append(
                {
                    "index": row.get("index"),
                    "probe_id": row.get("probe_id"),
                    "family": row.get("family"),
                    "name": row.get("name"),
                    "author_expected": row.get("author_expected"),
                    "current_solver_label": row.get("current_solver_label"),
                    "reasons": reasons,
                    "top_hit_paths": [hit.get("path") for hit in hits[:5]],
                }
            )
    flagged_rows.sort(key=lambda item: (-len(item["reasons"]), item["family"] or "", item["index"] or 0))

    family_review_flags: dict[str, Counter[str]] = defaultdict(Counter)
    for item in flagged_rows:
        for reason in item["reasons"]:
            family_review_flags[item["family"]][reason] += 1

    return {
        "schema": 1,
        "packets": len(rows),
        "by_expected": dict(sorted(by_expected.items())),
        "by_family": dict(sorted(by_family.items())),
        "current_mismatch_count": len(current_mismatches),
        "review_flag_count": len(flagged_rows),
        "family_review_flags": {
            family: dict(counter.most_common())
            for family, counter in sorted(family_review_flags.items())
        },
        "top_review_flag_packets": flagged_rows[:limit],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=DEFAULT_IN)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--limit", type=int, default=100)
    args = parser.parse_args()

    summary = summarize(load_packets(args.input), args.limit)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(summary, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
    print(
        f"packets={summary['packets']} current_mismatches={summary['current_mismatch_count']} "
        f"review_flags={summary['review_flag_count']} out={args.out}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
