#!/usr/bin/env python3
"""Build an exhaustive inventory for the parsed official specification shards.

This is the durable ledger for the document-reading loop.  The coverage report
answers "which documents already have sourced tests"; this inventory also keeps
stable per-document metadata so cartographer/reviewer agents can work through
the whole corpus in small batches without relying on memory.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from doc_coverage import (
    DEFAULT_DOC_ROOT,
    DEFAULT_TESTS,
    DEFAULT_TRIAGE,
    ROOT,
    collect_docs,
    doc_sort_key,
    evidence_map,
    load_sourced_cases,
    load_triage,
    normalize_doc_path,
    write_default_triage,
)


DEFAULT_INVENTORY = ROOT / "analysis" / "doc_inventory.jsonl"
DEFAULT_SUMMARY = ROOT / "analysis" / "doc_inventory_summary.md"
DEFAULT_QUEUE = ROOT / "analysis" / "doc_cartography_queue.md"

SOURCE_PDFS = {
    "core": "materials/Opal_Core_Spec.pdf",
    "opal": "materials/Opal_Core_Spec.pdf",
}


@dataclass
class InventoryRow:
    doc_id: str
    path: str
    family: str
    source_pdf: str
    section: str
    parent_path: str
    title: str
    sha256: str
    bytes: int
    chars: int
    words: int
    lines: int
    category: str
    priority: str
    normative_score: int
    high_risk_terms: list[str]
    case_count: int
    cases: list[str]
    triage_status: str
    triage_reason: str
    pipeline_state: str
    recommended_action: str
    needs_subshards: bool
    subshard_reason: str


def section_from_path(path: str) -> str:
    return path.rsplit("/", 1)[-1].removesuffix(".txt")


def parent_for(path: str, all_paths: set[str]) -> str:
    family, _, rest = path.partition("/")
    section = rest.removesuffix(".txt")
    parts = section.split(".")
    while len(parts) > 1:
        parts.pop()
        candidate = f"{family}/{'.'.join(parts)}.txt"
        if candidate in all_paths:
            return candidate
    return ""


def doc_id_for(path: str) -> str:
    return path.removesuffix(".txt").replace("/", ":")


def pipeline_state(doc: Any) -> str:
    if doc.case_count:
        return "covered_by_sourced_case"
    if doc.triage_status not in {"untriaged", "covered"}:
        return f"manual_triaged:{doc.triage_status}"
    if doc.priority in {"A", "B"}:
        return "pending_cartography"
    if doc.normative_score > 0:
        return "pending_low_priority_cartography"
    return "pending_non_normative_audit"


def recommended_action(state: str) -> str:
    if state == "covered_by_sourced_case":
        return "keep in regression coverage; revisit only for combination expansion"
    if state.startswith("manual_triaged:"):
        return "respect manual triage unless a cross-doc rule needs it"
    if state == "pending_cartography":
        return "send to cartographer agent for rule-slice extraction or explicit manual triage"
    if state == "pending_low_priority_cartography":
        return "defer until A/B queue shrinks or when cross-doc linker needs it"
    return "audit quickly; mark supporting_definition/duplicate/non_testable if appropriate"


def subshard_hint(chars: int, normative_score: int, text: str) -> tuple[bool, str]:
    table_like = len(re.findall(r"\bTable\b|^\s*\|", text, re.IGNORECASE | re.MULTILINE))
    reasons: list[str] = []
    if chars > 12000:
        reasons.append(f"large section ({chars} chars)")
    if normative_score > 80:
        reasons.append(f"many normative signals ({normative_score})")
    if table_like > 12:
        reasons.append(f"table-heavy ({table_like} table markers)")
    return bool(reasons), "; ".join(reasons)


def build_rows(doc_root: Path, tests_path: Path, triage_path: Path) -> list[InventoryRow]:
    write_default_triage(triage_path)
    triage = load_triage(triage_path)
    cases = load_sourced_cases(tests_path)
    docs = collect_docs(doc_root, evidence_map(cases), triage)
    all_paths = {doc.path for doc in docs}

    rows: list[InventoryRow] = []
    for doc in docs:
        file_path = doc_root / doc.path
        text = file_path.read_text(encoding="utf-8", errors="replace")
        encoded = text.encode("utf-8")
        family = doc.path.split("/", 1)[0]
        state = pipeline_state(doc)
        needs_subshards, subshard_reason = subshard_hint(len(text), doc.normative_score, text)
        rows.append(
            InventoryRow(
                doc_id=doc_id_for(doc.path),
                path=doc.path,
                family=family,
                source_pdf=SOURCE_PDFS.get(family, ""),
                section=section_from_path(doc.path),
                parent_path=parent_for(doc.path, all_paths),
                title=doc.title,
                sha256=hashlib.sha256(encoded).hexdigest(),
                bytes=len(encoded),
                chars=len(text),
                words=len(re.findall(r"\S+", text)),
                lines=len(text.splitlines()),
                category=doc.category,
                priority=doc.priority,
                normative_score=doc.normative_score,
                high_risk_terms=doc.high_risk_terms,
                case_count=doc.case_count,
                cases=doc.cases,
                triage_status=doc.triage_status,
                triage_reason=doc.triage_reason,
                pipeline_state=state,
                recommended_action=recommended_action(state),
                needs_subshards=needs_subshards,
                subshard_reason=subshard_reason,
            )
        )
    return rows


def render_summary(rows: list[InventoryRow]) -> str:
    by_family = Counter(row.family for row in rows)
    by_state = Counter(row.pipeline_state for row in rows)
    by_priority = Counter(row.priority for row in rows)
    by_category = Counter(row.category for row in rows)
    pending_ab = [
        row
        for row in rows
        if row.pipeline_state == "pending_cartography" and row.priority in {"A", "B"}
    ]
    pending_ab.sort(key=lambda row: (row.priority, -row.normative_score, row.path))
    subshard_rows = [row for row in rows if row.needs_subshards]

    lines: list[str] = []
    lines.append("# Official Document Inventory Summary")
    lines.append("")
    lines.append(f"Generated: {datetime.now().isoformat(timespec='seconds')}")
    lines.append("")
    lines.append("## Totals")
    lines.append("")
    lines.append(f"- Inventory rows: {len(rows)}")
    lines.append(f"- Families: {dict(sorted(by_family.items()))}")
    lines.append(f"- Covered by sourced cases: {by_state.get('covered_by_sourced_case', 0)}")
    lines.append(f"- Pending A/B cartography: {len(pending_ab)}")
    lines.append(f"- Sections recommended for subsharding: {len(subshard_rows)}")
    lines.append("")
    lines.append("## Pipeline State")
    lines.append("")
    for state, count in sorted(by_state.items()):
        lines.append(f"- `{state}`: {count}")
    lines.append("")
    lines.append("## Priority")
    lines.append("")
    for priority, count in sorted(by_priority.items()):
        lines.append(f"- `{priority}`: {count}")
    lines.append("")
    lines.append("## Category")
    lines.append("")
    for category, count in sorted(by_category.items()):
        lines.append(f"- `{category}`: {count}")
    lines.append("")
    lines.append("## Highest Priority Pending Documents")
    lines.append("")
    for row in pending_ab[:60]:
        terms = ", ".join(row.high_risk_terms[:6]) or "-"
        lines.append(
            f"- `{row.path}` [{row.priority}/{row.category}] "
            f"score={row.normative_score}, terms={terms}"
        )
        lines.append(f"  - title: {row.title}")
    lines.append("")
    lines.append("## Subshard Candidates")
    lines.append("")
    if not subshard_rows:
        lines.append("- None.")
    else:
        for row in sorted(subshard_rows, key=lambda item: (-item.normative_score, -item.chars, item.path))[:40]:
            lines.append(f"- `{row.path}`: {row.subshard_reason}")
    lines.append("")
    return "\n".join(lines) + "\n"


def render_queue(rows: list[InventoryRow], batch_size: int) -> str:
    pending = [
        row
        for row in rows
        if row.pipeline_state == "pending_cartography" and row.priority in {"A", "B"}
    ]
    pending.sort(key=lambda row: (row.priority, row.category, -row.normative_score, row.path))

    grouped: dict[tuple[str, str], list[InventoryRow]] = defaultdict(list)
    for row in pending:
        grouped[(row.priority, row.category)].append(row)

    lines: list[str] = []
    lines.append("# Cartography Queue")
    lines.append("")
    lines.append("This queue is regenerated from `analysis/doc_inventory.jsonl`.")
    lines.append("Each batch is small enough for one cartographer agent to inspect without relying on conversation memory.")
    lines.append("A/B priority shards stay in this queue even when the keyword heuristic gives them score 0; those batches should either produce a rule slice or get explicit manual triage.")
    lines.append("")
    lines.append(f"- Pending A/B documents: {len(pending)}")
    lines.append(f"- Suggested batch size: {batch_size}")
    lines.append("")
    for (priority, category), items in sorted(grouped.items()):
        lines.append(f"## {priority} / {category}")
        lines.append("")
        for index in range(0, len(items), batch_size):
            batch = items[index : index + batch_size]
            batch_id = f"{priority}-{category}-{index // batch_size + 1:03d}"
            lines.append(f"### Batch `{batch_id}`")
            lines.append("")
            for row in batch:
                sub = " subshard" if row.needs_subshards else ""
                lines.append(f"- `{row.path}` score={row.normative_score}{sub} - {row.title}")
            lines.append("")
    return "\n".join(lines)


def write_jsonl(path: Path, rows: list[InventoryRow]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(asdict(row), ensure_ascii=False, sort_keys=True) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--docs", type=Path, default=DEFAULT_DOC_ROOT)
    parser.add_argument("--tests", type=Path, default=DEFAULT_TESTS)
    parser.add_argument("--triage", type=Path, default=DEFAULT_TRIAGE)
    parser.add_argument("--inventory", type=Path, default=DEFAULT_INVENTORY)
    parser.add_argument("--summary", type=Path, default=DEFAULT_SUMMARY)
    parser.add_argument("--queue", type=Path, default=DEFAULT_QUEUE)
    parser.add_argument("--batch-size", type=int, default=20)
    args = parser.parse_args()

    rows = build_rows(args.docs, args.tests, args.triage)
    write_jsonl(args.inventory, rows)
    args.summary.write_text(render_summary(rows), encoding="utf-8")
    args.queue.write_text(render_queue(rows, max(1, args.batch_size)), encoding="utf-8")

    states = Counter(row.pipeline_state for row in rows)
    print(f"inventory_rows={len(rows)} inventory={args.inventory}")
    print(f"states={dict(sorted(states.items()))}")
    print(f"summary={args.summary}")
    print(f"queue={args.queue}")


if __name__ == "__main__":
    main()
