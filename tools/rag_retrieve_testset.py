#!/usr/bin/env python3
"""Run RAG retrieval against the current public testcase set."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from evaluate import case_number, load_json, load_labels
from src.rag_retrieval import build_query_from_trajectory, hit_to_json, load_chunks, retrieve


DEFAULT_DATASET_DIR = ROOT / "dataset" / "testcases"
DEFAULT_LABEL_PATH = ROOT / "dataset" / "label.jsonl"
DEFAULT_REPORT = ROOT / "analysis" / "rag_retrieval_testset.jsonl"
DEFAULT_SUMMARY = ROOT / "analysis" / "rag_retrieval_summary.md"


def target_summary(steps: list[dict]) -> dict:
    from src.solver_components.parsing import parse_event

    target = parse_event(steps[-1])
    return {
        "method": target.method,
        "kind": target.kind,
        "invoking": target.invoking_symbol or target.invoking_name or target.invoking_uid,
        "status": target.status,
        "sp": target.sp,
        "authority": target.authority,
    }


def render_summary(rows: list[dict], use_dense: bool, use_reranker: bool) -> str:
    lines = [
        "# RAG Retrieval Testset Summary",
        "",
        f"- cases: {len(rows)}",
        f"- dense: {use_dense}",
        f"- reranker: {use_reranker}",
        f"- cases_with_hits: {sum(bool(row['hits']) for row in rows)}",
        "",
        "## Top Hits",
        "",
    ]
    for row in rows:
        lines.append(f"### {row['case_id']} ({row.get('label', '?')})")
        target = row["target"]
        lines.append(
            f"- target: {target['method']} {target['invoking']} status={target['status']}"
        )
        for index, hit in enumerate(row["hits"][:5], start=1):
            score = hit["rerank_score"] if hit.get("rerank_score") is not None else hit["score"]
            lines.append(f"- {index}. `{hit['path']}` score={score:.4f} title={hit['title']}")
        lines.append("")
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset-dir", type=Path, default=DEFAULT_DATASET_DIR)
    parser.add_argument("--label-path", type=Path, default=DEFAULT_LABEL_PATH)
    parser.add_argument("--out", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--summary", type=Path, default=DEFAULT_SUMMARY)
    parser.add_argument("--case-limit", type=int, default=0, help="Limit cases for quick smoke runs.")
    parser.add_argument("--candidate-top-k", type=int, default=40)
    parser.add_argument("--final-top-k", type=int, default=10)
    parser.add_argument("--no-dense", action="store_true")
    parser.add_argument("--no-reranker", action="store_true")
    parser.add_argument("--include-text", action="store_true")
    args = parser.parse_args()

    labels = load_labels(args.label_path) if args.label_path.exists() else {}
    paths = sorted(args.dataset_dir.glob("tc*.json"), key=case_number)
    if args.case_limit:
        paths = paths[: args.case_limit]

    chunks = load_chunks()
    rows: list[dict] = []
    for path in paths:
        steps = load_json(path)
        query = build_query_from_trajectory(steps)
        hits = retrieve(
            query,
            chunks=chunks,
            candidate_top_k=args.candidate_top_k,
            final_top_k=args.final_top_k,
            use_dense=not args.no_dense,
            use_reranker=not args.no_reranker,
        )
        row = {
            "case_id": path.name,
            "label": labels.get(path.name),
            "target": target_summary(steps),
            "query": query,
            "hits": [hit_to_json(hit, include_text=args.include_text) for hit in hits],
        }
        rows.append(row)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
    args.summary.write_text(
        render_summary(rows, use_dense=not args.no_dense, use_reranker=not args.no_reranker),
        encoding="utf-8",
    )
    print(f"cases={len(rows)} chunks={len(chunks)} out={args.out} summary={args.summary}")


if __name__ == "__main__":
    main()
