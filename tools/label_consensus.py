#!/usr/bin/env python3
"""Independent label-review and consensus gate for sourced edge cases."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import sys
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CASES = ROOT / "tools" / "run_sourced_edges.py"
DEFAULT_REVIEW_DIR = ROOT / "analysis" / "label_reviews"
DEFAULT_REPORT = ROOT / "analysis" / "label_consensus_report.md"
DEFAULT_MATRIX = ROOT / "analysis" / "label_consensus_matrix.json"
DEFAULT_QUARANTINE = ROOT / "analysis" / "quarantined_sourced_cases.json"
DEFAULT_ACCEPTED = ROOT / "analysis" / "accepted_sourced_cases.json"
LOCAL_DOC_ROOT = ROOT / "artifacts" / "documents"


@dataclass
class Review:
    reviewer: str
    case_id: str
    label: str
    confidence: float
    rationale: str
    concerns: str
    source_refs: list[str]
    path: str
    line: int


def parse_confidence(value: Any) -> float:
    if isinstance(value, str):
        normalized = value.strip().lower()
        text_scores = {
            "high": 1.0,
            "medium": 0.75,
            "med": 0.75,
            "low": 0.5,
        }
        if normalized in text_scores:
            return text_scores[normalized]
    try:
        return max(0.0, min(1.0, float(value)))
    except (TypeError, ValueError):
        return 0.0


def load_case_module(path: Path) -> Any:
    spec = importlib.util.spec_from_file_location("sourced_edges_for_consensus", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load sourced edge cases from {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def slugify(text: str) -> str:
    lowered = text.lower()
    cleaned = re.sub(r"[^a-z0-9]+", "-", lowered).strip("-")
    return cleaned[:40] or "case"


def case_id(case: Any) -> str:
    digest = hashlib.sha1(f"{case.tag}\n{case.name}".encode("utf-8")).hexdigest()[:10]
    return f"{slugify(case.tag)}-{digest}"


def normalize_doc_path(value: str) -> str:
    value = value.replace("\\", "/")
    marker = "/documents/"
    if marker in value:
        return value.split(marker, 1)[1].lstrip("/")
    if value.startswith("artifacts/documents/"):
        return value.split("artifacts/documents/", 1)[1]
    return value.lstrip("/")


def resolve_source(value: str) -> Path | None:
    raw = Path(value)
    if raw.exists():
        return raw
    relative = normalize_doc_path(value)
    local = LOCAL_DOC_ROOT / relative
    if local.exists():
        return local
    return None


def _query_terms(query: str) -> list[str]:
    terms = re.findall(r"[A-Za-z0-9_]{4,}", query)
    stopwords = {
        "that",
        "this",
        "with",
        "from",
        "when",
        "then",
        "only",
        "table",
        "method",
        "source",
        "status",
        "return",
        "returned",
        "requested",
        "columns",
        "values",
    }
    unique: dict[str, str] = {}
    for term in terms:
        lowered = term.lower()
        if lowered in stopwords:
            continue
        unique.setdefault(lowered, term)
    return sorted(unique.values(), key=len, reverse=True)


def source_snippets(sources: list[str], max_chars: int = 12000, query: str = "") -> list[dict[str, str]]:
    snippets: list[dict[str, str]] = []
    terms = _query_terms(query)
    for source in sources:
        path = resolve_source(source)
        if path is None:
            snippets.append({"source": source, "text": "[source file not found]"})
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        normalized = re.sub(r"\s+", " ", text).strip()
        starts: list[int] = []
        for term in terms:
            match = re.search(re.escape(term), normalized, re.IGNORECASE)
            if match:
                start = max(0, match.start() - max_chars // 6)
                if all(abs(start - existing) > max_chars // 3 for existing in starts):
                    starts.append(start)
                if len(starts) >= 3:
                    break
        if not starts:
            starts = [0]
        part_budget = max(1000, max_chars // len(starts))
        parts: list[str] = []
        for start in sorted(starts):
            part = normalized[start : start + part_budget]
            if start:
                part = "... " + part
            if start + part_budget < len(normalized):
                part += " ..."
            parts.append(part)
        snippet = "\n[...]\n".join(parts)
        snippets.append({"source": normalize_doc_path(source), "text": snippet})
    return snippets


def compact_record(raw: dict[str, Any]) -> dict[str, Any]:
    input_obj = raw.get("input", {}) if isinstance(raw, dict) else {}
    output_obj = raw.get("output", {}) if isinstance(raw, dict) else {}
    method = input_obj.get("method")
    method_name = method.get("name") if isinstance(method, dict) else method
    invoking = input_obj.get("invoking_id", {})
    return {
        "input_command": input_obj.get("command") or input_obj.get("function") or input_obj.get("operation") or input_obj.get("type"),
        "method": method_name,
        "invoking_id": invoking,
        "args": input_obj.get("args") or (method.get("args") if isinstance(method, dict) else None),
        "output_status": output_obj.get("status_codes") or output_obj.get("status"),
        "output_return": output_obj.get("return") if "return" in output_obj else output_obj.get("return_values"),
        "output_args": output_obj.get("args"),
    }


def review_packet(
    case: Any,
    *,
    include_author_label: bool = False,
    include_case_name: bool = False,
    include_raw: bool = True,
) -> dict[str, Any]:
    sources = list(case.evidence.sources)
    packet = {
        "reviewer": "",
        "case_id": case_id(case),
        "tag": case.tag,
        "task": "Independently label whether the final response is protocol-compliant. Use only the evidence and trajectory. Return PASS or FAIL.",
        "label": None,
        "confidence": None,
        "rationale": "",
        "concerns": "",
        "source_refs": [],
        "evidence": {
            "sources": [normalize_doc_path(item) for item in sources],
            "rule_summary_from_author": case.evidence.rule,
            "source_snippets": source_snippets(sources, query=case.evidence.rule),
        },
        "trajectory": {
            "num_steps": len(case.trajectory),
            "context_steps": [compact_record(item) for item in case.trajectory[:-1]],
            "target_step": compact_record(case.trajectory[-1]),
        },
        "output_schema": {
            "reviewer": "stable reviewer id",
            "case_id": case_id(case),
            "label": "PASS or FAIL",
            "confidence": "0.0 to 1.0",
            "rationale": "short explanation grounded in source text",
            "concerns": "empty string if none; otherwise state ambiguity",
            "source_refs": ["source paths or sections used"],
        },
    }
    if include_author_label:
        packet["author_expected"] = case.expected
    if include_case_name:
        packet["case_name"] = case.name
    if include_raw:
        packet["trajectory"]["raw"] = case.trajectory
    return packet


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, default=str) + "\n")


def read_reviews(review_dir: Path) -> list[Review]:
    reviews: list[Review] = []
    if not review_dir.exists():
        return reviews
    for path in sorted(review_dir.glob("*.jsonl")):
        if path.name.endswith(".todo.jsonl"):
            continue
        with path.open("r", encoding="utf-8") as handle:
            for line_no, line in enumerate(handle, 1):
                if not line.strip():
                    continue
                data = json.loads(line)
                label = str(data.get("label", "")).upper()
                if label not in {"PASS", "FAIL"}:
                    continue
                reviewer = str(data.get("reviewer") or path.stem)
                confidence = parse_confidence(data.get("confidence", 0))
                raw_concerns = data.get("concerns", "")
                if isinstance(raw_concerns, list):
                    concerns = "; ".join(str(item) for item in raw_concerns if str(item).strip())
                elif raw_concerns is None:
                    concerns = ""
                else:
                    concerns = str(raw_concerns)
                reviews.append(
                    Review(
                        reviewer=reviewer,
                        case_id=str(data.get("case_id", "")),
                        label=label,
                        confidence=confidence,
                        rationale=str(data.get("rationale", "")),
                        concerns=concerns,
                        source_refs=list(data.get("source_refs", [])) if isinstance(data.get("source_refs", []), list) else [],
                        path=str(path),
                        line=line_no,
                    )
                )
    return reviews


def status_for(case: Any, reviews: list[Review], *, min_reviewers: int, min_confidence: float) -> tuple[str, str]:
    if len(reviews) < min_reviewers:
        return "needs_review", f"{len(reviews)}/{min_reviewers} independent reviews present"

    labels = {review.label for review in reviews}
    if len(labels) > 1:
        return "quarantine_disagreement", "reviewers disagree with each other"
    label = next(iter(labels))
    if label != case.expected:
        return "quarantine_author_disagreement", f"reviewer consensus {label} disagrees with author label {case.expected}"

    low_conf = [review for review in reviews if review.confidence < min_confidence]
    if low_conf:
        return "quarantine_low_confidence", f"{len(low_conf)} review(s) below confidence {min_confidence}"

    concerned = [review for review in reviews if review.concerns.strip()]
    if concerned:
        return "quarantine_concerns", f"{len(concerned)} review(s) recorded concerns"

    return "accepted", "all independent reviews agree with author label"


def matrix_rows(cases: list[Any], reviews: list[Review], *, min_reviewers: int, min_confidence: float) -> list[dict[str, Any]]:
    by_case: dict[str, list[Review]] = {}
    for review in reviews:
        by_case.setdefault(review.case_id, []).append(review)

    rows: list[dict[str, Any]] = []
    for item in cases:
        cid = case_id(item)
        item_reviews = by_case.get(cid, [])
        status, reason = status_for(item, item_reviews, min_reviewers=min_reviewers, min_confidence=min_confidence)
        rows.append(
            {
                "case_id": cid,
                "case_name": item.name,
                "tag": item.tag,
                "rule_id": getattr(item, "rule_id", ""),
                "concepts": list(getattr(item, "concepts", ())),
                "repair_paths": list(getattr(item, "repair_paths", ())),
                "repair_hint": getattr(item, "repair_hint", ""),
                "author_expected": item.expected,
                "status": status,
                "reason": reason,
                "review_count": len(item_reviews),
                "reviewers": [
                    {
                        "reviewer": review.reviewer,
                        "label": review.label,
                        "confidence": review.confidence,
                        "concerns": review.concerns,
                        "path": review.path,
                        "line": review.line,
                    }
                    for review in item_reviews
                ],
                "evidence_sources": [normalize_doc_path(source) for source in item.evidence.sources],
                "evidence_rule": item.evidence.rule,
            }
        )
    return rows


def render_report(rows: list[dict[str, Any]], *, review_dir: Path, min_reviewers: int, min_confidence: float) -> str:
    counts: dict[str, int] = {}
    for row in rows:
        counts[row["status"]] = counts.get(row["status"], 0) + 1

    lines: list[str] = []
    lines.append("# Label Consensus Report")
    lines.append("")
    lines.append(f"Generated: {datetime.now().isoformat(timespec='seconds')}")
    lines.append("")
    lines.append("## Policy")
    lines.append("")
    lines.append(f"- Minimum independent reviewers: {min_reviewers}")
    lines.append(f"- Minimum reviewer confidence: {min_confidence}")
    lines.append(f"- Review directory: `{review_dir.relative_to(ROOT) if review_dir.is_relative_to(ROOT) else review_dir}`")
    lines.append("- Author labels are not counted as independent reviews.")
    lines.append("- Case names and author labels are hidden in default review exports to reduce label leakage.")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    for status, count in sorted(counts.items()):
        lines.append(f"- {status}: {count}")
    lines.append("")
    lines.append("## Non-Accepted Cases")
    lines.append("")
    for row in rows:
        if row["status"] == "accepted":
            continue
        lines.append(f"- `{row['case_id']}` [{row['status']}] {row['tag']}")
        lines.append(f"  - internal name: {row['case_name']}")
        lines.append(f"  - author label: {row['author_expected']}")
        lines.append(f"  - reason: {row['reason']}")
        if row.get("concepts"):
            lines.append(f"  - concepts: {', '.join(row['concepts'])}")
        if row.get("repair_hint"):
            lines.append(f"  - repair hint: {row['repair_hint']}")
        lines.append(f"  - evidence: {', '.join(row['evidence_sources'])}")
        if row["reviewers"]:
            for review in row["reviewers"]:
                lines.append(f"  - {review['reviewer']}: {review['label']} conf={review['confidence']} concerns={review['concerns'] or '-'}")
    lines.append("")
    lines.append("## How To Add Reviews")
    lines.append("")
    lines.append("1. Generate blind packets:")
    lines.append("")
    lines.append("```bash")
    lines.append("python tools/label_consensus.py export --reviewer agent_alpha")
    lines.append("```")
    lines.append("")
    lines.append("2. Give `analysis/label_reviews/agent_alpha.todo.jsonl` to an independent agent.")
    lines.append("3. The agent writes completed labels to `analysis/label_reviews/agent_alpha.jsonl`.")
    lines.append("4. Re-run:")
    lines.append("")
    lines.append("```bash")
    lines.append("python tools/label_consensus.py report")
    lines.append("```")
    lines.append("")
    lines.append("5. Run sourced tests with the gate only after enough accepted cases exist:")
    lines.append("")
    lines.append("```bash")
    lines.append("python tools/run_sourced_edges.py --consensus-gate")
    lines.append("```")
    lines.append("")
    return "\n".join(lines)


def command_export(args: argparse.Namespace) -> None:
    module = load_case_module(args.cases)
    cases = module.build_cases()
    if args.tag:
        cases = [item for item in cases if item.tag == args.tag]
    if args.limit is not None:
        cases = cases[: args.limit]
    packets = [
        review_packet(
            item,
            include_author_label=args.include_author_label,
            include_case_name=args.include_case_name,
            include_raw=not args.no_raw,
        )
        for item in cases
    ]
    for packet in packets:
        packet["reviewer"] = args.reviewer
    output = args.output or (args.review_dir / f"{args.reviewer}.todo.jsonl")
    write_jsonl(output, packets)
    print(f"wrote {len(packets)} blind review packet(s) to {output}")


def command_report(args: argparse.Namespace) -> None:
    module = load_case_module(args.cases)
    cases = module.build_cases()
    reviews = read_reviews(args.review_dir)
    rows = matrix_rows(cases, reviews, min_reviewers=args.min_reviewers, min_confidence=args.min_confidence)

    args.matrix.parent.mkdir(parents=True, exist_ok=True)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.quarantine.parent.mkdir(parents=True, exist_ok=True)
    args.accepted.parent.mkdir(parents=True, exist_ok=True)

    args.matrix.write_text(json.dumps(rows, indent=2, ensure_ascii=False), encoding="utf-8")
    args.report.write_text(
        render_report(rows, review_dir=args.review_dir, min_reviewers=args.min_reviewers, min_confidence=args.min_confidence),
        encoding="utf-8",
    )
    quarantined = [row for row in rows if row["status"] != "accepted"]
    accepted = [row for row in rows if row["status"] == "accepted"]
    args.quarantine.write_text(json.dumps(quarantined, indent=2, ensure_ascii=False), encoding="utf-8")
    args.accepted.write_text(json.dumps(accepted, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"cases={len(rows)} reviews={len(reviews)} accepted={len(accepted)} quarantined={len(quarantined)}")
    print(f"report={args.report}")
    if args.strict and quarantined:
        raise SystemExit(1)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    export = subparsers.add_parser("export", help="Export blind review packets for one reviewer.")
    export.add_argument("--cases", type=Path, default=DEFAULT_CASES)
    export.add_argument("--review-dir", type=Path, default=DEFAULT_REVIEW_DIR)
    export.add_argument("--reviewer", required=True)
    export.add_argument("--output", type=Path)
    export.add_argument("--tag")
    export.add_argument("--limit", type=int)
    export.add_argument("--no-raw", action="store_true", help="Omit raw full trajectory and keep compact records only.")
    export.add_argument("--include-author-label", action="store_true")
    export.add_argument("--include-case-name", action="store_true")
    export.set_defaults(func=command_export)

    report = subparsers.add_parser("report", help="Build consensus matrix and quarantine list from completed reviews.")
    report.add_argument("--cases", type=Path, default=DEFAULT_CASES)
    report.add_argument("--review-dir", type=Path, default=DEFAULT_REVIEW_DIR)
    report.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    report.add_argument("--matrix", type=Path, default=DEFAULT_MATRIX)
    report.add_argument("--quarantine", type=Path, default=DEFAULT_QUARANTINE)
    report.add_argument("--accepted", type=Path, default=DEFAULT_ACCEPTED)
    report.add_argument("--min-reviewers", type=int, default=3)
    report.add_argument("--min-confidence", type=float, default=0.75)
    report.add_argument("--strict", action="store_true")
    report.set_defaults(func=command_report)
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
