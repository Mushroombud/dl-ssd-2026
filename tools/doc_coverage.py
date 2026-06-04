#!/usr/bin/env python3
"""Report official-document coverage by sourced edge tests.

The goal is not to prove full correctness automatically.  The goal is to keep
every official document section visible until it is either covered by a sourced
test or explicitly triaged with a reason.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DOC_ROOT = ROOT / "artifacts" / "documents"
DEFAULT_TESTS = ROOT / "tools" / "run_sourced_edges.py"
DEFAULT_TRIAGE = ROOT / "analysis" / "doc_coverage_triage.json"
DEFAULT_REPORT = ROOT / "analysis" / "doc_coverage_report.md"
DEFAULT_MATRIX = ROOT / "analysis" / "doc_coverage_matrix.json"


NORMATIVE_RE = re.compile(
    r"\b("
    r"SHALL|SHALL NOT|MUST|MUST NOT|REQUIRED|FAILS?|ERROR|INVALID|"
    r"NOT_AUTHORIZED|INVALID_PARAMETER|SUCCESS|RETURN|RETURNS|"
    r"REJECT|ALLOW|WRITE|READ|AUTHENTICAT|LOCK|RESET|"
    r"WHEN|IF|ONLY|TABLE|REQUIRED BEHAVIOR"
    r")\b",
    re.IGNORECASE,
)


HIGH_RISK_TERMS = {
    "StartSession",
    "Authenticate",
    "C_PIN",
    "TryLimit",
    "Tries",
    "Persistence",
    "GenKey",
    "ReEncrypt",
    "ReadLocked",
    "WriteLocked",
    "ReadLockEnabled",
    "WriteLockEnabled",
    "LockOnReset",
    "MBRControl",
    "MBR",
    "RangeStart",
    "RangeLength",
    "Set",
    "Get",
    "CreateRow",
    "DeleteRow",
    "DeleteSP",
    "Revert",
    "RevertSP",
    "ACE",
    "ACL",
    "BooleanExpr",
    "GetPackage",
    "SetPackage",
}


@dataclass
class DocInfo:
    path: str
    title: str
    category: str
    priority: str
    normative_score: int
    high_risk_terms: list[str]
    case_count: int
    cases: list[str]
    triage_status: str
    triage_reason: str
    snippets: list[str]


def normalize_doc_path(value: str) -> str:
    value = value.replace("\\", "/")
    marker = "/documents/"
    if marker in value:
        return value.split(marker, 1)[1].lstrip("/")
    if value.startswith("artifacts/documents/"):
        return value.split("artifacts/documents/", 1)[1]
    return value.lstrip("/")


def doc_sort_key(path: str) -> tuple[str, list[tuple[int, int | str]]]:
    family, _, rest = path.partition("/")
    stem = rest.removesuffix(".txt")
    parts: list[tuple[int, int | str]] = []
    for item in re.split(r"([0-9]+)", stem):
        if not item:
            continue
        parts.append((0, int(item)) if item.isdigit() else (1, item))
    return family, parts


def load_sourced_cases(tests_path: Path) -> list[Any]:
    spec = importlib.util.spec_from_file_location("sourced_edges_for_coverage", tests_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load sourced tests from {tests_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return list(module.build_cases())


def load_triage(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"schema": 1, "manual": {}}
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    data.setdefault("manual", {})
    return data


def first_title(text: str, fallback: str) -> str:
    for line in text.splitlines():
        stripped = line.strip()
        if stripped:
            return stripped[:160]
    return fallback


def split_snippets(text: str) -> list[str]:
    chunks: list[str] = []
    for paragraph in re.split(r"\n\s*\n", text):
        normalized = re.sub(r"\s+", " ", paragraph).strip()
        if not normalized:
            continue
        if NORMATIVE_RE.search(normalized):
            chunks.append(normalized[:260])
        if len(chunks) >= 3:
            break
    return chunks


def categorize(path: str, title: str, text: str) -> str:
    haystack = f"{path} {title} {text[:1200]}"
    if re.search(r"5\.3\.3\.16|5\.7\.3\.7|GenKey|ReEncrypt|NextKey|ActiveKey", haystack, re.I):
        return "genkey-reencrypt"
    if re.search(r"5\.3\.5|5\.4\.5|5\.7\.4|5\.1\.2|5\.1\.3|DeleteSP|Revert|RevertSP|Life Cycle|Lifecycle", haystack, re.I):
        return "lifecycle-revert"
    if re.search(r"5\.7\.3\.2|5\.7\.2\.2\.(4|5|6|7|8|9|10)\b|5\.7\.2\.5|MBRControl|ReadLocked|WriteLocked|ReadLockEnabled|WriteLockEnabled|RangeStart|RangeLength", haystack, re.I):
        return "host-io-locking-mbr"
    if re.search(r"5\.3\.2\.12|5\.3\.4\.1|C_PIN|TryLimit|Tries|Authenticate|StartSession|HostSigningAuthority|Authority Table|Disabled Authorities", haystack, re.I):
        return "auth-cpin-session"
    if re.search(r"5\.3\.3\.(2|3|4|5|6|7|8|9|10)\b|5\.3\.4\.2|CreateTable|CreateRow|DeleteRow|CellBlock|RowValues", haystack, re.I):
        return "table-methods"
    if re.search(r"5\.3\.3\.(11|12|13|14|15)\b|5\.3\.4\.3|ACE|ACL|BooleanExpr|DeleteMethod", haystack, re.I):
        return "acl-ace"
    if re.search(r"5\.3\.3\.(17|18)\b|5\.6\.|GetPackage|SetPackage|Random|Sign|Verify|FirmwareAttestation", haystack, re.I):
        return "package-crypto"
    if re.search(r"5\.2\.3|3\.3\.7|Session|ComID|SyncSession", haystack, re.I):
        return "protocol-session"
    if path.startswith("opal/"):
        return "opal-ssc"
    return "other"


def priority_for(path: str, category: str, text: str, terms: list[str], normative_score: int) -> str:
    if category in {"host-io-locking-mbr", "auth-cpin-session", "genkey-reencrypt"}:
        return "A"
    if category in {"table-methods", "acl-ace", "lifecycle-revert"}:
        return "B"
    if category in {"package-crypto", "protocol-session", "opal-ssc"} and (terms or normative_score >= 4):
        return "C"
    if normative_score >= 8 or len(terms) >= 3:
        return "B"
    if normative_score >= 2:
        return "C"
    return "D"


def collect_docs(doc_root: Path, evidence_by_source: dict[str, list[str]], triage: dict[str, Any]) -> list[DocInfo]:
    docs: list[DocInfo] = []
    manual = triage.get("manual", {})
    for file_path in sorted(doc_root.rglob("*.txt"), key=lambda p: doc_sort_key(normalize_doc_path(str(p.relative_to(doc_root))))):
        relative = normalize_doc_path(str(file_path.relative_to(doc_root)))
        if ".ipynb_checkpoints/" in relative or any(part.startswith("_") for part in relative.split("/")):
            continue
        text = file_path.read_text(encoding="utf-8", errors="replace")
        title = first_title(text, relative)
        terms = sorted(term for term in HIGH_RISK_TERMS if re.search(rf"\b{re.escape(term)}\b", text, re.I))
        normative_score = len(NORMATIVE_RE.findall(text))
        category = categorize(relative, title, text)
        priority = priority_for(relative, category, text, terms, normative_score)
        cases = sorted(set(evidence_by_source.get(relative, [])))
        entry = manual.get(relative, {})
        triage_status = entry.get("status", "covered" if cases else "untriaged")
        triage_reason = entry.get("reason", "")
        docs.append(
            DocInfo(
                path=relative,
                title=title,
                category=category,
                priority=priority,
                normative_score=normative_score,
                high_risk_terms=terms,
                case_count=len(cases),
                cases=cases,
                triage_status=triage_status,
                triage_reason=triage_reason,
                snippets=split_snippets(text),
            )
        )
    return docs


def evidence_map(cases: list[Any]) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for case in cases:
        for source in case.evidence.sources:
            relative = normalize_doc_path(str(source))
            result.setdefault(relative, []).append(case.name)
    return result


def count_by(items: list[DocInfo], key: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in items:
        value = str(getattr(item, key))
        counts[value] = counts.get(value, 0) + 1
    return dict(sorted(counts.items()))


def category_rows(docs: list[DocInfo]) -> list[str]:
    categories = sorted(set(doc.category for doc in docs))
    rows = [
        "| Category | Total | Covered | Triaged | Untriaged A/B |",
        "|---|---:|---:|---:|---:|",
    ]
    for category in categories:
        group = [doc for doc in docs if doc.category == category]
        covered = sum(1 for doc in group if doc.case_count)
        triaged = sum(1 for doc in group if doc.triage_status not in {"untriaged", "covered"})
        untriaged_ab = sum(1 for doc in group if doc.case_count == 0 and doc.triage_status == "untriaged" and doc.priority in {"A", "B"})
        rows.append(f"| {category} | {len(group)} | {covered} | {triaged} | {untriaged_ab} |")
    return rows


def doc_line(doc: DocInfo) -> str:
    terms = ", ".join(doc.high_risk_terms[:6])
    if len(doc.high_risk_terms) > 6:
        terms += ", ..."
    snippet = doc.snippets[0] if doc.snippets else ""
    return (
        f"- `{doc.path}` [{doc.priority}/{doc.category}] "
        f"score={doc.normative_score}, terms={terms or '-'}\n"
        f"  - title: {doc.title}\n"
        f"  - snippet: {snippet or '-'}"
    )


def render_report(docs: list[DocInfo], cases: list[Any], triage_path: Path) -> str:
    covered = [doc for doc in docs if doc.case_count]
    untriaged_ab = [
        doc
        for doc in docs
        if doc.case_count == 0 and doc.triage_status == "untriaged" and doc.priority in {"A", "B"}
    ]
    untriaged_normative = [
        doc
        for doc in docs
        if doc.case_count == 0 and doc.triage_status == "untriaged" and doc.normative_score > 0
    ]
    high_risk_uncovered = sorted(
        untriaged_ab,
        key=lambda doc: (doc.priority, -doc.normative_score, doc.path),
    )

    lines: list[str] = []
    lines.append("# Official Document Coverage Report")
    lines.append("")
    lines.append(f"Generated: {datetime.now().isoformat(timespec='seconds')}")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- Official document files: {len(docs)}")
    lines.append(f"- Sourced edge cases: {len(cases)}")
    lines.append(f"- Documents referenced by sourced tests: {len(covered)}")
    lines.append(f"- Untriaged normative documents: {len(untriaged_normative)}")
    lines.append(f"- Untriaged A/B priority documents: {len(untriaged_ab)}")
    lines.append(f"- Triage file: `{triage_path.relative_to(ROOT) if triage_path.is_relative_to(ROOT) else triage_path}`")
    lines.append("")
    lines.append("## By Category")
    lines.append("")
    lines.extend(category_rows(docs))
    lines.append("")
    lines.append("## By Priority")
    lines.append("")
    for priority, count in count_by(docs, "priority").items():
        lines.append(f"- {priority}: {count}")
    lines.append("")
    lines.append("## Highest Priority Uncovered Documents")
    lines.append("")
    lines.append("These should either get sourced tests or be manually triaged with a reason.")
    lines.append("")
    if high_risk_uncovered:
        for doc in high_risk_uncovered[:80]:
            lines.append(doc_line(doc))
    else:
        lines.append("No untriaged A/B priority documents.")
    lines.append("")
    lines.append("## Currently Covered Documents")
    lines.append("")
    for doc in sorted(covered, key=lambda item: doc_sort_key(item.path)):
        lines.append(f"- `{doc.path}`: {doc.case_count} case(s)")
        for case_name in doc.cases[:5]:
            lines.append(f"  - {case_name}")
        if len(doc.cases) > 5:
            lines.append(f"  - ... {len(doc.cases) - 5} more")
    lines.append("")
    lines.append("## Workflow")
    lines.append("")
    lines.append("1. Refresh `python3 tools/build_doc_inventory.py` and pick the next batch from `analysis/doc_cartography_queue.md`.")
    lines.append("2. Classify each shard as testable, supporting/cross-doc only, duplicate/index, non-testable, or manually triaged.")
    lines.append("3. For each testable rule, write one rule card: official sources, exact assertion type, cross-doc dependencies, and whether exact status is proven.")
    lines.append("4. Add only narrowed candidates to `tools/run_sourced_edges.py`; prefer impossible-`SUCCESS` FAIL cases when the document proves rejection but not a concrete error status.")
    lines.append("5. Run the new tag locally, then create three blind review packets with `tools/label_consensus.py export --tag <tag> --reviewer <id>`.")
    lines.append("6. Run `python3 tools/label_consensus.py report`; treat only accepted consensus cases as trusted regression data.")
    lines.append("7. Fix solver code only for accepted-case mismatches, then run consensus gate, full sourced, synthetic, unit/public eval, coverage, and inventory.")
    lines.append("")
    lines.append("Manual triage statuses should be used only when a section is truly informative, out of scope, duplicated elsewhere, or covered indirectly.")
    lines.append("")
    return "\n".join(lines) + "\n"


def write_default_triage(path: Path) -> None:
    if path.exists():
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "schema": 1,
        "manual": {
            "_example/path.txt": {
                "status": "informative|out_of_scope|duplicate|covered_indirectly|deferred",
                "reason": "Explain why this official section does not need a direct sourced test yet.",
            }
        },
    }
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--docs", type=Path, default=DEFAULT_DOC_ROOT)
    parser.add_argument("--tests", type=Path, default=DEFAULT_TESTS)
    parser.add_argument("--triage", type=Path, default=DEFAULT_TRIAGE)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--matrix", type=Path, default=DEFAULT_MATRIX)
    parser.add_argument("--strict", action="store_true", help="Exit nonzero when untriaged A/B docs remain.")
    args = parser.parse_args()

    if not args.docs.exists():
        raise SystemExit(f"Document root not found: {args.docs}")
    if not args.tests.exists():
        raise SystemExit(f"Sourced tests not found: {args.tests}")

    write_default_triage(args.triage)
    triage = load_triage(args.triage)
    cases = load_sourced_cases(args.tests)
    docs = collect_docs(args.docs, evidence_map(cases), triage)

    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.matrix.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(render_report(docs, cases, args.triage), encoding="utf-8")
    args.matrix.write_text(
        json.dumps([asdict(doc) for doc in docs], indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    untriaged_ab = [
        doc
        for doc in docs
        if doc.case_count == 0 and doc.triage_status == "untriaged" and doc.priority in {"A", "B"}
    ]
    print(f"docs={len(docs)} cases={len(cases)} covered_docs={sum(1 for doc in docs if doc.case_count)}")
    print(f"untriaged_A_B={len(untriaged_ab)} report={args.report}")
    if args.strict and untriaged_ab:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
