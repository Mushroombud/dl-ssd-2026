#!/usr/bin/env python3
"""Enrich parsed spec shards with detailed OpenDataLoader PDF extraction.

The existing artifacts/documents/{core,opal}/*.txt files are the stable,
section-sized corpus used by the rule and coverage tools.  This script keeps
those files intact and writes PDF-derived detail sidecars under
artifacts/documents/_pdf_enrichment/{core,opal}/.

OpenDataLoader is used as the primary parser because it preserves element
types, page numbers, bounding boxes, reading order, and table structure.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DOC_ROOT = ROOT / "artifacts" / "documents"
DEFAULT_EXTRACT_ROOT = ROOT / "analysis" / "pdf_extract" / "opendataloader"
DEFAULT_ENRICH_ROOT = DEFAULT_DOC_ROOT / "_pdf_enrichment"

PDFS = {
    # Existing artifacts/documents/opal shards correspond to the Opal SSC spec.
    "opal": ROOT / "materials" / "Opal_Core_Spec.pdf",
    # The family test-case PDF is useful RAG evidence, but it does not map to
    # the existing opal section_title.json.  It is stored as a separate family.
    "testcases": ROOT / "materials" / "Opal_Family_Test_Case_Spec.pdf",
}

NORMATIVE_RE = re.compile(
    r"\b("
    r"SHALL|SHALL NOT|MUST|MUST NOT|REQUIRED|FAILS?|ERROR|INVALID|"
    r"NOT_AUTHORIZED|INVALID_PARAMETER|SUCCESS|RETURN|RETURNS|"
    r"REJECT|ALLOW|WRITE|READ|AUTHENTICAT|LOCK|RESET|WHEN|IF|ONLY"
    r")\b",
    re.IGNORECASE,
)


@dataclass
class SectionExtraction:
    family: str
    section: str
    title: str
    existing_path: str
    detail_path: str
    meta_path: str
    tables_path: str
    rules_path: str
    source_pdf: str
    pages: list[int]
    existing_chars: int
    extracted_chars: int
    added_blocks: int
    tables: int
    rules: int
    status: str
    reason: str


def natural_section_key(value: str) -> tuple[int | str, ...]:
    parts: list[int | str] = []
    for item in re.split(r"([0-9]+)", value):
        if not item:
            continue
        parts.append(int(item) if item.isdigit() else item)
    return tuple(parts)


def load_section_titles(doc_root: Path, family: str) -> dict[str, str]:
    path = doc_root / family / "section_title.json"
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def normalize_text(value: str) -> str:
    value = value.replace("\u2013", "-").replace("\u2014", "-")
    value = value.replace("\u2018", "'").replace("\u2019", "'")
    value = value.replace("\u201c", '"').replace("\u201d", '"')
    return re.sub(r"\s+", " ", value).strip().lower()


def safe_stem(path: Path) -> str:
    return path.stem.replace(" ", "_")


def import_opendataloader() -> Any:
    try:
        import opendataloader_pdf  # type: ignore

        return opendataloader_pdf
    except ModuleNotFoundError as exc:
        raise SystemExit(
            "opendataloader-pdf is not installed in this environment. "
            "Install it with: uv pip install opendataloader-pdf"
        ) from exc


def run_opendataloader(
    family: str,
    pdf_path: Path,
    extract_root: Path,
    force: bool,
    pages: str | None,
) -> Path:
    output_dir = extract_root / family
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / f"{safe_stem(pdf_path)}.json"
    if json_path.exists() and not force:
        return json_path

    opendataloader_pdf = import_opendataloader()
    opendataloader_pdf.convert(
        input_path=str(pdf_path),
        output_dir=str(output_dir),
        format="json,markdown",
        table_method="cluster",
        reading_order="xycut",
        image_output="off",
        quiet=True,
        pages=pages,
    )
    if not json_path.exists():
        candidates = sorted(output_dir.glob("*.json"))
        if len(candidates) == 1:
            return candidates[0]
        raise FileNotFoundError(f"OpenDataLoader did not create expected JSON: {json_path}")
    return json_path


def walk_nodes(nodes: Iterable[dict[str, Any]]) -> Iterable[dict[str, Any]]:
    for node in nodes:
        yield node
        for key in ("kids", "list items", "rows", "cells"):
            children = node.get(key)
            if isinstance(children, list):
                for child in walk_nodes([item for item in children if isinstance(item, dict)]):
                    yield child


def node_text(node: dict[str, Any]) -> str:
    if isinstance(node.get("content"), str):
        return node["content"].strip()
    chunks: list[str] = []
    for key in ("kids", "list items", "rows", "cells"):
        children = node.get(key)
        if isinstance(children, list):
            for child in children:
                if isinstance(child, dict):
                    text = node_text(child)
                    if text:
                        chunks.append(text)
    return " ".join(chunks).strip()


def table_cell_text(cell: dict[str, Any]) -> str:
    chunks: list[str] = []
    for kid in cell.get("kids", []) or []:
        if isinstance(kid, dict):
            text = node_text(kid)
            if text:
                chunks.append(text)
    return re.sub(r"\s+", " ", " ".join(chunks)).strip()


def table_to_rows(table: dict[str, Any]) -> list[list[str]]:
    rows: list[list[str]] = []
    for row in table.get("rows", []) or []:
        if not isinstance(row, dict):
            continue
        cells = row.get("cells", []) or []
        ordered = sorted(
            [cell for cell in cells if isinstance(cell, dict)],
            key=lambda cell: int(cell.get("column number", 0) or 0),
        )
        rows.append([table_cell_text(cell) for cell in ordered])
    return rows


def render_markdown_table(rows: list[list[str]]) -> str:
    if not rows:
        return ""
    width = max(len(row) for row in rows)
    padded = [row + [""] * (width - len(row)) for row in rows]
    header = padded[0]
    body = padded[1:] if len(padded) > 1 else []
    lines = [
        "| " + " | ".join(cell.replace("\n", " ") for cell in header) + " |",
        "| " + " | ".join("---" for _ in header) + " |",
    ]
    for row in body:
        lines.append("| " + " | ".join(cell.replace("\n", " ") for cell in row) + " |")
    return "\n".join(lines)


def render_node(node: dict[str, Any]) -> str:
    node_type = str(node.get("type", ""))
    text = node_text(node)
    if not text and node_type != "table":
        return ""
    if node_type == "heading":
        level = int(node.get("heading level", 2) or 2)
        level = min(max(level, 2), 6)
        return f"{'#' * level} {text}"
    if node_type == "list":
        items = []
        for item in node.get("list items", []) or []:
            if isinstance(item, dict):
                item_text = node_text(item)
                if item_text:
                    items.append(f"- {item_text.lstrip('+-* \u2022')}")
        return "\n".join(items)
    if node_type == "table":
        rows = table_to_rows(node)
        table_md = render_markdown_table(rows)
        if table_md:
            caption = text if text and text not in table_md else ""
            return f"{caption}\n\n{table_md}".strip()
        return text
    return text


def heading_section(text: str, known_sections: set[str]) -> str | None:
    stripped = re.sub(r"\s+", " ", text).strip()
    stripped = re.sub(r"^(?:[#*\-\u2022]\s*)+", "", stripped)
    match = re.match(r"^([0-9]+(?:\.[0-9]+)*)(?=\s|:|$)", stripped)
    if match:
        section = match.group(1)
        return section if section in known_sections else None
    match = re.match(r"^([A-Z]{2,6}-[0-9]+(?:\.[0-9]+)?)\b", stripped, re.I)
    if match:
        section = match.group(1).upper()
        return section if section in known_sections else None
    return None


def derived_section_id(text: str, fallback_index: int) -> str | None:
    stripped = re.sub(r"\s+", " ", text).strip()
    if not stripped:
        return None
    if stripped in {"S P", "T I", "O N"}:
        return None
    if re.fullmatch(r"[A-Z ,.'&-]{5,}", stripped) and stripped in {
        "CONTENTS",
        "TABLES",
        "List of Tables",
        "List of Figures",
        "DISCLAIMERS, NOTICES, AND LICENSE TERMS",
    }:
        return None
    numeric = re.match(r"^([0-9]+(?:\.[0-9]+)*)(?=\s|:|$)", stripped)
    if numeric:
        return numeric.group(1)
    coded = re.match(r"^([A-Z]{2,6}-[0-9]+(?:\.[0-9]+)?)\b", stripped, re.I)
    if coded:
        return coded.group(1).upper()
    if stripped in {"Notes", "Prerequisites", "Test Sequence", "Expected Response"}:
        return None
    slug = re.sub(r"[^A-Za-z0-9]+", "-", stripped).strip("-").lower()[:48]
    return f"h{fallback_index:04d}-{slug}" if slug else None


def derive_section_titles_from_headings(data: dict[str, Any]) -> dict[str, str]:
    titles: dict[str, str] = {}
    for index, node in enumerate(data.get("kids", []) or [], start=1):
        if not isinstance(node, dict) or node.get("type") != "heading":
            continue
        text = node_text(node)
        section = derived_section_id(text, index)
        if section is None or section in titles:
            continue
        title = re.sub(rf"^{re.escape(section)}\s*:?\s*", "", text, flags=re.I).strip()
        titles[section] = title or text
    return titles


def section_heading_sort_key(section: str) -> tuple[int, tuple[int | str, ...]]:
    if re.match(r"^[0-9]+(?:\.[0-9]+)*$", section):
        return 0, natural_section_key(section)
    return 1, natural_section_key(section)


def existing_section_path(doc_root: Path, family: str, section: str) -> Path:
    return doc_root / family / f"{section}.txt"


def existing_path_for_display(path: Path) -> str:
    if path.exists():
        return display_path(path)
    return ""


def ensure_known_sections(titles: dict[str, str], data: dict[str, Any]) -> dict[str, str]:
    if titles:
        return titles
    return derive_section_titles_from_headings(data)


def section_from_heading_text(text: str, known_sections: set[str]) -> str | None:
    stripped = re.sub(r"\s+", " ", text).strip()
    numeric = re.match(r"^([0-9]+(?:\.[0-9]+)*)(?=\s|:|$)", stripped)
    if numeric:
        section = numeric.group(1)
        return section if section in known_sections else None
    coded = re.match(r"^([A-Z]{2,6}-[0-9]+(?:\.[0-9]+)?)\b", stripped, re.I)
    if coded:
        section = coded.group(1).upper()
        return section if section in known_sections else None
    return section if section in known_sections else None


def assign_nodes_to_sections(data: dict[str, Any], titles: dict[str, str]) -> dict[str, list[dict[str, Any]]]:
    sections: dict[str, list[dict[str, Any]]] = defaultdict(list)
    current: str | None = None
    known_sections = set(titles)
    top_nodes = data.get("kids", []) or []
    body_start_page: int | None = None
    for node in top_nodes:
        if not isinstance(node, dict) or node.get("type") != "heading":
            continue
        if heading_section(node_text(node), known_sections):
            page = node.get("page number")
            if isinstance(page, int):
                body_start_page = page
                break
    for node in top_nodes:
        if not isinstance(node, dict):
            continue
        page = node.get("page number")
        if body_start_page is not None and isinstance(page, int) and page < body_start_page:
            continue
        candidate = heading_section(node_text(node), known_sections)
        if candidate:
            current = candidate
        if current:
            sections[current].append(node)
    return sections


def split_blocks(markdown: str) -> list[str]:
    blocks = []
    for block in re.split(r"\n\s*\n", markdown):
        clean = block.strip()
        if clean:
            blocks.append(clean)
    return blocks


def block_is_new(block: str, existing_norm: str) -> bool:
    norm = normalize_text(block)
    if not norm or len(norm) < 40:
        return False
    if norm in existing_norm:
        return False
    # Short table rows and normative sentences are useful even when partial.
    return bool(NORMATIVE_RE.search(block) or "|" in block or len(norm) >= 120)


def extract_tables(section: str, nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    table_index = 0
    for node in nodes:
        for item in walk_nodes([node]):
            if item.get("type") != "table":
                continue
            table_index += 1
            table_rows = table_to_rows(item)
            rows.append(
                {
                    "section": section,
                    "table_index": table_index,
                    "page": item.get("page number"),
                    "bounding_box": item.get("bounding box"),
                    "number_of_rows": item.get("number of rows") or len(table_rows),
                    "number_of_columns": item.get("number of columns")
                    or max((len(row) for row in table_rows), default=0),
                    "text": node_text(item),
                    "rows": table_rows,
                }
            )
    return rows


def rule_candidates(section: str, title: str, blocks: list[str], tables: list[dict[str, Any]]) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for index, block in enumerate(blocks, start=1):
        if not NORMATIVE_RE.search(block):
            continue
        candidates.append(
            {
                "rule_id": f"{section}:text:{index:03d}",
                "section": section,
                "title": title,
                "kind": "normative_text",
                "source": block[:1200],
                "status": "candidate_for_review",
            }
        )
    for table in tables:
        rows = table.get("rows") or []
        if len(rows) < 2:
            continue
        header = [str(cell) for cell in rows[0]]
        for row_index, row in enumerate(rows[1:], start=1):
            row_text = " ".join(str(cell) for cell in row)
            if not NORMATIVE_RE.search(row_text):
                continue
            candidates.append(
                {
                    "rule_id": f"{section}:table:{table['table_index']:02d}:{row_index:03d}",
                    "section": section,
                    "title": title,
                    "kind": "table_row",
                    "table_index": table["table_index"],
                    "header": header,
                    "row": row,
                    "status": "candidate_for_review",
                }
            )
    return candidates


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def display_path(path: Path) -> str:
    resolved = path.resolve()
    try:
        return str(resolved.relative_to(ROOT))
    except ValueError:
        return str(path)


def enrich_family(
    family: str,
    doc_root: Path,
    extract_root: Path,
    enrich_root: Path,
    force_parse: bool,
    pages: str | None,
    min_added_blocks: int,
) -> list[SectionExtraction]:
    pdf_path = PDFS[family]
    json_path = run_opendataloader(family, pdf_path, extract_root, force_parse, pages)
    data = json.loads(json_path.read_text(encoding="utf-8"))
    titles = load_section_titles(doc_root, family)
    titles = ensure_known_sections(titles, data)
    by_section = assign_nodes_to_sections(data, titles)
    out_base = enrich_root / family
    results: list[SectionExtraction] = []

    for section in sorted(titles, key=section_heading_sort_key):
        nodes = by_section.get(section, [])
        existing_path = existing_section_path(doc_root, family, section)
        existing = existing_path.read_text(encoding="utf-8", errors="replace") if existing_path.exists() else ""
        rendered_blocks = [render_node(node) for node in nodes]
        rendered = "\n\n".join(block for block in rendered_blocks if block.strip()).strip()
        existing_norm = normalize_text(existing)
        blocks = split_blocks(rendered)
        added = [block for block in blocks if block_is_new(block, existing_norm)]
        tables = extract_tables(section, nodes)
        rules = rule_candidates(section, titles[section], added, tables)
        pages_seen = sorted(
            {
                int(item["page number"])
                for node in nodes
                for item in walk_nodes([node])
                if isinstance(item.get("page number"), int)
            }
        )

        status = "skipped"
        reason = "no extracted section nodes"
        if nodes:
            if len(added) >= min_added_blocks or tables or rules or len(existing) < 200:
                status = "written"
                reason = "new detailed blocks, tables, rules, or sparse existing shard"
            else:
                reason = "existing shard already contains the extracted detail"

        detail_path = out_base / "details" / f"{section}.md"
        meta_path = out_base / "meta" / f"{section}.json"
        tables_path = out_base / "tables" / f"{section}.jsonl"
        rules_path = out_base / "rules" / f"{section}.jsonl"

        if status == "written":
            detail_path.parent.mkdir(parents=True, exist_ok=True)
            header = [
                f"# {section} {titles[section]}",
                "",
            ]
            detail_path.write_text("\n".join(header + added) + "\n", encoding="utf-8")
            write_jsonl(tables_path, tables)
            write_jsonl(rules_path, rules)

        meta = {
            "family": family,
            "section": section,
            "title": titles[section],
            "status": status,
            "reason": reason,
            "source_pdf": str(pdf_path.relative_to(ROOT)),
            "parser": "opendataloader-pdf",
            "parser_json": display_path(json_path),
            "existing_path": existing_path_for_display(existing_path),
            "detail_path": display_path(detail_path) if status == "written" else "",
            "tables_path": display_path(tables_path) if status == "written" else "",
            "rules_path": display_path(rules_path) if status == "written" else "",
            "pages": pages_seen,
            "existing_chars": len(existing),
            "extracted_chars": len(rendered),
            "added_blocks": len(added),
            "tables": len(tables),
            "rules": len(rules),
        }
        write_json(meta_path, meta)
        results.append(
            SectionExtraction(
                family=family,
                section=section,
                title=titles[section],
                existing_path=existing_path_for_display(existing_path),
                detail_path=display_path(detail_path) if status == "written" else "",
                meta_path=display_path(meta_path),
                tables_path=display_path(tables_path) if status == "written" else "",
                rules_path=display_path(rules_path) if status == "written" else "",
                source_pdf=str(pdf_path.relative_to(ROOT)),
                pages=pages_seen,
                existing_chars=len(existing),
                extracted_chars=len(rendered),
                added_blocks=len(added),
                tables=len(tables),
                rules=len(rules),
                status=status,
                reason=reason,
            )
        )
    return results


def render_summary(rows: list[SectionExtraction]) -> str:
    by_family = Counter(row.family for row in rows)
    by_status = Counter(row.status for row in rows)
    written = [row for row in rows if row.status == "written"]
    written.sort(
        key=lambda row: (
            -row.rules,
            -row.tables,
            -row.added_blocks,
            row.family,
            section_heading_sort_key(row.section),
        )
    )
    lines = [
        "# PDF Enrichment Summary",
        "",
        f"- total_sections: {len(rows)}",
        f"- families: {dict(sorted(by_family.items()))}",
        f"- status: {dict(sorted(by_status.items()))}",
        f"- written_sections: {len(written)}",
        "",
        "## Top Written Sections",
        "",
    ]
    for row in written[:50]:
        lines.append(
            f"- `{row.family}/{row.section}` {row.title}: "
            f"added_blocks={row.added_blocks}, tables={row.tables}, rules={row.rules}, pages={row.pages or '-'}"
        )
    return "\n".join(lines) + "\n"


def render_readme() -> str:
    return """# PDF Enrichment Artifacts

This directory contains detailed PDF-derived sidecars generated by
`tools/enrich_documents_from_pdfs.py`.

The existing `artifacts/documents/{core,opal}/*.txt` shards remain the stable
section corpus.  These enrichment files are supplemental RAG evidence extracted
with OpenDataLoader PDF parsing.

Layout:

- `manifest.jsonl`: one row per aligned section.
- `summary.md`: run summary and highest-signal written sections.
- `{family}/details/{section}.md`: added detail blocks not already present in the stable shard.
- `{family}/meta/{section}.json`: source PDF, pages, parser output, and counts.
- `{family}/tables/{section}.jsonl`: structured table rows extracted from the PDF.
- `{family}/rules/{section}.jsonl`: candidate rule snippets for review, not automatically trusted rules.

Families:

- `opal`: `materials/Opal_Core_Spec.pdf`, aligned to existing `artifacts/documents/opal`.
- `testcases`: `materials/Opal_Family_Test_Case_Spec.pdf`, heading-derived sections.

Regenerate:

```bash
.venv/bin/python tools/enrich_documents_from_pdfs.py --force-parse
```
"""


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--doc-root", type=Path, default=DEFAULT_DOC_ROOT)
    parser.add_argument("--extract-root", type=Path, default=DEFAULT_EXTRACT_ROOT)
    parser.add_argument("--enrich-root", type=Path, default=DEFAULT_ENRICH_ROOT)
    parser.add_argument("--family", choices=sorted(PDFS), action="append")
    parser.add_argument("--force-parse", action="store_true")
    parser.add_argument("--pages", help="OpenDataLoader page selector, e.g. 1-20. Mainly for smoke tests.")
    parser.add_argument("--min-added-blocks", type=int, default=1)
    parser.add_argument("--summary", type=Path, default=DEFAULT_ENRICH_ROOT / "summary.md")
    args = parser.parse_args()

    families = args.family or sorted(PDFS)
    all_rows: list[SectionExtraction] = []
    for family in families:
        all_rows.extend(
            enrich_family(
                family=family,
                doc_root=args.doc_root,
                extract_root=args.extract_root,
                enrich_root=args.enrich_root,
                force_parse=args.force_parse,
                pages=args.pages,
                min_added_blocks=args.min_added_blocks,
            )
        )

    args.summary.parent.mkdir(parents=True, exist_ok=True)
    args.summary.write_text(render_summary(all_rows), encoding="utf-8")
    (args.enrich_root / "README.md").write_text(render_readme(), encoding="utf-8")
    manifest = args.enrich_root / "manifest.jsonl"
    write_jsonl(manifest, [asdict(row) for row in all_rows])
    print(f"sections={len(all_rows)} written={sum(1 for row in all_rows if row.status == 'written')}")
    print(f"summary={display_path(args.summary)}")
    print(f"manifest={display_path(manifest)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
