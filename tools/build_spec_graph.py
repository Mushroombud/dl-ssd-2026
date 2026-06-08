#!/usr/bin/env python3
"""Build a lightweight spec graph from official TCG/Opal text extracts.

This graph is intentionally conservative.  It treats deterministic table
parsing as trusted enough to generate rule candidates, but every generated rule
still carries a review status before it can be used as accepted coverage.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

DEFAULT_DOC_ROOT = ROOT / "artifacts" / "documents"
DEFAULT_OUT_DIR = ROOT / "analysis" / "spec_graph"
DEFAULT_SOURCED_TESTS = ROOT / "tools" / "run_sourced_edges.py"

TARGET_SECTION = "core/5.7.3.2.txt"
DOC_MARKER = "/documents/"

TABLE_SPECS = {
    "Table 230 Interface Read Command Access": {
        "operation": "HostRead",
        "short": "table230",
        "expected_rows": 14,
        "columns": {
            "MBR Control Enable": "MBRControl.Enable",
            "MBR Control Done": "MBRControl.Done",
            "Starting LBA Within MBR": "LBA.StartWithinMBR",
            "Ending LBA within MBR": "LBA.EndWithinMBR",
            "ReadLockEnabled for Requested LBA range": "Locking.ReadLockEnabled",
            "ReadLocked for Requested LBA Range": "Locking.ReadLocked",
        },
    },
    "Table 231 Interface Write Command Access": {
        "operation": "HostWrite",
        "short": "table231",
        "expected_rows": 13,
        "columns": {
            "MBRControlEnable": "MBRControl.Enable",
            "MBRControlDone": "MBRControl.Done",
            "Starting LBA Within MBR": "LBA.StartWithinMBR",
            "Ending LBA within MBR": "LBA.EndWithinMBR",
            "WriteLockEnabled for Requested LBA range": "Locking.WriteLockEnabled",
            "WriteLocked for Requested LBA Range": "Locking.WriteLocked",
        },
    },
}


def normalize_doc_path(value: str) -> str:
    value = value.replace("\\", "/")
    if DOC_MARKER in value:
        return value.split(DOC_MARKER, 1)[1].lstrip("/")
    if value.startswith("artifacts/documents/"):
        return value.split("artifacts/documents/", 1)[1]
    return value.lstrip("/")


def section_id(relative_path: str) -> str:
    return f"section:{relative_path.removesuffix('.txt')}"


def rule_id(section_path: str, table_short: str, row_index: int) -> str:
    stem = section_path.removesuffix(".txt").replace("/", "-")
    return f"{stem}-{table_short}-row{row_index:02d}"


def entity_id(kind: str, name: str) -> str:
    return f"entity:{kind}:{name}"


def stable_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def first_title(text: str, fallback: str) -> str:
    for line in text.splitlines():
        stripped = line.strip()
        if stripped:
            return stripped[:180]
    return fallback


def doc_sort_key(path: str) -> tuple[str, list[tuple[int, int | str]]]:
    family, _, rest = path.partition("/")
    parts: list[tuple[int, int | str]] = []
    for item in re.split(r"([0-9]+)", rest.removesuffix(".txt")):
        if not item:
            continue
        parts.append((0, int(item)) if item.isdigit() else (1, item))
    return family, parts


def collect_sections(doc_root: Path) -> list[dict[str, Any]]:
    sections: list[dict[str, Any]] = []
    files = sorted(
        doc_root.rglob("*.txt"),
        key=lambda path: doc_sort_key(normalize_doc_path(str(path.relative_to(doc_root)))),
    )
    for file_path in files:
        relative = normalize_doc_path(str(file_path.relative_to(doc_root)))
        if ".ipynb_checkpoints/" in relative:
            continue
        text = file_path.read_text(encoding="utf-8", errors="replace")
        family, _, _ = relative.partition("/")
        sections.append(
            {
                "node_id": section_id(relative),
                "kind": "Section",
                "path": relative,
                "title": first_title(text, relative),
                "family": family,
                "chars": len(text),
                "words": len(re.findall(r"\S+", text)),
                "sha1": hashlib.sha1(text.encode("utf-8", errors="replace")).hexdigest(),
                "extraction_confidence": "deterministic_file_inventory",
            }
        )
    return sections


def extract_markdown_table(text: str, table_title: str) -> tuple[list[str], list[list[str]], list[str]]:
    start = text.find(table_title)
    if start < 0:
        raise ValueError(f"Could not find table title: {table_title}")
    block_match = re.search(r"```markdown\s*(.*?)```", text[start:], re.S)
    if block_match is None:
        raise ValueError(f"Could not find markdown block after: {table_title}")
    block = block_match.group(1).strip("\n")
    raw_lines = [line.rstrip() for line in block.splitlines() if line.strip().startswith("|")]
    if len(raw_lines) < 3:
        raise ValueError(f"Markdown table too short after: {table_title}")
    headers = split_table_row(raw_lines[0])
    rows: list[list[str]] = []
    row_lines: list[str] = []
    for line in raw_lines[2:]:
        cells = split_table_row(line)
        if len(cells) != len(headers):
            raise ValueError(f"Column count mismatch in {table_title}: {line}")
        rows.append(cells)
        row_lines.append(line)
    return headers, rows, row_lines


def split_table_row(line: str) -> list[str]:
    return [cell.strip() for cell in line.strip().strip("|").split("|")]


def normalize_condition_value(value: str) -> bool | str:
    normalized = re.sub(r"\s+", " ", value).strip()
    lowered = normalized.lower()
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    if lowered == "n/a":
        return "any"
    if lowered.startswith("mixed"):
        return "mixed"
    return normalized


def parse_expected_behavior(operation: str, text: str) -> dict[str, Any]:
    normalized = re.sub(r"\s+", " ", text).strip()
    lowered = normalized.lower()
    if "return data from mbr table" in lowered:
        return {"type": "read_returns", "value": "mbr_table_data", "raw": normalized}
    if "return all zeroes" in lowered:
        return {"type": "read_returns", "value": "all_zeroes", "raw": normalized}
    if "return user data" in lowered:
        return {"type": "read_returns", "value": "user_data", "raw": normalized}
    if "write user data" in lowered:
        return {"type": "write_allowed", "value": "user_data", "raw": normalized}
    if "data protection error" in lowered:
        direction = "to_host" if operation == "HostRead" else "from_host"
        return {
            "type": "error",
            "value": "data_protection_error_no_data",
            "direction": direction,
            "status_family": "Data Protection Error",
            "raw": normalized,
        }
    return {"type": "unknown", "value": normalized, "raw": normalized}


class GraphBuilder:
    def __init__(self) -> None:
        self.entities: dict[str, dict[str, Any]] = {}
        self.edges: list[dict[str, Any]] = []

    def add_entity(self, kind: str, name: str, **extra: Any) -> str:
        node_id = entity_id(kind, name)
        entity = {"node_id": node_id, "kind": kind, "name": name}
        entity.update(extra)
        if node_id not in self.entities:
            self.entities[node_id] = entity
        else:
            self.entities[node_id].update({key: value for key, value in extra.items() if key not in self.entities[node_id]})
        return node_id

    def add_edge(self, src: str, rel: str, dst: str, **extra: Any) -> None:
        edge = {"src": src, "rel": rel, "dst": dst}
        edge.update(extra)
        self.edges.append(edge)


def build_table_rules(doc_root: Path, graph: GraphBuilder) -> list[dict[str, Any]]:
    target_path = doc_root / TARGET_SECTION
    text = target_path.read_text(encoding="utf-8", errors="replace")
    rules: list[dict[str, Any]] = []
    section_node = section_id(TARGET_SECTION)

    for table_title, spec in TABLE_SPECS.items():
        operation = str(spec["operation"])
        table_short = str(spec["short"])
        expected_rows = int(spec["expected_rows"])
        column_map = dict(spec["columns"])
        headers, rows, row_lines = extract_markdown_table(text, table_title)
        if len(rows) != expected_rows:
            raise ValueError(f"{table_title} expected {expected_rows} rows, got {len(rows)}")

        table_node = graph.add_entity(
            "Table",
            f"{TARGET_SECTION}:{table_title}",
            title=table_title,
            path=TARGET_SECTION,
            table_short=table_short,
        )
        graph.add_edge(section_node, "CONTAINS_TABLE", table_node)
        operation_node = graph.add_entity("Operation", operation)

        for header in headers:
            column_node = graph.add_entity("Column", f"{table_title}:{header}", table=table_title, header=header)
            graph.add_edge(table_node, "HAS_COLUMN", column_node)

        for row_index, cells in enumerate(rows, start=1):
            row = dict(zip(headers, cells))
            conditions: dict[str, Any] = {}
            condition_raw: dict[str, str] = {}
            for header, variable in column_map.items():
                conditions[variable] = normalize_condition_value(row[header])
                condition_raw[variable] = row[header]
            behavior = parse_expected_behavior(operation, row["Required Behavior"])
            rid = rule_id(TARGET_SECTION, table_short, row_index)
            rule_node = f"rule:{rid}"
            rule = {
                "rule_id": rid,
                "node_id": rule_node,
                "kind": "Rule",
                "source": {
                    "path": TARGET_SECTION,
                    "table": table_title,
                    "row_index": row_index,
                    "row_text": row_lines[row_index - 1],
                },
                "operation": operation,
                "conditions": conditions,
                "condition_raw": condition_raw,
                "expected_behavior": behavior,
                "extraction": {
                    "method": "deterministic_markdown_table_parser",
                    "trust_tier": "T1",
                    "confidence": 1.0,
                    "review_status": "needs_review",
                },
            }
            rules.append(rule)

            graph.add_entity("Rule", rid, path=TARGET_SECTION, table=table_title, row_index=row_index)
            graph.add_edge(section_node, "CONTAINS_RULE", rule_node)
            graph.add_edge(table_node, "HAS_RULE", rule_node, row_index=row_index)
            graph.add_edge(rule_node, "USES_OPERATION", operation_node)
            for variable, value in conditions.items():
                condition_node = graph.add_entity("StateVariable", variable)
                graph.add_edge(rule_node, "HAS_CONDITION", condition_node, value=value, raw=condition_raw[variable])
            behavior_name = f"{behavior['type']}:{behavior['value']}"
            behavior_node = graph.add_entity(
                "ExpectedBehavior",
                behavior_name,
                behavior_type=behavior["type"],
                behavior_value=behavior["value"],
            )
            graph.add_edge(rule_node, "EXPECTS", behavior_node, raw=behavior["raw"])
    return rules


def load_sourced_cases(path: Path) -> tuple[list[Any], Any]:
    spec = importlib.util.spec_from_file_location("sourced_edges_for_spec_graph", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load sourced tests from {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return list(module.build_cases()), module


def target_operation(case_item: Any) -> str | None:
    target = case_item.trajectory[-1]
    command = target.get("input", {}).get("command")
    if command == "Read":
        return "HostRead"
    if command == "Write":
        return "HostWrite"
    return None


def word_set(text: str) -> set[str]:
    return set(re.findall(r"[a-z0-9]+", text.lower()))


def behavior_hints(case_item: Any) -> set[str]:
    text = f"{case_item.name} {case_item.evidence.rule}".lower()
    hints: set[str] = set()
    if "zero" in text:
        hints.add("all_zeroes")
    if "user data" in text or "old user data" in text or "accepts write" in text or "unlocked" in text:
        hints.add("user_data")
    if "mbr" in text and ("inside" in text or "shadow" in text):
        hints.add("mbr_table_data")
    if "data protection" in text or "error" in text or "locked range" in text or "mixed" in text:
        hints.add("data_protection_error_no_data")
    return hints


def as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y", "on"}
    return bool(value)


def effective_ranges_for_lba(state: Any, lba: tuple[int, int] | None) -> list[Any]:
    from src.solver import RangeState

    global_range = state.ranges.get(0) or RangeState(range_id=0)
    if lba is None:
        return [global_range]

    start, end = lba
    overlaps: list[tuple[int, int, Any]] = []
    for range_state in state.ranges.values():
        if range_state.range_id == 0 or range_state.range_length <= 0:
            continue
        r_start = range_state.range_start
        r_end = r_start + range_state.range_length - 1
        if end < r_start or start > r_end:
            continue
        overlaps.append((max(start, r_start), min(end, r_end), range_state))

    if not overlaps:
        return [global_range]

    overlaps.sort(key=lambda item: (item[0], item[1], item[2].range_id))
    ranges: list[Any] = []
    seen: set[int] = set()
    for _, _, range_state in overlaps:
        ranges.append(range_state)
        seen.add(range_state.range_id)

    cursor = start
    uncovered = False
    for covered_start, covered_end, _ in overlaps:
        if cursor < covered_start:
            uncovered = True
            break
        cursor = max(cursor, covered_end + 1)
        if cursor > end:
            break
    if cursor <= end:
        uncovered = True
    if uncovered and 0 not in seen:
        ranges.append(global_range)
    return ranges


def lock_condition_values(ranges: list[Any], mode: str) -> tuple[bool, bool | str]:
    enabled_attr = f"{mode}_lock_enabled"
    locked_attr = f"{mode}_locked"
    enabled = any(bool(getattr(range_state, enabled_attr)) for range_state in ranges)
    effective_locked = [bool(getattr(range_state, enabled_attr)) and bool(getattr(range_state, locked_attr)) for range_state in ranges]
    if not effective_locked:
        return False, False
    if len(set(effective_locked)) > 1:
        return enabled, "mixed"
    return enabled, effective_locked[0]


def state_before_target(case_item: Any) -> Any:
    from src.solver import State, apply_transition, parse_event

    state = State()
    for raw in case_item.trajectory[:-1]:
        apply_transition(state, parse_event(raw))
    return state


def observed_conditions_for_case(case_item: Any) -> dict[str, Any] | None:
    from src.solver import DEFAULT_MBR_SHADOW_LBA_COUNT, parse_event

    operation = target_operation(case_item)
    if operation not in {"HostRead", "HostWrite"}:
        return None

    state = state_before_target(case_item)
    target = parse_event(case_item.trajectory[-1])
    conditions: dict[str, Any] = {
        "MBRControl.Enable": as_bool(state.mbr.get("Enabled")),
        "MBRControl.Done": as_bool(state.mbr.get("Done")),
    }
    if conditions["MBRControl.Enable"] and not conditions["MBRControl.Done"] and target.lba is not None:
        start, end = target.lba
        conditions["LBA.StartWithinMBR"] = 0 <= start < DEFAULT_MBR_SHADOW_LBA_COUNT
        conditions["LBA.EndWithinMBR"] = 0 <= end < DEFAULT_MBR_SHADOW_LBA_COUNT
    else:
        conditions["LBA.StartWithinMBR"] = "any"
        conditions["LBA.EndWithinMBR"] = "any"

    ranges = effective_ranges_for_lba(state, target.lba)
    if operation == "HostRead":
        enabled, locked = lock_condition_values(ranges, "read")
        conditions["Locking.ReadLockEnabled"] = enabled
        conditions["Locking.ReadLocked"] = locked
    else:
        enabled, locked = lock_condition_values(ranges, "write")
        conditions["Locking.WriteLockEnabled"] = enabled
        conditions["Locking.WriteLocked"] = locked
    return conditions


def rule_matches_observed(rule: dict[str, Any], observed: dict[str, Any]) -> bool:
    for key, expected in rule["conditions"].items():
        actual = observed.get(key, "any")
        if expected == "any" or actual == "any":
            continue
        if expected != actual:
            return False
    return True


def score_candidate(case_item: Any, rule: dict[str, Any], observed: dict[str, Any] | None = None) -> float:
    if observed is not None:
        if target_operation(case_item) != rule["operation"]:
            return 0.0
        if not rule_matches_observed(rule, observed):
            return 0.0
        return 1.0

    score = 0.0
    op = target_operation(case_item)
    if op is not None and rule["operation"] == op:
        score += 0.35

    text = f"{case_item.name} {case_item.evidence.rule}".lower()
    conditions = rule["conditions"]
    if "done true" in text and conditions.get("MBRControl.Done") is True:
        score += 0.10
    if "active" in text and conditions.get("MBRControl.Enable") is True:
        score += 0.08
    if "partial-boundary" in text and conditions.get("LBA.StartWithinMBR") is True and conditions.get("LBA.EndWithinMBR") is False:
        score += 0.12
    if "inside" in text and conditions.get("LBA.StartWithinMBR") is True:
        score += 0.08
    if "outside" in text and conditions.get("LBA.StartWithinMBR") in {False, "any"}:
        score += 0.06
    if "disabled" in text and (conditions.get("Locking.ReadLockEnabled") is False or conditions.get("Locking.WriteLockEnabled") is False):
        score += 0.10
    if "unlocked" in text and (conditions.get("Locking.ReadLocked") is False or conditions.get("Locking.WriteLocked") is False):
        score += 0.10
    if "mixed" in text and (conditions.get("Locking.ReadLocked") == "mixed" or conditions.get("Locking.WriteLocked") == "mixed"):
        score += 0.12
    if "read-locked" in text and conditions.get("Locking.ReadLocked") is True:
        score += 0.10
    if "write-locked" in text and conditions.get("Locking.WriteLocked") is True:
        score += 0.10

    expected_value = str(rule["expected_behavior"]["value"])
    if expected_value in behavior_hints(case_item):
        score += 0.18

    rule_words = word_set(rule["source"]["row_text"] + " " + stable_json(rule["expected_behavior"]))
    case_words = word_set(case_item.name + " " + case_item.evidence.rule)
    if rule_words and case_words:
        score += min(0.12, len(rule_words & case_words) / max(1, len(rule_words | case_words)) * 0.50)
    return round(min(score, 1.0), 4)


def build_test_links(cases: list[Any], sourced_module: Any, rules: list[dict[str, Any]], graph: GraphBuilder) -> list[dict[str, Any]]:
    rules_by_source: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for rule in rules:
        rules_by_source[rule["source"]["path"]].append(rule)

    test_links: list[dict[str, Any]] = []
    for case_item in cases:
        case_identifier = sourced_module.case_id(case_item)
        test_node = graph.add_entity(
            "TestCase",
            case_identifier,
            case_name=case_item.name,
            expected=case_item.expected,
            tag=case_item.tag,
        )
        evidence_sources = [normalize_doc_path(source) for source in case_item.evidence.sources]
        for source in evidence_sources:
            graph.add_edge(test_node, "TEST_CITES_SECTION", section_id(source), case_name=case_item.name)

        candidates: list[dict[str, Any]] = []
        observed = observed_conditions_for_case(case_item)
        for source in evidence_sources:
            for rule in rules_by_source.get(source, []):
                score = score_candidate(case_item, rule, observed)
                if score >= 0.30:
                    candidates.append(
                        {
                            "rule_id": rule["rule_id"],
                            "score": score,
                            "link_status": "candidate_unreviewed",
                            "reason": "same source section plus reconstructed final-state condition match",
                        }
                    )
                    graph.add_edge(
                        test_node,
                        "CANDIDATE_COVERS_RULE",
                        rule["node_id"],
                        score=score,
                        link_status="candidate_unreviewed",
                    )
        candidates.sort(key=lambda item: (-item["score"], item["rule_id"]))
        test_links.append(
            {
                "test_id": case_identifier,
                "case_name": case_item.name,
                "tag": case_item.tag,
                "author_expected": case_item.expected,
                "evidence_sources": evidence_sources,
                "evidence_rule": case_item.evidence.rule,
                "candidate_rules": candidates[:5],
            }
        )
    return test_links


def dedupe_edges(edges: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    unique: list[dict[str, Any]] = []
    for edge in edges:
        key = stable_json(edge)
        if key in seen:
            continue
        seen.add(key)
        unique.append(edge)
    return unique


def render_report(
    sections: list[dict[str, Any]],
    entities: list[dict[str, Any]],
    rules: list[dict[str, Any]],
    edges: list[dict[str, Any]],
    test_links: list[dict[str, Any]],
) -> str:
    table_counts = Counter(rule["source"]["table"] for rule in rules)
    operation_counts = Counter(rule["operation"] for rule in rules)
    behavior_counts = Counter(f"{rule['expected_behavior']['type']}:{rule['expected_behavior']['value']}" for rule in rules)
    candidate_rule_ids = {
        candidate["rule_id"]
        for link in test_links
        for candidate in link["candidate_rules"]
        if candidate["link_status"] == "candidate_unreviewed"
    }
    uncovered = [rule for rule in rules if rule["rule_id"] not in candidate_rule_ids]

    lines = [
        "# Spec Graph Report",
        "",
        "This report is generated by `tools/build_spec_graph.py`.",
        "",
        "Important: candidate test links are not accepted coverage. They are review queue items.",
        "",
        "## Summary",
        "",
        f"- sections indexed: {len(sections)}",
        f"- entities: {len(entities)}",
        f"- deterministic rules: {len(rules)}",
        f"- edges: {len(edges)}",
        f"- sourced tests linked: {len(test_links)}",
        f"- rules with at least one candidate test link: {len(candidate_rule_ids)}",
        f"- rules with no candidate test link yet: {len(uncovered)}",
        "",
        "## Rules By Table",
        "",
    ]
    for table, count in sorted(table_counts.items()):
        lines.append(f"- {table}: {count}")
    lines.extend(["", "## Rules By Operation", ""])
    for operation, count in sorted(operation_counts.items()):
        lines.append(f"- {operation}: {count}")
    lines.extend(["", "## Rules By Expected Behavior", ""])
    for behavior, count in sorted(behavior_counts.items()):
        lines.append(f"- {behavior}: {count}")

    lines.extend(["", "## Uncovered Deterministic Rules", ""])
    if uncovered:
        for rule in uncovered:
            lines.append(
                f"- `{rule['rule_id']}`: {rule['source']['table']} row {rule['source']['row_index']} -> "
                f"{rule['expected_behavior']['type']}:{rule['expected_behavior']['value']}"
            )
    else:
        lines.append("- none by candidate-link heuristic")

    lines.extend(["", "## Highest-Scoring Test Link Candidates", ""])
    rows: list[tuple[float, str, str]] = []
    for link in test_links:
        for candidate in link["candidate_rules"][:1]:
            rows.append((candidate["score"], link["case_name"], candidate["rule_id"]))
    for score, case_name, rid in sorted(rows, reverse=True)[:20]:
        lines.append(f"- {score:.2f} `{rid}` <- {case_name}")

    lines.extend(
        [
            "",
            "## Review Policy",
            "",
            "- `rules.jsonl` rows have `review_status=needs_review` even when extracted deterministically.",
            "- `test_links.jsonl` uses `candidate_unreviewed`; it must not be treated as final coverage.",
            "- The next trustworthy step is to create reviewer packets per uncovered or low-confidence rule.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--doc-root", type=Path, default=DEFAULT_DOC_ROOT)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    parser.add_argument("--sourced-tests", type=Path, default=DEFAULT_SOURCED_TESTS)
    args = parser.parse_args()

    sections = collect_sections(args.doc_root)
    graph = GraphBuilder()
    rules = build_table_rules(args.doc_root, graph)
    cases, sourced_module = load_sourced_cases(args.sourced_tests)
    test_links = build_test_links(cases, sourced_module, rules, graph)

    entities = sorted(graph.entities.values(), key=lambda row: row["node_id"])
    edges = sorted(dedupe_edges(graph.edges), key=lambda row: (row["src"], row["rel"], row["dst"], stable_json(row)))
    rules = sorted(rules, key=lambda row: row["rule_id"])
    test_links = sorted(test_links, key=lambda row: row["test_id"])

    args.out_dir.mkdir(parents=True, exist_ok=True)
    write_jsonl(args.out_dir / "sections.jsonl", sections)
    write_jsonl(args.out_dir / "entities.jsonl", entities)
    write_jsonl(args.out_dir / "rules.jsonl", rules)
    write_jsonl(args.out_dir / "edges.jsonl", edges)
    write_jsonl(args.out_dir / "test_links.jsonl", test_links)
    (args.out_dir / "graph_report.md").write_text(
        render_report(sections, entities, rules, edges, test_links),
        encoding="utf-8",
    )

    print(f"sections={len(sections)}")
    print(f"entities={len(entities)}")
    print(f"rules={len(rules)}")
    print(f"edges={len(edges)}")
    print(f"test_links={len(test_links)}")
    print(f"wrote={args.out_dir}")


if __name__ == "__main__":
    main()
