#!/usr/bin/env python3
"""Audit whether final-target expectations are exact enough.

The hidden benchmark judges only the final operation.  Earlier operations are
state setup, so the verifier should not accept broad response families for the
target unless that ambiguity is explicitly intentional.
"""

from __future__ import annotations

import argparse
import copy
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.solver import (  # noqa: E402
    FAIL,
    INSUFFICIENT_ROWS,
    INSUFFICIENT_SPACE,
    INVALID_PARAMETER,
    NOT_AUTHORIZED,
    SP_BUSY,
    SP_DISABLED,
    SP_FROZEN,
    SUCCESS,
    State,
    _apply_invocation_auth_for_target,
    _explicit_authas_known_wrong,
    _implicit_session_for_event,
    _output_return_values,
    _raw_tcg_method_event,
    _tighten_raw_tcg_final_expectation,
    apply_transition,
    expected_status,
    parse_event,
    predict_trajectory,
)
from src.solver_components.models import Event, ExpectedResponse  # noqa: E402


PASS_EQUIVALENT = {SUCCESS, None, "PASS"}
FAILURE_STATUSES = {
    FAIL,
    NOT_AUTHORIZED,
    INVALID_PARAMETER,
    INSUFFICIENT_SPACE,
    INSUFFICIENT_ROWS,
    SP_DISABLED,
    SP_FROZEN,
    SP_BUSY,
}

PAYLOAD_GUARD_FIELDS = (
    "expected_read_result",
    "forbidden_read_result",
    "expected_return_length",
    "expected_return_uinteger_count",
    "expected_return_cells",
    "optional_return_cells",
    "expected_return_min_cells",
    "expected_return_max_cells",
    "expected_return_cell_lte",
    "expected_return_min_values",
    "expected_return_max_values",
    "optional_return_min_values",
    "optional_return_max_values",
    "expected_return_allowed_values",
    "expected_return_bit_masks",
    "required_return_names",
    "required_any_return_names",
    "forbidden_return_names",
    "expected_return_values",
    "expected_return_properties",
    "optional_return_properties",
    "forbidden_return_properties",
    "validate_tper_properties",
    "required_return_columns",
    "forbidden_return_columns",
    "expected_return_column_types",
    "require_typed_return_columns",
    "expected_return_bool",
    "require_return_bool",
    "forbidden_return_bool",
    "forbid_return_bool_literal",
    "forbid_return_bool_payload",
    "forbid_return_status_bool_payload",
    "forbid_bare_status_return_payload",
    "require_non_empty_return_payload",
    "require_return_byte_payload",
    "expected_return_uid_list",
    "expected_return_uid_list_length",
    "expected_return_uid_list_min_length",
    "expected_return_uid_refs",
    "required_return_uid_refs",
    "forbidden_return_uid_refs",
    "forbidden_return_uid_ref_prefixes",
    "expected_return_pattern",
    "expected_return_byte_positions",
    "expected_read_byte_positions",
    "expected_return_min_length",
    "forbid_read_result_presence",
    "expected_zero_read_result",
)

BOOLEAN_FLAG_GUARD_FIELDS = {
    "validate_tper_properties",
    "require_typed_return_columns",
    "require_return_bool",
    "forbid_return_bool_literal",
    "forbid_return_bool_payload",
    "forbid_return_status_bool_payload",
    "forbid_bare_status_return_payload",
    "require_non_empty_return_payload",
    "require_return_byte_payload",
    "expected_return_uid_list",
    "forbid_read_result_presence",
    "expected_zero_read_result",
}

OPTIONAL_SCALAR_GUARD_FIELDS = {
    "expected_read_result",
    "forbidden_read_result",
    "expected_return_length",
    "expected_return_uinteger_count",
    "expected_return_bool",
    "forbidden_return_bool",
    "expected_return_uid_list_length",
    "expected_return_uid_list_min_length",
    "expected_return_pattern",
    "expected_return_min_length",
}


def labels_by_filename(path: Path) -> dict[str, str]:
    labels: dict[str, str] = {}
    if not path.exists():
        return labels
    with path.open() as handle:
        for line in handle:
            if not line.strip():
                continue
            raw = json.loads(line)
            labels[raw["filename"]] = raw["label"].upper()
    return labels


def dataset_cases(testcase_dir: Path, label_path: Path) -> list[dict[str, Any]]:
    labels = labels_by_filename(label_path)
    cases: list[dict[str, Any]] = []
    for path in sorted(testcase_dir.glob("*.json")):
        with path.open() as handle:
            trajectory = json.load(handle)
        cases.append(
            {
                "source": "dataset",
                "id": path.name,
                "name": path.name,
                "tag": "dataset",
                "expected_verdict": labels.get(path.name),
                "trajectory": trajectory,
            }
        )
    return cases


def synthetic_cases(tag: str | None) -> list[dict[str, Any]]:
    from tools.run_synthetic_edges import build_cases

    cases = []
    for case in build_cases():
        if tag is not None and case.tag != tag:
            continue
        cases.append(
            {
                "source": "synthetic",
                "id": case.name,
                "name": case.name,
                "tag": case.tag,
                "expected_verdict": case.expected,
                "trajectory": case.trajectory,
            }
        )
    return cases


def sourced_cases(tag: str | None, consensus_gate: bool, consensus_matrix: Path) -> list[dict[str, Any]]:
    from tools.run_sourced_edges import build_cases, case_id, consensus_accepted_ids

    accepted = consensus_accepted_ids(consensus_matrix) if consensus_gate else None
    cases = []
    for case in build_cases():
        if tag is not None and case.tag != tag:
            continue
        resolved_case_id = case_id(case)
        if accepted is not None and resolved_case_id not in accepted:
            continue
        cases.append(
            {
                "source": "sourced",
                "id": resolved_case_id,
                "name": case.name,
                "tag": case.tag,
                "expected_verdict": case.expected,
                "trajectory": case.trajectory,
            }
        )
    return cases


def state_before_target(trajectory: list[dict[str, Any]]) -> State:
    state = State()
    for raw in trajectory[:-1]:
        apply_transition(state, parse_event(raw))
    return state


def expectation_before_compare(trajectory: list[dict[str, Any]]) -> tuple[ExpectedResponse, Event]:
    state = state_before_target(trajectory)
    event = parse_event(trajectory[-1])
    working_state = state
    if event.implicit_session and not state.session.open and event.kind == "tcg_method":
        working_state = copy.deepcopy(state)
        working_state.session = _implicit_session_for_event(working_state, event, assume_authenticated=False)
    added_authority, credential_unknown = _apply_invocation_auth_for_target(working_state, event)
    try:
        expected = expected_status(working_state, event)
        if _explicit_authas_known_wrong(working_state, event):
            expected.allowed_statuses = {NOT_AUTHORIZED} if _raw_tcg_method_event(event) else {NOT_AUTHORIZED, FAIL}
            expected.forbidden_statuses = set(expected.forbidden_statuses) | {SUCCESS}
        if added_authority is not None and credential_unknown:
            expected.allowed_statuses = set(expected.allowed_statuses) | {NOT_AUTHORIZED}
        expected = _tighten_raw_tcg_final_expectation(expected, event)
        return expected, event
    finally:
        if added_authority is not None:
            working_state.session.authenticated.discard(added_authority)


def truthy_payload_guards(expected: ExpectedResponse) -> list[str]:
    guards = []
    for field_name in PAYLOAD_GUARD_FIELDS:
        value = getattr(expected, field_name)
        if field_name in BOOLEAN_FLAG_GUARD_FIELDS:
            if value is True:
                guards.append(field_name)
            continue
        if field_name in OPTIONAL_SCALAR_GUARD_FIELDS:
            if value is not None:
                guards.append(field_name)
            continue
        if value not in (None, [], {}, (), set()):
            guards.append(field_name)
    return guards


def target_payload_present(event: Event) -> bool:
    if event.kind == "host_io" and event.method == "Read":
        return event.read_result is not None
    payload = _output_return_values(event.raw)
    return payload not in (None, [], {}, ())


def classify(expected: ExpectedResponse, event: Event) -> str:
    allowed = set(expected.allowed_statuses)
    success = allowed & PASS_EQUIVALENT
    failures = allowed & FAILURE_STATUSES
    other = allowed - PASS_EQUIVALENT - FAILURE_STATUSES
    raw_tcg = event.kind == "tcg_method" and _raw_tcg_method_event(event)

    if expected.allow_generic_failure_status:
        return "explicit_generic_failure"
    if expected.allow_status_alternatives and len(allowed) > 1:
        return "explicit_status_alternatives"
    if success and failures:
        return "mixed_success_failure"
    if len(failures) > 1:
        return "broad_failure"
    if raw_tcg and success and allowed != {SUCCESS}:
        return "broad_success"
    if success and other:
        return "broad_success"
    if other and len(allowed) > 1:
        return "broad_other"
    if success:
        return "exact_success_with_payload_guard" if truthy_payload_guards(expected) else "exact_success_status_only"
    if failures:
        return "exact_failure_status"
    if len(allowed) == 1:
        return "exact_other_status"
    return "empty_or_unknown"


def method_key(event: Event) -> str:
    invoking = event.invoking_symbol or event.invoking_name or event.invoking_uid or "<unknown>"
    return f"{event.kind}:{event.method}:{invoking}"


def audit_case(case: dict[str, Any]) -> dict[str, Any]:
    expected, event = expectation_before_compare(case["trajectory"])
    solver_verdict = predict_trajectory(case["trajectory"])
    guards = truthy_payload_guards(expected)
    category = classify(expected, event)
    has_payload = target_payload_present(event)
    success_allowed = bool(set(expected.allowed_statuses) & PASS_EQUIVALENT)
    return {
        "source": case["source"],
        "id": case["id"],
        "name": case["name"],
        "tag": case["tag"],
        "expected_verdict": case.get("expected_verdict"),
        "solver_verdict": solver_verdict,
        "verdict_mismatch": case.get("expected_verdict") not in (None, solver_verdict),
        "category": category,
        "method_key": method_key(event),
        "kind": event.kind,
        "method": event.method,
        "invoking_symbol": event.invoking_symbol,
        "target_status": event.status,
        "allowed_statuses": sorted(str(item) for item in expected.allowed_statuses),
        "forbidden_statuses": sorted(str(item) for item in expected.forbidden_statuses),
        "allow_generic_failure_status": expected.allow_generic_failure_status,
        "allow_status_alternatives": expected.allow_status_alternatives,
        "raw_tcg_exact_status": expected.raw_tcg_exact_status,
        "confidence": expected.confidence,
        "reason": expected.reason,
        "payload_guards": guards,
        "target_payload_present": has_payload,
        "success_payload_unconstrained": success_allowed and has_payload and not guards,
        "raw_tcg_method": _raw_tcg_method_event(event),
    }


def collect_cases(args: argparse.Namespace) -> list[dict[str, Any]]:
    sources = set(args.source)
    cases: list[dict[str, Any]] = []
    if "dataset" in sources:
        cases.extend(dataset_cases(args.testcase_dir, args.label_path))
    if "synthetic" in sources:
        cases.extend(synthetic_cases(args.tag))
    if "sourced" in sources:
        cases.extend(sourced_cases(args.tag, args.consensus_gate, args.consensus_matrix))
    if args.limit is not None:
        cases = cases[: args.limit]
    return cases


def print_summary(rows: list[dict[str, Any]], *, top: int) -> None:
    category_counts = Counter(row["category"] for row in rows)
    mismatch_count = sum(1 for row in rows if row["verdict_mismatch"])
    payload_unconstrained = [row for row in rows if row["success_payload_unconstrained"]]
    status_only_success = [row for row in rows if row["category"] == "exact_success_status_only"]
    broad_rows = [
        row
        for row in rows
        if row["category"] in {"broad_failure", "mixed_success_failure", "broad_success", "broad_other", "empty_or_unknown"}
    ]

    print(f"audited cases: {len(rows)}")
    print(f"verdict mismatches: {mismatch_count}")
    print("expectation categories:", json.dumps(dict(sorted(category_counts.items())), sort_keys=True))
    print(f"broad or unknown final expectations: {len(broad_rows)}")
    print(f"success targets with status-only expectation: {len(status_only_success)}")
    print(f"success targets with payload but no payload guard: {len(payload_unconstrained)}")

    for title, selected in (
        ("broad by method", broad_rows),
        ("status-only success by method", status_only_success),
        ("payload-unconstrained success by method", payload_unconstrained),
    ):
        counts = Counter(row["method_key"] for row in selected)
        print(f"\n{title}:")
        if not counts:
            print("  none")
            continue
        for key, count in counts.most_common(top):
            print(f"  {count:5d}  {key}")

    by_tag: dict[str, Counter[str]] = defaultdict(Counter)
    for row in broad_rows:
        by_tag[row["tag"]][row["category"]] += 1
    if by_tag:
        print("\nbroad categories by tag:")
        for tag, counts in sorted(by_tag.items(), key=lambda item: (-sum(item[1].values()), item[0]))[:top]:
            print(f"  {sum(counts.values()):5d}  {tag}  {json.dumps(dict(sorted(counts.items())), sort_keys=True)}")


def write_jsonl(rows: Iterable[dict[str, Any]]) -> None:
    try:
        for row in rows:
            print(json.dumps(row, ensure_ascii=False, default=str))
    except BrokenPipeError:
        return


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--source",
        action="append",
        choices=("dataset", "synthetic", "sourced"),
        default=None,
        help="Case source to audit. May be passed multiple times. Default: dataset.",
    )
    parser.add_argument("--tag", help="Limit synthetic/sourced cases to one tag.")
    parser.add_argument("--limit", type=int, help="Audit only the first N selected cases.")
    parser.add_argument("--jsonl", action="store_true", help="Emit detailed JSONL instead of a summary.")
    parser.add_argument("--category", action="append", help="With --jsonl, emit only rows in this category.")
    parser.add_argument("--payload-unconstrained-only", action="store_true", help="With --jsonl, emit only payload-unconstrained successes.")
    parser.add_argument("--max-jsonl", type=int, help="With --jsonl, emit at most this many rows after filtering.")
    parser.add_argument("--top", type=int, default=20, help="Number of summary rows to print per section.")
    parser.add_argument("--consensus-gate", action="store_true", help="For sourced cases, use accepted consensus cases only.")
    parser.add_argument("--consensus-matrix", type=Path, default=ROOT / "analysis" / "label_consensus_matrix.json")
    parser.add_argument("--testcase-dir", type=Path, default=ROOT / "dataset" / "testcases")
    parser.add_argument("--label-path", type=Path, default=ROOT / "dataset" / "label.jsonl")
    args = parser.parse_args()
    if args.source is None:
        args.source = ["dataset"]
    return args


def main() -> None:
    args = parse_args()
    rows = [audit_case(case) for case in collect_cases(args)]
    if args.category:
        categories = set(args.category)
        rows = [row for row in rows if row["category"] in categories]
    if args.payload_unconstrained_only:
        rows = [row for row in rows if row["success_payload_unconstrained"]]
    if args.max_jsonl is not None and args.jsonl:
        rows = rows[: args.max_jsonl]
    if args.jsonl:
        write_jsonl(rows)
    else:
        print_summary(rows, top=args.top)


if __name__ == "__main__":
    main()
