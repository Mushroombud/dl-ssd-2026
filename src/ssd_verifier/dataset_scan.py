from __future__ import annotations

import argparse
import collections
import json
from pathlib import Path
from typing import Any

from src.solver import parse_event


def _case_number(path: Path) -> int:
    digits = "".join(ch for ch in path.stem if ch.isdigit())
    return int(digits or 0)


def _load_labels(path: Path | None) -> dict[str, str]:
    if path is None or not path.exists():
        return {}
    labels: dict[str, str] = {}
    for line in path.read_text().splitlines():
        if not line.strip():
            continue
        record = json.loads(line)
        labels[record["filename"]] = record["label"]
    return labels


def _top(counter: collections.Counter[Any], limit: int) -> list[tuple[Any, int]]:
    return counter.most_common(limit)


def scan_dataset(dataset_dir: Path, label_path: Path | None = None, top_k: int = 20) -> str:
    labels = _load_labels(label_path)
    files = sorted(dataset_dir.glob("tc*.json"), key=_case_number)

    method_counts: collections.Counter[str] = collections.Counter()
    object_counts: collections.Counter[str] = collections.Counter()
    uid_counts: collections.Counter[str] = collections.Counter()
    status_counts: collections.Counter[str | None] = collections.Counter()
    target_counts: collections.Counter[tuple[str, str, str]] = collections.Counter()
    target_status_counts: collections.Counter[str | None] = collections.Counter()
    set_columns: collections.Counter[tuple[str, int]] = collections.Counter()
    genkey_cases: list[str] = []
    host_io_cases: list[str] = []
    unknown_examples: list[str] = []

    for path in files:
        trajectory = json.loads(path.read_text())
        label = labels.get(path.name, "?")
        for index, raw in enumerate(trajectory):
            event = parse_event(raw)
            is_target = index == len(trajectory) - 1
            method_counts[event.method] += 1
            object_counts[event.invoking_symbol or event.invoking_name or event.kind] += 1
            uid_counts[event.invoking_uid] += bool(event.invoking_uid)
            status_counts[event.status] += 1
            if event.method == "Set":
                for column in event.values:
                    set_columns[(event.invoking_symbol, column)] += 1
            if event.method == "GenKey":
                genkey_cases.append(path.name)
            if event.kind == "host_io":
                host_io_cases.append(path.name)
            if event.method == "UNKNOWN" and len(unknown_examples) < top_k:
                unknown_examples.append(f"{path.name}#{index + 1}: {json.dumps(raw, ensure_ascii=False)[:300]}")
            if is_target:
                target_counts[(event.method, event.invoking_symbol or event.kind, label)] += 1
                target_status_counts[event.status] += 1

    lines = [
        f"total trajectories: {len(files)}",
        f"label distribution: {dict(collections.Counter(labels.values())) if labels else '{}'}",
        "",
        "method distribution:",
    ]
    lines.extend(f"- {method}: {count}" for method, count in _top(method_counts, top_k))
    lines.append("")
    lines.append("object distribution:")
    lines.extend(f"- {obj}: {count}" for obj, count in _top(object_counts, top_k))
    lines.append("")
    lines.append("status distribution:")
    lines.extend(f"- {status}: {count}" for status, count in _top(status_counts, top_k))
    lines.append("")
    lines.append("target distribution:")
    lines.extend(f"- {method} / {obj} / {label}: {count}" for (method, obj, label), count in _top(target_counts, top_k))
    lines.append("")
    lines.append("target status distribution:")
    lines.extend(f"- {status}: {count}" for status, count in _top(target_status_counts, top_k))
    lines.append("")
    lines.append("Set object/column distribution:")
    lines.extend(f"- {obj} column {column}: {count}" for (obj, column), count in _top(set_columns, top_k))
    lines.append("")
    lines.append(f"GenKey cases: {sorted(set(genkey_cases))}")
    lines.append(f"Host I/O cases: {sorted(set(host_io_cases))}")
    if unknown_examples:
        lines.append("")
        lines.append("unknown examples:")
        lines.extend(f"- {example}" for example in unknown_examples)
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description="Profile offline TCG/Opal trajectory JSON files.")
    parser.add_argument("dataset_dir", type=Path, nargs="?", default=Path("dataset/testcases"))
    parser.add_argument("--labels", type=Path, default=Path("dataset/label.jsonl"))
    parser.add_argument("--top-k", type=int, default=20)
    args = parser.parse_args()
    label_path = args.labels if args.labels.exists() else None
    print(scan_dataset(args.dataset_dir, label_path, args.top_k), end="")


if __name__ == "__main__":
    main()
