#!/usr/bin/env python3
"""RAG-assisted audit packets for SSD verifier probe labels and spec gaps."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.rag_retrieval import build_query_from_trajectory, hit_to_json, json_default, load_chunks, retrieve
from src.solver import parse_event, predict_trajectory


DEFAULT_OUT_DIR = ROOT / "analysis" / "spec_audit"
DEFAULT_PROBE_OUT = DEFAULT_OUT_DIR / "probe_packets.jsonl"
DEFAULT_PROBE_SWEEP_OUT = DEFAULT_OUT_DIR / "probe_sweep_packets.jsonl"
DEFAULT_PROBE_SWEEP_SUMMARY = DEFAULT_OUT_DIR / "probe_sweep_summary.json"
DEFAULT_OBLIGATION_OUT = DEFAULT_OUT_DIR / "obligation_packets.jsonl"
DEFAULT_PROFILE_OUT = DEFAULT_OUT_DIR / "runtime_profile.json"
DOC_ROOT = ROOT / "artifacts" / "documents"
EMBEDDINGS = ROOT / "artifacts" / "rag_index" / "dense_embeddings.npy"
EMBEDDING_MODEL = ROOT / "artifacts" / "models" / "Qwen3-Embedding-0.6B"
RERANKER_MODEL = ROOT / "artifacts" / "models" / "Qwen3-Reranker-0.6B"
SCORE_PROBE_LOOP = ROOT / "tools" / "score_probe_loop.py"

NORMATIVE_RE = re.compile(
    r"\b("
    r"SHALL|SHALL NOT|MUST|MUST NOT|REQUIRED|ONLY IF|IF|WHEN|"
    r"INVALID|ERROR|NOT_AUTHORIZED|INVALID_PARAMETER|SUCCESS|FAIL|"
    r"RETURNS?|REJECT|ALLOW|WRITE|READ|AUTHENTICAT|LOCK|RESET|"
    r"RESERVED|BIT|COLUMN|RANGE|SESSION|AUTHORITY|C_PIN"
    r")\b",
    re.IGNORECASE,
)
TOKEN_RE = re.compile(r"[A-Za-z0-9_./:-]+")


def stable_id(*parts: Any) -> str:
    payload = "\n".join(str(part) for part in parts)
    return hashlib.sha1(payload.encode("utf-8", errors="replace")).hexdigest()[:16]


def write_jsonl(path: Path, records: Iterable[dict[str, Any]]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True, default=json_default) + "\n")
            count += 1
    return count


def load_score_probe_module() -> Any:
    spec = importlib.util.spec_from_file_location("score_probe_loop_for_audit", SCORE_PROBE_LOOP)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load {SCORE_PROBE_LOOP}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def compact_event(raw: dict[str, Any]) -> dict[str, Any]:
    event = parse_event(raw)
    return {
        "kind": event.kind,
        "method": event.method,
        "invoking": event.invoking_symbol or event.invoking_name or event.invoking_uid,
        "status": event.status,
        "sp": event.sp,
        "authority": event.authority,
        "columns": sorted(event.columns),
        "values": dict(event.values),
    }


def probe_query(probe: Any) -> str:
    pieces = [
        f"probe: {probe.name}",
        f"family: {probe.family}",
        f"author rule: {probe.why}",
        f"expected protocol compliance label: {probe.expected}",
    ]
    if probe.trajectory:
        pieces.append("trajectory query:")
        pieces.append(build_query_from_trajectory(probe.trajectory))
    return "\n".join(pieces)


def hit_json(hit: Any, text_chars: int) -> dict[str, Any]:
    data = hit_to_json(hit, include_text=False)
    if text_chars > 0:
        data["text"] = hit.text[:text_chars]
    return data


def evidence_hits(query: str, chunks: list[Any], args: argparse.Namespace) -> list[dict[str, Any]]:
    hits = retrieve(
        query,
        chunks=chunks,
        candidate_top_k=args.candidate_top_k,
        final_top_k=args.final_top_k,
        use_dense=args.dense,
        use_reranker=args.reranker,
    )
    text_chars = args.hit_text_chars if args.include_text else 0
    return [hit_json(hit, text_chars) for hit in hits]


def iter_probe_packets(args: argparse.Namespace) -> Iterable[dict[str, Any]]:
    module = load_score_probe_module()
    chunks = load_chunks()
    probes = module.all_probes()
    if args.family:
        probes = [probe for probe in probes if probe.family == args.family]
    if args.offset:
        probes = probes[args.offset :]
    if args.limit is not None:
        probes = probes[: args.limit]

    for index, probe in enumerate(probes, start=args.offset + 1):
        query = probe_query(probe)
        got = predict_trajectory(probe.trajectory)
        yield {
            "schema": 1,
            "packet_type": "probe_oracle_audit",
            "probe_id": stable_id(probe.family, probe.name, probe.why),
            "index": index,
            "name": probe.name,
            "family": probe.family,
            "author_expected": probe.expected,
            "current_solver_label": got,
            "author_rule_summary": probe.why,
            "target_event": compact_event(probe.trajectory[-1]) if probe.trajectory else {},
            "last_events": [compact_event(raw) for raw in probe.trajectory[-min(4, len(probe.trajectory)) :]],
            "query": query[:2500],
            "retrieval": {
                "dense": args.dense,
                "reranker": args.reranker,
                "candidate_top_k": args.candidate_top_k,
                "final_top_k": args.final_top_k,
                "hits": evidence_hits(query, chunks, args),
            },
            "review_task": (
                "Blindly decide whether the final target event is protocol-compliant using only "
                "retrieved official spec evidence. Return PASS, FAIL, AMBIGUOUS, or UNSUPPORTED."
            ),
        }


def probe_sweep(args: argparse.Namespace) -> dict[str, Any]:
    args.dense = True
    args.reranker = True
    args.include_text = True
    args.limit = None
    args.offset = 0
    args.family = ""
    started = time.time()
    module = load_score_probe_module()
    probes = module.all_probes()
    by_family: dict[str, int] = {}
    for probe in probes:
        by_family[probe.family] = by_family.get(probe.family, 0) + 1
    count = write_jsonl(args.out, iter_probe_packets(args))
    summary = {
        "schema": 1,
        "mode": "gpu_qwen_reranker_full_probe_sweep",
        "out": str(args.out),
        "probes": count,
        "expected_probes": len(probes),
        "seconds": round(time.time() - started, 3),
        "dense": True,
        "reranker": True,
        "candidate_top_k": args.candidate_top_k,
        "final_top_k": args.final_top_k,
        "hit_text_chars": args.hit_text_chars,
        "by_family": dict(sorted(by_family.items())),
    }
    args.summary.parent.mkdir(parents=True, exist_ok=True)
    args.summary.write_text(json.dumps(summary, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
    return summary


def iter_doc_files() -> Iterable[Path]:
    for path in sorted(DOC_ROOT.rglob("*.txt")):
        relative = path.relative_to(DOC_ROOT).as_posix()
        parts = relative.split("/")
        if ".ipynb_checkpoints" in parts or any(part.startswith("_") for part in parts):
            continue
        yield path


def split_normative_candidates(text: str, max_per_doc: int) -> list[str]:
    candidates: list[str] = []
    for paragraph in re.split(r"\n\s*\n", text):
        normalized = re.sub(r"\s+", " ", paragraph).strip()
        if len(normalized) < 40 or not NORMATIVE_RE.search(normalized):
            continue
        candidates.append(normalized[:1200])
        if len(candidates) >= max_per_doc:
            break
    return candidates


def coverage_terms() -> dict[str, set[str]]:
    module = load_score_probe_module()
    terms: dict[str, set[str]] = {}
    for probe in module.all_probes():
        bucket = terms.setdefault(probe.family, set())
        for token in TOKEN_RE.findall(f"{probe.name} {probe.why}"):
            if len(token) >= 4:
                bucket.add(token.lower())
    return terms


def coverage_hints(candidate: str, by_family: dict[str, set[str]], limit: int = 5) -> list[dict[str, Any]]:
    tokens = {token.lower() for token in TOKEN_RE.findall(candidate) if len(token) >= 4}
    scored: list[tuple[str, int]] = []
    for family, family_terms in by_family.items():
        overlap = len(tokens & family_terms)
        if overlap:
            scored.append((family, overlap))
    scored.sort(key=lambda item: (-item[1], item[0]))
    return [{"family": family, "term_overlap": overlap} for family, overlap in scored[:limit]]


def obligation_query(relative_path: str, candidate: str) -> str:
    return "\n".join(
        [
            "official TCG Opal SSD normative obligation",
            f"source path: {relative_path}",
            candidate,
            "Find direct supporting or conflicting sections and related exceptions.",
        ]
    )


def iter_obligation_packets(args: argparse.Namespace) -> Iterable[dict[str, Any]]:
    chunks = load_chunks()
    family_terms = coverage_terms()
    emitted = 0
    for path in iter_doc_files():
        relative = path.relative_to(DOC_ROOT).as_posix()
        if args.path_contains and args.path_contains not in relative:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for local_index, candidate in enumerate(split_normative_candidates(text, args.max_per_doc), start=1):
            if emitted < args.offset:
                emitted += 1
                continue
            if args.limit is not None and emitted >= args.offset + args.limit:
                return
            query = obligation_query(relative, candidate)
            yield {
                "schema": 1,
                "packet_type": "spec_obligation_gap_audit",
                "obligation_id": stable_id(relative, local_index, candidate),
                "source_path": relative,
                "local_index": local_index,
                "candidate_text": candidate,
                "coverage_hints": coverage_hints(candidate, family_terms),
                "query": query[:2500],
                "retrieval": {
                    "dense": args.dense,
                    "reranker": args.reranker,
                    "candidate_top_k": args.candidate_top_k,
                    "final_top_k": args.final_top_k,
                    "hits": evidence_hits(query, chunks, args),
                },
                "review_task": (
                    "Normalize this spec text into a testable obligation, then decide whether existing "
                    "probe families appear to cover it. Return COVERED, PARTIAL, MISSING, AMBIGUOUS, or OUT_OF_SCOPE."
                ),
            }
            emitted += 1


def profile(args: argparse.Namespace) -> dict[str, Any]:
    result: dict[str, Any] = {
        "schema": 1,
        "cwd": str(ROOT),
        "dense_embeddings": {"path": str(EMBEDDINGS), "exists": EMBEDDINGS.exists()},
        "embedding_model": {"path": str(EMBEDDING_MODEL), "exists": EMBEDDING_MODEL.exists()},
        "reranker_model": {"path": str(RERANKER_MODEL), "exists": RERANKER_MODEL.exists()},
        "env": {
            "CUDA_VISIBLE_DEVICES": os.environ.get("CUDA_VISIBLE_DEVICES"),
            "PYTORCH_ENABLE_MPS_FALLBACK": os.environ.get("PYTORCH_ENABLE_MPS_FALLBACK"),
            "RAG_EMBEDDING_BATCH_SIZE": os.environ.get("RAG_EMBEDDING_BATCH_SIZE"),
            "RAG_RERANKER_BATCH_SIZE": os.environ.get("RAG_RERANKER_BATCH_SIZE"),
        },
        "recommendation": "",
        "timings": {},
    }
    chunks = load_chunks()
    result["chunks"] = len(chunks)
    query = "StartSession SessionManager HostSigningAuthority C_PIN authentication NOT_AUTHORIZED"
    modes = [("lexical", False, False)]
    if args.run_models:
        modes.extend([("dense", True, False), ("reranker", True, True)])
    else:
        result["timings"]["dense"] = {"skipped": "pass --run-models to benchmark; default avoids accidental embedding rebuilds"}
        result["timings"]["reranker"] = {"skipped": "pass --run-models to benchmark"}
    for name, dense, reranker in modes:
        if dense and not EMBEDDINGS.exists() and not EMBEDDING_MODEL.exists():
            result["timings"][name] = {"skipped": "missing embeddings and embedding model"}
            continue
        if reranker and not RERANKER_MODEL.exists():
            result["timings"][name] = {"skipped": "missing reranker model"}
            continue
        started = time.time()
        try:
            hits = retrieve(
                query,
                chunks=chunks,
                candidate_top_k=args.candidate_top_k,
                final_top_k=min(args.final_top_k, 3),
                use_dense=dense,
                use_reranker=reranker,
            )
            result["timings"][name] = {
                "seconds": round(time.time() - started, 3),
                "hits": [hit.path for hit in hits],
            }
        except Exception as exc:  # noqa: BLE001
            result["timings"][name] = {"error": f"{type(exc).__name__}: {exc}"}

    reranker_seconds = result["timings"].get("reranker", {}).get("seconds")
    dense_seconds = result["timings"].get("dense", {}).get("seconds")
    if not args.run_models:
        result["recommendation"] = "local_safe_for_lexical; run model benchmark only on GPU server or with --run-models intentionally"
    elif isinstance(reranker_seconds, (int, float)) and reranker_seconds <= 5:
        result["recommendation"] = "local_ok_for_small_batches; use GPU server for full probe+obligation sweep"
    elif isinstance(dense_seconds, (int, float)) and dense_seconds <= 3:
        result["recommendation"] = "local_dense_ok; run reranker on GPU server or omit --reranker locally"
    else:
        result["recommendation"] = "use_gpu_server_for_dense_or_reranker; local only without --dense/--reranker"
    return result


def add_common_retrieval_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--dense", action="store_true", help="Use prebuilt Qwen embeddings or build them if missing.")
    parser.add_argument("--reranker", action="store_true", help="Use Qwen reranker on fused candidates.")
    parser.add_argument("--candidate-top-k", type=int, default=24)
    parser.add_argument("--final-top-k", type=int, default=6)
    parser.add_argument("--include-text", action="store_true", help="Include hit text snippets. Increases JSONL size.")
    parser.add_argument("--hit-text-chars", type=int, default=700, help="Chars of each evidence hit to include when --include-text is set.")
    parser.add_argument("--limit", type=int, default=20)
    parser.add_argument("--offset", type=int, default=0)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    profile_parser = subparsers.add_parser("profile", help="Benchmark retrieval modes and recommend local/server placement.")
    profile_parser.add_argument("--candidate-top-k", type=int, default=12)
    profile_parser.add_argument("--final-top-k", type=int, default=3)
    profile_parser.add_argument("--run-models", action="store_true", help="Actually load Qwen models. May rebuild embeddings if metadata differs.")
    profile_parser.add_argument("--out", type=Path, default=DEFAULT_PROFILE_OUT)

    probe_parser = subparsers.add_parser("probe-packets", help="Export RAG-bound blind review packets for score probes.")
    add_common_retrieval_args(probe_parser)
    probe_parser.add_argument("--family", default="")
    probe_parser.add_argument("--out", type=Path, default=DEFAULT_PROBE_OUT)

    sweep_parser = subparsers.add_parser("probe-sweep", help="GPU full sweep of every score probe with Qwen dense retrieval and reranker.")
    sweep_parser.add_argument("--candidate-top-k", type=int, default=32)
    sweep_parser.add_argument("--final-top-k", type=int, default=5)
    sweep_parser.add_argument("--hit-text-chars", type=int, default=700)
    sweep_parser.add_argument("--out", type=Path, default=DEFAULT_PROBE_SWEEP_OUT)
    sweep_parser.add_argument("--summary", type=Path, default=DEFAULT_PROBE_SWEEP_SUMMARY)

    obligation_parser = subparsers.add_parser("obligation-packets", help="Export RAG-bound candidate spec obligation packets.")
    add_common_retrieval_args(obligation_parser)
    obligation_parser.add_argument("--max-per-doc", type=int, default=3)
    obligation_parser.add_argument("--path-contains", default="")
    obligation_parser.add_argument("--out", type=Path, default=DEFAULT_OBLIGATION_OUT)

    args = parser.parse_args()
    if args.command == "profile":
        record = profile(args)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(record, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
        print(f"profile={args.out} recommendation={record['recommendation']}")
        return 0
    if args.command == "probe-packets":
        count = write_jsonl(args.out, iter_probe_packets(args))
        print(f"probe_packets={count} out={args.out}")
        return 0
    if args.command == "probe-sweep":
        summary = probe_sweep(args)
        print(f"probe_sweep={summary['probes']} out={summary['out']} summary={args.summary}")
        return 0
    if args.command == "obligation-packets":
        count = write_jsonl(args.out, iter_obligation_packets(args))
        print(f"obligation_packets={count} out={args.out}")
        return 0
    raise AssertionError(args.command)


if __name__ == "__main__":
    raise SystemExit(main())
