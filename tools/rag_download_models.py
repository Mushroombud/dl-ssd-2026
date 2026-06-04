#!/usr/bin/env python3
"""Download open-source RAG models into artifacts/models for offline use."""

from __future__ import annotations

import argparse
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODEL_ROOT = ROOT / "artifacts" / "models"

MODELS = {
    "embedding": ("Qwen/Qwen3-Embedding-0.6B", MODEL_ROOT / "Qwen3-Embedding-0.6B"),
    "reranker": ("Qwen/Qwen3-Reranker-0.6B", MODEL_ROOT / "Qwen3-Reranker-0.6B"),
}


def download_model(kind: str) -> Path:
    from huggingface_hub import snapshot_download

    repo_id, target = MODELS[kind]
    target.mkdir(parents=True, exist_ok=True)
    print(f"downloading {kind}: {repo_id} -> {target}")
    snapshot_download(
        repo_id=repo_id,
        local_dir=target,
    )
    return target


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--model",
        choices=["all", *MODELS],
        default="all",
        help="Model to download. Defaults to both embedding and reranker.",
    )
    args = parser.parse_args()

    selected = MODELS if args.model == "all" else {args.model: MODELS[args.model]}
    for kind in selected:
        path = download_model(kind)
        print(f"{kind}={path}")


if __name__ == "__main__":
    main()
