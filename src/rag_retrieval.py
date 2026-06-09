"""In-memory exact hybrid retrieval over the local spec artifacts.

This module is intentionally separate from the public rule-based solver.  The
official evaluator stays lightweight, while RAG experiments can use local
open-source embedding and reranking models stored under artifacts/models.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable

from src.solver_components.parsing import parse_event


ROOT = Path(__file__).resolve().parents[1]
DOC_ROOT = ROOT / "artifacts" / "documents"
MODEL_ROOT = ROOT / "artifacts" / "models"
INDEX_ROOT = ROOT / "artifacts" / "rag_index"
EMBEDDING_MODEL_DIR = MODEL_ROOT / "Qwen3-Embedding-0.6B"
RERANKER_MODEL_DIR = MODEL_ROOT / "Qwen3-Reranker-0.6B"
DEFAULT_EMBEDDING_BATCH_SIZE = int(os.environ.get("RAG_EMBEDDING_BATCH_SIZE", "16"))
DEFAULT_RERANKER_BATCH_SIZE = int(os.environ.get("RAG_RERANKER_BATCH_SIZE", "4"))

TOKEN_RE = re.compile(r"[A-Za-z0-9_./:-]+")
SYMBOL_RE = re.compile(r"\b[A-Za-z][A-Za-z0-9_]{2,}\b|[0-9A-Fa-f]{8,}")


def json_default(value: Any) -> Any:
    if isinstance(value, (bytes, bytearray)):
        return {"type": "bytes", "hex": bytes(value).hex(), "length": len(value)}
    if isinstance(value, set):
        return sorted(value)
    return str(value)


def optional_int_env(name: str) -> int | None:
    value = os.environ.get(name)
    if value is None or not value.strip():
        return None
    return int(value)


@dataclass(frozen=True)
class Chunk:
    chunk_id: str
    path: str
    title: str
    family: str
    section: str
    source_kind: str
    text: str


@dataclass
class RetrievalHit:
    chunk_id: str
    path: str
    title: str
    family: str
    section: str
    source_kind: str
    score: float
    bm25_score: float = 0.0
    dense_score: float = 0.0
    keyword_score: float = 0.0
    rrf_score: float = 0.0
    rerank_score: float | None = None
    text: str = ""


def _normalize_path(path: Path) -> str:
    return path.relative_to(DOC_ROOT).as_posix()


def _first_title(text: str, fallback: str) -> str:
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            return stripped.lstrip("#").strip() or fallback
        if stripped:
            return stripped[:120]
    return fallback


def _section_from_path(relative: str) -> str:
    name = Path(relative).stem
    if "/details/" in relative:
        return name
    return relative.rsplit("/", 1)[-1].removesuffix(".txt").removesuffix(".md")


def iter_corpus_files(doc_root: Path = DOC_ROOT) -> Iterable[Path]:
    for path in sorted(doc_root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in {".txt", ".md"}:
            continue
        relative = _normalize_path(path)
        parts = relative.split("/")
        if ".ipynb_checkpoints" in parts:
            continue
        if "_pdf_enrichment" in parts and "/details/" not in relative:
            continue
        if any(part.startswith("_") for part in parts) and "_pdf_enrichment" not in parts:
            continue
        yield path


def load_chunks(doc_root: Path = DOC_ROOT) -> list[Chunk]:
    chunks: list[Chunk] = []
    for path in iter_corpus_files(doc_root):
        relative = _normalize_path(path)
        text = path.read_text(encoding="utf-8", errors="replace").strip()
        if not text:
            continue
        family = relative.split("/", 1)[0]
        source_kind = "pdf_enrichment" if relative.startswith("_pdf_enrichment/") else "stable_artifact"
        section = _section_from_path(relative)
        chunk_id = hashlib.sha1(relative.encode("utf-8")).hexdigest()[:16]
        chunks.append(
            Chunk(
                chunk_id=chunk_id,
                path=relative,
                title=_first_title(text, section),
                family=family,
                section=section,
                source_kind=source_kind,
                text=text,
            )
        )
    return chunks


def tokenize(text: str) -> list[str]:
    return [token.lower() for token in TOKEN_RE.findall(text)]


def query_symbols(text: str) -> set[str]:
    return {token.lower() for token in SYMBOL_RE.findall(text)}


class BM25Index:
    def __init__(self, chunks: list[Chunk]) -> None:
        self.chunks = chunks
        self.doc_tokens = [tokenize(chunk.title + "\n" + chunk.text) for chunk in chunks]
        self.doc_lens = [len(tokens) for tokens in self.doc_tokens]
        self.avgdl = sum(self.doc_lens) / max(1, len(self.doc_lens))
        self.term_freqs = [Counter(tokens) for tokens in self.doc_tokens]
        doc_freq: Counter[str] = Counter()
        for tokens in self.doc_tokens:
            doc_freq.update(set(tokens))
        total_docs = len(chunks)
        self.idf = {
            term: math.log(1.0 + (total_docs - freq + 0.5) / (freq + 0.5))
            for term, freq in doc_freq.items()
        }

    def search(self, query: str, top_k: int = 80) -> list[tuple[int, float]]:
        query_terms = tokenize(query)
        if not query_terms:
            return []
        k1 = 1.5
        b = 0.75
        scores: list[tuple[int, float]] = []
        for index, freqs in enumerate(self.term_freqs):
            score = 0.0
            doc_len = self.doc_lens[index] or 1
            norm = k1 * (1.0 - b + b * doc_len / max(1.0, self.avgdl))
            for term in query_terms:
                tf = freqs.get(term, 0)
                if tf <= 0:
                    continue
                score += self.idf.get(term, 0.0) * (tf * (k1 + 1.0)) / (tf + norm)
            if score > 0:
                scores.append((index, score))
        scores.sort(key=lambda item: item[1], reverse=True)
        return scores[:top_k]


def keyword_boost(chunks: list[Chunk], query: str, top_k: int = 40) -> list[tuple[int, float]]:
    symbols = query_symbols(query)
    if not symbols:
        return []
    scores: list[tuple[int, float]] = []
    for index, chunk in enumerate(chunks):
        haystack = (chunk.path + "\n" + chunk.title + "\n" + chunk.text).lower()
        score = 0.0
        for symbol in symbols:
            if symbol in haystack:
                score += 3.0 if len(symbol) >= 8 else 1.0
        if score > 0:
            scores.append((index, score))
    scores.sort(key=lambda item: item[1], reverse=True)
    return scores[:top_k]


def rrf_merge(rankings: list[list[tuple[int, float]]], k: float = 60.0) -> dict[int, float]:
    fused: dict[int, float] = defaultdict(float)
    for ranking in rankings:
        for rank, (index, _score) in enumerate(ranking, start=1):
            fused[index] += 1.0 / (k + rank)
    return dict(fused)


class DenseEmbedder:
    def __init__(
        self,
        model_dir: Path = EMBEDDING_MODEL_DIR,
        max_seq_length: int | None = optional_int_env("RAG_EMBEDDING_MAX_SEQ_LENGTH"),
        batch_size: int = DEFAULT_EMBEDDING_BATCH_SIZE,
    ) -> None:
        if not model_dir.exists():
            raise FileNotFoundError(f"Embedding model not found: {model_dir}")
        from sentence_transformers import SentenceTransformer

        self.model = SentenceTransformer(str(model_dir), local_files_only=True, trust_remote_code=True)
        if max_seq_length is not None:
            self.model.max_seq_length = max_seq_length
        self.max_seq_length = int(self.model.max_seq_length)
        self.batch_size = batch_size

    def encode_docs(self, texts: list[str]) -> Any:
        return self.model.encode(
            texts,
            batch_size=self.batch_size,
            normalize_embeddings=True,
            convert_to_numpy=True,
            show_progress_bar=True,
        )

    def encode_query(self, query: str) -> Any:
        return self.model.encode(
            [query],
            prompt_name="query",
            normalize_embeddings=True,
            convert_to_numpy=True,
            show_progress_bar=False,
        )[0]


class CrossEncoderReranker:
    def __init__(
        self,
        model_dir: Path = RERANKER_MODEL_DIR,
        max_length: int | None = optional_int_env("RAG_RERANKER_MAX_LENGTH"),
        batch_size: int = DEFAULT_RERANKER_BATCH_SIZE,
    ) -> None:
        if not model_dir.exists():
            raise FileNotFoundError(f"Reranker model not found: {model_dir}")
        from sentence_transformers import CrossEncoder

        try:
            kwargs: dict[str, Any] = {"local_files_only": True, "trust_remote_code": True}
            if max_length is not None:
                kwargs["max_length"] = max_length
            self.model = CrossEncoder(str(model_dir), **kwargs)
        except TypeError:
            kwargs = {"trust_remote_code": True}
            if max_length is not None:
                kwargs["max_length"] = max_length
            self.model = CrossEncoder(str(model_dir), **kwargs)
        self.max_length = max_length
        self.batch_size = batch_size

    def rerank(self, query: str, hits: list[RetrievalHit], top_k: int) -> list[RetrievalHit]:
        pairs = [(query, hit.title + "\n" + hit.text) for hit in hits]
        if not pairs:
            return []
        scores = self.model.predict(pairs, batch_size=self.batch_size, show_progress_bar=True)
        for hit, score in zip(hits, scores):
            hit.rerank_score = float(score)
            hit.score = float(score)
        hits.sort(key=lambda item: item.rerank_score if item.rerank_score is not None else -999.0, reverse=True)
        return hits[:top_k]


def _index_signature(chunks: list[Chunk]) -> str:
    digest = hashlib.sha256()
    for chunk in chunks:
        digest.update(chunk.path.encode("utf-8"))
        digest.update(b"\0")
        digest.update(hashlib.sha256(chunk.text.encode("utf-8", errors="replace")).digest())
    return digest.hexdigest()


def embedding_text(chunk: Chunk) -> str:
    return chunk.title + "\n" + chunk.text


def load_or_build_embeddings(chunks: list[Chunk], embedder: DenseEmbedder, index_root: Path = INDEX_ROOT) -> Any:
    import numpy as np

    index_root.mkdir(parents=True, exist_ok=True)
    signature = _index_signature(chunks)
    meta_path = index_root / "dense_index_meta.json"
    vectors_path = index_root / "dense_embeddings.npy"
    if meta_path.exists() and vectors_path.exists():
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        if (
            meta.get("signature") == signature
            and meta.get("model") == EMBEDDING_MODEL_DIR.name
            and meta.get("max_seq_length") == embedder.max_seq_length
        ):
            return np.load(vectors_path)

    texts = [embedding_text(chunk) for chunk in chunks]
    vectors = embedder.encode_docs(texts)
    np.save(vectors_path, vectors)
    meta_path.write_text(
        json.dumps(
            {
                "signature": signature,
                "model": EMBEDDING_MODEL_DIR.name,
                "max_seq_length": embedder.max_seq_length,
                "chunks": len(chunks),
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return vectors


def dense_search(chunks: list[Chunk], vectors: Any, query_vector: Any, top_k: int = 80) -> list[tuple[int, float]]:
    import numpy as np

    scores = np.asarray(vectors @ query_vector)
    if scores.size == 0:
        return []
    limit = min(top_k, scores.size)
    candidates = np.argpartition(-scores, limit - 1)[:limit]
    ranked = sorted(((int(index), float(scores[index])) for index in candidates), key=lambda item: item[1], reverse=True)
    return ranked


class HybridRetriever:
    def __init__(self, chunks: list[Chunk] | None = None, use_dense: bool = True, use_reranker: bool = True) -> None:
        self.chunks = chunks or load_chunks()
        self.use_dense = use_dense
        self.use_reranker = use_reranker
        self.bm25 = BM25Index(self.chunks)
        self.embedder = DenseEmbedder() if use_dense else None
        self.vectors = load_or_build_embeddings(self.chunks, self.embedder) if self.embedder is not None else None
        self.reranker = CrossEncoderReranker() if use_reranker else None

    def retrieve(
        self,
        query: str,
        bm25_top_k: int = 80,
        dense_top_k: int = 80,
        keyword_top_k: int = 40,
        candidate_top_k: int = 80,
        final_top_k: int = 10,
    ) -> list[RetrievalHit]:
        bm25_hits = self.bm25.search(query, bm25_top_k)
        keyword_hits = keyword_boost(self.chunks, query, keyword_top_k)

        dense_hits: list[tuple[int, float]] = []
        if self.embedder is not None and self.vectors is not None:
            query_vector = self.embedder.encode_query(query)
            dense_hits = dense_search(self.chunks, self.vectors, query_vector, dense_top_k)

        fused_scores = rrf_merge([bm25_hits, dense_hits, keyword_hits])
        bm25_by_index = dict(bm25_hits)
        dense_by_index = dict(dense_hits)
        keyword_by_index = dict(keyword_hits)
        ranked_indices = sorted(fused_scores, key=lambda index: fused_scores[index], reverse=True)[:candidate_top_k]

        hits: list[RetrievalHit] = []
        for index in ranked_indices:
            chunk = self.chunks[index]
            hit = RetrievalHit(
                chunk_id=chunk.chunk_id,
                path=chunk.path,
                title=chunk.title,
                family=chunk.family,
                section=chunk.section,
                source_kind=chunk.source_kind,
                score=fused_scores[index],
                bm25_score=bm25_by_index.get(index, 0.0),
                dense_score=dense_by_index.get(index, 0.0),
                keyword_score=keyword_by_index.get(index, 0.0),
                rrf_score=fused_scores[index],
                text=chunk.text,
            )
            hits.append(hit)

        if self.reranker is not None:
            return self.reranker.rerank(query, hits, final_top_k)
        return hits[:final_top_k]


def build_query_from_trajectory(steps: list[dict[str, Any]]) -> str:
    target = parse_event(steps[-1])
    previous = [parse_event(raw) for raw in steps[:-1]]
    pieces = [
        "Retrieve specification passages that determine whether the final Opal/TCG Storage operation is compliant.",
        f"target method: {target.method}",
        f"target kind: {target.kind}",
        f"target invoking object: {target.invoking_symbol or target.invoking_name or target.invoking_uid}",
        f"target status: {target.status}",
    ]
    if target.sp:
        pieces.append(f"target SP: {target.sp}")
    if target.authority:
        pieces.append(f"target authority: {target.authority}")
    if target.values:
        pieces.append("target columns/values: " + json.dumps(target.values, sort_keys=True, ensure_ascii=False, default=json_default)[:800])
    if target.required:
        pieces.append("target required args: " + json.dumps(target.required, sort_keys=True, ensure_ascii=False, default=json_default)[:800])
    if target.optional:
        pieces.append("target optional args: " + json.dumps(target.optional, sort_keys=True, ensure_ascii=False, default=json_default)[:800])
    if previous:
        context = []
        for event in previous[-5:]:
            context.append(
                " ".join(
                    part
                    for part in [
                        event.method,
                        event.invoking_symbol or event.invoking_name or event.invoking_uid,
                        event.status or "",
                        event.sp or "",
                        event.authority or "",
                    ]
                    if part
                )
            )
        pieces.append("recent context: " + " ; ".join(context))
    pieces.append(json.dumps(steps[-1], sort_keys=True, ensure_ascii=False, default=json_default)[:1600])
    return "\n".join(pieces)


def retrieve(
    query: str,
    chunks: list[Chunk] | None = None,
    bm25_top_k: int = 80,
    dense_top_k: int = 80,
    keyword_top_k: int = 40,
    candidate_top_k: int = 80,
    final_top_k: int = 10,
    use_dense: bool = True,
    use_reranker: bool = True,
) -> list[RetrievalHit]:
    chunks = chunks or load_chunks()
    engine = HybridRetriever(chunks=chunks, use_dense=use_dense, use_reranker=use_reranker)
    return engine.retrieve(
        query,
        bm25_top_k=bm25_top_k,
        dense_top_k=dense_top_k,
        keyword_top_k=keyword_top_k,
        candidate_top_k=candidate_top_k,
        final_top_k=final_top_k,
    )


def hit_to_json(hit: RetrievalHit, include_text: bool = False) -> dict[str, Any]:
    data = asdict(hit)
    if not include_text:
        data.pop("text", None)
    else:
        data["text"] = hit.text[:2000]
    return data
