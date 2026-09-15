"""
Qdrant vector RAG layer for telco SOP / RFC / historical RCA knowledge.

Capabilities:
  - Collection bootstrap with cosine similarity
  - SOP markdown ingestion with OpenAI (or hash-based offline) embeddings
  - Semantic retrieval tool callable by the RAG Agent
"""

from __future__ import annotations

import hashlib
import logging
import math
import re
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

from qdrant_client import QdrantClient
from qdrant_client.http import models as qmodels
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from config import Settings, get_settings
from observability import traced
from schema import RAGDocument, RAGResult

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Embedding backends
# ---------------------------------------------------------------------------


class EmbeddingBackend:
    """Abstract embedding interface."""

    def embed(self, texts: Sequence[str]) -> list[list[float]]:
        raise NotImplementedError


class OpenAIEmbeddingBackend(EmbeddingBackend):
    """OpenAI text-embedding-3-small (or compatible) backend."""

    def __init__(self, settings: Settings) -> None:
        from openai import OpenAI

        kwargs: dict[str, Any] = {
            "api_key": settings.openai_api_key.get_secret_value(),
        }
        if settings.openai_base_url:
            kwargs["base_url"] = settings.openai_base_url
        self._client = OpenAI(**kwargs)
        self._model = settings.embedding_model
        self._dim = settings.qdrant_vector_size

    @retry(
        reraise=True,
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=10),
    )
    def embed(self, texts: Sequence[str]) -> list[list[float]]:
        if not texts:
            return []
        kwargs: dict[str, Any] = {
            "model": self._model,
            "input": list(texts),
        }
        if self._model.startswith("text-embedding-3"):
            kwargs["dimensions"] = self._dim
        response = self._client.embeddings.create(
            **kwargs,
        )
        return [item.embedding for item in response.data]


class OfflineHashEmbeddingBackend(EmbeddingBackend):
    """
    Deterministic pseudo-embedding for air-gapped / offline lab demos.

    Uses signed feature hashing over lexical tokens. This is not a semantic
    embedding model, but shared network terms map to shared finite dimensions,
    making the offline RAG path deterministic and testable.
    """

    def __init__(self, dim: int = 1536) -> None:
        self._dim = dim

    def embed(self, texts: Sequence[str]) -> list[list[float]]:
        return [self._one(t) for t in texts]

    def _one(self, text: str) -> list[float]:
        vector = [0.0] * self._dim
        tokens = re.findall(r"[a-z0-9_.:/-]+", text.lower())
        # Add adjacent token pairs to retain a small amount of phrase context.
        features = tokens + [
            f"{left}::{right}" for left, right in zip(tokens, tokens[1:])
        ]
        for feature in features:
            digest = hashlib.blake2b(feature.encode("utf-8"), digest_size=16).digest()
            index = int.from_bytes(digest[:8], "little") % self._dim
            sign = 1.0 if digest[8] & 1 else -1.0
            vector[index] += sign

        norm = math.sqrt(sum(value * value for value in vector))
        if norm == 0.0:
            return vector
        normalized = [value / norm for value in vector]
        if not all(math.isfinite(value) for value in normalized):
            raise ValueError("offline embedding produced a non-finite value")
        return normalized


def build_embedding_backend(settings: Settings) -> EmbeddingBackend:
    if settings.is_offline() or settings.llm_provider.lower() == "deepseek":
        logger.warning(
            "Using OfflineHashEmbeddingBackend (offline_mode or DeepSeek chat-only)"
        )
        return OfflineHashEmbeddingBackend(dim=settings.qdrant_vector_size)
    return OpenAIEmbeddingBackend(settings)


# ---------------------------------------------------------------------------
# Document chunking
# ---------------------------------------------------------------------------


def chunk_markdown(text: str, *, max_chars: int = 1200, overlap: int = 150) -> list[str]:
    """Split markdown on headings / blank lines with soft char limits."""
    sections = re.split(r"(?=\n#{1,3}\s)", text.strip())
    chunks: list[str] = []
    for section in sections:
        section = section.strip()
        if not section:
            continue
        if len(section) <= max_chars:
            chunks.append(section)
            continue
        start = 0
        while start < len(section):
            end = min(start + max_chars, len(section))
            chunks.append(section[start:end].strip())
            if end >= len(section):
                break
            start = max(0, end - overlap)
    return [c for c in chunks if c]


# ---------------------------------------------------------------------------
# Vector store
# ---------------------------------------------------------------------------


@dataclass
class _MemoryPoint:
    point_id: str
    vector: list[float]
    payload: dict[str, Any]


def _cosine(a: list[float], b: list[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a)) or 1.0
    nb = math.sqrt(sum(y * y for y in b)) or 1.0
    return dot / (na * nb)


class VectorRAGStore:
    """Qdrant-backed SOP knowledge store with in-memory fallback."""

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self._client: QdrantClient | None = None
        self._embedder = build_embedding_backend(self.settings)
        self._memory: list[_MemoryPoint] = []
        self._use_memory = False
        self._next_connect_attempt = 0.0
        self._ingest_lock = threading.Lock()

    @property
    def collection_name(self) -> str:
        """Keep incompatible embedding spaces in separate collections."""
        if isinstance(self._embedder, OfflineHashEmbeddingBackend):
            suffix = "offline_hash_v2"
        else:
            suffix = re.sub(r"[^a-zA-Z0-9_-]+", "_", self.settings.embedding_model)
        return f"{self.settings.qdrant_collection}__{suffix}"

    def connect(self) -> QdrantClient | None:
        """
        Connect to Qdrant. On failure, switch to in-memory mode (no raise).
        """
        if self._use_memory:
            if time.monotonic() < self._next_connect_attempt:
                return None
        if self._client is not None:
            return self._client
        try:
            client = QdrantClient(url=self.settings.qdrant_url, timeout=5)
            client.get_collections()
            self._client = client
            self._use_memory = False
            logger.info("Connected to Qdrant at %s", self.settings.qdrant_url)
            return self._client
        except Exception as exc:  # noqa: BLE001
            self._use_memory = True
            self._client = None
            self._next_connect_attempt = time.monotonic() + 30.0
            logger.warning(
                "Qdrant unavailable (%s); using in-memory RAG fallback", exc
            )
            return None

    @property
    def client(self) -> QdrantClient:
        conn = self.connect()
        if conn is None:
            raise RuntimeError("Qdrant client unavailable (memory mode active)")
        return conn

    def ensure_collection(self) -> None:
        """Create the SOP collection if missing (no-op in memory mode)."""
        if self.connect() is None:
            return
        name = self.collection_name
        existing = {c.name for c in self.client.get_collections().collections}
        if name not in existing:
            self.client.create_collection(
                collection_name=name,
                vectors_config=qmodels.VectorParams(
                    size=self.settings.qdrant_vector_size,
                    distance=qmodels.Distance.COSINE,
                ),
            )
            logger.info(
                "Created Qdrant collection '%s' (dim=%d)",
                name,
                self.settings.qdrant_vector_size,
            )
        else:
            logger.debug("Qdrant collection '%s' already exists", name)

        if self._memory:
            self.client.upsert(
                collection_name=name,
                points=[
                    qmodels.PointStruct(
                        id=point.point_id,
                        vector=point.vector,
                        payload=point.payload,
                    )
                    for point in self._memory
                ],
                wait=True,
            )
            logger.info("Flushed %d memory points to Qdrant", len(self._memory))
            self._memory.clear()

    # ------------------------------------------------------------------
    # Ingest
    # ------------------------------------------------------------------

    @traced("rag.ingest_directory")
    def ingest_directory(self, directory: Path | None = None) -> int:
        """
        Walk a directory of .md SOP files and upsert chunks into Qdrant
        (or memory fallback).

        Returns the number of chunks upserted.
        """
        directory = directory or self.settings.sop_knowledge_dir
        if not directory.exists():
            logger.warning("SOP knowledge dir missing: %s", directory)
            return 0

        self.ensure_collection()
        files = sorted(directory.glob("**/*.md"))
        total = 0
        for path in files:
            total += self.ingest_file(path)
        logger.info(
            "Ingested %d chunks from %d files (memory=%s)",
            total,
            len(files),
            self._use_memory,
        )
        return total

    @traced("rag.ingest_file")
    def ingest_file(self, path: Path) -> int:
        text = path.read_text(encoding="utf-8")
        title = path.stem.replace("_", " ").title()
        chunks = chunk_markdown(text)
        if not chunks:
            return 0

        vectors = self._embedder.embed(chunks)
        points: list[qmodels.PointStruct] = []
        for idx, (chunk, vector) in enumerate(zip(chunks, vectors)):
            point_id = self._stable_id(f"{path.name}:{idx}:{chunk[:64]}")
            payload = {
                "title": title,
                "content": chunk,
                "source": str(path.name),
                "chunk_index": idx,
                "doc_type": "sop",
            }
            if self.connect() is None:
                self._memory.append(
                    _MemoryPoint(point_id=point_id, vector=vector, payload=payload)
                )
            else:
                points.append(
                    qmodels.PointStruct(
                        id=point_id,
                        vector=vector,
                        payload=payload,
                    )
                )

        if points:
            self.client.upsert(
                collection_name=self.collection_name,
                points=points,
                wait=True,
            )
        logger.info(
            "Upserted %d chunks from %s (memory=%s)",
            len(chunks),
            path.name,
            self._use_memory,
        )
        return len(chunks)

    # ------------------------------------------------------------------
    # Retrieve
    # ------------------------------------------------------------------

    @traced("rag.retrieve")
    def retrieve(
        self,
        query: str,
        *,
        top_k: int = 5,
        score_threshold: float | None = None,
    ) -> RAGResult:
        """Semantic search over the SOP knowledge base."""
        if score_threshold is None:
            score_threshold = (
                0.05
                if isinstance(self._embedder, OfflineHashEmbeddingBackend)
                else 0.15
            )
        # Concurrent callers (the eval runner scores cases on a thread pool)
        # must not each trigger the lazy auto-ingest, which would duplicate
        # every SOP chunk in the index.
        with self._ingest_lock:
            self.ensure_collection()
            # Auto-load SOPs into memory if empty and Qdrant is down.
            if self.connect() is None and not self._memory:
                self.ingest_directory()
            elif self.connect() is not None:
                count = self.client.count(
                    collection_name=self.collection_name,
                    exact=True,
                ).count
                if count == 0:
                    logger.warning(
                        "Qdrant collection '%s' is empty; ingesting SOPs",
                        self.collection_name,
                    )
                    self.ingest_directory()

        query_vec = self._embedder.embed([query])[0]
        documents: list[RAGDocument] = []
        sop_steps: list[str] = []
        historical: list[str] = []

        if self._use_memory or self.connect() is None:
            scored = [
                (self._hybrid_score(query, query_vec, p), p) for p in self._memory
            ]
            scored.sort(key=lambda x: x[0], reverse=True)
            hits_iter = [
                (score, p) for score, p in scored[:top_k] if score >= score_threshold
            ]
            for score, point in hits_iter:
                payload = point.payload
                documents.append(
                    RAGDocument(
                        doc_id=point.point_id,
                        title=str(payload.get("title", "untitled")),
                        content=str(payload.get("content", "")),
                        score=max(0.0, min(1.0, float(score))),
                        source=str(payload.get("source", "sop")),
                        metadata={
                            "chunk_index": payload.get("chunk_index"),
                            "doc_type": payload.get("doc_type"),
                        },
                    )
                )
        else:
            response = self.client.query_points(
                collection_name=self.collection_name,
                query=query_vec,
                limit=max(top_k * 3, 8),
                with_payload=True,
            )
            reranked: list[tuple[float, Any]] = []
            for hit in response.points:
                payload = hit.payload or {}
                lexical = self._lexical_overlap(
                    query, str(payload.get("content", ""))
                )
                dense = float(hit.score or 0.0)
                reranked.append((0.65 * dense + 0.35 * lexical, hit))
            reranked.sort(key=lambda x: x[0], reverse=True)
            for score, hit in reranked[:top_k]:
                if score < score_threshold:
                    continue
                payload = hit.payload or {}
                documents.append(
                    RAGDocument(
                        doc_id=str(hit.id),
                        title=str(payload.get("title", "untitled")),
                        content=str(payload.get("content", "")),
                        score=max(0.0, min(1.0, float(score))),
                        source=str(payload.get("source", "sop")),
                        metadata={
                            "chunk_index": payload.get("chunk_index"),
                            "doc_type": payload.get("doc_type"),
                        },
                    )
                )

        for doc in documents:
            for line in doc.content.splitlines():
                stripped = line.strip()
                if re.match(r"^(\d+[\).\]]|[-*])\s+", stripped):
                    sop_steps.append(stripped)
                if "case:" in stripped.lower() or "history:" in stripped.lower():
                    historical.append(stripped)

        return RAGResult(
            query=query,
            documents=documents,
            sop_steps=sop_steps[:20],
            historical_cases=historical[:10],
        )

    def _hybrid_score(
        self, query: str, query_vec: list[float], point: _MemoryPoint
    ) -> float:
        dense = _cosine(query_vec, point.vector)
        lexical = self._lexical_overlap(query, str(point.payload.get("content", "")))
        return 0.65 * dense + 0.35 * lexical

    @staticmethod
    def _lexical_overlap(query: str, content: str) -> float:
        query_tokens = set(re.findall(r"[a-z0-9_]+", query.lower()))
        doc_tokens = set(re.findall(r"[a-z0-9_]+", content.lower()))
        if not query_tokens or not doc_tokens:
            return 0.0
        return len(query_tokens & doc_tokens) / len(query_tokens)

    @staticmethod
    def _stable_id(key: str) -> str:
        """Deterministic UUID-like hex id for upsert idempotency."""
        return hashlib.md5(key.encode("utf-8")).hexdigest()


# Module-level singleton for agent tool binding
_STORE: VectorRAGStore | None = None
_STORE_LOCK = threading.Lock()


def get_rag_store() -> VectorRAGStore:
    global _STORE
    if _STORE is None:
        with _STORE_LOCK:
            if _STORE is None:
                _STORE = VectorRAGStore()
    return _STORE


@traced("tool.rag_search_sop")
def rag_search_sop(query: str, top_k: int = 5) -> dict[str, Any]:
    """
    LangChain / Agent-callable tool wrapper.

    Returns a plain dict (JSON-serializable) for LLM tool responses.
    """
    result = get_rag_store().retrieve(query, top_k=top_k)
    return result.model_dump(mode="json")
