"""
Vector store + similarity search.

Once text is embedded, "search" becomes geometry: embed the query, then find the
stored chunk vectors pointing in the most similar direction.

**Cosine similarity** is the standard measure:

        cos(a, b) =  (a · b) / (‖a‖ · ‖b‖)

It compares *direction*, not magnitude — so a short chunk and a long chunk about
the same topic still score high. Range is [-1, 1]; for the non-negative embedding
spaces we use it lands in [0, 1], which we expose directly as the score.

Exact (brute-force) search compares the query to every vector — O(n·d), perfect
recall, fine up to ~10^5 chunks. ChromaDB swaps in an **HNSW** approximate index
for scale: it walks a navigable small-world graph to find near neighbors in
roughly O(log n), trading a sliver of recall for big speedups.

Two backends behind one interface:
  - ChromaVectorStore   — production, persistent, HNSW. Lazy-imports chromadb.
  - InMemoryVectorStore — dev/test. Exact cosine in pure Python. Same results,
    no service to run, so the pipeline is testable in CI.
"""
from __future__ import annotations

import math
from typing import Protocol

from app.services.rag.schemas import Chunk, RetrievalResult, SourceType


def cosine_similarity(a: list[float], b: list[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    if na == 0 or nb == 0:
        return 0.0
    return dot / (na * nb)


class VectorStore(Protocol):
    def add(self, chunks: list[Chunk]) -> int: ...
    def query(self, embedding: list[float], top_k: int = 5,
              sources: list[SourceType] | None = None) -> list[RetrievalResult]: ...
    def count(self) -> int: ...
    def reset(self) -> None: ...


# ──────────────────────────────────────────────────────────────────────────────
# Dev / test: exact cosine in memory
# ──────────────────────────────────────────────────────────────────────────────
class InMemoryVectorStore:
    def __init__(self):
        self._chunks: dict[str, Chunk] = {}

    def add(self, chunks: list[Chunk]) -> int:
        n = 0
        for c in chunks:
            if c.embedding is None:
                raise ValueError(f"chunk {c.chunk_id} has no embedding")
            self._chunks[c.chunk_id] = c   # content-addressed id → idempotent upsert
            n += 1
        return n

    def query(self, embedding, top_k=5, sources=None) -> list[RetrievalResult]:
        allowed = {s for s in sources} if sources else None
        scored: list[RetrievalResult] = []
        for c in self._chunks.values():
            if allowed and c.source_type not in allowed:
                continue
            scored.append(RetrievalResult(chunk=c, score=cosine_similarity(embedding, c.embedding)))
        scored.sort(key=lambda r: r.score, reverse=True)
        return scored[:top_k]

    def count(self) -> int:
        return len(self._chunks)

    def reset(self) -> None:
        self._chunks.clear()


# ──────────────────────────────────────────────────────────────────────────────
# Production: ChromaDB (HNSW, persistent)
# ──────────────────────────────────────────────────────────────────────────────
class ChromaVectorStore:
    """
    Wraps a Chroma collection. We pass embeddings in explicitly (computed by our
    EmbeddingProvider) rather than letting Chroma embed, so the same provider
    serves both ingestion and query and the two never drift.
    """

    def __init__(self, collection: str = "aada_knowledge",
                 persist_dir: str | None = None,
                 host: str | None = None, port: int | None = None):
        import chromadb  # lazy
        from chromadb.config import Settings

        # Telemetry off explicitly: the client's posthog call fails with an
        # upstream signature mismatch and logs at error level on every request.
        settings = Settings(anonymized_telemetry=False)
        if host:
            self._client = chromadb.HttpClient(host=host, port=port or 8000, settings=settings)
        elif persist_dir:
            self._client = chromadb.PersistentClient(path=persist_dir, settings=settings)
        else:
            self._client = chromadb.EphemeralClient(settings=settings)
        self._name = collection
        # cosine space to match our similarity measure
        self._col = self._client.get_or_create_collection(
            name=collection, metadata={"hnsw:space": "cosine"}
        )

    def add(self, chunks: list[Chunk]) -> int:
        if not chunks:
            return 0
        self._col.upsert(
            ids=[c.chunk_id for c in chunks],
            embeddings=[c.embedding for c in chunks],
            documents=[c.text for c in chunks],
            metadatas=[self._meta(c) for c in chunks],
        )
        return len(chunks)

    def query(self, embedding, top_k=5, sources=None) -> list[RetrievalResult]:
        where = None
        if sources:
            vals = [s.value for s in sources]
            where = {"source_type": {"$in": vals}}
        res = self._col.query(
            query_embeddings=[embedding], n_results=top_k, where=where,
            include=["documents", "metadatas", "distances"],
        )
        out: list[RetrievalResult] = []
        ids = res["ids"][0]
        for i, cid in enumerate(ids):
            meta = res["metadatas"][0][i] or {}
            chunk = Chunk(
                chunk_id=cid,
                doc_id=meta.get("doc_id", ""),
                source_type=SourceType(meta.get("source_type", "nist")),
                title=meta.get("title", ""),
                text=res["documents"][0][i],
                metadata=meta,
            )
            # Chroma returns cosine *distance* (1 - similarity); convert back.
            score = 1.0 - float(res["distances"][0][i])
            out.append(RetrievalResult(chunk=chunk, score=score))
        return out

    def count(self) -> int:
        return self._col.count()

    def reset(self) -> None:
        self._client.delete_collection(self._name)
        self._col = self._client.get_or_create_collection(
            name=self._name, metadata={"hnsw:space": "cosine"}
        )

    @staticmethod
    def _meta(c: Chunk) -> dict:
        # Chroma metadata values must be scalars; flatten/serialize the rest.
        flat = {"doc_id": c.doc_id, "source_type": c.source_type.value, "title": c.title}
        for k, v in c.metadata.items():
            if isinstance(v, (str, int, float, bool)):
                flat[k] = v
            elif isinstance(v, (list, tuple)):
                flat[k] = ", ".join(map(str, v))
        return flat
