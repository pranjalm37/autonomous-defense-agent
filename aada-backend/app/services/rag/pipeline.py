"""
RAGPipeline — ties chunking, embeddings, and the vector store together.

    ingest(documents)        chunk → embed → store
    retrieve(query, ...)     embed query → similarity search → ranked results
    build_context(query)     retrieve → format a cited context block for an LLM
    enrich_for_detection(..) convenience query for the detection/AI layer

`from_settings()` chooses real vs. offline providers from config, so the same
pipeline runs in production (OpenAI + ChromaDB) and in tests (hashing + memory)
with no code change at the call sites.
"""
from __future__ import annotations

from functools import lru_cache

from app.logging_config import get_logger
from app.services.rag.chunking import chunk_document
from app.services.rag.embeddings import (
    EmbeddingProvider,
    HashingEmbeddingProvider,
    OpenAIEmbeddingProvider,
)
from app.services.rag.schemas import Chunk, KnowledgeDocument, RetrievalResult, SourceType
from app.services.rag.vectorstore import (
    ChromaVectorStore,
    InMemoryVectorStore,
    VectorStore,
)

logger = get_logger(__name__)


class RAGPipeline:
    def __init__(self, embeddings: EmbeddingProvider, store: VectorStore,
                 *, chunk_size: int = 800, chunk_overlap: int = 120):
        self.embeddings = embeddings
        self.store = store
        self.chunk_size = chunk_size
        self.chunk_overlap = chunk_overlap

    # ── Ingestion ─────────────────────────────────────────────────────────────
    def ingest(self, documents: list[KnowledgeDocument]) -> dict:
        all_chunks: list[Chunk] = []
        for doc in documents:
            all_chunks.extend(
                chunk_document(doc, chunk_size=self.chunk_size, overlap=self.chunk_overlap)
            )
        if not all_chunks:
            return {"documents": len(documents), "chunks": 0, "stored": 0}

        vectors = self.embeddings.embed_documents([c.text for c in all_chunks])
        for chunk, vec in zip(all_chunks, vectors):
            chunk.embedding = vec
        stored = self.store.add(all_chunks)

        logger.info("rag_ingest", documents=len(documents), chunks=len(all_chunks),
                    stored=stored, provider=self.embeddings.name)
        return {"documents": len(documents), "chunks": len(all_chunks), "stored": stored}

    # ── Retrieval ─────────────────────────────────────────────────────────────
    def retrieve(self, query: str, *, top_k: int = 5,
                 sources: list[SourceType] | None = None,
                 min_score: float = 0.0) -> list[RetrievalResult]:
        q_vec = self.embeddings.embed_query(query)
        results = self.store.query(q_vec, top_k=top_k, sources=sources)
        return [r for r in results if r.score >= min_score]

    def build_context(self, query: str, *, top_k: int = 5,
                      sources: list[SourceType] | None = None,
                      max_chars: int = 4000) -> str:
        """Assemble a cited, length-bounded context block for an LLM prompt."""
        results = self.retrieve(query, top_k=top_k, sources=sources)
        blocks, used = [], 0
        for r in results:
            header = f"{r.citation} {r.chunk.title}"
            body = r.chunk.text
            block = f"### {header}\n{body}"
            if used + len(block) > max_chars:
                break
            blocks.append(block)
            used += len(block)
        return "\n\n".join(blocks)

    def enrich_for_detection(self, *, threat_type: str | None = None,
                             mitre_techniques: list[str] | None = None,
                             top_k: int = 4) -> list[RetrievalResult]:
        """Pull defender context (detections, mitigations, playbooks) for an alert."""
        terms = [threat_type or ""] + (mitre_techniques or [])
        query = " ".join(t for t in terms if t).strip() or "incident response"
        return self.retrieve(query, top_k=top_k)

    def count(self) -> int:
        return self.store.count()


# ──────────────────────────────────────────────────────────────────────────────
# Factory
# ──────────────────────────────────────────────────────────────────────────────
def build_pipeline(
    *, openai_api_key: str | None = None,
    embedding_model: str = "text-embedding-3-small",
    chroma_persist_dir: str | None = None,
    chroma_host: str | None = None,
    chroma_port: int | None = None,
    collection: str = "aada_knowledge",
    chunk_size: int = 800,
    chunk_overlap: int = 120,
    force_offline: bool = False,
) -> RAGPipeline:
    """
    Wire providers from explicit args. Falls back to offline providers when no
    OpenAI key / Chroma target is configured, so dev and CI 'just work'.
    """
    if openai_api_key and not force_offline:
        embeddings: EmbeddingProvider = OpenAIEmbeddingProvider(openai_api_key, embedding_model)
    else:
        embeddings = HashingEmbeddingProvider()

    if (chroma_persist_dir or chroma_host) and not force_offline:
        store: VectorStore = ChromaVectorStore(
            collection=collection, persist_dir=chroma_persist_dir,
            host=chroma_host, port=chroma_port,
        )
    else:
        store = InMemoryVectorStore()

    logger.info("rag_pipeline_built", embeddings=embeddings.name,
                store=type(store).__name__)
    return RAGPipeline(embeddings, store, chunk_size=chunk_size, chunk_overlap=chunk_overlap)


def build_pipeline_from_settings(force_offline: bool = False) -> RAGPipeline:
    from app.config import get_settings
    s = get_settings()
    return build_pipeline(
        openai_api_key=getattr(s, "openai_api_key", None),
        embedding_model=getattr(s, "embedding_model", "text-embedding-3-small"),
        chroma_persist_dir=getattr(s, "chroma_persist_dir", None),
        chroma_host=getattr(s, "chroma_host", None),
        chroma_port=getattr(s, "chroma_port", None),
        collection=getattr(s, "rag_collection", "aada_knowledge"),
        chunk_size=getattr(s, "rag_chunk_size", 800),
        chunk_overlap=getattr(s, "rag_chunk_overlap", 120),
        force_offline=force_offline,
    )


@lru_cache
def get_default_pipeline() -> RAGPipeline:
    """
    Process-wide cached pipeline. On first call, if the store is empty it
    auto-ingests the bundled knowledge base (handy in dev / in-memory mode). In
    production with a pre-populated ChromaDB, count() > 0 so ingestion is skipped.
    Shared by the knowledge endpoints and the AI analyst.
    """
    pipeline = build_pipeline_from_settings()
    if pipeline.count() == 0:
        from app.services.rag.knowledge import load_all
        pipeline.ingest(load_all())
    return pipeline
