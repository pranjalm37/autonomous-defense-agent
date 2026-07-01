"""
Knowledge-base (RAG) endpoints.

    POST /knowledge/query    semantic search over the security knowledge base
    GET  /knowledge/stats    vector count + active providers
    POST /knowledge/ingest   (re)load and embed all knowledge sources  [admin]

The pipeline is built once and cached. On first use, if the vector store is empty
it auto-ingests the bundled knowledge base, so the API works out of the box in
dev. In production the store (ChromaDB) is pre-populated by `python -m
app.services.rag.ingest`, so the auto-ingest is skipped.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends

from app.dependencies import get_current_user, require_roles
from app.logging_config import get_logger
from app.models.user import User
from app.schemas.knowledge import (
    IngestResult, KnowledgeQuery, KnowledgeQueryResult, KnowledgeStats, RetrievedChunk,
)
from app.services.rag.pipeline import get_default_pipeline as get_pipeline
from app.services.rag.knowledge import load_all

logger = get_logger(__name__)
router = APIRouter(prefix="/knowledge", tags=["knowledge"])


@router.post("/query", response_model=KnowledgeQueryResult)
async def query_knowledge(
    body: KnowledgeQuery,
    _: User = Depends(get_current_user),
) -> KnowledgeQueryResult:
    """Retrieve the most relevant knowledge chunks for a natural-language query."""
    pipeline = get_pipeline()
    results = pipeline.retrieve(
        body.query, top_k=body.top_k, sources=body.sources, min_score=body.min_score,
    )
    return KnowledgeQueryResult(
        query=body.query,
        results=[
            RetrievedChunk(
                score=round(r.score, 4),
                source_type=r.chunk.source_type,
                title=r.chunk.title,
                citation=r.citation,
                doc_id=r.chunk.doc_id,
                text=r.chunk.text,
            )
            for r in results
        ],
    )


@router.get("/stats", response_model=KnowledgeStats)
async def knowledge_stats(_: User = Depends(get_current_user)) -> KnowledgeStats:
    pipeline = get_pipeline()
    return KnowledgeStats(
        total_chunks=pipeline.count(),
        embedding_provider=pipeline.embeddings.name,
        store=type(pipeline.store).__name__,
    )


@router.post("/ingest", response_model=IngestResult, status_code=201)
async def ingest_knowledge(
    _: User = Depends(require_roles("analyst", "admin")),
) -> IngestResult:
    """Reload all knowledge sources and (re)embed them. Idempotent."""
    pipeline = get_pipeline()
    result = pipeline.ingest(load_all())
    return IngestResult(**result)
