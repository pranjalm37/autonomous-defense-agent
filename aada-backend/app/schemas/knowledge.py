from pydantic import BaseModel, Field

from app.services.rag.schemas import SourceType


class KnowledgeQuery(BaseModel):
    query: str = Field(..., min_length=2)
    top_k: int = Field(5, ge=1, le=20)
    sources: list[SourceType] | None = None     # restrict to specific knowledge bases
    min_score: float = Field(0.0, ge=0.0, le=1.0)


class RetrievedChunk(BaseModel):
    score: float
    source_type: SourceType
    title: str
    citation: str
    doc_id: str
    text: str


class KnowledgeQueryResult(BaseModel):
    query: str
    results: list[RetrievedChunk]


class KnowledgeStats(BaseModel):
    total_chunks: int
    embedding_provider: str
    store: str


class IngestResult(BaseModel):
    documents: int
    chunks: int
    stored: int
