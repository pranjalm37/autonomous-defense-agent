"""
RAG data types.

The pipeline moves data through three shapes:

    KnowledgeDocument   one coherent source item (an ATT&CK technique, an OWASP
                        entry, a Sigma rule, a NIST section, an IR playbook).
        │  chunk()
        ▼
    Chunk               a retrievable unit + its embedding. Chunks — not whole
                        documents — are what we embed and search.
        │  retrieve()
        ▼
    RetrievalResult     a chunk plus the similarity score for a given query.
"""
from __future__ import annotations

import enum
import hashlib
from dataclasses import dataclass, field


class SourceType(str, enum.Enum):
    MITRE_ATTACK = "mitre_attack"
    OWASP_TOP10 = "owasp_top10"
    SIGMA_RULE = "sigma_rule"
    NIST = "nist"
    IR_GUIDE = "ir_guide"


class ChunkStrategy(str, enum.Enum):
    STRUCTURED = "structured"      # doc is already atomic → 1 chunk
    MARKDOWN = "markdown"          # split on markdown headings
    RECURSIVE = "recursive"        # generic size-based splitting


@dataclass
class KnowledgeDocument:
    """One item loaded from a knowledge source, before chunking."""
    doc_id: str                       # stable id, e.g. "mitre:T1110"
    source_type: SourceType
    title: str
    text: str
    metadata: dict = field(default_factory=dict)
    chunk_strategy: ChunkStrategy = ChunkStrategy.RECURSIVE


@dataclass
class Chunk:
    """A retrievable unit. `chunk_id` is content-addressed for idempotent upserts."""
    chunk_id: str
    doc_id: str
    source_type: SourceType
    title: str
    text: str
    metadata: dict = field(default_factory=dict)
    embedding: list[float] | None = None

    @staticmethod
    def make_id(doc_id: str, index: int, text: str) -> str:
        h = hashlib.sha1(f"{doc_id}|{index}|{text}".encode()).hexdigest()[:16]
        return f"{doc_id}#{index}-{h}"


@dataclass
class RetrievalResult:
    chunk: Chunk
    score: float          # similarity in [0, 1] — higher is closer

    @property
    def citation(self) -> str:
        st = self.chunk.source_type.value
        ref = self.chunk.metadata.get("reference") or self.chunk.doc_id
        return f"[{st}:{ref}]"
