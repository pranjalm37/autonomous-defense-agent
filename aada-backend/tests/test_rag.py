"""
RAG tests — chunking, embedding determinism, similarity ranking, and the full
ingest→retrieve pipeline over the real seed knowledge base. All offline (hashing
embeddings + in-memory store); no OpenAI key or ChromaDB required.
"""
from __future__ import annotations

import math

import pytest

from app.services.rag import SourceType, build_pipeline
from app.services.rag.chunking import _split_recursive, chunk_document
from app.services.rag.embeddings import HashingEmbeddingProvider
from app.services.rag.knowledge import load_all
from app.services.rag.schemas import ChunkStrategy, KnowledgeDocument
from app.services.rag.vectorstore import cosine_similarity


# ── Chunking ──────────────────────────────────────────────────────────────────
def test_structured_doc_is_single_chunk():
    doc = KnowledgeDocument(
        doc_id="mitre:T1110", source_type=SourceType.MITRE_ATTACK,
        title="T1110 Brute Force", text="A" * 100 + " brute force " + "B" * 100,
        chunk_strategy=ChunkStrategy.STRUCTURED,
    )
    chunks = chunk_document(doc)
    assert len(chunks) == 1
    assert chunks[0].chunk_id.startswith("mitre:T1110#0")


def test_recursive_split_respects_size_and_overlap():
    text = ". ".join(f"sentence number {i} with some filler words" for i in range(60))
    pieces = _split_recursive(text, chunk_size=200, overlap=40)
    assert len(pieces) > 1
    assert all(len(p) <= 320 for p in pieces)   # size + overlap headroom


def test_markdown_chunking_splits_on_headings():
    doc = KnowledgeDocument(
        doc_id="nist:x", source_type=SourceType.NIST, title="X",
        text="# Title\n\n## Containment\n" + "word " * 50 + "\n## Recovery\n" + "word " * 50,
        chunk_strategy=ChunkStrategy.MARKDOWN,
    )
    chunks = chunk_document(doc, chunk_size=400)
    joined = " ".join(c.text for c in chunks)
    assert "Containment" in joined and "Recovery" in joined
    assert len(chunks) >= 2


# ── Embeddings ────────────────────────────────────────────────────────────────
def test_hashing_embeddings_are_deterministic_and_normalized():
    p = HashingEmbeddingProvider(dim=128)
    v1 = p.embed_query("ssh brute force attack")
    v2 = p.embed_query("ssh brute force attack")
    assert v1 == v2                                   # deterministic
    assert math.isclose(sum(x * x for x in v1), 1.0, rel_tol=1e-6)  # L2-normalized


def test_shared_vocabulary_scores_higher_than_unrelated():
    p = HashingEmbeddingProvider(dim=512)
    q = p.embed_query("ssh brute force failed password login")
    related = p.embed_query("repeated failed ssh password login attempts")
    unrelated = p.embed_query("owasp sql injection database query")
    assert cosine_similarity(q, related) > cosine_similarity(q, unrelated)


# ── Full pipeline over the real knowledge base ────────────────────────────────
@pytest.fixture(scope="module")
def pipeline():
    p = build_pipeline(force_offline=True)
    docs = load_all()
    assert docs, "seed knowledge base should load"
    p.ingest(docs)
    return p


def test_knowledge_base_loads_all_sources():
    docs = load_all()
    sources = {d.source_type for d in docs}
    assert sources == {
        SourceType.MITRE_ATTACK, SourceType.OWASP_TOP10,
        SourceType.SIGMA_RULE, SourceType.NIST, SourceType.IR_GUIDE,
    }


def test_retrieve_brute_force_returns_relevant(pipeline):
    results = pipeline.retrieve("many failed ssh login attempts from one ip", top_k=5)
    assert results
    top_text = (results[0].chunk.title + results[0].chunk.text).lower()
    assert "brute" in top_text or "ssh" in top_text


def test_retrieve_sql_injection_hits_owasp(pipeline):
    results = pipeline.retrieve("sql injection in login form", top_k=5)
    assert any(r.chunk.source_type == SourceType.OWASP_TOP10 for r in results)


def test_source_filter_restricts_results(pipeline):
    results = pipeline.retrieve("incident containment", top_k=5, sources=[SourceType.NIST])
    assert results
    assert all(r.chunk.source_type == SourceType.NIST for r in results)


def test_scores_are_sorted_descending(pipeline):
    results = pipeline.retrieve("privilege escalation sudo root", top_k=6)
    scores = [r.score for r in results]
    assert scores == sorted(scores, reverse=True)


def test_build_context_is_cited_and_bounded(pipeline):
    ctx = pipeline.build_context("credential stuffing", top_k=3, max_chars=1500)
    assert len(ctx) <= 1600
    assert "[" in ctx and "]" in ctx          # citations present


def test_enrich_for_detection(pipeline):
    results = pipeline.enrich_for_detection(
        threat_type="brute_force", mitre_techniques=["T1110"], top_k=3,
    )
    assert results


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
