"""
Document chunking.

Why chunk at all? Embedding models have a token limit and, more importantly,
a single vector can only represent so much meaning. Embed a whole 40-page NIST
PDF as one vector and a query about "containment" retrieves the entire document
with a mediocre score. Chunk it into sections and the containment paragraph
surfaces precisely. Chunking = the granularity of retrieval.

Trade-off:
  - chunks too LARGE  → diluted meaning, irrelevant text dragged into the prompt
  - chunks too SMALL  → lost context, a sentence with no surrounding meaning

We pick the strategy per source instead of one-size-fits-all:
  - STRUCTURED  — ATT&CK/OWASP/Sigma items are already atomic; 1 chunk each.
  - MARKDOWN    — NIST / IR guides split on headings (semantic boundaries).
  - RECURSIVE   — fallback: split on paragraph→line→sentence with overlap.

`overlap` carries a tail of the previous chunk into the next so a concept that
straddles a boundary still appears whole in at least one chunk.
"""
from __future__ import annotations

import re
from collections.abc import Sequence

from app.services.rag.schemas import Chunk, ChunkStrategy, KnowledgeDocument

DEFAULT_CHUNK_SIZE = 800       # characters (~200 tokens at ~4 chars/token)
DEFAULT_OVERLAP = 120

# Ordered separators: try to break on the most semantic boundary that fits.
_SEPARATORS = ["\n\n", "\n", ". ", "? ", "! ", "; ", ", ", " "]


def chunk_document(
    doc: KnowledgeDocument,
    *,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    overlap: int = DEFAULT_OVERLAP,
) -> list[Chunk]:
    """Dispatch to the right strategy for this document's source type."""
    if doc.chunk_strategy == ChunkStrategy.STRUCTURED:
        pieces = [doc.text.strip()]
    elif doc.chunk_strategy == ChunkStrategy.MARKDOWN:
        pieces = _split_markdown(doc.text, chunk_size, overlap)
    else:
        pieces = _split_recursive(doc.text, chunk_size, overlap)

    chunks: list[Chunk] = []
    for i, text in enumerate(p for p in pieces if p.strip()):
        chunks.append(Chunk(
            chunk_id=Chunk.make_id(doc.doc_id, i, text),
            doc_id=doc.doc_id,
            source_type=doc.source_type,
            title=doc.title,
            text=text.strip(),
            metadata={**doc.metadata, "chunk_index": i},
        ))
    return chunks


# ──────────────────────────────────────────────────────────────────────────────
def _split_markdown(text: str, chunk_size: int, overlap: int) -> list[str]:
    """
    Split on markdown headings, keeping each heading with its body. Sections that
    are still larger than chunk_size are recursively split.
    """
    lines = text.splitlines()
    sections: list[str] = []
    current: list[str] = []

    def flush():
        if current:
            sections.append("\n".join(current).strip())

    heading = re.compile(r"^#{1,6}\s+\S")
    for line in lines:
        if heading.match(line) and current:
            flush()
            current = [line]
        else:
            current.append(line)
    flush()

    out: list[str] = []
    for sec in sections:
        if len(sec) <= chunk_size:
            out.append(sec)
        else:
            out.extend(_split_recursive(sec, chunk_size, overlap))
    return out or _split_recursive(text, chunk_size, overlap)


def _split_recursive(text: str, chunk_size: int, overlap: int, _depth: int = 0) -> list[str]:
    """Greedy pack into ~chunk_size pieces, breaking on the best separator."""
    text = text.strip()
    if len(text) <= chunk_size:
        return [text] if text else []

    sep = _best_separator(text, chunk_size)
    parts = text.split(sep) if sep else list(text)

    chunks: list[str] = []
    buf = ""
    for part in parts:
        candidate = part if not buf else f"{buf}{sep}{part}"
        if len(candidate) <= chunk_size:
            buf = candidate
            continue
        if buf:
            chunks.append(buf)
        # A single part bigger than chunk_size → recurse with a finer separator.
        if len(part) > chunk_size:
            chunks.extend(_split_recursive(part, chunk_size, overlap, _depth + 1))
            buf = ""
        else:
            buf = part
    if buf:
        chunks.append(buf)

    return _apply_overlap(chunks, overlap) if _depth == 0 else chunks


def _best_separator(text: str, chunk_size: int) -> str:
    for sep in _SEPARATORS:
        if sep in text:
            return sep
    return ""


def _apply_overlap(chunks: Sequence[str], overlap: int) -> list[str]:
    if overlap <= 0 or len(chunks) <= 1:
        return list(chunks)
    out = [chunks[0]]
    for prev, cur in zip(chunks, chunks[1:]):
        tail = prev[-overlap:]
        # start the tail at a word boundary so we don't bisect a token
        if " " in tail:
            tail = tail[tail.index(" ") + 1:]
        out.append(f"{tail} {cur}".strip())
    return out
