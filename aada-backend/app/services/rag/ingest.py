"""
Knowledge-base ingestion script.

    # production (reads OPENAI_API_KEY + CHROMA_* from .env/settings)
    python -m app.services.rag.ingest

    # offline (hashing embeddings + in-memory store) — quick sanity run
    python -m app.services.rag.ingest --offline

    # custom data directory
    python -m app.services.rag.ingest --data-dir ./data/knowledge

Loads every knowledge source, chunks + embeds, and writes to the vector store.
Re-running is idempotent: chunk ids are content-addressed, so unchanged chunks
upsert in place and edited documents replace their old chunks.
"""
from __future__ import annotations

import argparse
import sys

from app.services.rag.knowledge import load_all
from app.services.rag.pipeline import build_pipeline_from_settings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Ingest the AADA knowledge base.")
    parser.add_argument("--data-dir", default=None, help="path to data/knowledge")
    parser.add_argument("--offline", action="store_true",
                        help="force hashing embeddings + in-memory store")
    args = parser.parse_args(argv)

    documents = load_all(args.data_dir)
    if not documents:
        print("No knowledge documents found — check --data-dir.", file=sys.stderr)
        return 1

    pipeline = build_pipeline_from_settings(force_offline=args.offline)
    result = pipeline.ingest(documents)

    by_source: dict[str, int] = {}
    for d in documents:
        by_source[d.source_type.value] = by_source.get(d.source_type.value, 0) + 1

    print("Knowledge base ingested:")
    print(f"  embeddings : {pipeline.embeddings.name}")
    print(f"  store      : {type(pipeline.store).__name__} (total vectors: {pipeline.count()})")
    print(f"  documents  : {result['documents']}")
    print(f"  chunks     : {result['chunks']}")
    for src, n in sorted(by_source.items()):
        print(f"    - {src:16} {n} docs")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
