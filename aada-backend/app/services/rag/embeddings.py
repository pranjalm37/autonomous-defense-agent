"""
Embeddings.

An *embedding* is a fixed-length vector of floats that represents the *meaning*
of a piece of text. The model is trained so that texts with similar meaning land
close together in the vector space — "SSH brute force" and "repeated failed
password attempts over SSH" point in nearly the same direction even though they
share few words. That geometric closeness is what makes semantic search possible
(see vectorstore.py for the similarity math).

Two providers behind one interface:

  - OpenAIEmbeddingProvider — production. Calls text-embedding-3-small (1536-dim).
  - HashingEmbeddingProvider — offline/dev/test. A deterministic hashed
    bag-of-words: no network, no API key, reproducible. It is NOT semantically
    trained, but texts sharing vocabulary still cluster, which is enough to
    exercise the chunking → embed → search → rank pipeline end-to-end in CI.

Swap them via config; the rest of the system never knows which is active.
"""
from __future__ import annotations

import hashlib
import math
import re
from typing import Protocol


class EmbeddingProvider(Protocol):
    name: str
    dim: int

    def embed_documents(self, texts: list[str]) -> list[list[float]]: ...
    def embed_query(self, text: str) -> list[float]: ...


# ──────────────────────────────────────────────────────────────────────────────
# Production: OpenAI
# ──────────────────────────────────────────────────────────────────────────────
class OpenAIEmbeddingProvider:
    """Lazy-imports `openai` so the package loads without the dependency."""

    _DIMS = {
        "text-embedding-3-small": 1536,
        "text-embedding-3-large": 3072,
        "text-embedding-ada-002": 1536,
    }

    def __init__(self, api_key: str, model: str = "text-embedding-3-small", batch_size: int = 128):
        from openai import OpenAI  # lazy
        self._client = OpenAI(api_key=api_key)
        self.model = model
        self.name = f"openai:{model}"
        self.dim = self._DIMS.get(model, 1536)
        self._batch = batch_size

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        vectors: list[list[float]] = []
        for i in range(0, len(texts), self._batch):
            batch = [t.replace("\n", " ") for t in texts[i:i + self._batch]]
            resp = self._client.embeddings.create(model=self.model, input=batch)
            vectors.extend(d.embedding for d in resp.data)
        return vectors

    def embed_query(self, text: str) -> list[float]:
        return self.embed_documents([text])[0]


# ──────────────────────────────────────────────────────────────────────────────
# Offline: deterministic hashed bag-of-words
# ──────────────────────────────────────────────────────────────────────────────
class HashingEmbeddingProvider:
    """
    Hashes each token into one of `dim` buckets (the "hashing trick"), weights by
    sublinear term frequency, then L2-normalizes. Deterministic and dependency-free.
    Shared vocabulary → overlapping buckets → higher cosine similarity.
    """

    _TOKEN = re.compile(r"[a-z0-9]+")

    def __init__(self, dim: int = 256):
        self.dim = dim
        self.name = f"hashing:{dim}"

    def _embed(self, text: str) -> list[float]:
        counts: dict[int, int] = {}
        for tok in self._TOKEN.findall(text.lower()):
            bucket = int(hashlib.md5(tok.encode()).hexdigest(), 16) % self.dim
            counts[bucket] = counts.get(bucket, 0) + 1
        vec = [0.0] * self.dim
        for bucket, c in counts.items():
            vec[bucket] = 1.0 + math.log(c)        # sublinear TF damps repetition
        norm = math.sqrt(sum(v * v for v in vec)) or 1.0
        return [v / norm for v in vec]

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        return [self._embed(t) for t in texts]

    def embed_query(self, text: str) -> list[float]:
        return self._embed(text)
