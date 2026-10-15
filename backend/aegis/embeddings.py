"""Local, dependency-free text embeddings for FalkorDB's HNSW vector index.

The agent anchors unstructured security alerts to graph nodes with a vector KNN query
(``CALL db.idx.vector.queryNodes``). For a hackathon demo that must run without any API key,
we use a deterministic *hashing-trick* embedding: word unigrams, word bigrams, identifier tokens
(e.g. ``jwt-crypto-core``) and character trigrams are hashed into a fixed-size signed vector and
L2-normalised, so cosine distance in FalkorDB reflects lexical/sub-word overlap between an alert
and a CVE summary or function signature.

It is intentionally simple and swappable: ``embed()`` is the only entry point, and the dimension
comes from ``settings.embed_dim`` (which must match the vector index dimension created in seed.py).
Replace the body of ``embed`` with a call to a real embedding model (e.g. a 384-dim MiniLM model)
to get semantic rather than lexical matching without touching any other module.
"""
from __future__ import annotations

import hashlib
import math
import re
from collections import Counter

from .config import settings

_WORD_RE = re.compile(r"[a-z0-9]+(?:[-_.][a-z0-9]+)*")
_STOPWORDS = {
    "the", "a", "an", "and", "or", "of", "in", "on", "to", "by", "for", "with", "is", "are", "was", "were",
    "be", "been", "it", "its", "this", "that", "as", "at", "from", "via", "into", "than", "then", "has", "have",
    "had", "not", "no", "yes", "we", "our", "you", "your", "they", "their", "all", "any", "may", "can", "will",
}


def tokenize(text: str) -> list[str]:
    """Lower-case identifier-aware tokens (keeps ``jwt-crypto-core`` as one token and also splits it)."""
    tokens: list[str] = []
    for ident in _WORD_RE.findall(text.lower()):
        tokens.append(ident)
        if any(sep in ident for sep in "-_."):
            tokens.extend(part for part in re.split(r"[-_.]", ident) if part)
    return [t for t in tokens if t and t not in _STOPWORDS]


def keywords(text: str, max_terms: int = 12, min_len: int = 4) -> list[str]:
    """Distinct alphanumeric keywords suitable for a RediSearch full-text OR query."""
    seen: list[str] = []
    for tok in tokenize(text):
        word = re.sub(r"[^a-z0-9]", "", tok)
        if len(word) >= min_len and word not in seen and not word.isdigit():
            seen.append(word)
        if len(seen) >= max_terms:
            break
    return seen


def _features(text: str) -> Counter[str]:
    feats: Counter[str] = Counter()
    toks = tokenize(text)
    for tok in toks:
        weight = 1.6 if any(sep in tok for sep in "-_.") else 1.0  # identifiers are strong signals
        feats[f"w:{tok}"] += weight
        padded = f"#{tok}#"
        for i in range(len(padded) - 2):
            feats[f"c:{padded[i:i+3]}"] += 0.35
    for a, b in zip(toks, toks[1:]):
        feats[f"b:{a}_{b}"] += 0.8
    return feats


def _slot(feature: str, dim: int) -> tuple[int, float]:
    digest = hashlib.blake2b(feature.encode("utf-8"), digest_size=8).digest()
    value = int.from_bytes(digest, "big")
    sign = 1.0 if (value & 1) == 0 else -1.0
    return (value >> 1) % dim, sign


def embed(text: str, dim: int | None = None) -> list[float]:
    """Deterministic hashed embedding of ``text`` as a unit-length list of floats."""
    dim = dim or settings.embed_dim
    vec = [0.0] * dim
    for feature, count in _features(text).items():
        idx, sign = _slot(feature, dim)
        # log1p keeps every weighted feature positive (1 + ln(w) went negative for fractional trigram weights,
        # which made morphological variants anti-correlated) while still damping repeated terms
        vec[idx] += sign * math.log1p(count)
    norm = math.sqrt(sum(v * v for v in vec))
    if norm == 0.0:
        vec[0] = 1.0  # empty text -> a fixed unit vector so the index never receives a zero vector
        return vec
    return [round(v / norm, 6) for v in vec]


def embed_many(texts: list[str], dim: int | None = None) -> list[list[float]]:
    return [embed(t, dim) for t in texts]


def cosine_distance(a: list[float], b: list[float]) -> float:
    """1 - cosine similarity, matching FalkorDB's cosine vector-index distance semantics."""
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a)) or 1.0
    nb = math.sqrt(sum(y * y for y in b)) or 1.0
    return 1.0 - dot / (na * nb)
