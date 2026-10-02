"""Runbook retriever — the retrieval half of RAG for the SOC agent.

Given an incident, it finds the most relevant response runbook from the local
knowledge base so the agent's triage is grounded in your playbooks, not just the
model's guesswork.

IMPLEMENTED HERE: dependency-free lexical retrieval (term overlap) over the
markdown runbooks in `soc/knowledge/`. Deterministic, explainable, free, CI-safe.
OPTIONAL UPGRADE: swap this for embedding-based semantic search (a vector store +
an embeddings model) behind the same `retrieve()` interface — the agent doesn't
change.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

KNOWLEDGE_DIR = Path(__file__).resolve().parent / "knowledge"

_STOP = {
    "the", "a", "an", "of", "in", "to", "and", "for", "from", "on", "at", "is",
    "are", "be", "this", "that", "any", "if", "or", "it", "with", "new", "via",
}


def _tokens(text: str) -> list[str]:
    return [t for t in re.findall(r"[a-z0-9]+", text.lower()) if t not in _STOP]


@dataclass(frozen=True)
class Runbook:
    name: str
    title: str
    text: str
    score: float = 0.0


class RunbookRetriever:
    def __init__(self, knowledge_dir: Path = KNOWLEDGE_DIR) -> None:
        self._docs: list[Runbook] = []
        for path in sorted(Path(knowledge_dir).glob("*.md")):
            text = path.read_text(encoding="utf-8")
            first = text.splitlines()[0] if text.splitlines() else path.stem
            title = first.lstrip("# ").strip()
            self._docs.append(Runbook(name=path.stem, title=title, text=text))

    def retrieve(self, query: str, k: int = 1) -> list[Runbook]:
        q_terms = set(_tokens(query))
        scored: list[Runbook] = []
        for d in self._docs:
            doc_terms = set(_tokens(d.text))
            if not doc_terms:
                continue
            overlap = len(q_terms & doc_terms)
            scored.append(Runbook(d.name, d.title, d.text, score=float(overlap)))
        scored.sort(key=lambda r: r.score, reverse=True)
        return [r for r in scored[:k] if r.score > 0]
