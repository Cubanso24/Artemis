"""
RAG (Retrieval-Augmented Generation) pipeline for Artemis.

Stores past findings, network baselines, and threat intelligence in a
ChromaDB vector store so the LLM can reason about historical context
when analysing new data.

Architecture
------------
- **Collections**: ``findings``, ``baselines``, ``threat_intel``
- **Embeddings**: Uses Ollama (same server already running for the LLM)
  via the ``/api/embeddings`` endpoint, defaulting to ``nomic-embed-text``.
  Falls back to a lightweight local sentence-transformer if Ollama
  embeddings fail.
- **Retrieval**: query-time similarity search returns the top-*k* most
  relevant historical items and formats them for prompt injection.
"""

import hashlib
import json
import logging
import os
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

import requests as _requests

logger = logging.getLogger("artemis.llm.rag")

# ---------------------------------------------------------------------------
# Embedding helpers
# ---------------------------------------------------------------------------

_OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434").rstrip("/")
# Embedding model — must be an actual embedding model, NOT a chat model.
# Falls back to sentence-transformers if Ollama embeddings fail.
_EMBED_MODEL = os.getenv("RAG_EMBED_MODEL", "nomic-embed-text")

# Lazy-loaded fallback
_FALLBACK_ENCODER = None
# Circuit breaker: once Ollama embeddings fail, skip straight to fallback
_OLLAMA_EMBED_FAILED = False


def _embed_ollama(texts: List[str]) -> Optional[List[List[float]]]:
    """Get embeddings from the Ollama server."""
    global _OLLAMA_EMBED_FAILED
    if _OLLAMA_EMBED_FAILED:
        return None
    try:
        results = []
        for text in texts:
            resp = _requests.post(
                f"{_OLLAMA_URL}/api/embeddings",
                json={"model": _EMBED_MODEL, "prompt": text},
                timeout=30,
            )
            if resp.status_code != 200:
                logger.warning(
                    f"Ollama embedding failed (status {resp.status_code}) "
                    f"for model '{_EMBED_MODEL}' — switching to "
                    f"sentence-transformers fallback"
                )
                _OLLAMA_EMBED_FAILED = True
                return None
            vec = resp.json().get("embedding")
            if vec is None:
                _OLLAMA_EMBED_FAILED = True
                return None
            results.append(vec)
        return results
    except Exception as e:
        logger.debug(f"Ollama embedding failed: {e}")
        _OLLAMA_EMBED_FAILED = True
        return None


def _embed_fallback(texts: List[str]) -> List[List[float]]:
    """Fallback: use sentence-transformers (auto-downloaded)."""
    global _FALLBACK_ENCODER
    if _FALLBACK_ENCODER is None:
        try:
            from sentence_transformers import SentenceTransformer
            _FALLBACK_ENCODER = SentenceTransformer("all-MiniLM-L6-v2")
            logger.info("Loaded fallback sentence-transformer for RAG embeddings")
        except ImportError:
            logger.warning(
                "sentence-transformers not installed and Ollama embeddings "
                "unavailable.  RAG will be disabled.  Install with: "
                "pip install sentence-transformers"
            )
            return []
    return _FALLBACK_ENCODER.encode(texts, show_progress_bar=False).tolist()


def embed(texts: List[str]) -> List[List[float]]:
    """Embed *texts* using Ollama, falling back to sentence-transformers."""
    vecs = _embed_ollama(texts)
    if vecs is not None:
        return vecs
    return _embed_fallback(texts)


# ---------------------------------------------------------------------------
# RAG Store
# ---------------------------------------------------------------------------

class RAGStore:
    """ChromaDB-backed vector store for Artemis RAG.

    Collections
    -----------
    findings
        Past hunting findings (activity_type, description, indicators,
        severity, MITRE, analyst feedback).
    baselines
        Network baseline profiles (normal traffic patterns, known
        services, expected behaviours).
    threat_intel
        Threat intelligence enrichments (IOCs, campaign descriptions,
        TTP profiles).
    """

    def __init__(
        self,
        persist_dir: str = "data/rag_store",
        ollama_url: Optional[str] = None,
    ):
        global _OLLAMA_URL
        if ollama_url:
            _OLLAMA_URL = ollama_url.rstrip("/")

        self._persist_dir = persist_dir
        self._client = None  # lazy init
        self._collections: Dict[str, Any] = {}

    # ------------------------------------------------------------------
    # Lazy initialisation (so import never fails)
    # ------------------------------------------------------------------

    def _ensure_client(self):
        if self._client is not None:
            return True
        try:
            import chromadb
            from chromadb.config import Settings

            os.makedirs(self._persist_dir, exist_ok=True)
            self._client = chromadb.Client(Settings(
                chroma_db_impl="duckdb+parquet",
                persist_directory=self._persist_dir,
                anonymized_telemetry=False,
            ))
            logger.info(f"ChromaDB initialised at {self._persist_dir}")
            return True
        except ImportError:
            logger.warning(
                "chromadb not installed — RAG disabled.  "
                "Install with: pip install chromadb"
            )
            return False
        except Exception as e:
            # Newer ChromaDB versions use different Settings
            try:
                import chromadb
                os.makedirs(self._persist_dir, exist_ok=True)
                self._client = chromadb.PersistentClient(
                    path=self._persist_dir,
                )
                logger.info(f"ChromaDB initialised at {self._persist_dir}")
                return True
            except Exception as e2:
                logger.error(f"ChromaDB init failed: {e}; retry: {e2}")
                return False

    def _get_collection(self, name: str):
        if name in self._collections:
            return self._collections[name]
        if not self._ensure_client():
            return None
        col = self._client.get_or_create_collection(
            name=name,
            metadata={"hnsw:space": "cosine"},
        )
        # Verify embedding dimensions match current model.  If the
        # collection was created with a different embedding model (e.g.
        # 384-dim fallback vs 768-dim Ollama) we must recreate it.
        try:
            count = col.count()
            if count > 0:
                probe = embed(["dimension probe"])
                if probe:
                    current_dim = len(probe[0])
                    sample = col.peek(1)
                    if sample and sample.get("embeddings") and sample["embeddings"]:
                        stored_dim = len(sample["embeddings"][0])
                        if stored_dim != current_dim:
                            logger.warning(
                                f"Embedding dimension mismatch in '{name}': "
                                f"stored={stored_dim}, current={current_dim}. "
                                f"Recreating collection."
                            )
                            self._client.delete_collection(name)
                            col = self._client.get_or_create_collection(
                                name=name,
                                metadata={"hnsw:space": "cosine"},
                            )
        except Exception as e:
            logger.debug(f"Dimension check skipped for '{name}': {e}")
        self._collections[name] = col
        return col

    @property
    def available(self) -> bool:
        return self._ensure_client()

    # ------------------------------------------------------------------
    # Index operations
    # ------------------------------------------------------------------

    def index_finding(self, finding: Dict[str, Any]) -> bool:
        """Add a hunting finding to the vector store.

        *finding* should have keys like ``activity_type``, ``description``,
        ``indicators``, ``severity``, ``mitre_techniques``, ``agent_name``,
        ``confidence``, and optionally ``analyst_feedback``.
        """
        col = self._get_collection("findings")
        if col is None:
            return False

        text = self._finding_to_text(finding)
        doc_id = self._doc_id(text)

        vecs = embed([text])
        if not vecs:
            return False

        try:
            col.upsert(
                ids=[doc_id],
                embeddings=vecs,
                documents=[text],
                metadatas=[{
                    "activity_type": str(finding.get("activity_type", "")),
                    "severity": str(finding.get("severity", "")),
                    "agent_name": str(finding.get("agent_name", "")),
                    "confidence": float(finding.get("confidence", 0)),
                    "timestamp": finding.get("timestamp", datetime.utcnow().isoformat()),
                    "feedback": str(finding.get("analyst_feedback", "")),
                }],
            )
            return True
        except Exception as e:
            logger.error(f"Failed to index finding: {e}")
            return False

    def index_baseline(self, baseline: Dict[str, Any]) -> bool:
        """Store a network baseline profile."""
        col = self._get_collection("baselines")
        if col is None:
            return False

        text = self._baseline_to_text(baseline)
        doc_id = self._doc_id(text)

        vecs = embed([text])
        if not vecs:
            return False

        try:
            col.upsert(
                ids=[doc_id],
                embeddings=vecs,
                documents=[text],
                metadatas=[{
                    "type": str(baseline.get("type", "network")),
                    "scope": str(baseline.get("scope", "global")),
                    "timestamp": baseline.get(
                        "timestamp", datetime.utcnow().isoformat()
                    ),
                }],
            )
            return True
        except Exception as e:
            logger.error(f"Failed to index baseline: {e}")
            return False

    def index_threat_intel(self, intel: Dict[str, Any]) -> bool:
        """Store a threat intelligence entry."""
        col = self._get_collection("threat_intel")
        if col is None:
            return False

        text = self._intel_to_text(intel)
        doc_id = self._doc_id(text)

        vecs = embed([text])
        if not vecs:
            return False

        try:
            col.upsert(
                ids=[doc_id],
                embeddings=vecs,
                documents=[text],
                metadatas=[{
                    "source": str(intel.get("source", "")),
                    "type": str(intel.get("type", "")),
                    "timestamp": intel.get(
                        "timestamp", datetime.utcnow().isoformat()
                    ),
                }],
            )
            return True
        except Exception as e:
            logger.error(f"Failed to index threat intel: {e}")
            return False

    # ------------------------------------------------------------------
    # Batch indexing (for post-hunt persistence)
    # ------------------------------------------------------------------

    def index_hunt_results(
        self,
        findings: List[Dict[str, Any]],
        network_stats: Optional[Dict[str, Any]] = None,
    ) -> int:
        """Index all findings from a completed hunt cycle.

        Optionally stores network statistics as a baseline snapshot.
        Returns the number of successfully indexed items.
        """
        count = 0
        for f in findings:
            if self.index_finding(f):
                count += 1
        if network_stats:
            if self.index_baseline(network_stats):
                count += 1
        logger.info(f"Indexed {count}/{len(findings)} findings into RAG store")
        return count

    # ------------------------------------------------------------------
    # Retrieval
    # ------------------------------------------------------------------

    def query_similar_findings(
        self, query: str, n_results: int = 5,
        filter_meta: Optional[Dict] = None,
    ) -> List[Dict[str, Any]]:
        """Return the *n* most similar past findings."""
        return self._query("findings", query, n_results, filter_meta)

    def query_baselines(
        self, query: str, n_results: int = 3,
        filter_meta: Optional[Dict] = None,
    ) -> List[Dict[str, Any]]:
        """Return relevant network baselines."""
        return self._query("baselines", query, n_results, filter_meta)

    def query_threat_intel(
        self, query: str, n_results: int = 5,
        filter_meta: Optional[Dict] = None,
    ) -> List[Dict[str, Any]]:
        """Return relevant threat intelligence entries."""
        return self._query("threat_intel", query, n_results, filter_meta)

    def _query(
        self, collection: str, query: str, n_results: int,
        filter_meta: Optional[Dict],
    ) -> List[Dict[str, Any]]:
        col = self._get_collection(collection)
        if col is None:
            return []

        vecs = embed([query])
        if not vecs:
            return []

        try:
            kwargs: Dict[str, Any] = {
                "query_embeddings": vecs,
                "n_results": n_results,
            }
            if filter_meta:
                kwargs["where"] = filter_meta

            results = col.query(**kwargs)

            items = []
            docs = results.get("documents", [[]])[0]
            metas = results.get("metadatas", [[]])[0]
            dists = results.get("distances", [[]])[0]
            for doc, meta, dist in zip(docs, metas, dists):
                items.append({
                    "text": doc,
                    "metadata": meta,
                    "similarity": 1.0 - dist,  # cosine distance → similarity
                })
            return items
        except Exception as e:
            # Dimension mismatch — stale collection from a different model
            if "dimension" in str(e).lower():
                logger.warning(
                    f"Embedding dimension mismatch in '{collection}', "
                    f"recreating collection: {e}"
                )
                try:
                    self._client.delete_collection(collection)
                    self._collections.pop(collection, None)
                except Exception:
                    pass
            else:
                logger.error(f"RAG query failed on {collection}: {e}")
            return []

    # ------------------------------------------------------------------
    # Context building for prompts
    # ------------------------------------------------------------------

    def build_context(
        self,
        current_findings_text: str,
        network_summary: str = "",
        n_findings: int = 5,
        n_baselines: int = 3,
        n_intel: int = 5,
    ) -> str:
        """Build a RAG context string suitable for prompt injection.

        Queries all three collections and returns a formatted block
        that can be prepended to the LLM prompt.
        """
        if not self.available:
            return ""

        sections = []

        # Similar past findings
        similar = self.query_similar_findings(
            current_findings_text, n_results=n_findings
        )
        if similar:
            lines = ["=== HISTORICAL FINDINGS (similar past detections) ==="]
            for i, item in enumerate(similar, 1):
                sim = item["similarity"]
                fb = item["metadata"].get("feedback", "")
                fb_str = f" [Analyst: {fb}]" if fb else ""
                lines.append(
                    f"{i}. (similarity={sim:.2f}){fb_str}\n"
                    f"   {item['text'][:500]}"
                )
            sections.append("\n".join(lines))

        # Network baselines
        if network_summary:
            baselines = self.query_baselines(
                network_summary, n_results=n_baselines
            )
            if baselines:
                lines = ["=== NETWORK BASELINES (known-normal patterns) ==="]
                for i, item in enumerate(baselines, 1):
                    lines.append(f"{i}. {item['text'][:400]}")
                sections.append("\n".join(lines))

        # Threat intel
        query = current_findings_text[:500]
        intel = self.query_threat_intel(query, n_results=n_intel)
        if intel:
            lines = ["=== THREAT INTELLIGENCE (relevant entries) ==="]
            for i, item in enumerate(intel, 1):
                lines.append(f"{i}. [{item['metadata'].get('source', '?')}] "
                             f"{item['text'][:400]}")
            sections.append("\n".join(lines))

        if not sections:
            return ""

        return "\n\n".join(sections) + "\n"

    # ------------------------------------------------------------------
    # Text serialisation helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _finding_to_text(f: Dict) -> str:
        parts = [
            f"[{f.get('severity', '?').upper()}] {f.get('activity_type', '?')}",
            f.get("description", ""),
        ]
        indicators = f.get("indicators", [])
        if indicators:
            parts.append(f"Indicators: {', '.join(str(i) for i in indicators[:10])}")
        techniques = f.get("mitre_techniques", [])
        if techniques:
            parts.append(f"MITRE: {', '.join(techniques[:5])}")
        agent = f.get("agent_name", "")
        if agent:
            parts.append(f"Agent: {agent}")
        return " | ".join(p for p in parts if p)

    @staticmethod
    def _baseline_to_text(b: Dict) -> str:
        parts = [f"Baseline ({b.get('type', 'network')})"]
        for key in ("total_nodes", "internal_nodes", "top_ports",
                     "top_protocols", "dns_servers", "domain_controllers",
                     "gateways", "description"):
            val = b.get(key)
            if val:
                parts.append(f"{key}: {val}")
        return " | ".join(parts)

    @staticmethod
    def _intel_to_text(i: Dict) -> str:
        parts = [
            f"[{i.get('source', '?')}] {i.get('type', '?')}",
            i.get("description", ""),
        ]
        iocs = i.get("iocs", [])
        if iocs:
            parts.append(f"IOCs: {', '.join(str(x) for x in iocs[:10])}")
        ttps = i.get("ttps", [])
        if ttps:
            parts.append(f"TTPs: {', '.join(ttps[:5])}")
        return " | ".join(p for p in parts if p)

    @staticmethod
    def _doc_id(text: str) -> str:
        return hashlib.sha256(text.encode()).hexdigest()[:24]
