"""Analyst interaction routes: chat with Artemis and upload PCAPs."""

import json
import logging
import os
import tempfile
from typing import Optional

from fastapi import APIRouter, UploadFile, File
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from artemis.managers import db_manager

logger = logging.getLogger("artemis.api.analyst")

router = APIRouter()


# ---------------------------------------------------------------------------
# Lazy-initialised LLM client (same config as the hunt pipeline)
# ---------------------------------------------------------------------------

_llm_client = None
_rag_store = None


def _get_llm_client():
    global _llm_client
    if _llm_client is not None:
        return _llm_client

    from artemis.llm.client import LLMClient

    # Read config from same file the hunt manager uses
    cfg = {}
    cfg_path = os.path.join("config", "llm_settings.json")
    if os.path.exists(cfg_path):
        try:
            with open(cfg_path) as f:
                cfg = json.load(f)
        except Exception:
            pass

    backend = cfg.get("backend") or os.environ.get("LLM_BACKEND", "auto")

    # Apply config to env so LLMClient picks up the right model/URL
    ollama_url = (
        cfg.get("ollama_url")
        or os.environ.get("OLLAMA_URL")
        or "http://localhost:11434"
    )
    os.environ.setdefault("OLLAMA_URL", ollama_url)

    if cfg.get("ollama_model"):
        os.environ["OLLAMA_MODEL"] = cfg["ollama_model"]
    if cfg.get("anthropic_api_key"):
        os.environ.setdefault("ANTHROPIC_API_KEY", cfg["anthropic_api_key"])

    _llm_client = LLMClient(backend=backend)
    logger.info(f"Analyst LLM client initialised (backend={_llm_client.backend})")
    return _llm_client


def _get_rag_store():
    global _rag_store
    if _rag_store is not None:
        return _rag_store

    from artemis.llm.rag import RAGStore
    _rag_store = RAGStore()
    return _rag_store


# ---------------------------------------------------------------------------
# Request schemas
# ---------------------------------------------------------------------------

class AnalystQueryRequest(BaseModel):
    """Ask Artemis a question about the current hunt."""
    question: str
    include_findings: bool = True
    include_cases: bool = True
    include_rag: bool = True


# ---------------------------------------------------------------------------
# POST /api/analyst/query  — chat with Artemis
# ---------------------------------------------------------------------------

@router.post("/api/analyst/query")
async def analyst_query(body: AnalystQueryRequest):
    """Conversational query: ask Artemis about findings, IPs, techniques, etc.

    Assembles context from the DB (findings, cases, technique precision)
    and RAG store, then sends the analyst's question to the coordinator
    LLM (Sonnet) with a specialised system prompt.
    """
    client = _get_llm_client()
    if not client or not client.available:
        return JSONResponse(
            status_code=503,
            content={"error": "LLM backend unavailable"},
        )

    from artemis.llm.prompts import (
        ANALYST_CHAT_SYSTEM,
        format_analyst_context,
    )

    # Gather context
    recent_findings = []
    recent_cases = []
    technique_precision = {}
    rag_context = ""

    if body.include_findings:
        try:
            recent_findings = db_manager.get_findings(limit=20)
        except Exception:
            pass

    if body.include_cases:
        try:
            recent_cases = db_manager.get_cases(limit=15, status="open")
        except Exception:
            # Fallback: get all recent cases if status filter fails
            try:
                recent_cases = db_manager.get_cases(limit=15)
            except Exception:
                pass

    try:
        technique_precision = db_manager.get_technique_precision()
    except Exception:
        pass

    if body.include_rag:
        try:
            rag = _get_rag_store()
            if rag.available:
                rag_context = rag.build_context(
                    current_findings_text=body.question,
                    n_findings=5,
                    n_baselines=2,
                    n_intel=3,
                )
        except Exception:
            pass

    context_text = format_analyst_context(
        recent_findings=recent_findings,
        recent_cases=recent_cases,
        technique_precision=technique_precision,
        rag_context=rag_context,
    )

    user_message = f"{context_text}\n\n---\nAnalyst question: {body.question}"

    # Use coordinator model (Sonnet) for high-quality reasoning
    answer = client.coordinator_complete(
        messages=[{"role": "user", "content": user_message}],
        system=ANALYST_CHAT_SYSTEM,
        max_tokens=2048,
    )

    if answer is None:
        return JSONResponse(
            status_code=502,
            content={"error": "LLM call failed — check backend logs"},
        )

    return {
        "answer": answer,
        "context_summary": {
            "findings_included": len(recent_findings),
            "cases_included": len(recent_cases),
            "techniques_tracked": len(technique_precision),
            "rag_available": bool(rag_context),
        },
    }


# ---------------------------------------------------------------------------
# POST /api/analyst/upload-pcap  — upload and hunt on a PCAP file
# ---------------------------------------------------------------------------

@router.post("/api/analyst/upload-pcap")
async def upload_pcap(
    file: UploadFile = File(...),
    max_packets: Optional[int] = None,
):
    """Upload a PCAP file, extract features, and run the hunting pipeline.

    The PCAP is processed by the existing PCAPAnalyzer integration which
    produces the same data format the hunting agents expect.  The
    coordinator then runs a full hunt cycle on the extracted data.
    """
    # Validate file type
    if not file.filename or not file.filename.lower().endswith(
        (".pcap", ".pcapng", ".cap")
    ):
        return JSONResponse(
            status_code=400,
            content={
                "error": "File must be a PCAP (.pcap, .pcapng, or .cap)"
            },
        )

    # Save to temp file
    try:
        suffix = os.path.splitext(file.filename)[1]
        with tempfile.NamedTemporaryFile(
            delete=False, suffix=suffix, dir="/tmp"
        ) as tmp:
            contents = await file.read()
            tmp.write(contents)
            tmp_path = tmp.name
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"error": f"Failed to save upload: {e}"},
        )

    try:
        # Extract features with PCAPAnalyzer
        from artemis.integrations.pcap_analyzer import PCAPAnalyzer

        analyzer = PCAPAnalyzer()
        data = analyzer.analyze_pcap(tmp_path, max_packets=max_packets)

        if not data:
            return JSONResponse(
                status_code=422,
                content={"error": "PCAP analysis produced no data"},
            )

        # Run the hunting pipeline
        from artemis.meta_learner.coordinator import MetaLearnerCoordinator

        coordinator = MetaLearnerCoordinator(
            deployment_mode="parallel",
            enable_parallel_execution=True,
            max_workers=4,
            llm_backend=_get_llm_client().backend if _get_llm_client() else "auto",
        )

        assessment = coordinator.hunt(data=data)

        # Summarise results
        findings_summary = []
        for f in assessment.get("findings", []):
            findings_summary.append({
                "activity_type": getattr(f, "activity_type", str(f)),
                "description": getattr(f, "description", "")[:300],
                "indicators": getattr(f, "indicators", [])[:10],
                "affected_assets": getattr(f, "affected_assets", [])[:10],
            })

        return {
            "filename": file.filename,
            "packets_analyzed": len(data.get("network_connections", [])),
            "final_confidence": assessment["final_confidence"],
            "severity": (
                assessment["severity"].value
                if hasattr(assessment["severity"], "value")
                else str(assessment["severity"])
            ),
            "total_findings": assessment.get("total_findings", 0),
            "findings": findings_summary,
            "mitre_techniques": assessment.get("mitre_techniques", []),
            "recommendations": assessment.get("recommendations", []),
        }

    except ImportError as e:
        return JSONResponse(
            status_code=501,
            content={
                "error": f"Missing dependency: {e}. "
                "Install with: pip install scapy"
            },
        )
    except Exception as e:
        logger.error(f"PCAP hunt failed: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"error": f"PCAP analysis failed: {e}"},
        )
    finally:
        # Clean up temp file
        try:
            os.unlink(tmp_path)
        except Exception:
            pass
