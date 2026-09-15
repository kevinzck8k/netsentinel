"""
Published-style baselines for ablation.

Aligned with common RCA papers / telco RAG demos:

  rule_only     Drain/regex taxonomy only (no RCA, no SOP)
  single_agent  syslog → RCA  (CoT-style, no tools)
  rag_only      syslog + SOP retrieval, no live CLI  (TeleOps / RAG-LLM)
  multi_agent   triage + event-aware CLI + RAG + RCA  (this system)

Literature counterparts:
  Flow-of-Action (arXiv:2502.08224)  — CoT / ReAct / Reflexion baselines
  RCACopilot (arXiv:2507.03224)      — statistical ranking + LLM, no MAS tools
  TeleOps (github.com/udaytamma/teleops) — 11-rule matcher vs RAG-LLM
"""

from __future__ import annotations

import json
import logging
from typing import Any
from uuid import uuid4

from agents import _get_llm, _heuristic_rca, _invoke_structured, heuristic_triage
from observability import traced
from schema import RAGResult, RCAReport

logger = logging.getLogger(__name__)

SINGLE_AGENT_SYSTEM = """You are a single network diagnostician.
You see only one syslog line. You have NO live telemetry and NO SOP manuals.
Produce a strict RCA JSON. Keep confidence_score <= 0.45 because evidence is incomplete.
Do not invent CLI output that you did not observe.
"""

RAG_ONLY_SYSTEM = """You are a RAG-only network diagnostician (TeleOps-style).
You may use retrieved SOP text. You have NO live device CLI.
Do not invent interface/BGP state that was not in the syslog or SOP.
Keep confidence_score <= 0.55.
"""


@traced("baseline.rule_only")
def run_rule_only(raw_syslog: str, *, incident_id: str | None = None) -> dict[str, Any]:
    """Regex/Drain-style classifier — the classical log-analytics baseline."""
    del incident_id
    triage = heuristic_triage(raw_syslog)
    return {
        "triage": triage.model_dump(mode="json"),
        "telemetry": {},
        "rag": {"query": "", "documents": [], "sop_steps": [], "historical_cases": []},
        "rca_report": None,
        "current_agent": "rule_only",
    }


@traced("baseline.single_agent")
def run_single_agent(raw_syslog: str, *, incident_id: str | None = None) -> dict[str, Any]:
    """Diagnose from syslog alone — CoT / single-prompt control group."""
    incident_id = incident_id or str(uuid4())
    triage = heuristic_triage(raw_syslog)
    llm = _get_llm()
    report: RCAReport

    if llm is not None:
        try:
            report = _invoke_structured(
                llm,
                RCAReport,
                SINGLE_AGENT_SYSTEM,
                json.dumps(
                    {
                        "syslog": raw_syslog,
                        "heuristic_triage": triage.model_dump(mode="json"),
                        "incident_id": incident_id,
                    },
                    ensure_ascii=False,
                ),
            )
            if not report.incident_id:
                report.incident_id = incident_id
        except Exception as exc:  # noqa: BLE001
            logger.warning("Single-agent LLM failed (%s); heuristic fallback", exc)
            report = _heuristic_rca(
                triage.model_dump(mode="json"), {}, {}, incident_id
            )
            report.confidence_score = min(report.confidence_score, 0.45)
    else:
        report = _heuristic_rca(triage.model_dump(mode="json"), {}, {}, incident_id)
        report.confidence_score = min(report.confidence_score, 0.45)

    return {
        "triage": triage.model_dump(mode="json"),
        "telemetry": {},
        "rag": {"query": "", "documents": [], "sop_steps": [], "historical_cases": []},
        "rca_report": report.model_dump(mode="json"),
        "current_agent": "single_agent",
    }


@traced("baseline.rag_only")
def run_rag_only(raw_syslog: str, *, incident_id: str | None = None) -> dict[str, Any]:
    """TeleOps-style: syslog + SOP retrieval, no live CLI probes."""
    incident_id = incident_id or str(uuid4())
    triage = heuristic_triage(raw_syslog)
    payload = triage.model_dump(mode="json")
    query = (
        f"SOP for {payload.get('event_type')} on device {payload.get('device_name')}. "
        f"Symptoms: {payload.get('summary')}. Keywords: {', '.join(payload.get('keywords') or [])}."
    )
    try:
        from vector_rag import get_rag_store

        rag = get_rag_store().retrieve(query, top_k=5)
    except Exception as exc:  # noqa: BLE001
        logger.warning("RAG-only retrieval failed: %s", exc)
        rag = RAGResult(query=query, documents=[], sop_steps=[], historical_cases=[])

    llm = _get_llm()
    report: RCAReport
    rag_dump = rag.model_dump(mode="json")
    if llm is not None:
        try:
            report = _invoke_structured(
                llm,
                RCAReport,
                RAG_ONLY_SYSTEM,
                json.dumps(
                    {
                        "syslog": raw_syslog,
                        "triage": payload,
                        "retrieved_sops": [
                            {
                                "title": d.get("title"),
                                "content": (d.get("content") or "")[:800],
                            }
                            for d in rag_dump.get("documents") or []
                        ],
                        "incident_id": incident_id,
                    },
                    ensure_ascii=False,
                ),
            )
            if not report.incident_id:
                report.incident_id = incident_id
        except Exception as exc:  # noqa: BLE001
            logger.warning("RAG-only LLM failed (%s); heuristic fallback", exc)
            report = _heuristic_rca(payload, {}, rag_dump, incident_id)
            report.confidence_score = min(report.confidence_score, 0.55)
    else:
        report = _heuristic_rca(payload, {}, rag_dump, incident_id)
        report.confidence_score = min(report.confidence_score, 0.55)

    return {
        "triage": payload,
        "telemetry": {},
        "rag": rag_dump,
        "rca_report": report.model_dump(mode="json"),
        "current_agent": "rag_only",
    }
