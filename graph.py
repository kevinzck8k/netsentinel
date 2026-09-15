"""
LangGraph StateGraph assembly for the Telco Multi-Agent AIOps pipeline.

Graph topology
--------------
                    ┌─────────────┐
                    │   triage    │
                    └──────┬──────┘
           ┌───────────────┼────────────────┐
           │ abort         │ continue       │ skip_telemetry
           ▼               ▼                ▼
        [END]        ┌───────────┐     ┌─────────┐
                     │ telemetry │     │   rag   │
                     └─────┬─────┘     └────┬────┘
                           │                │
                           ▼                │
                     ┌─────────┐            │
                     │   rag   │◄───────────┘
                     └────┬────┘
                          ▼
                   ┌──────────────┐
                   │ rca_architect│
                   └──────┬───────┘
                          ▼
                        [END]

Persistence: SqliteSaver checkpointer (lab/checkpoints.sqlite)
"""

from __future__ import annotations

import atexit
import logging
import sqlite3
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph

from agents import (
    rag_agent,
    rca_architect_agent,
    telemetry_agent,
    triage_agent,
)
from config import get_settings
from observability import traced
from schema import AIOpsState

logger = logging.getLogger(__name__)
_CHECKPOINT_CONNECTIONS: list[sqlite3.Connection] = []


def _close_checkpoint_connections() -> None:
    for connection in _CHECKPOINT_CONNECTIONS:
        try:
            connection.close()
        except sqlite3.Error:
            pass
    _CHECKPOINT_CONNECTIONS.clear()


atexit.register(_close_checkpoint_connections)

# Node name constants
NODE_TRIAGE = "triage_agent"
NODE_TELEMETRY = "telemetry_agent"
NODE_RAG = "rag_agent"
NODE_RCA = "rca_architect_agent"


# ---------------------------------------------------------------------------
# Conditional routing
# ---------------------------------------------------------------------------


def route_after_rca(
    state: AIOpsState,
) -> Literal["telemetry_agent", "__end__"]:
    """RCA may request one extra telemetry pass when evidence is insufficient."""
    if state.get("evidence_gap") and int(state.get("retry_count") or 0) <= 1:
        logger.info("Routing: rca → telemetry (evidence_gap retry)")
        return NODE_TELEMETRY
    return "__end__"


def route_after_triage(
    state: AIOpsState,
) -> Literal["telemetry_agent", "rag_agent", "__end__"]:
    """
    Conditional edge after Triage:

      - abort           → END (informational noise)
      - skip_telemetry  → RAG directly
      - continue        → Telemetry (default for critical/major)
    """
    decision = (state.get("route_decision") or "continue").lower()
    triage = state.get("triage") or {}
    severity = str(triage.get("severity", "")).lower()

    if decision == "abort" or severity == "info":
        logger.info("Routing: triage → END (abort/info)")
        return "__end__"
    if decision == "skip_telemetry":
        logger.info("Routing: triage → rag (skip_telemetry)")
        return NODE_RAG
    logger.info("Routing: triage → telemetry")
    return NODE_TELEMETRY


# ---------------------------------------------------------------------------
# Checkpointer
# ---------------------------------------------------------------------------


def build_checkpointer():
    """
    Prefer SqliteSaver for durable lab runs; fall back to MemorySaver.

    SqliteSaver APIs differ slightly across langgraph-checkpoint-sqlite
    versions — we probe imports defensively.
    """
    settings = get_settings()
    db_path: Path = settings.checkpoint_db_path
    db_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        from langgraph.checkpoint.sqlite import SqliteSaver

        conn = sqlite3.connect(str(db_path), check_same_thread=False)
        _CHECKPOINT_CONNECTIONS.append(conn)
        checkpointer = SqliteSaver(conn)
        logger.info("Using SqliteSaver at %s", db_path)
        return checkpointer
    except Exception as exc:  # noqa: BLE001
        logger.warning("SqliteSaver unavailable (%s); using MemorySaver", exc)
        return MemorySaver()


# ---------------------------------------------------------------------------
# Graph builder
# ---------------------------------------------------------------------------


def build_aiops_graph(*, compile_graph: bool = True):
    """
    Construct (and optionally compile) the 4-agent StateGraph.

    Returns a compiled CompiledStateGraph when compile_graph=True,
    otherwise the uncompiled StateGraph builder.
    """
    graph = StateGraph(AIOpsState)

    # Register nodes
    graph.add_node(NODE_TRIAGE, triage_agent)
    graph.add_node(NODE_TELEMETRY, telemetry_agent)
    graph.add_node(NODE_RAG, rag_agent)
    graph.add_node(NODE_RCA, rca_architect_agent)

    # Entry
    graph.add_edge(START, NODE_TRIAGE)

    # Conditional edges from triage
    graph.add_conditional_edges(
        NODE_TRIAGE,
        route_after_triage,
        {
            NODE_TELEMETRY: NODE_TELEMETRY,
            NODE_RAG: NODE_RAG,
            "__end__": END,
        },
    )

    # Linear: telemetry → rag → rca, with one evidence-gap retry
    graph.add_edge(NODE_TELEMETRY, NODE_RAG)
    graph.add_edge(NODE_RAG, NODE_RCA)
    graph.add_conditional_edges(
        NODE_RCA,
        route_after_rca,
        {
            NODE_TELEMETRY: NODE_TELEMETRY,
            "__end__": END,
        },
    )

    if not compile_graph:
        return graph

    checkpointer = build_checkpointer()
    compiled = graph.compile(checkpointer=checkpointer)
    logger.info("AIOps StateGraph compiled with checkpointer=%s", type(checkpointer).__name__)
    return compiled


# Module-level compiled graph (lazy)
_COMPILED = None


def get_compiled_graph():
    global _COMPILED
    if _COMPILED is None:
        _COMPILED = build_aiops_graph(compile_graph=True)
    return _COMPILED


# ---------------------------------------------------------------------------
# Invocation helper
# ---------------------------------------------------------------------------


@traced("graph.run_incident")
def run_incident(
    raw_syslog: str,
    *,
    syslog_event: dict[str, Any] | None = None,
    thread_id: str | None = None,
    incident_id: str | None = None,
) -> dict[str, Any]:
    """
    Execute a full Multi-Agent diagnosis for one syslog incident.

    Parameters
    ----------
    raw_syslog :
        Raw syslog text.
    syslog_event :
        Optional pre-parsed SyslogEvent dict.
    thread_id :
        LangGraph thread id for checkpoint continuity.
    incident_id :
        Correlation id propagated into the RCA report.

    Returns
    -------
    Final AIOpsState as a plain dict (includes rca_report when successful).
    """
    graph = get_compiled_graph()
    run_id = str(uuid4())
    incident_id = incident_id or str(uuid4())
    thread_id = thread_id or f"incident-{incident_id}"

    initial: AIOpsState = {
        "run_id": run_id,
        "incident_id": incident_id,
        "raw_syslog": raw_syslog,
        "syslog_event": syslog_event or {},
        "messages": [],
        "errors": [],
        "retry_count": 0,
        "current_agent": "",
        "route_decision": "continue",
        "evidence_gap": False,
    }

    config = {"configurable": {"thread_id": thread_id}}
    logger.info(
        "Invoking graph run_id=%s incident_id=%s thread_id=%s",
        run_id,
        incident_id,
        thread_id,
    )

    try:
        final_state = graph.invoke(initial, config=config)
    except Exception:
        logger.exception("Graph invocation failed for incident_id=%s", incident_id)
        raise

    return dict(final_state)


def pretty_rca(state: dict[str, Any]) -> str:
    """Render the RCA report as pretty JSON for CLI / logs."""
    import json

    report = state.get("rca_report")
    if not report:
        return json.dumps(
            {"status": "no_rca", "route": state.get("route_decision"), "messages": state.get("messages")},
            indent=2,
            ensure_ascii=False,
        )
    return json.dumps(report, indent=2, ensure_ascii=False, default=str)
