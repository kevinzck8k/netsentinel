"""
Pydantic v2 data contracts & LangGraph shared state for the AIOps pipeline.

Defines:
  - Severity / EventType enumerations
  - Triage / Telemetry / RAG intermediate payloads
  - RCAReport — strict final JSON output from the RCA Architect Agent
  - AIOpsState — TypedDict flowing through the LangGraph StateGraph
"""

from __future__ import annotations

import operator
from datetime import datetime, timezone
from enum import Enum
from typing import Annotated, Any, Literal, Optional, TypedDict
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator, model_validator


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class Severity(str, Enum):
    """ITU-T X.733 aligned alarm severity."""

    CRITICAL = "critical"
    MAJOR = "major"
    MINOR = "minor"
    WARNING = "warning"
    INFO = "info"
    UNKNOWN = "unknown"


class EventType(str, Enum):
    """Normalized fault taxonomy for telco network events."""

    BGP_SESSION_DOWN = "bgp_session_down"
    BGP_FLAP = "bgp_flap"
    INTERFACE_DOWN = "interface_down"
    LINK_FAILURE = "link_failure"
    HIGH_CPU = "high_cpu"
    HIGH_MEMORY = "high_memory"
    OSPF_ADJACENCY_DOWN = "ospf_adjacency_down"
    ROUTE_WITHDRAWAL = "route_withdrawal"
    AUTH_FAILURE = "auth_failure"
    UNKNOWN = "unknown"


# Single source of truth for the fault-class → severity convention.
# The Triage prompt, the heuristic classifier and the golden-case generator all
# read this map, so labels and predictions can never drift apart.
EVENT_SEVERITY: dict[str, str] = {
    EventType.BGP_SESSION_DOWN.value: Severity.CRITICAL.value,
    EventType.INTERFACE_DOWN.value: Severity.CRITICAL.value,
    EventType.LINK_FAILURE.value: Severity.CRITICAL.value,
    EventType.BGP_FLAP.value: Severity.MAJOR.value,
    EventType.OSPF_ADJACENCY_DOWN.value: Severity.MAJOR.value,
    EventType.HIGH_CPU.value: Severity.MAJOR.value,
    EventType.HIGH_MEMORY.value: Severity.MAJOR.value,
    EventType.AUTH_FAILURE.value: Severity.WARNING.value,
    EventType.ROUTE_WITHDRAWAL.value: Severity.WARNING.value,
}


class AgentName(str, Enum):
    TRIAGE = "triage_agent"
    TELEMETRY = "telemetry_agent"
    RAG = "rag_agent"
    RCA = "rca_architect_agent"


# ---------------------------------------------------------------------------
# Intermediate agent payloads
# ---------------------------------------------------------------------------


class SyslogEvent(BaseModel):
    """Raw syslog message after UDP receive / Redis Stream ingest."""

    event_id: str = Field(default_factory=lambda: str(uuid4()))
    received_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    raw_message: str
    source_ip: Optional[str] = None
    facility: Optional[int] = None
    severity_code: Optional[int] = None
    hostname: Optional[str] = None
    app_name: Optional[str] = None
    timestamp: Optional[datetime] = None

    model_config = {"extra": "forbid"}


class TriageResult(BaseModel):
    """Structured output of the Triage Agent."""

    device_name: str = Field(..., description="Canonical device hostname, e.g. r1")
    device_ip: Optional[str] = Field(None, description="Mgmt or peer IP if known")
    event_type: EventType = EventType.UNKNOWN
    severity: Severity = Severity.UNKNOWN
    summary: str = Field(..., min_length=1, max_length=512)
    keywords: list[str] = Field(default_factory=list)
    requires_telemetry: bool = True
    confidence: float = Field(ge=0.0, le=1.0, default=0.5)

    model_config = {"extra": "forbid", "use_enum_values": True}


class TelemetrySnapshot(BaseModel):
    """Real-time node state collected by the Telemetry Agent."""

    device_name: str
    collected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    commands_executed: list[str] = Field(default_factory=list)
    bgp_summary: Optional[str] = None
    interface_status: Optional[str] = None
    route_table_snippet: Optional[str] = None
    raw_outputs: dict[str, str] = Field(default_factory=dict)
    collection_errors: list[str] = Field(default_factory=list)
    healthy: Optional[bool] = None

    model_config = {"extra": "forbid"}


class RAGDocument(BaseModel):
    """Single retrieved knowledge chunk."""

    doc_id: str
    title: str
    content: str
    score: float = Field(ge=0.0, le=1.0)
    source: str = "sop"
    metadata: dict[str, Any] = Field(default_factory=dict)


class RAGResult(BaseModel):
    """Aggregated RAG retrieval from the RAG Agent."""

    query: str
    documents: list[RAGDocument] = Field(default_factory=list)
    sop_steps: list[str] = Field(default_factory=list)
    historical_cases: list[str] = Field(default_factory=list)

    model_config = {"extra": "forbid"}


# ---------------------------------------------------------------------------
# Final RCA report (strict JSON contract)
# ---------------------------------------------------------------------------


class RemediationStep(BaseModel):
    """Single actionable remediation instruction."""

    order: int = Field(ge=1)
    action: str = Field(..., min_length=1)
    command: Optional[str] = Field(
        None, description="Exact CLI/vtysh command if applicable"
    )
    risk_level: Literal["low", "medium", "high"] = "low"
    expected_outcome: str = ""


class RCAReport(BaseModel):
    """
    Strictly validated Root Cause Analysis report produced by Agent 4.

    This is the canonical contract consumed by NOC dashboards / ticketing
    systems (ServiceNow, PagerDuty, etc.).
    """

    incident_id: str = Field(default_factory=lambda: str(uuid4()))
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    root_cause: str = Field(..., min_length=10, max_length=2048)
    affected_nodes: list[str] = Field(..., min_length=1)
    confidence_score: float = Field(..., ge=0.0, le=1.0)
    remediation_steps: list[RemediationStep] = Field(..., min_length=1)
    event_type: EventType = EventType.UNKNOWN
    severity: Severity = Severity.UNKNOWN
    evidence_summary: str = ""
    rag_references: list[str] = Field(default_factory=list)
    telemetry_highlights: list[str] = Field(default_factory=list)
    next_actions: list[str] = Field(default_factory=list)

    model_config = {"extra": "forbid", "use_enum_values": True}

    @field_validator("affected_nodes")
    @classmethod
    def _normalize_nodes(cls, nodes: list[str]) -> list[str]:
        cleaned = [n.strip().lower() for n in nodes if n and n.strip()]
        if not cleaned:
            raise ValueError("affected_nodes must contain at least one node")
        return list(dict.fromkeys(cleaned))

    @model_validator(mode="after")
    def _sort_remediation(self) -> RCAReport:
        self.remediation_steps = sorted(
            self.remediation_steps, key=lambda s: s.order
        )
        return self


# ---------------------------------------------------------------------------
# LangGraph shared state
# ---------------------------------------------------------------------------


def _merge_errors(left: list[str], right: list[str]) -> list[str]:
    """Reducer that appends error messages across nodes."""
    return (left or []) + (right or [])


class AIOpsState(TypedDict, total=False):
    """
    Shared state document flowing through the Multi-Agent StateGraph.

    Fields marked with Annotated reducers accumulate across fan-out nodes.
    """

    # Correlation / tracing
    run_id: str
    incident_id: str

    # Ingest
    raw_syslog: str
    syslog_event: dict[str, Any]

    # Agent outputs (serialized dicts for checkpoint compatibility)
    triage: dict[str, Any]
    telemetry: dict[str, Any]
    rag: dict[str, Any]
    rca_report: dict[str, Any]

    # Control-plane
    current_agent: str
    route_decision: str  # e.g. "continue" | "skip_telemetry" | "abort"
    evidence_gap: bool  # RCA requests another telemetry pass
    messages: Annotated[list[str], operator.add]
    errors: Annotated[list[str], _merge_errors]
    retry_count: int
