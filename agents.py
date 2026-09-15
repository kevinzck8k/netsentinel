"""
Multi-Agent node functions for the Telco AIOps StateGraph.

Agent roster
------------
1. Triage Agent      — parse syslog → device / event_type / severity
2. Telemetry Agent   — probe live node state via diagnostic tools
3. RAG Agent         — retrieve SOP / historical RCA from Qdrant
4. RCA Architect     — synthesize a strict RCAReport JSON

Each node:
  - Accepts / returns AIOpsState (TypedDict)
  - Is wrapped in an OTel span
  - Degrades gracefully to heuristic logic when offline_mode=True
"""

from __future__ import annotations

import json
import logging
import re
import threading
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from tenacity import retry, stop_after_attempt, wait_exponential

from config import get_settings
from observability import traced
from schema import (
    EVENT_SEVERITY,
    AgentName,
    EventType,
    RCAReport,
    RAGResult,
    RemediationStep,
    Severity,
    TelemetrySnapshot,
    TriageResult,
)
from tools import collect_telemetry_bundle
from vector_rag import get_rag_store

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Shared LLM helper
# ---------------------------------------------------------------------------


def _get_llm():
    """Return a LangChain chat model, or None in offline mode."""
    settings = get_settings()
    if settings.is_offline():
        return None
    try:
        from langchain_openai import ChatOpenAI

        kwargs: dict[str, Any] = {
            "model": settings.resolved_llm_model(),
            "temperature": settings.llm_temperature,
            "max_retries": settings.llm_max_retries,
            "api_key": settings.openai_api_key.get_secret_value(),
        }
        base_url = settings.resolved_llm_base_url()
        if base_url:
            kwargs["base_url"] = base_url
        extra_body = settings.resolved_llm_extra_body()
        if extra_body:
            kwargs["extra_body"] = extra_body
        return ChatOpenAI(**kwargs)
    except Exception as exc:  # noqa: BLE001
        logger.warning("LLM init failed, falling back to heuristics: %s", exc)
        return None


# Every agent silently degrades to heuristics when an LLM call fails, which
# would otherwise make a fully-heuristic run indistinguishable from a real
# DeepSeek run in the eval report. These counters make that visible.
LLM_CALL_STATS: dict[str, int] = {"ok": 0, "failed": 0}
# The eval runner scores cases on a thread pool, so `+= 1` on the shared dict
# would lose increments without a lock.
_STATS_LOCK = threading.Lock()


def _record_llm_call(outcome: str) -> None:
    with _STATS_LOCK:
        LLM_CALL_STATS[outcome] += 1


def llm_call_stats() -> dict[str, int]:
    with _STATS_LOCK:
        return dict(LLM_CALL_STATS)


def reset_llm_call_stats() -> None:
    with _STATS_LOCK:
        LLM_CALL_STATS.update(ok=0, failed=0)


def _invoke_structured(llm, schema_cls, system: str, user: str):
    """Invoke LLM with structured Pydantic output; raise on failure."""
    structured = llm.with_structured_output(
        schema_cls, method=get_settings().llm_structured_method
    )
    try:
        result = structured.invoke(
            [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ]
        )
    except Exception:
        _record_llm_call("failed")
        raise
    _record_llm_call("ok")
    return result


def _invoke_text(llm, system: str, user: str) -> str:
    """Invoke LLM for free-form text; raise on failure."""
    try:
        resp = llm.invoke(
            [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ]
        )
    except Exception:
        _record_llm_call("failed")
        raise
    _record_llm_call("ok")
    return getattr(resp, "content", str(resp))


# ---------------------------------------------------------------------------
# Heuristic parsers (offline / fallback)
# ---------------------------------------------------------------------------

_DEVICE_RE = re.compile(
    r"\b(r[12]|router[-_]?[12]|pe[-_]?\d+|leaf[-_]?\d+|spine[-_]?\d+)\b",
    re.IGNORECASE,
)
_IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
                    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")

_EVENT_PATTERNS: list[tuple[EventType, re.Pattern[str]]] = [
    # Flap / anomaly before generic "bgp ... down" so churn cases classify correctly
    (EventType.BGP_FLAP,
     re.compile(
         r"bgp.*flap|neighbor.*flapping|bgp.*anomal|routing\s*churn|"
         r"announcements?\s*[≈~=]",
         re.I,
     )),
    (EventType.AUTH_FAILURE,
     re.compile(
         r"auth(entication)?\s*fail|failed\s*password|bad\s*password|"
         r"tcp\s*md5|invalid\s*user|digest\s*mismatch",
         re.I,
     )),
    (EventType.BGP_SESSION_DOWN,
     re.compile(r"bgp.*(down|idle|reset|notification|cease)|%BGP-5-ADJCHANGE.*Down", re.I)),
    (EventType.INTERFACE_DOWN,
     re.compile(r"interface.*(down|changed state to down)|%LINEPROTO|%LINK-3-UPDOWN", re.I)),
    (EventType.LINK_FAILURE,
     re.compile(r"link\s*(fail|loss)|carrier\s*lost|bfd.*(down|session)|physical\s+link", re.I)),
    (EventType.OSPF_ADJACENCY_DOWN,
     re.compile(r"ospf.*(down|adjacency|neighbor.*lost|adjchg)", re.I)),
    (EventType.HIGH_CPU,
     re.compile(r"high\s*cpu|cpu\s*(usage|utilization).*(9\d|100)", re.I)),
    (EventType.HIGH_MEMORY,
     re.compile(r"memory\s*(low|exhaust|pressure)|oom", re.I)),
    (EventType.ROUTE_WITHDRAWAL,
     re.compile(r"(route|prefix).{0,48}withdraw", re.I)),
]


def canonicalize_device(name: str) -> str:
    """Normalize hostname spelling to the lab inventory form.

    The LLM and the regex path disagree on separators (`leaf1` vs `leaf-1`),
    which would otherwise show up as a wrong affected node.
    """
    device = (name or "").strip().lower()
    if not device:
        return "unknown"
    device = re.sub(r"^router[-_]?([0-9]+)$", r"r\1", device)
    device = re.sub(r"^(leaf|spine)[-_]?([0-9]+)$", r"\1-\2", device)
    device = re.sub(r"^(pe|p|ce)[-_]([0-9]+)$", r"\1\2", device)
    return device


def heuristic_triage(raw: str) -> TriageResult:
    """Rule-based syslog triage used when LLM is unavailable."""
    device_match = _DEVICE_RE.search(raw)
    device = canonicalize_device(
        device_match.group(1) if device_match else "unknown"
    )

    ip_match = _IP_RE.search(raw)
    device_ip = ip_match.group(0) if ip_match else None

    event_type = EventType.UNKNOWN
    severity = Severity.UNKNOWN
    for et, pattern in _EVENT_PATTERNS:
        if pattern.search(raw):
            event_type = et
            severity = Severity(EVENT_SEVERITY[et.value])
            break

    if event_type == EventType.UNKNOWN:
        severity = Severity.WARNING

    keywords = []
    for token in ("bgp", "ospf", "interface", "eth1", "down", "idle", "flap", "cpu"):
        if token in raw.lower():
            keywords.append(token)

    requires_telemetry = severity in {
        Severity.CRITICAL,
        Severity.MAJOR,
        Severity.WARNING,
    } and event_type != EventType.UNKNOWN and device != "unknown"

    return TriageResult(
        device_name=device,
        device_ip=device_ip,
        event_type=event_type,
        severity=severity,
        summary=raw.strip()[:240] or "Unrecognized syslog event",
        keywords=keywords,
        requires_telemetry=requires_telemetry,
        confidence=0.72 if event_type != EventType.UNKNOWN else 0.35,
    )


# ---------------------------------------------------------------------------
# Agent 1 — Triage
# ---------------------------------------------------------------------------

# Descriptions only; the severity column is generated from EVENT_SEVERITY so the
# prompt can never disagree with the labels the evaluator scores against.
_TAXONOMY_HINTS: dict[str, str] = {
    EventType.BGP_SESSION_DOWN.value: "peer left Established / Idle / Active / hold-timer expiry",
    EventType.INTERFACE_DOWN.value: "port or interface no longer forwarding, admin or oper down",
    EventType.LINK_FAILURE.value: "layer-1 or BFD failure: carrier/light loss, fiber cut, BFD down",
    EventType.BGP_FLAP.value: (
        "repeated session transitions, routing churn, or an announcement/"
        "withdrawal burst reported as a BGP anomaly"
    ),
    EventType.OSPF_ADJACENCY_DOWN.value: "IGP neighbour left FULL, stuck ExStart, dead-timer expiry",
    EventType.HIGH_CPU.value: "sustained control-plane CPU saturation",
    EventType.HIGH_MEMORY.value: "memory exhaustion / OOM / unbounded daemon growth",
    EventType.AUTH_FAILURE.value: "TCP-MD5 or AAA/SSH credential rejection, wrong shared secret",
    EventType.ROUTE_WITHDRAWAL.value: (
        "prefixes gone: withdraw storm, prefix missing from the table, "
        "hijack that blackholes a prefix"
    ),
}


def _taxonomy_table() -> str:
    return "\n".join(
        f"  {EVENT_SEVERITY[event]:<9} {event:<21} {hint}"
        for event, hint in _TAXONOMY_HINTS.items()
    )


TRIAGE_SYSTEM = f"""You are a Tier-1 Telco NOC Triage Agent.

Input is one alarm. It may be a vendor syslog line (FRR, Cisco IOS, JunOS,
SNMP trap) OR a free-text operator note that contains no vendor keywords.
Classify both kinds; never answer `unknown` when the text clearly describes
one of the fault classes below.

Fault taxonomy and the severity each class always carries (ITU-T X.733 style
convention used by this platform — follow it exactly, do not re-judge it):

{_taxonomy_table()}

Disambiguation rules:
  - Classify by the symptom the alarm reports, not by the upstream cause. A
    BGP route leak or hijack therefore splits two ways: when it is reported as
    an anomaly / routing churn with announcement and withdrawal counts it is
    bgp_flap; when it is reported as a withdraw storm or prefixes missing from
    the table it is route_withdrawal. The word "leak" alone decides nothing.
  - bgp_flap requires repetition: several transitions, or an announcement/
    withdrawal burst reported with counts. One prefix withdrawn and then
    re-announced is not a flap — if the origin is unexpected that is a hijack,
    so classify it route_withdrawal.
  - A wrong key or secret is auth_failure, never a link or session fault.
  - "Session bounced N times" is bgp_flap, not bgp_session_down.
  - Fiber/optics/BFD damage is link_failure; an administratively shut port is
    interface_down.
  - Prefix disappearing from a peer's table is route_withdrawal even when the
    session itself is healthy.

Other fields:
  - device_name: the canonical lab hostname exactly as written in the alarm
    (r1, r2, pe1..pe4, leaf-1, leaf-2, spine-1, spine-2). Keep hyphens.
  - device_ip: peer or management IP if present, else null.
  - summary: one sentence, no invented facts.
  - keywords: salient tokens from the alarm.
  - requires_telemetry: true whenever the fault is actionable on a device.
  - confidence: lower it for free-text notes, but still commit to a class.
"""


@traced("agent.triage")
def triage_agent(state: dict[str, Any]) -> dict[str, Any]:
    """Node: consume raw syslog → TriageResult."""
    raw = state.get("raw_syslog") or ""
    if not raw and state.get("syslog_event"):
        raw = state["syslog_event"].get("raw_message", "")

    logger.info("[Triage] processing message len=%d", len(raw))
    llm = _get_llm()
    result: TriageResult

    if llm is not None:
        try:
            result = _invoke_structured(
                llm,
                TriageResult,
                TRIAGE_SYSTEM,
                f"Syslog message:\n{raw}",
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("Triage LLM failed (%s); using heuristic", exc)
            result = heuristic_triage(raw)
    else:
        result = heuristic_triage(raw)

    result.device_name = canonicalize_device(result.device_name)
    event_hostname = str((state.get("syslog_event") or {}).get("hostname") or "").strip()
    if result.device_name == "unknown" and event_hostname:
        result.device_name = canonicalize_device(event_hostname)
        result.requires_telemetry = result.event_type != EventType.UNKNOWN.value

    is_info = result.severity in (Severity.INFO, Severity.INFO.value)
    is_unknown_event = result.event_type in (EventType.UNKNOWN, EventType.UNKNOWN.value)
    route = "continue"
    # Only drop the incident when it is both informational and unclassified —
    # an actionable fault mislabelled `info` must still be investigated.
    if is_info and is_unknown_event:
        route = "abort"
    elif not result.requires_telemetry:
        route = "skip_telemetry"

    return {
        "triage": result.model_dump(mode="json"),
        "current_agent": AgentName.TRIAGE.value,
        "route_decision": route,
        "messages": [f"Triage: {result.event_type} sev={result.severity} device={result.device_name}"],
        "errors": [],
    }


# ---------------------------------------------------------------------------
# Agent 2 — Telemetry
# ---------------------------------------------------------------------------

TELEMETRY_SYSTEM = """You are a Network Telemetry Agent for FRRouting labs.
Given triage context, decide which diagnostic commands matter and summarize health.
You will receive raw CLI outputs — extract BGP state, interface state, anomalies.
"""


@traced("agent.telemetry")
@retry(reraise=True, stop=stop_after_attempt(2), wait=wait_exponential(min=1, max=4))
def telemetry_agent(state: dict[str, Any]) -> dict[str, Any]:
    """Node: gather live device state via diagnostic tools."""
    triage = state.get("triage") or {}
    device = str(triage.get("device_name") or "r1").lower()

    event_type = str(triage.get("event_type") or "")
    logger.info(
        "[Telemetry] collecting event-aware bundle device=%s event=%s",
        device,
        event_type,
    )
    errors: list[str] = []

    try:
        bundle = collect_telemetry_bundle(device, event_type=event_type)
        snapshot = TelemetrySnapshot(
            device_name=device,
            collected_at=datetime.now(timezone.utc),
            commands_executed=bundle.get("commands_executed", []),
            bgp_summary=bundle.get("bgp_summary"),
            interface_status=bundle.get("interface_status"),
            route_table_snippet=bundle.get("route_table_snippet"),
            raw_outputs=bundle.get("raw_outputs", {}),
            collection_errors=bundle.get("collection_errors", []),
            healthy=bundle.get("healthy"),
        )
    except Exception as exc:  # noqa: BLE001
        logger.exception("Telemetry collection failed")
        errors.append(str(exc))
        snapshot = TelemetrySnapshot(
            device_name=device,
            collection_errors=[str(exc)],
            healthy=None,
        )

    # Optional LLM enrichment of health flag
    llm = _get_llm()
    if llm is not None and snapshot.bgp_summary:
        try:
            prompt = (
                f"Triage: {json.dumps(triage)}\n"
                f"BGP Summary:\n{snapshot.bgp_summary}\n"
                f"Interface:\n{snapshot.interface_status}\n"
                "Reply with JSON {\"healthy\": true/false, \"note\": \"...\"} only."
            )
            content = _invoke_text(llm, TELEMETRY_SYSTEM, prompt)
            match = re.search(r"\{.*\}", content, re.S)
            if match:
                parsed = json.loads(match.group(0))
                if "healthy" in parsed:
                    snapshot.healthy = bool(parsed["healthy"])
        except Exception as exc:  # noqa: BLE001
            logger.debug("Telemetry LLM enrichment skipped: %s", exc)

    return {
        "telemetry": snapshot.model_dump(mode="json"),
        "current_agent": AgentName.TELEMETRY.value,
        "messages": [
            f"Telemetry: device={device} healthy={snapshot.healthy} "
            f"cmds={len(snapshot.commands_executed)}"
        ],
        "errors": errors,
    }


# ---------------------------------------------------------------------------
# Agent 3 — RAG
# ---------------------------------------------------------------------------

RAG_SYSTEM = """You are a Telco Knowledge RAG Agent.
Given an alarm triage payload, formulate a precise retrieval query for SOP manuals
and extract actionable remediation steps from retrieved documents.
"""


@traced("agent.rag")
def rag_agent(state: dict[str, Any]) -> dict[str, Any]:
    """Node: retrieve SOP / historical experience from Qdrant."""
    triage = state.get("triage") or {}
    telemetry = state.get("telemetry") or {}
    event_type = triage.get("event_type", "unknown")
    device = triage.get("device_name", "unknown")
    summary = triage.get("summary", "")
    keywords = triage.get("keywords") or []
    healthy = telemetry.get("healthy")
    bgp = (telemetry.get("bgp_summary") or "")[:240]
    iface = (telemetry.get("interface_status") or "")[:160]

    query = (
        f"SOP for {event_type} on device {device}. "
        f"Symptoms: {summary}. Keywords: {', '.join(keywords)}. "
        f"Live telemetry healthy={healthy}. BGP: {bgp}. Interface: {iface}. "
        "Include remediation steps and historical RCA cases."
    )

    logger.info("[RAG] query=%s", query[:120])
    errors: list[str] = []

    try:
        store = get_rag_store()
        result = store.retrieve(query, top_k=5)
    except Exception as exc:  # noqa: BLE001
        logger.exception("RAG retrieval failed")
        errors.append(str(exc))
        result = RAGResult(query=query, documents=[], sop_steps=[], historical_cases=[])

    # Optional LLM post-processing to refine sop_steps
    llm = _get_llm()
    if llm is not None and result.documents:
        try:
            docs_blob = "\n---\n".join(
                f"[{d.title}] {d.content[:600]}" for d in result.documents
            )
            content = _invoke_text(
                llm,
                RAG_SYSTEM,
                (
                    f"Event: {event_type}\nDocuments:\n{docs_blob}\n\n"
                    "List 5 concise remediation steps as a JSON array of strings."
                ),
            )
            match = re.search(r"\[.*\]", content, re.S)
            if match:
                steps = json.loads(match.group(0))
                if isinstance(steps, list) and steps:
                    result.sop_steps = [str(s) for s in steps][:10]
        except Exception as exc:  # noqa: BLE001
            logger.debug("RAG LLM refinement skipped: %s", exc)

    return {
        "rag": result.model_dump(mode="json"),
        "current_agent": AgentName.RAG.value,
        "messages": [
            f"RAG: docs={len(result.documents)} sop_steps={len(result.sop_steps)}"
        ],
        "errors": errors,
    }


# ---------------------------------------------------------------------------
# Agent 4 — RCA Architect
# ---------------------------------------------------------------------------

RCA_SYSTEM = """You are a Principal Network Architect performing Root Cause Analysis.
Synthesize triage, live telemetry, and SOP retrieval into a strict RCA report.
Rules:
  - root_cause must be specific and evidence-based (min 10 chars)
  - root_cause must name, in plain words, the protocol or subsystem that failed
    and the affected element — e.g. "OSPF adjacency to neighbour 10.0.0.2 on
    eth1 is down", "CPU utilization saturated on r1", "prefix 10.20.0.0/16
    withdrawn by the peer". An operator must be able to grep it by fault class.
  - affected_nodes must list real device names, keeping the hostname spelling
    used by triage (r1, pe2, leaf-1, ...)
  - confidence_score in [0,1] reflecting evidence strength
  - remediation_steps must be ordered, actionable, with risk_level
  - Prefer network-layer causes (link down, BGP hold timer, misconfig) over vague guesses
  - If telemetry collection_errors are present and no live output exists, state
    that root cause is unconfirmed, keep confidence_score <= 0.3, and do not
    invent device state
"""


def _heuristic_rca(
    triage: dict[str, Any],
    telemetry: dict[str, Any],
    rag: dict[str, Any],
    incident_id: str,
) -> RCAReport:
    """Deterministic RCA builder for offline / fallback path."""
    event_type = triage.get("event_type", EventType.UNKNOWN.value)
    severity = triage.get("severity", Severity.UNKNOWN.value)
    device = str(triage.get("device_name") or "r1").lower()
    peer = "r2" if device == "r1" else "r1" if device == "r2" else "unknown-peer"

    bgp = (telemetry or {}).get("bgp_summary") or ""
    iface = (telemetry or {}).get("interface_status") or ""
    healthy = (telemetry or {}).get("healthy")
    collection_errors = (telemetry or {}).get("collection_errors") or []
    raw_outputs = (telemetry or {}).get("raw_outputs") or {}
    telemetry_unavailable = bool(collection_errors) and not any(
        value and not str(value).startswith("ERROR:")
        for value in raw_outputs.values()
    )

    if telemetry_unavailable:
        root_cause = (
            f"Telemetry collection failed for {device}; the '{event_type}' alarm "
            "is not yet corroborated by live device evidence."
        )
        confidence = 0.25
        steps = [
            RemediationStep(
                order=1,
                action="Restore diagnostic connectivity and recollect telemetry",
                command="show ip bgp summary",
                risk_level="low",
                expected_outcome="Live CLI evidence is available for RCA",
            ),
            RemediationStep(
                order=2,
                action="Escalate without executing disruptive remediation",
                command=None,
                risk_level="low",
                expected_outcome="Operator validates the alarm before changes",
            ),
        ]
    elif event_type == EventType.INTERFACE_DOWN.value:
        root_cause = (
            f"Physical/data-link failure on {device}:eth1 — interface is DOWN, "
            f"causing eBGP session to {peer} to drop (hold-timer expiry / next-hop unreachable)."
        )
        confidence = 0.88
        steps = [
            RemediationStep(
                order=1,
                action=f"Verify cable/optics and interface admin state on {device} eth1",
                command="show interface eth1",
                risk_level="low",
                expected_outcome="Interface reports UP/UP with carrier",
            ),
            RemediationStep(
                order=2,
                action="Bring interface administratively up if shut",
                command="vtysh -c 'configure terminal' -c 'interface eth1' -c 'no shutdown'",
                risk_level="medium",
                expected_outcome="Interface transitions to UP",
            ),
            RemediationStep(
                order=3,
                action="Confirm BGP neighbor returns to Established",
                command="show ip bgp summary",
                risk_level="low",
                expected_outcome="Neighbor state = Established, prefixes exchanged",
            ),
        ]
    elif event_type in {
        EventType.BGP_SESSION_DOWN.value,
        EventType.BGP_FLAP.value,
    }:
        flap_note = (
            " Repeated session flap / routing anomaly detected."
            if event_type == EventType.BGP_FLAP.value
            else ""
        )
        root_cause = (
            f"eBGP session between {device} and {peer} is not Established "
            f"(observed Idle/Active).{flap_note} Likely causes: underlying link failure, "
            f"TCP 179 blocked, ASN mismatch, or hold-timer expiry after peer unreachable."
        )
        confidence = 0.82 if healthy is False else 0.7
        peer_ip = "192.168.12.2" if device == "r1" else "192.168.12.1"
        steps = [
            RemediationStep(
                order=1,
                action="Check underlay reachability to BGP peer",
                command=f"ping -c 3 {peer_ip}",
                risk_level="low",
                expected_outcome="0% packet loss",
            ),
            RemediationStep(
                order=2,
                action="Inspect BGP neighbor state and last notification",
                command="show ip bgp neighbors",
                risk_level="low",
                expected_outcome="Identify Idle/Active reason code",
            ),
            RemediationStep(
                order=3,
                action="Clear BGP session after underlay restored",
                command=f"vtysh -c 'clear ip bgp {peer_ip}'",
                risk_level="medium",
                expected_outcome="Session renegotiates to Established",
            ),
        ]
    elif event_type == EventType.AUTH_FAILURE.value:
        root_cause = (
            f"Control-plane authentication failure on {device}: TCP-MD5 digest "
            f"mismatch or login auth failure. This is a credential/policy issue, "
            f"not a physical link down."
        )
        confidence = 0.78
        steps = [
            RemediationStep(
                order=1,
                action="Compare BGP TCP-MD5 keys on both peers without logging secrets",
                command="show running-config | include neighbor",
                risk_level="low",
                expected_outcome="Both sides use the same authentication key",
            ),
            RemediationStep(
                order=2,
                action="If SSH/login failure, block abusive sources and restore AAA",
                command=None,
                risk_level="low",
                expected_outcome="Authentication failures stop repeating",
            ),
        ]
    elif event_type == EventType.OSPF_ADJACENCY_DOWN.value:
        root_cause = (
            f"OSPF adjacency down on {device}: neighbor left FULL, typically "
            f"after a link flap, hello/dead mismatch, or area/MTU mismatch."
        )
        confidence = 0.8
        steps = [
            RemediationStep(
                order=1,
                action="Inspect OSPF neighbor and interface MTU/hello timers",
                command="show ip ospf neighbor",
                risk_level="low",
                expected_outcome="Neighbor returns to FULL/DR or FULL/BDR",
            ),
        ]
    elif event_type == EventType.HIGH_CPU.value:
        root_cause = (
            f"Sustained high CPU utilization on {device} — control-plane "
            f"process contention (BGP UPDATE storm, debug left on, or scan)."
        )
        confidence = 0.76
        steps = [
            RemediationStep(
                order=1,
                action="Identify top CPU processes and disable leftover debug",
                command="top -bn1 | head",
                risk_level="low",
                expected_outcome="CPU utilization returns below 80%",
            ),
        ]
    elif event_type == EventType.HIGH_MEMORY.value:
        root_cause = (
            f"Memory pressure / exhaustion on {device}; risk of process restart "
            f"and secondary session reset."
        )
        confidence = 0.74
        steps = [
            RemediationStep(
                order=1,
                action="Inspect memory pools and restart non-critical daemons if needed",
                command="free -m",
                risk_level="medium",
                expected_outcome="Free memory recovers; no OOM kills",
            ),
        ]
    elif event_type == EventType.ROUTE_WITHDRAWAL.value:
        root_cause = (
            f"Prefix / route withdrawal observed on {device} — peer originated "
            f"a withdraw, or an upstream leak/hijack removed reachability."
        )
        confidence = 0.77
        steps = [
            RemediationStep(
                order=1,
                action="Diff RIB/FIB against the previous prefix baseline",
                command="show ip bgp",
                risk_level="low",
                expected_outcome="Withdrawn prefixes and origin AS identified",
            ),
        ]
    elif event_type == EventType.LINK_FAILURE.value:
        root_cause = (
            f"Physical link / BFD session failure on {device}: carrier lost or "
            f"BFD went down, collapsing dependent IGP/BGP adjacencies."
        )
        confidence = 0.86
        steps = [
            RemediationStep(
                order=1,
                action="Check optics, BFD, and far-end interface state",
                command="show interface eth1",
                risk_level="low",
                expected_outcome="Carrier and BFD session restore",
            ),
        ]
    else:
        root_cause = (
            f"Suspected network anomaly on {device} classified as '{event_type}'. "
            f"Telemetry healthy={healthy}; further correlation required."
        )
        confidence = float(triage.get("confidence") or 0.5)
        steps = [
            RemediationStep(
                order=1,
                action="Re-run diagnostic bundle and correlate with recent changes",
                command="show ip bgp summary",
                risk_level="low",
                expected_outcome="Baseline telemetry captured",
            ),
            RemediationStep(
                order=2,
                action="Escalate to Tier-2 with full RCA package if symptom persists",
                command=None,
                risk_level="low",
                expected_outcome="Ticket enriched with evidence",
            ),
        ]

    sop_steps = (rag or {}).get("sop_steps") or []
    for i, sop in enumerate(sop_steps[:2], start=len(steps) + 1):
        steps.append(
            RemediationStep(
                order=i,
                action=sop[:200],
                risk_level="low",
                expected_outcome="Per SOP guidance",
            )
        )

    rag_refs = [
        d.get("title", d.get("source", "sop"))
        for d in ((rag or {}).get("documents") or [])
        if isinstance(d, dict)
    ]

    highlights = []
    if bgp:
        highlights.append(bgp.splitlines()[0][:160])
    if iface:
        highlights.append(iface.splitlines()[0][:160])
    if healthy is not None:
        highlights.append(f"telemetry.healthy={healthy}")

    return RCAReport(
        incident_id=incident_id,
        root_cause=root_cause,
        affected_nodes=[device] + ([peer] if peer.startswith("r") else []),
        confidence_score=confidence,
        remediation_steps=steps,
        event_type=event_type,
        severity=severity,
        evidence_summary=str(triage.get("summary") or "")[:512],
        rag_references=rag_refs,
        telemetry_highlights=highlights,
        next_actions=[
            "Monitor BGP Established state for 15 minutes",
            "Update change window notes if link maintenance is related",
        ],
    )


@traced("agent.rca_architect")
def rca_architect_agent(state: dict[str, Any]) -> dict[str, Any]:
    """Node: synthesize Triage + Telemetry + RAG → RCAReport."""
    triage = state.get("triage") or {}
    telemetry = state.get("telemetry") or {}
    rag = state.get("rag") or {}
    incident_id = state.get("incident_id") or str(uuid4())

    logger.info("[RCA] synthesizing report incident_id=%s", incident_id)
    errors: list[str] = []
    llm = _get_llm()
    report: RCAReport

    if llm is not None:
        try:
            user_payload = {
                "triage": triage,
                "telemetry": {
                    "device_name": telemetry.get("device_name"),
                    "healthy": telemetry.get("healthy"),
                    "bgp_summary": (telemetry.get("bgp_summary") or "")[:2000],
                    "interface_status": (telemetry.get("interface_status") or "")[:2000],
                    "collection_errors": telemetry.get("collection_errors"),
                },
                "rag": {
                    "sop_steps": rag.get("sop_steps"),
                    "historical_cases": rag.get("historical_cases"),
                    "documents": [
                        {"title": d.get("title"), "score": d.get("score"),
                         "content": (d.get("content") or "")[:800]}
                        for d in (rag.get("documents") or [])[:4]
                        if isinstance(d, dict)
                    ],
                },
                "incident_id": incident_id,
            }
            report = _invoke_structured(
                llm,
                RCAReport,
                RCA_SYSTEM,
                json.dumps(user_payload, ensure_ascii=False),
            )
            # Ensure incident_id preserved
            if not report.incident_id:
                report.incident_id = incident_id
        except Exception as exc:  # noqa: BLE001
            logger.warning("RCA LLM failed (%s); using heuristic", exc)
            errors.append(f"rca_llm_fallback: {exc}")
            report = _heuristic_rca(triage, telemetry, rag, incident_id)
    else:
        report = _heuristic_rca(triage, telemetry, rag, incident_id)

    docs = (rag or {}).get("documents") or []
    collection_errors = (telemetry or {}).get("collection_errors") or []
    already_retried = int(state.get("retry_count") or 0) >= 1
    evidence_gap = (not already_retried) and (
        report.confidence_score < 0.4 or not docs or bool(collection_errors)
    )

    return {
        "rca_report": report.model_dump(mode="json"),
        "current_agent": AgentName.RCA.value,
        "incident_id": report.incident_id,
        "evidence_gap": evidence_gap,
        "retry_count": int(state.get("retry_count") or 0) + (1 if evidence_gap else 0),
        "messages": [
            f"RCA: confidence={report.confidence_score:.2f} "
            f"nodes={report.affected_nodes} cause={report.root_cause[:80]}..."
        ],
        "errors": errors,
    }
