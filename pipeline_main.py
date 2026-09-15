#!/usr/bin/env python3
"""
Telco Multi-Agent AIOps Platform — main pipeline entrypoint.

Flow
----
  UDP Syslog (default :5514)
        │
        ▼
  Redis Streams  (telco:syslog:events)
        │
        ▼
  Consumer loop → LangGraph Multi-Agent (Triage → Telemetry → RAG → RCA)
        │
        ▼
  Structured RCA JSON (stdout / lab/reports/)

Usage
-----
  # Bootstrap infra + knowledge, then run the full pipeline
  python pipeline_main.py serve

  # One-shot diagnosis from a raw syslog string (no UDP needed)
  python pipeline_main.py diagnose --message "%BGP-5-ADJCHANGE: neighbor 192.168.12.2 Down"

  # Ingest SOPs into Qdrant only
  python pipeline_main.py ingest-sops

  # Inject a synthetic syslog into Redis (for integration tests)
  python pipeline_main.py inject-syslog --message "..."

  # Score against golden cases (accuracy report)
  OFFLINE_MODE=true python pipeline_main.py evaluate --triage-only
"""

from __future__ import annotations

import json
import logging
import re
import signal
import socketserver
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from uuid import uuid4

import structlog
import typer
from rich.console import Console
from rich.json import JSON as RichJSON
from rich.panel import Panel

from config import PROJECT_ROOT, get_settings
from graph import pretty_rca, run_incident
from observability import init_observability
from redis_bus import RedisStreamBus
from schema import SyslogEvent
from vector_rag import get_rag_store

app = typer.Typer(
    name="telco-aiops",
    help="Telco Multi-Agent AIOps Platform CLI",
    add_completion=False,
    no_args_is_help=True,
)
console = Console()
logger = structlog.get_logger(__name__)

REPORTS_DIR = PROJECT_ROOT / "lab" / "reports"
_SHUTDOWN = threading.Event()


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------


def configure_logging(level: str = "INFO") -> None:
    logging.basicConfig(
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
        level=getattr(logging, level.upper(), logging.INFO),
        stream=sys.stdout,
    )
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.dev.ConsoleRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, level.upper(), logging.INFO)
        ),
        cache_logger_on_first_use=True,
    )


# ---------------------------------------------------------------------------
# Syslog UDP receiver
# ---------------------------------------------------------------------------

# RFC 3164 / lightly RFC 5424 tolerant
_SYSLOG_RE = re.compile(
    r"^<(?P<pri>\d{1,3})>"
    r"(?P<body>.*)$",
    re.DOTALL,
)


def parse_syslog_datagram(data: bytes, source_ip: str) -> SyslogEvent:
    """Parse a UDP syslog datagram into a SyslogEvent."""
    text = data.decode("utf-8", errors="replace").strip()
    facility: Optional[int] = None
    severity_code: Optional[int] = None
    hostname: Optional[str] = None
    body = text

    match = _SYSLOG_RE.match(text)
    if match:
        pri = int(match.group("pri"))
        facility = pri // 8
        severity_code = pri % 8
        body = match.group("body").strip()

    # Heuristic hostname extraction (second token often)
    tokens = body.split()
    if len(tokens) >= 2 and not tokens[0].isdigit():
        # skip timestamp-ish first token(s)
        for tok in tokens[:4]:
            if re.match(r"^[A-Za-z][\w\-.]+$", tok) and tok.lower() not in {
                "jan", "feb", "mar", "apr", "may", "jun",
                "jul", "aug", "sep", "oct", "nov", "dec",
            }:
                hostname = tok
                break

    return SyslogEvent(
        event_id=str(uuid4()),
        raw_message=body or text,
        source_ip=source_ip,
        facility=facility,
        severity_code=severity_code,
        hostname=hostname,
        received_at=datetime.now(timezone.utc),
    )


class _SyslogUDPHandler(socketserver.BaseRequestHandler):
    """UDP handler that publishes every datagram onto Redis Streams."""

    bus: RedisStreamBus  # injected on server

    def handle(self) -> None:
        data = self.request[0]
        source_ip = self.client_address[0]
        try:
            event = parse_syslog_datagram(data, source_ip)
            self.bus.publish_syslog(event)
            logger.info(
                "syslog_received",
                event_id=event.event_id,
                source_ip=source_ip,
                preview=event.raw_message[:80],
            )
        except Exception as exc:  # noqa: BLE001
            logger.exception("syslog_handler_error", error=str(exc))


class SyslogUDPServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True


def start_syslog_server(bus: RedisStreamBus) -> SyslogUDPServer:
    settings = get_settings()
    _SyslogUDPHandler.bus = bus
    server = SyslogUDPServer(
        (settings.syslog_bind_host, settings.syslog_bind_port),
        _SyslogUDPHandler,
    )
    thread = threading.Thread(
        target=server.serve_forever,
        name="syslog-udp",
        daemon=True,
    )
    thread.start()
    console.print(
        f"[bold green]✓[/] Syslog UDP listening on "
        f"{settings.syslog_bind_host}:{settings.syslog_bind_port}"
    )
    return server


# ---------------------------------------------------------------------------
# Consumer → LangGraph
# ---------------------------------------------------------------------------


def persist_report(state: dict, incident_id: str) -> Path:
    """Write RCA JSON to lab/reports/."""
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    path = REPORTS_DIR / f"rca_{incident_id}.json"
    payload = {
        "incident_id": incident_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "rca_report": state.get("rca_report"),
        "triage": state.get("triage"),
        "telemetry": state.get("telemetry"),
        "rag": {
            "query": (state.get("rag") or {}).get("query"),
            "doc_count": len((state.get("rag") or {}).get("documents") or []),
            "sop_steps": (state.get("rag") or {}).get("sop_steps"),
        },
        "messages": state.get("messages"),
        "errors": state.get("errors"),
    }
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    return path


def process_event(event: SyslogEvent) -> dict:
    """Run the Multi-Agent graph for one SyslogEvent and persist the report."""
    state = run_incident(
        raw_syslog=event.raw_message,
        syslog_event=event.model_dump(mode="json"),
        incident_id=event.event_id,
        thread_id=f"syslog-{event.event_id}",
    )
    path = persist_report(state, event.event_id)
    console.print(
        Panel(
            RichJSON(pretty_rca(state)),
            title=f"RCA Report — {event.event_id}",
            border_style="cyan",
        )
    )
    console.print(f"[dim]saved → {path}[/]")
    return state


def consumer_loop(bus: RedisStreamBus) -> None:
    """Blocking loop: XREADGROUP → LangGraph → XACK."""
    bus.ensure_consumer_group()
    console.print("[bold green]✓[/] Redis consumer loop started")

    def _process_entry(entry_id: str, fields: dict[str, str]) -> None:
        try:
            event = bus._fields_to_event(fields)
            process_event(event)
            bus.ack(entry_id)
        except Exception as exc:  # noqa: BLE001
            attempts = bus.delivery_attempts(entry_id)
            logger.exception(
                "event_processing_failed",
                entry_id=entry_id,
                delivery_attempts=attempts,
                error=str(exc),
            )
            if attempts >= bus.settings.redis_max_delivery_attempts:
                bus.dead_letter(
                    entry_id,
                    fields,
                    error=str(exc),
                    delivery_attempts=attempts,
                )
            else:
                logger.warning(
                    "event_left_pending_for_retry",
                    entry_id=entry_id,
                    delivery_attempts=attempts,
                )

    while not _SHUTDOWN.is_set():
        try:
            # Recover events abandoned by dead workers before reading new ones.
            batch = bus.claim_stale()
            if not batch:
                batch = bus.consume()
            if not batch:
                continue
            for entry_id, fields in batch:
                _process_entry(entry_id, fields)
        except Exception as exc:  # noqa: BLE001
            logger.exception("consumer_loop_error", error=str(exc))
            _SHUTDOWN.wait(2.0)


# ---------------------------------------------------------------------------
# Bootstrap helpers
# ---------------------------------------------------------------------------


def bootstrap_knowledge() -> None:
    """Ensure Qdrant collection exists and SOPs are ingested."""
    store = get_rag_store()
    store.ensure_collection()
    count = store.ingest_directory()
    console.print(f"[bold green]✓[/] Qdrant SOP ingest complete ({count} chunks)")


def _install_signal_handlers(server: SyslogUDPServer | None = None) -> None:
    def _handler(signum, frame):  # noqa: ANN001, ARG001
        console.print("\n[yellow]Shutting down…[/]")
        _SHUTDOWN.set()
        if server is not None:
            server.shutdown()

    signal.signal(signal.SIGINT, _handler)
    signal.signal(signal.SIGTERM, _handler)


# ---------------------------------------------------------------------------
# CLI commands
# ---------------------------------------------------------------------------


@app.command("ingest-sops")
def cmd_ingest_sops() -> None:
    """Initialize Qdrant and ingest knowledge/sops/*.md."""
    configure_logging(get_settings().log_level)
    init_observability()
    bootstrap_knowledge()


@app.command("inject-syslog")
def cmd_inject_syslog(
    message: str = typer.Option(
        ...,
        "--message",
        "-m",
        help="Raw syslog body to publish onto Redis Streams",
    ),
    source_ip: str = typer.Option("127.0.0.1", "--source-ip"),
) -> None:
    """Publish a synthetic syslog event into Redis (does not run the graph)."""
    configure_logging(get_settings().log_level)
    bus = RedisStreamBus()
    bus.ensure_consumer_group()
    stream_id, event = bus.publish_raw(message, source_ip=source_ip)
    console.print(f"[green]Published[/] stream_id={stream_id} event_id={event.event_id}")
    bus.close()


@app.command("diagnose")
def cmd_diagnose(
    message: str = typer.Option(
        ...,
        "--message",
        "-m",
        help="Raw syslog message to diagnose immediately",
    ),
    ingest: bool = typer.Option(
        True,
        "--ingest/--no-ingest",
        help="Ingest SOP knowledge before diagnosis",
    ),
) -> None:
    """One-shot Multi-Agent diagnosis (bypasses UDP / Redis consumer)."""
    settings = get_settings()
    configure_logging(settings.log_level)
    init_observability()
    if ingest:
        try:
            bootstrap_knowledge()
        except Exception as exc:  # noqa: BLE001
            console.print(f"[yellow]SOP ingest skipped:[/] {exc}")

    event = SyslogEvent(raw_message=message, source_ip="cli")
    process_event(event)


@app.command("serve")
def cmd_serve(
    ingest: bool = typer.Option(True, "--ingest/--no-ingest"),
    skip_syslog: bool = typer.Option(
        False,
        "--skip-syslog",
        help="Only run Redis consumer (no UDP listener)",
    ),
) -> None:
    """
    Start the full pipeline: Syslog UDP → Redis Streams → Multi-Agent consumer.
    """
    settings = get_settings()
    configure_logging(settings.log_level)
    init_observability()

    console.print(
        Panel.fit(
            f"[bold]{settings.app_name}[/]\n"
            f"env={settings.app_env}  offline={settings.is_offline()}\n"
            f"redis={settings.redis_url}\n"
            f"qdrant={settings.qdrant_url}",
            title="Telco Multi-Agent AIOps",
            border_style="blue",
        )
    )

    if ingest:
        try:
            bootstrap_knowledge()
        except Exception as exc:  # noqa: BLE001
            console.print(f"[yellow]Warning:[/] SOP ingest failed: {exc}")

    bus = RedisStreamBus()
    bus.ensure_consumer_group()

    server: SyslogUDPServer | None = None
    if not skip_syslog:
        server = start_syslog_server(bus)

    _install_signal_handlers(server)
    try:
        consumer_loop(bus)
    finally:
        if server is not None:
            server.shutdown()
            server.server_close()
        bus.close()
        console.print("[bold]Bye.[/]")


@app.command("evaluate")
def cmd_evaluate(
    golden: Path = typer.Option(
        PROJECT_ROOT / "datasets" / "eval" / "golden_cases.jsonl",
        "--golden",
        "-g",
    ),
    triage_only: bool = typer.Option(
        False,
        "--triage-only",
        help="Only score Triage (faster)",
    ),
    limit: Optional[int] = typer.Option(None, "--limit", "-n"),
    category: Optional[str] = typer.Option(None, "--category", "-c"),
    ingest: bool = typer.Option(False, "--ingest/--no-ingest"),
    single_agent: bool = typer.Option(False, "--single-agent"),
    rag_only: bool = typer.Option(False, "--rag-only"),
    ablation: bool = typer.Option(False, "--ablation"),
    sample: Optional[int] = typer.Option(None, "--sample"),
    seed: int = typer.Option(7, "--seed"),
) -> None:
    """Score the pipeline against golden_cases.jsonl and print accuracy."""
    from eval_runner import run_ablation, run_evaluation

    if ablation:
        compare = run_ablation(
            golden=golden,
            limit=limit,
            category=category,
            ingest=ingest,
            sample=sample,
            seed=seed,
        )
        if compare["multi_agent"]["accuracy"] < 0.70:
            raise typer.Exit(code=1)
        return

    method = "multi_agent"
    if triage_only:
        method = "rule_only"
    elif single_agent:
        method = "single_agent"
    elif rag_only:
        method = "rag_only"
    report = run_evaluation(
        golden=golden,
        method=method,
        limit=limit,
        category=category,
        ingest=ingest,
        sample=sample,
        seed=seed,
    )
    if report.accuracy < 0.70:
        raise typer.Exit(code=1)


@app.command("demo")
def cmd_demo() -> None:
    """
    End-to-end lab demo: ingest SOPs, inject a BGP-down syslog, run diagnosis.
    """
    settings = get_settings()
    configure_logging(settings.log_level)
    init_observability()

    try:
        bootstrap_knowledge()
    except Exception as exc:  # noqa: BLE001
        console.print(f"[yellow]SOP ingest skipped:[/] {exc}")

    sample = (
        "<166>Jul 30 12:00:01 r1 bgpd[42]: "
        "%BGP-5-ADJCHANGE: neighbor 192.168.12.2 Down - "
        "Peer closed the session / Interface eth1 down"
    )
    console.print(f"[cyan]Demo syslog:[/] {sample}")

    # Also publish to Redis for observability
    try:
        bus = RedisStreamBus()
        bus.ensure_consumer_group()
        bus.publish_raw(sample, source_ip="127.0.0.1")
        bus.close()
    except Exception as exc:  # noqa: BLE001
        console.print(f"[yellow]Redis publish skipped:[/] {exc}")

    event = SyslogEvent(raw_message=sample, source_ip="demo", hostname="r1")
    process_event(event)


if __name__ == "__main__":
    app()
