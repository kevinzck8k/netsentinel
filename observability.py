"""
OpenTelemetry + Traceloop observability bootstrap.

Provides:
  - init_observability()  — call once at process start
  - traced()              — decorator for tool / agent spans
  - get_tracer()          — module-level tracer accessor
"""

from __future__ import annotations

import functools
import logging
from typing import Any, Callable, ParamSpec, TypeVar

from opentelemetry import trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter
from opentelemetry.trace import Status, StatusCode

from config import get_settings

logger = logging.getLogger(__name__)

P = ParamSpec("P")
R = TypeVar("R")

_INITIALIZED = False
_TRACER_NAME = "telco.aiops"


def init_observability() -> None:
    """
    Initialize OTel TracerProvider and optionally Traceloop / OTLP export.

    Safe to call multiple times; subsequent calls are no-ops.
    """
    global _INITIALIZED
    if _INITIALIZED:
        return

    settings = get_settings()
    if not settings.otel_enabled:
        logger.info("OpenTelemetry disabled via settings")
        _INITIALIZED = True
        return

    resource = Resource.create(
        {
            "service.name": settings.otel_service_name,
            "service.namespace": "telco-aiops",
            "deployment.environment": settings.app_env,
        }
    )
    provider = TracerProvider(resource=resource)

    # Console exporter — opt-in to avoid drowning CLI demos in span JSON.
    import os

    if os.getenv("OTEL_CONSOLE_EXPORTER", "").lower() in {"1", "true", "yes"}:
        provider.add_span_processor(BatchSpanProcessor(ConsoleSpanExporter()))
        logger.info("OTel console span exporter enabled")

    # Optional OTLP HTTP exporter (Jaeger / Tempo / Grafana Alloy).
    # Lab default skips OTLP unless forced — avoids connection-refused noise.
    force_otlp = os.getenv("OTEL_EXPORTER_OTLP_FORCE", "").lower() in {
        "1",
        "true",
        "yes",
    }
    if force_otlp or settings.app_env != "lab":
        try:
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
                OTLPSpanExporter,
            )

            otlp = OTLPSpanExporter(
                endpoint=f"{settings.otel_exporter_endpoint}/v1/traces"
            )
            provider.add_span_processor(BatchSpanProcessor(otlp))
            logger.info(
                "OTLP exporter configured → %s", settings.otel_exporter_endpoint
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("OTLP exporter unavailable: %s", exc)
    else:
        logger.info(
            "OTLP exporter skipped in lab mode "
            "(set OTEL_EXPORTER_OTLP_FORCE=true to enable)"
        )

    trace.set_tracer_provider(provider)

    # Optional Traceloop (LLM-aware instrumentation).
    try:
        api_key = settings.traceloop_api_key.get_secret_value().strip()
        if api_key:
            from traceloop.sdk import Traceloop

            Traceloop.init(
                app_name=settings.otel_service_name,
                api_key=api_key,
                disable_batch=settings.app_env == "lab",
            )
            logger.info("Traceloop SDK initialized")
    except Exception as exc:  # noqa: BLE001
        logger.warning("Traceloop init skipped: %s", exc)

    _INITIALIZED = True
    logger.info("Observability stack ready")


def get_tracer() -> trace.Tracer:
    """Return the shared tracer (no-op provider if OTel not initialized)."""
    return trace.get_tracer(_TRACER_NAME)


def traced(
    name: str | None = None,
    *,
    attributes: dict[str, Any] | None = None,
) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """
    Decorator that wraps a function in an OpenTelemetry span.

    Usage::

        @traced("netmiko.show_ip_bgp")
        def show_ip_bgp(device: str) -> str: ...
    """

    def decorator(fn: Callable[P, R]) -> Callable[P, R]:
        span_name = name or f"{fn.__module__}.{fn.__qualname__}"

        @functools.wraps(fn)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            tracer = get_tracer()
            with tracer.start_as_current_span(span_name) as span:
                if attributes:
                    for k, v in attributes.items():
                        span.set_attribute(k, str(v))
                # Capture first string-ish positional arg as device hint.
                if args and isinstance(args[0], str):
                    span.set_attribute("aiops.device", args[0])
                try:
                    result = fn(*args, **kwargs)
                    span.set_status(Status(StatusCode.OK))
                    return result
                except Exception as exc:
                    span.record_exception(exc)
                    span.set_status(Status(StatusCode.ERROR, str(exc)))
                    raise

        return wrapper

    return decorator
