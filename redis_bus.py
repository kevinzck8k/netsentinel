"""
Redis Streams message bus — decouples syslog ingest from Multi-Agent consumers.

Stream layout
-------------
  Key:   telco:syslog:events   (configurable)
  Fields:
    event_id, raw_message, source_ip, received_at, facility, severity_code
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Iterator
from uuid import uuid4

import redis
from redis.exceptions import ResponseError
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from config import Settings, get_settings
from schema import SyslogEvent

logger = logging.getLogger(__name__)


class RedisStreamBus:
    """Production-oriented Redis Streams producer / consumer wrapper."""

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self._client: redis.Redis | None = None

    # ------------------------------------------------------------------
    # Connection lifecycle
    # ------------------------------------------------------------------

    @retry(
        reraise=True,
        stop=stop_after_attempt(5),
        wait=wait_exponential(multiplier=0.5, min=0.5, max=8),
        retry=retry_if_exception_type((redis.ConnectionError, redis.TimeoutError)),
    )
    def connect(self) -> redis.Redis:
        """Establish (or re-establish) a Redis connection with retry."""
        if self._client is not None:
            try:
                self._client.ping()
                return self._client
            except redis.RedisError:
                self._client = None

        self._client = redis.Redis.from_url(
            self.settings.redis_url,
            decode_responses=True,
            socket_connect_timeout=5,
            socket_timeout=10,
            health_check_interval=30,
        )
        self._client.ping()
        logger.info("Connected to Redis at %s", self.settings.redis_url)
        return self._client

    @property
    def client(self) -> redis.Redis:
        if self._client is None:
            return self.connect()
        return self._client

    def close(self) -> None:
        if self._client is not None:
            try:
                self._client.close()
            except Exception:  # noqa: BLE001
                pass
            self._client = None

    # ------------------------------------------------------------------
    # Consumer group bootstrap
    # ------------------------------------------------------------------

    def ensure_consumer_group(self) -> None:
        """Create the stream + consumer group if they do not yet exist."""
        client = self.connect()
        stream = self.settings.redis_stream_key
        group = self.settings.redis_consumer_group
        try:
            client.xgroup_create(stream, group, id="0", mkstream=True)
            logger.info("Created consumer group '%s' on stream '%s'", group, stream)
        except ResponseError as exc:
            if "BUSYGROUP" in str(exc):
                logger.debug("Consumer group '%s' already exists", group)
            else:
                raise

    # ------------------------------------------------------------------
    # Produce
    # ------------------------------------------------------------------

    def publish_syslog(self, event: SyslogEvent) -> str:
        """
        XADD a SyslogEvent onto the stream.

        Returns the Redis stream entry ID.
        """
        payload = {
            "event_id": event.event_id,
            "raw_message": event.raw_message,
            "source_ip": event.source_ip or "",
            "received_at": event.received_at.isoformat(),
            "facility": str(event.facility) if event.facility is not None else "",
            "severity_code": (
                str(event.severity_code) if event.severity_code is not None else ""
            ),
            "hostname": event.hostname or "",
            "app_name": event.app_name or "",
        }
        entry_id = self.client.xadd(
            self.settings.redis_stream_key,
            payload,
            maxlen=self.settings.redis_stream_maxlen,
            approximate=False,
        )
        logger.info(
            "Published syslog event_id=%s stream_id=%s", event.event_id, entry_id
        )
        return str(entry_id)

    def publish_raw(
        self,
        raw_message: str,
        *,
        source_ip: str | None = None,
    ) -> tuple[str, SyslogEvent]:
        """Convenience helper: wrap a raw string and publish."""
        event = SyslogEvent(
            event_id=str(uuid4()),
            raw_message=raw_message,
            source_ip=source_ip,
            received_at=datetime.now(timezone.utc),
        )
        stream_id = self.publish_syslog(event)
        return stream_id, event

    # ------------------------------------------------------------------
    # Consume
    # ------------------------------------------------------------------

    def consume(
        self,
        *,
        count: int | None = None,
        block_ms: int | None = None,
    ) -> list[tuple[str, dict[str, str]]]:
        """
        XREADGROUP from the consumer group.

        Returns a list of (stream_entry_id, field_dict) tuples.
        """
        self.ensure_consumer_group()
        count = count or self.settings.redis_batch_size
        block_ms = block_ms if block_ms is not None else self.settings.redis_block_ms

        results = self.client.xreadgroup(
            groupname=self.settings.redis_consumer_group,
            consumername=self.settings.redis_consumer_name,
            streams={self.settings.redis_stream_key: ">"},
            count=count,
            block=block_ms,
        )
        if not results:
            return []

        entries: list[tuple[str, dict[str, str]]] = []
        for _stream_name, messages in results:
            for entry_id, fields in messages:
                entries.append((entry_id, fields))
        return entries

    def claim_stale(
        self,
        *,
        count: int | None = None,
    ) -> list[tuple[str, dict[str, str]]]:
        """Reclaim messages left pending by crashed or stalled consumers."""
        self.ensure_consumer_group()
        result = self.client.xautoclaim(
            name=self.settings.redis_stream_key,
            groupname=self.settings.redis_consumer_group,
            consumername=self.settings.redis_consumer_name,
            min_idle_time=self.settings.redis_pending_idle_ms,
            start_id="0-0",
            count=count or self.settings.redis_batch_size,
        )
        if len(result) < 2:
            return []
        return [(entry_id, fields) for entry_id, fields in result[1]]

    def delivery_attempts(self, entry_id: str) -> int:
        """Return Redis' delivery count for a pending stream entry."""
        pending = self.client.xpending_range(
            name=self.settings.redis_stream_key,
            groupname=self.settings.redis_consumer_group,
            min=entry_id,
            max=entry_id,
            count=1,
        )
        if not pending:
            return 0
        return int(pending[0].get("times_delivered", 1))

    def dead_letter(
        self,
        entry_id: str,
        fields: dict[str, Any],
        *,
        error: str,
        delivery_attempts: int,
    ) -> str:
        """Atomically-ish copy a failed event to DLQ, then acknowledge it."""
        payload = {
            **{str(key): str(value) for key, value in fields.items()},
            "original_entry_id": entry_id,
            "failed_at": datetime.now(timezone.utc).isoformat(),
            "error": error[:2_000],
            "delivery_attempts": str(delivery_attempts),
        }
        dlq_id = self.client.xadd(
            self.settings.redis_dlq_stream_key,
            payload,
            maxlen=100_000,
            approximate=False,
        )
        self.ack(entry_id)
        logger.error(
            "Moved stream entry %s to DLQ %s after %d attempts",
            entry_id,
            dlq_id,
            delivery_attempts,
        )
        return str(dlq_id)

    def ack(self, entry_id: str) -> None:
        """Acknowledge a successfully processed stream entry."""
        self.client.xack(
            self.settings.redis_stream_key,
            self.settings.redis_consumer_group,
            entry_id,
        )

    def iter_events(self) -> Iterator[tuple[str, SyslogEvent]]:
        """Infinite generator yielding (entry_id, SyslogEvent)."""
        while True:
            batch = self.consume()
            for entry_id, fields in batch:
                try:
                    event = self._fields_to_event(fields)
                    yield entry_id, event
                except Exception as exc:  # noqa: BLE001
                    logger.exception("Failed to decode stream entry %s: %s", entry_id, exc)
                    self.ack(entry_id)

    @staticmethod
    def _fields_to_event(fields: dict[str, Any]) -> SyslogEvent:
        received_at_raw = fields.get("received_at") or ""
        try:
            received_at = datetime.fromisoformat(received_at_raw)
        except ValueError:
            received_at = datetime.now(timezone.utc)

        facility = fields.get("facility") or None
        severity_code = fields.get("severity_code") or None

        return SyslogEvent(
            event_id=fields.get("event_id") or str(uuid4()),
            raw_message=fields.get("raw_message") or "",
            source_ip=fields.get("source_ip") or None,
            received_at=received_at,
            facility=int(facility) if facility else None,
            severity_code=int(severity_code) if severity_code else None,
            hostname=fields.get("hostname") or None,
            app_name=fields.get("app_name") or None,
        )

    def stream_info(self) -> dict[str, Any]:
        """Return XINFO STREAM for operational dashboards."""
        try:
            info = self.client.xinfo_stream(self.settings.redis_stream_key)
            return dict(info) if info else {}
        except ResponseError:
            return {"length": 0, "status": "stream_missing"}


def dump_event_json(event: SyslogEvent) -> str:
    """Serialize a SyslogEvent for logging / debug."""
    return json.dumps(event.model_dump(mode="json"), ensure_ascii=False)
