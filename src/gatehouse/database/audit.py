"""Bounded, batchable, redacting audit-event writer."""

from __future__ import annotations

import json
import sqlite3
import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass
from typing import Any

from gatehouse.credentials.redaction import SecretScanner

from .connection import transaction


class AuditBufferFullError(RuntimeError):
    """Audit backpressure is explicit; security events are never silently dropped."""


@dataclass(frozen=True, slots=True)
class AuditEvent:
    event_id: str
    occurred_at_ms: int
    event_type: str
    severity: str
    payload_json: str
    session_id: str | None = None
    root_run_id: str | None = None
    request_id: str | None = None
    attempt_id: str | None = None
    service_id: str | None = None
    operation: str | None = None
    preserve: bool = False


class BoundedAuditWriter:
    """Accumulate a bounded batch and commit it in one short transaction."""

    def __init__(
        self,
        *,
        capacity: int = 1_000,
        default_batch_size: int = 100,
        scanner: SecretScanner | None = None,
    ) -> None:
        if capacity <= 0:
            raise ValueError("audit buffer capacity must be positive")
        if default_batch_size <= 0 or default_batch_size > capacity:
            raise ValueError("default batch size must be within the buffer capacity")
        self._capacity = capacity
        self._default_batch_size = default_batch_size
        self._scanner = scanner or SecretScanner()
        self._events: deque[AuditEvent] = deque()
        self._lock = threading.Lock()

    @property
    def pending_count(self) -> int:
        with self._lock:
            return len(self._events)

    @property
    def capacity(self) -> int:
        return self._capacity

    def emit(
        self,
        event_type: str,
        severity: str,
        payload: dict[str, Any] | None = None,
        *,
        occurred_at_ms: int | None = None,
        event_id: str | None = None,
        session_id: str | None = None,
        root_run_id: str | None = None,
        request_id: str | None = None,
        attempt_id: str | None = None,
        service_id: str | None = None,
        operation: str | None = None,
        preserve: bool = False,
    ) -> str:
        if not event_type or not severity:
            raise ValueError("event_type and severity are required")
        sanitized = self._scanner.sanitize(payload or {})
        payload_json = json.dumps(sanitized, sort_keys=True, separators=(",", ":"))
        self._scanner.assert_clean(payload_json, location="audit payload")
        identifier = event_id or f"evt_{uuid.uuid4().hex}"
        event = AuditEvent(
            event_id=identifier,
            occurred_at_ms=(int(time.time() * 1_000) if occurred_at_ms is None else occurred_at_ms),
            event_type=event_type,
            severity=severity,
            payload_json=payload_json,
            session_id=session_id,
            root_run_id=root_run_id,
            request_id=request_id,
            attempt_id=attempt_id,
            service_id=service_id,
            operation=operation,
            preserve=preserve,
        )
        with self._lock:
            if len(self._events) >= self._capacity:
                raise AuditBufferFullError(
                    f"audit buffer reached its bounded capacity of {self._capacity}"
                )
            self._events.append(event)
        return identifier

    def flush(
        self,
        connection: sqlite3.Connection,
        *,
        maximum_events: int | None = None,
    ) -> int:
        batch_limit = self._default_batch_size if maximum_events is None else maximum_events
        if batch_limit <= 0:
            raise ValueError("maximum_events must be positive")

        with self._lock:
            batch = tuple(list(self._events)[:batch_limit])
            if not batch:
                return 0
            with transaction(connection, "IMMEDIATE"):
                connection.executemany(
                    """
                    INSERT INTO audit_events(
                        event_id, occurred_at_ms, event_type, severity,
                        session_id, root_run_id, request_id, attempt_id,
                        service_id, operation, preserve, payload_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    [
                        (
                            event.event_id,
                            event.occurred_at_ms,
                            event.event_type,
                            event.severity,
                            event.session_id,
                            event.root_run_id,
                            event.request_id,
                            event.attempt_id,
                            event.service_id,
                            event.operation,
                            int(event.preserve),
                            event.payload_json,
                        )
                        for event in batch
                    ],
                )
            for _ in batch:
                self._events.popleft()
            return len(batch)
