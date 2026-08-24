"""Best-effort user-session notifications with no approval authority."""

from __future__ import annotations

import os
import queue
import sys
import threading
from collections import OrderedDict
from collections.abc import Callable
from typing import Annotated, Literal, Protocol
from urllib.parse import urlsplit, urlunsplit

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator


class NotificationEvent(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    kind: Literal["approval_required", "incident"]
    requesting_client: Annotated[str, Field(min_length=1, max_length=160)]
    service: Annotated[str, Field(min_length=1, max_length=64)]
    operation: Annotated[str, Field(min_length=1, max_length=64)]
    cost_ceiling: Annotated[int | None, Field(ge=0)] = None
    expires_at_ms: Annotated[int | None, Field(ge=0)] = None
    severity: Annotated[str | None, Field(max_length=32)] = None
    dashboard_url: Annotated[str, Field(min_length=28, max_length=32)]

    @field_validator("dashboard_url")
    @classmethod
    def _fixed_numeric_loopback_dashboard(cls, value: str) -> str:
        try:
            parsed = urlsplit(value)
            port = parsed.port
        except ValueError as error:
            raise ValueError("notification dashboard URL is invalid") from error
        if (
            parsed.scheme.casefold() != "http"
            or parsed.hostname != "127.0.0.1"
            or port is None
            or not 1 <= port <= 65_535
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path != "/dashboard"
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError(
                "notification dashboard URL must be a fixed numeric loopback dashboard"
            )
        return urlunsplit(("http", f"127.0.0.1:{port}", "/dashboard", "", ""))


class ApprovalPendingSignal(BaseModel):
    """Secret-free identity for a new durable approval awaiting local action."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    approval_id: Annotated[
        str,
        Field(min_length=1, max_length=160, pattern=r"^[A-Za-z0-9_.:-]+$"),
    ]
    request_id: Annotated[
        str,
        Field(
            min_length=30,
            max_length=30,
            pattern=r"^req_[0-7][0-9A-HJKMNP-TV-Z]{25}$",
        ),
    ]
    session_id: Annotated[
        str,
        Field(min_length=1, max_length=160, pattern=r"^[A-Za-z0-9_.:-]+$"),
    ]
    root_run_id: Annotated[
        str,
        Field(min_length=1, max_length=160, pattern=r"^[A-Za-z0-9_.:-]+$"),
    ]
    client_id: Annotated[
        str,
        Field(min_length=1, max_length=160, pattern=r"^[A-Za-z0-9_.:-]+$"),
    ]
    workspace_id: Annotated[
        str,
        Field(min_length=1, max_length=160, pattern=r"^[A-Za-z0-9_.:-]+$"),
    ]
    requesting_client: Annotated[str, Field(min_length=1, max_length=160)]
    service: Annotated[
        str,
        Field(min_length=1, max_length=64, pattern=r"^[a-z0-9_-]+$"),
    ]
    operation: Annotated[
        str,
        Field(min_length=1, max_length=64, pattern=r"^[a-z0-9_.-]+$"),
    ]
    request_fingerprint: Annotated[str | None, Field(min_length=16, max_length=256)] = None


class ToastAdapter(Protocol):
    def show(self, *, title: str, body: str, launch_url: str) -> None: ...


class NotificationSink(Protocol):
    def notify(self, event: NotificationEvent) -> bool: ...


class ApprovalPendingSignalSink(Protocol):
    """Non-blocking producer surface; deliberately has no decision mutation."""

    def submit(self, signal: ApprovalPendingSignal) -> bool: ...


class DashboardApprovalNotificationRelay:
    """Reduce a bound approval signal to safe human-facing dashboard context."""

    def __init__(self, sink: NotificationSink, *, dashboard_url: str) -> None:
        # Validate the fixed local destination once without retaining a partial event.
        validated = NotificationEvent(
            kind="approval_required",
            requesting_client="gatehouse",
            service="gatehouse",
            operation="approval",
            dashboard_url=dashboard_url,
        )
        self._sink = sink
        self._dashboard_url = validated.dashboard_url

    def __call__(self, signal: ApprovalPendingSignal) -> None:
        self._sink.notify(
            NotificationEvent(
                kind="approval_required",
                requesting_client=signal.requesting_client,
                service=signal.service,
                operation=signal.operation,
                dashboard_url=self._dashboard_url,
            )
        )


class BoundedApprovalPendingDispatcher:
    """Deliver approval signals off the request path with fixed memory/thread bounds."""

    def __init__(
        self,
        callback: Callable[[ApprovalPendingSignal], None],
        *,
        maximum_pending: int = 32,
        maximum_deduplicated: int = 256,
    ) -> None:
        if not 1 <= maximum_pending <= 1_024:
            raise ValueError("notification queue bound must be between one and 1024")
        if not 1 <= maximum_deduplicated <= 4_096:
            raise ValueError("notification deduplication bound must be between one and 4096")
        self._callback = callback
        self._queue: queue.Queue[ApprovalPendingSignal] = queue.Queue(maxsize=maximum_pending)
        self._maximum_deduplicated = maximum_deduplicated
        self._deduplicated: OrderedDict[str, None] = OrderedDict()
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._closed = False
        self._worker = threading.Thread(
            target=self._run,
            name="gatehouse-approval-notifier",
            daemon=True,
        )
        self._worker.start()

    def submit(self, signal: ApprovalPendingSignal) -> bool:
        if not isinstance(signal, ApprovalPendingSignal):
            raise TypeError("approval notification requires a validated signal")
        with self._lock:
            if self._closed:
                return False
            if signal.approval_id in self._deduplicated:
                self._deduplicated.move_to_end(signal.approval_id)
                return True
            try:
                self._queue.put_nowait(signal)
            except queue.Full:
                return False
            self._deduplicated[signal.approval_id] = None
            while len(self._deduplicated) > self._maximum_deduplicated:
                self._deduplicated.popitem(last=False)
            return True

    def close(self, *, maximum_wait_seconds: float = 1.0) -> bool:
        if not 0 <= maximum_wait_seconds <= 5:
            raise ValueError("notification close wait must be between zero and five seconds")
        with self._lock:
            self._closed = True
            self._stop.set()
        self._worker.join(timeout=maximum_wait_seconds)
        return not self._worker.is_alive()

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                signal = self._queue.get(timeout=0.1)
            except queue.Empty:
                continue
            try:
                self._deliver(signal)
            finally:
                self._queue.task_done()

    def _deliver(self, signal: ApprovalPendingSignal) -> bool:
        try:
            self._callback(signal)
        except Exception:
            # Notifications are best effort and never influence invocation state.
            return False
        return True


class WindowsBestEffortNotifier:
    """Signal a bounded event; the dashboard remains the only approval authority."""

    def __init__(self, adapter: ToastAdapter | None = None) -> None:
        self._adapter = adapter

    def notify(self, event: NotificationEvent) -> bool:
        title = (
            "Gatehouse approval required"
            if event.kind == "approval_required"
            else "Gatehouse incident"
        )
        fields = [
            f"Client: {event.requesting_client}",
            f"Operation: {event.service}.{event.operation}",
        ]
        if event.cost_ceiling is not None:
            fields.append(f"Cost ceiling: {event.cost_ceiling}")
        if event.expires_at_ms is not None:
            fields.append(f"Expires: {event.expires_at_ms}")
        if event.severity is not None:
            fields.append(f"Severity: {event.severity}")
        body = "\n".join(fields)
        if self._adapter is not None:
            try:
                self._adapter.show(
                    title=title,
                    body=body,
                    launch_url=event.dashboard_url,
                )
                return True
            except OSError:
                return False
        if os.name == "nt":
            try:
                import winsound

                winsound.MessageBeep(winsound.MB_ICONEXCLAMATION)
            except (ImportError, RuntimeError):
                return False
        return False


def main() -> None:
    notifier = WindowsBestEffortNotifier()
    for line in sys.stdin:
        if len(line.encode("utf-8")) > 16_384:
            continue
        try:
            event = NotificationEvent.model_validate_json(line)
        except ValidationError:
            continue
        notifier.notify(event)
