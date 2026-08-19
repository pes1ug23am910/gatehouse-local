"""Best-effort user-session notifications with no approval authority."""

from __future__ import annotations

import os
import sys
from typing import Annotated, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, ValidationError


class NotificationEvent(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    kind: Literal["approval_required", "incident"]
    requesting_client: Annotated[str, Field(min_length=1, max_length=160)]
    service: Annotated[str, Field(min_length=1, max_length=64)]
    operation: Annotated[str, Field(min_length=1, max_length=64)]
    cost_ceiling: Annotated[int | None, Field(ge=0)] = None
    expires_at_ms: Annotated[int | None, Field(ge=0)] = None
    severity: Annotated[str | None, Field(max_length=32)] = None
    dashboard_url: Annotated[
        str,
        Field(pattern=r"^http://(?:127\.0\.0\.1|localhost):\d{1,5}/"),
    ]


class ToastAdapter(Protocol):
    def show(self, *, title: str, body: str, launch_url: str) -> None: ...


class NotificationSink(Protocol):
    def notify(self, event: NotificationEvent) -> bool: ...


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
