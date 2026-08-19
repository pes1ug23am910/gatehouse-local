from __future__ import annotations

from gatehouse.notifier import NotificationEvent, WindowsBestEffortNotifier


class FakeToast:
    def __init__(self) -> None:
        self.messages: list[tuple[str, str, str]] = []

    def show(self, *, title: str, body: str, launch_url: str) -> None:
        self.messages.append((title, body, launch_url))


def test_notifier_signals_dashboard_without_approval_authority() -> None:
    toast = FakeToast()
    notifier = WindowsBestEffortNotifier(toast)
    event = NotificationEvent(
        kind="approval_required",
        requesting_client="editor-one",
        service="firecrawl",
        operation="crawl.start",
        cost_ceiling=25,
        expires_at_ms=2_000,
        dashboard_url="http://127.0.0.1:47622/dashboard",
    )
    assert notifier.notify(event)
    assert toast.messages == [
        (
            "Gatehouse approval required",
            "Client: editor-one\nOperation: firecrawl.crawl.start\nCost ceiling: 25\nExpires: 2000",
            "http://127.0.0.1:47622/dashboard",
        )
    ]
    assert not hasattr(notifier, "approve")
    assert not hasattr(notifier, "deny")


def test_notification_schema_rejects_extra_action_fields() -> None:
    payload = {
        "kind": "approval_required",
        "requesting_client": "editor-one",
        "service": "firecrawl",
        "operation": "search",
        "dashboard_url": "http://localhost:47622/dashboard",
        "approve": True,
    }
    try:
        NotificationEvent.model_validate(payload)
    except ValueError:
        pass
    else:
        raise AssertionError("notification events must not carry approval actions")
