from __future__ import annotations

import threading

import pytest

from gatehouse.notifier import (
    ApprovalPendingSignal,
    BoundedApprovalPendingDispatcher,
    DashboardApprovalNotificationRelay,
    NotificationEvent,
    WindowsBestEffortNotifier,
)


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


@pytest.mark.parametrize(
    "dashboard_url",
    [
        "http://localhost:47622/dashboard",
        "http://127.0.0.1:47622/dashboard?approve=true",
        "http://127.0.0.1:99999/dashboard",
        "https://127.0.0.1:47622/dashboard",
    ],
)
def test_notification_dashboard_is_an_exact_numeric_loopback_destination(
    dashboard_url: str,
) -> None:
    with pytest.raises(ValueError):
        NotificationEvent(
            kind="approval_required",
            requesting_client="editor-one",
            service="firecrawl",
            operation="search",
            dashboard_url=dashboard_url,
        )


def test_bounded_approval_dispatcher_deduplicates_without_mutation_authority() -> None:
    delivered: list[ApprovalPendingSignal] = []
    observed = threading.Event()

    def callback(signal: ApprovalPendingSignal) -> None:
        delivered.append(signal)
        observed.set()

    dispatcher = BoundedApprovalPendingDispatcher(
        callback,
        maximum_pending=2,
        maximum_deduplicated=4,
    )
    signal = ApprovalPendingSignal(
        approval_id="apr_one",
        request_id="req_00000000000000000000000001",
        session_id="ses_one",
        root_run_id="run_one",
        client_id="client_one",
        workspace_id="ws_one",
        requesting_client="editor-one",
        service="firecrawl",
        operation="search",
        request_fingerprint="fp_0123456789abcdef",
    )
    try:
        assert dispatcher.submit(signal)
        assert dispatcher.submit(signal)
        assert observed.wait(1)
    finally:
        dispatcher.close(maximum_wait_seconds=1)

    assert delivered == [signal]
    assert not hasattr(dispatcher, "approve")
    assert not hasattr(dispatcher, "deny")


def test_dashboard_relay_exposes_only_redacted_routing_context() -> None:
    toast = FakeToast()
    relay = DashboardApprovalNotificationRelay(
        WindowsBestEffortNotifier(toast),
        dashboard_url="http://127.0.0.1:47622/dashboard",
    )
    signal = ApprovalPendingSignal(
        approval_id="apr_one",
        request_id="req_00000000000000000000000001",
        session_id="ses_one",
        root_run_id="run_one",
        client_id="client_one",
        workspace_id="ws_one",
        requesting_client="editor-one",
        service="firecrawl",
        operation="search",
    )

    relay(signal)

    rendered = repr(toast.messages)
    assert "editor-one" in rendered
    assert "firecrawl.search" in rendered
    assert "apr_one" not in rendered
    assert "req_" not in rendered
    assert "ses_one" not in rendered
    assert "run_one" not in rendered


def test_notification_dispatch_queue_drops_excess_work_without_blocking_submitter() -> None:
    entered = threading.Event()
    release = threading.Event()

    def callback(_: ApprovalPendingSignal) -> None:
        entered.set()
        release.wait(1)

    def signal(ordinal: int) -> ApprovalPendingSignal:
        return ApprovalPendingSignal(
            approval_id=f"apr_{ordinal}",
            request_id=f"req_{ordinal:026d}",
            session_id="ses_one",
            root_run_id="run_one",
            client_id="client_one",
            workspace_id="ws_one",
            requesting_client="editor-one",
            service="firecrawl",
            operation="search",
        )

    dispatcher = BoundedApprovalPendingDispatcher(
        callback,
        maximum_pending=1,
        maximum_deduplicated=4,
    )
    try:
        assert dispatcher.submit(signal(1))
        assert entered.wait(1)
        assert dispatcher.submit(signal(2))
        assert not dispatcher.submit(signal(3))
    finally:
        release.set()
        dispatcher.close(maximum_wait_seconds=1)
