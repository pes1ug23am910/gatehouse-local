"""Approval- and incident-notification signals without mutation authority."""

from .main import (
    ApprovalPendingSignal,
    ApprovalPendingSignalSink,
    BoundedApprovalPendingDispatcher,
    DashboardApprovalNotificationRelay,
    NotificationEvent,
    NotificationSink,
    WindowsBestEffortNotifier,
)

__all__ = [
    "ApprovalPendingSignal",
    "ApprovalPendingSignalSink",
    "BoundedApprovalPendingDispatcher",
    "DashboardApprovalNotificationRelay",
    "NotificationEvent",
    "NotificationSink",
    "WindowsBestEffortNotifier",
]
