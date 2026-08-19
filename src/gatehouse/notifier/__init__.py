"""Approval- and incident-notification signals without mutation authority."""

from .main import NotificationEvent, NotificationSink, WindowsBestEffortNotifier

__all__ = ["NotificationEvent", "NotificationSink", "WindowsBestEffortNotifier"]
