"""Health-aware, lease-guarded, bounded daemon restart control."""

from gatehouse.watchdog.controller import (
    ProbeResult,
    RestartPolicy,
    WatchdogController,
    WatchdogOutcome,
)

__all__ = ["ProbeResult", "RestartPolicy", "WatchdogController", "WatchdogOutcome"]
