"""One-shot watchdog decisions with durable restart accounting."""

from __future__ import annotations

import json
import sqlite3
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from enum import StrEnum

from gatehouse.database.connection import transaction
from gatehouse.database.repository import GatehouseRepository

_DAEMON_STATES = frozenset(
    {
        "RECOVERING",
        "READY",
        "DEGRADED_READ_ONLY",
        "DEGRADED_NO_PROVIDER",
        "DRAINING",
        "FAILED_CLOSED",
        "STOPPED",
    }
)


class ProbeAttestation(StrEnum):
    NO_RESPONDER = "no_responder"
    UNVERIFIED = "unverified"
    MISMATCH = "mismatch"
    MATCHED = "matched"


@dataclass(frozen=True, slots=True)
class ProbeResult:
    live: bool
    ready: bool
    daemon_state: str | None = None
    detail: str | None = None
    agent_status_code: int | None = None
    control_status_code: int | None = None
    attestation: ProbeAttestation = ProbeAttestation.UNVERIFIED

    def has_matched_status(self) -> bool:
        """Recheck the public probe seam before accepting a live state."""

        return (
            self.attestation is ProbeAttestation.MATCHED
            and self.live is True
            and type(self.ready) is bool
            and type(self.agent_status_code) is int
            and self.agent_status_code == 200
            and type(self.control_status_code) is int
            and self.control_status_code == 200
            and type(self.daemon_state) is str
            and self.daemon_state in _DAEMON_STATES
            and self.ready == (self.daemon_state == "READY")
        )

    def has_no_responder(self) -> bool:
        """Only the explicit absence result can enter restart accounting."""

        return (
            self.attestation is ProbeAttestation.NO_RESPONDER
            and self.live is False
            and self.ready is False
            and self.daemon_state is None
            and self.agent_status_code is None
            and self.control_status_code is None
        )


@dataclass(frozen=True, slots=True)
class RestartPolicy:
    maximum_restarts: int = 5
    restart_window_ms: int = 10 * 60 * 1_000
    crash_loop_cooldown_ms: int = 15 * 60 * 1_000
    lease_ttl_ms: int = 60_000

    def __post_init__(self) -> None:
        if (
            min(
                self.maximum_restarts,
                self.restart_window_ms,
                self.crash_loop_cooldown_ms,
                self.lease_ttl_ms,
            )
            <= 0
        ):
            raise ValueError("watchdog bounds must be positive")


class WatchdogOutcome(StrEnum):
    HEALTHY = "healthy"
    PROVIDERS_DISABLED = "providers_disabled"
    LIVE_DEGRADED = "live_degraded"
    CONFIG_MISMATCH = "config_mismatch"
    CONFIG_UNVERIFIED = "config_unverified"
    FAILED_CLOSED = "failed_closed"
    RESTARTED = "restarted"
    RESTART_FAILED = "restart_failed"
    LEASE_BUSY = "lease_busy"
    CRASH_LOOP_COOLDOWN = "crash_loop_cooldown"


Probe = Callable[[], Awaitable[ProbeResult]]
Restart = Callable[[], Awaitable[bool]]


class WatchdogController:
    """Evaluate health once; Task Scheduler owns recurrence."""

    def __init__(
        self,
        *,
        connection: sqlite3.Connection,
        probe: Probe,
        restart: Restart,
        owner_id: str,
        policy: RestartPolicy | None = None,
        allow_provider_disabled_state: bool = False,
    ) -> None:
        if not owner_id:
            raise ValueError("watchdog owner identifier is required")
        if type(allow_provider_disabled_state) is not bool:
            raise ValueError("disabled provider-state acceptance must be Boolean")
        self._connection = connection
        self._repository = GatehouseRepository(connection)
        self._probe = probe
        self._restart = restart
        self._owner_id = owner_id
        self._policy = policy or RestartPolicy()
        self._allow_provider_disabled_state = allow_provider_disabled_state

    async def run_once(self, *, now_ms: int) -> WatchdogOutcome:
        probe = await self._probe()
        if probe.attestation is ProbeAttestation.MISMATCH:
            return WatchdogOutcome.CONFIG_MISMATCH
        if probe.has_matched_status():
            if probe.ready:
                return WatchdogOutcome.HEALTHY
            if probe.daemon_state == "FAILED_CLOSED":
                return WatchdogOutcome.FAILED_CLOSED
            if self._allow_provider_disabled_state and probe.daemon_state == "DEGRADED_NO_PROVIDER":
                return WatchdogOutcome.PROVIDERS_DISABLED
            return WatchdogOutcome.LIVE_DEGRADED
        if not probe.has_no_responder():
            return WatchdogOutcome.CONFIG_UNVERIFIED
        if self._in_crash_loop(now_ms):
            return WatchdogOutcome.CRASH_LOOP_COOLDOWN

        lease = self._repository.acquire_lease(
            lease_type="WATCHDOG_RESTART",
            lease_key="gatehoused",
            owner_id=self._owner_id,
            now_ms=now_ms,
            expires_at_ms=now_ms + self._policy.lease_ttl_ms,
        )
        if not lease.acquired or lease.lease_id is None:
            return WatchdogOutcome.LEASE_BUSY
        try:
            restarted = await self._restart()
            outcome = WatchdogOutcome.RESTARTED if restarted else WatchdogOutcome.RESTART_FAILED
            self._record_restart(now_ms=now_ms, outcome=outcome)
            return outcome
        finally:
            self._repository.release_lease(
                lease_id=lease.lease_id,
                owner_id=self._owner_id,
                now_ms=now_ms,
            )

    def _in_crash_loop(self, now_ms: int) -> bool:
        window_start = now_ms - self._policy.restart_window_ms
        recent = int(
            self._connection.execute(
                """
                SELECT COUNT(*) FROM alerts
                WHERE category = 'watchdog_restart' AND created_at_ms >= ?
                """,
                (window_start,),
            ).fetchone()[0]
        )
        if recent < self._policy.maximum_restarts:
            return False
        last = self._connection.execute(
            """
            SELECT MAX(created_at_ms) FROM alerts
            WHERE category = 'watchdog_restart'
            """
        ).fetchone()[0]
        return last is not None and now_ms < int(last) + self._policy.crash_loop_cooldown_ms

    def _record_restart(self, *, now_ms: int, outcome: WatchdogOutcome) -> None:
        with transaction(self._connection):
            self._connection.execute(
                """
                INSERT INTO alerts(
                    alert_id, severity, category, state, title, summary,
                    created_at_ms, preserve, metadata_json
                ) VALUES (?, 'MEDIUM', 'watchdog_restart', 'OPEN',
                          'Daemon restart attempt', ?, ?, 1, ?)
                """,
                (
                    f"alert_{uuid.uuid4().hex}",
                    "The watchdog made a bounded restart attempt.",
                    now_ms,
                    json.dumps({"outcome": outcome.value}, sort_keys=True),
                ),
            )
