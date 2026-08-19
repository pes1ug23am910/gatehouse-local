"""Mutable lifecycle health shared by the two loopback applications."""

from __future__ import annotations

from collections.abc import Callable, Iterable

from gatehouse.api import ReadinessSnapshot


class RuntimeHealthProbe:
    """Expose one bounded snapshot while startup and shutdown advance state."""

    def __init__(
        self,
        *,
        version: str,
        schema_version: int,
        policy_version: str,
        now_ms: Callable[[], int],
        started_at_ms: int,
    ) -> None:
        if not version or not policy_version:
            raise ValueError("health version fields are required")
        if schema_version < 0 or started_at_ms < 0:
            raise ValueError("health timestamps and versions cannot be negative")
        self._version = version
        self._schema_version = schema_version
        self._policy_version = policy_version
        self._now_ms = now_ms
        self._started_at_ms = started_at_ms
        self._status = "RECOVERING"
        self._degraded_components: tuple[str, ...] = ()

    @property
    def status(self) -> str:
        return self._status

    def transition(
        self,
        status: str,
        *,
        degraded_components: Iterable[str] = (),
    ) -> None:
        normalized = status.strip().upper()
        if normalized not in {
            "RECOVERING",
            "READY",
            "DEGRADED_READ_ONLY",
            "DEGRADED_NO_PROVIDER",
            "DRAINING",
            "FAILED_CLOSED",
            "STOPPED",
        }:
            raise ValueError("unsupported daemon health state")
        components = tuple(sorted(set(degraded_components)))
        if any(not component or len(component) > 100 for component in components):
            raise ValueError("degraded component identifiers are invalid")
        self._status = normalized
        self._degraded_components = components

    async def readiness(self) -> ReadinessSnapshot:
        uptime_ms = max(0, self._now_ms() - self._started_at_ms)
        return ReadinessSnapshot(
            ready=self._status == "READY",
            status=self._status,
            version=self._version,
            schema_version=self._schema_version,
            policy_version=self._policy_version,
            uptime_seconds=uptime_ms // 1_000,
            degraded_components=list(self._degraded_components),
        )
