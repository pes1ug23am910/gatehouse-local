"""Fail-closed admission state shared by the daemon's loopback realms."""

from __future__ import annotations

from enum import StrEnum

from .errors import ErrorCode, make_error

_DRAIN_RECONCILIATION_OPERATIONS = frozenset(
    {
        "firecrawl.crawl.status",
        "firecrawl.crawl.cancel",
    }
)


class RuntimeAdmissionState(StrEnum):
    RECOVERING = "RECOVERING"
    ACCEPTING = "ACCEPTING"
    DRAINING = "DRAINING"
    FAILED_CLOSED = "FAILED_CLOSED"
    STOPPED = "STOPPED"


class RuntimeAdmissionController:
    """Reject new durable work unless startup recovery has opened admission."""

    def __init__(self) -> None:
        self._state = RuntimeAdmissionState.RECOVERING

    @property
    def state(self) -> RuntimeAdmissionState:
        return self._state

    def begin_accepting(self) -> None:
        if self._state is not RuntimeAdmissionState.RECOVERING:
            raise RuntimeError("daemon admission can only open after recovery")
        self._state = RuntimeAdmissionState.ACCEPTING

    def begin_draining(self) -> None:
        if self._state is RuntimeAdmissionState.DRAINING:
            return
        if self._state not in {
            RuntimeAdmissionState.RECOVERING,
            RuntimeAdmissionState.ACCEPTING,
        }:
            raise RuntimeError("daemon admission cannot drain from its current state")
        self._state = RuntimeAdmissionState.DRAINING

    def fail_closed(self) -> None:
        if self._state is not RuntimeAdmissionState.STOPPED:
            self._state = RuntimeAdmissionState.FAILED_CLOSED

    def stop(self) -> None:
        self._state = RuntimeAdmissionState.STOPPED

    def require_session_launch(self) -> None:
        self._require_accepting()

    def require_root_run_creation(self) -> None:
        self._require_accepting()

    def require_invocation(self, operation_id: str) -> None:
        if self._state is RuntimeAdmissionState.ACCEPTING:
            return
        if (
            self._state in {RuntimeAdmissionState.RECOVERING, RuntimeAdmissionState.DRAINING}
            and operation_id in _DRAIN_RECONCILIATION_OPERATIONS
        ):
            return
        self._reject()

    def _require_accepting(self) -> None:
        if self._state is not RuntimeAdmissionState.ACCEPTING:
            self._reject()

    def _reject(self) -> None:
        raise make_error(
            ErrorCode.DAEMON_DEGRADED,
            retryable=True,
            retry_after_seconds=1,
            details={"daemon_state": self._state.value},
        )
