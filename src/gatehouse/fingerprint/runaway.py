"""Bounded repeated-equivalent and aggregate request-burst detection."""

from __future__ import annotations

from collections import OrderedDict, deque
from dataclasses import dataclass
from enum import StrEnum

from .hmac import RequestFingerprint


class RunawayDecision(StrEnum):
    ALLOW = "ALLOW"
    OPENED = "OPENED"
    BLOCKED = "BLOCKED"


class RunawayTrigger(StrEnum):
    REPEATED_EQUIVALENT = "REPEATED_EQUIVALENT"
    AGGREGATE_BURST = "AGGREGATE_BURST"
    DETECTOR_CAPACITY = "DETECTOR_CAPACITY"


@dataclass(frozen=True, slots=True)
class RunawayObservation:
    decision: RunawayDecision
    trigger: RunawayTrigger | None = None

    def __post_init__(self) -> None:
        if (self.decision is RunawayDecision.ALLOW) != (self.trigger is None):
            raise ValueError("only an allowed observation can omit its trigger")


@dataclass(slots=True)
class _FingerprintWindow:
    arrivals: deque[int]


@dataclass(slots=True)
class _ScopeWindow:
    fingerprints: OrderedDict[tuple[int, int, bytes], _FingerprintWindow]
    aggregate_arrivals: deque[int]
    last_arrival_ms: int
    trigger: RunawayTrigger | None = None


class RunawayDetector:
    """Detect equivalent repetition and varied aggregate bursts in one bounded scope.

    The caller chooses the attribution scope represented by ``session_id``.  The
    durable quarantine service passes an exact session/root-run/service digest.
    Once opened, this detector never heals because time elapsed; only an explicit
    ``forget_session`` call can clear process-local state.  Durable state remains
    authoritative when the detector is used by the SQLite service.
    """

    def __init__(
        self,
        *,
        threshold: int = 5,
        aggregate_threshold: int = 20,
        window_ms: int = 30_000,
        cooldown_ms: int = 120_000,
        maximum_fingerprints_per_session: int = 256,
        maximum_sessions: int = 1_024,
    ) -> None:
        if threshold < 2 or aggregate_threshold < 2:
            raise ValueError("runaway thresholds must be at least two")
        if aggregate_threshold < threshold:
            raise ValueError("aggregate threshold cannot be below the equivalent threshold")
        if (
            min(
                window_ms,
                cooldown_ms,
                maximum_fingerprints_per_session,
                maximum_sessions,
            )
            <= 0
        ):
            raise ValueError("runaway bounds must be positive")
        self.threshold = threshold
        self.aggregate_threshold = aggregate_threshold
        self.window_ms = window_ms
        # Retained as a parsed compatibility value.  It is intentionally not an
        # automatic recovery authority.
        self.cooldown_ms = cooldown_ms
        self.maximum_fingerprints_per_session = maximum_fingerprints_per_session
        self.maximum_sessions = maximum_sessions
        self._sessions: OrderedDict[str, _ScopeWindow] = OrderedDict()

    def observe_arrival(
        self,
        *,
        session_id: str,
        fingerprint: RequestFingerprint,
        now_ms: int,
    ) -> RunawayObservation:
        if not session_id:
            raise ValueError("session_id is required")
        self._evict_stale_scopes(now_ms)
        scope = self._sessions.get(session_id)
        if scope is None:
            if len(self._sessions) >= self.maximum_sessions:
                return RunawayObservation(
                    RunawayDecision.OPENED,
                    RunawayTrigger.DETECTOR_CAPACITY,
                )
            scope = _ScopeWindow(OrderedDict(), deque(), now_ms)
            self._sessions[session_id] = scope
        else:
            self._sessions.move_to_end(session_id)

        if scope.trigger is not None:
            return RunawayObservation(RunawayDecision.BLOCKED, scope.trigger)

        scope.last_arrival_ms = now_ms
        cutoff = now_ms - self.window_ms
        while scope.aggregate_arrivals and scope.aggregate_arrivals[0] <= cutoff:
            scope.aggregate_arrivals.popleft()
        scope.aggregate_arrivals.append(now_ms)

        key = fingerprint.key
        window = scope.fingerprints.get(key)
        if window is None:
            if len(scope.fingerprints) >= self.maximum_fingerprints_per_session:
                scope.fingerprints.popitem(last=False)
            window = _FingerprintWindow(deque())
            scope.fingerprints[key] = window
        else:
            scope.fingerprints.move_to_end(key)
        while window.arrivals and window.arrivals[0] <= cutoff:
            window.arrivals.popleft()
        window.arrivals.append(now_ms)

        if len(window.arrivals) >= self.threshold:
            scope.trigger = RunawayTrigger.REPEATED_EQUIVALENT
            return RunawayObservation(RunawayDecision.OPENED, scope.trigger)
        if len(scope.aggregate_arrivals) >= self.aggregate_threshold:
            scope.trigger = RunawayTrigger.AGGREGATE_BURST
            return RunawayObservation(RunawayDecision.OPENED, scope.trigger)
        return RunawayObservation(RunawayDecision.ALLOW)

    def _evict_stale_scopes(self, now_ms: int) -> None:
        cutoff = now_ms - self.window_ms
        stale = tuple(
            session_id
            for session_id, scope in self._sessions.items()
            if scope.trigger is None and scope.last_arrival_ms <= cutoff
        )
        for session_id in stale:
            self._sessions.pop(session_id, None)

    def record_arrival(
        self,
        *,
        session_id: str,
        fingerprint: RequestFingerprint,
        now_ms: int,
    ) -> RunawayDecision:
        return self.observe_arrival(
            session_id=session_id,
            fingerprint=fingerprint,
            now_ms=now_ms,
        ).decision

    def retry_after_ms(
        self,
        *,
        session_id: str,
        fingerprint: RequestFingerprint,
        now_ms: int,
    ) -> int | None:
        del fingerprint, now_ms
        scope = self._sessions.get(session_id)
        if scope is None or scope.trigger is None:
            return None
        # Human recovery, not a timer, is required after an opening.
        return None

    def trigger_for(self, session_id: str) -> RunawayTrigger | None:
        scope = self._sessions.get(session_id)
        return None if scope is None else scope.trigger

    def forget_session(self, session_id: str) -> None:
        self._sessions.pop(session_id, None)

    @property
    def tracked_fingerprints(self) -> int:
        return sum(len(scope.fingerprints) for scope in self._sessions.values())

    @property
    def tracked_sessions(self) -> int:
        return len(self._sessions)
