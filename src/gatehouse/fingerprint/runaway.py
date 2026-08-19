"""Bounded per-session repeated-request detection."""

from __future__ import annotations

from collections import OrderedDict, deque
from dataclasses import dataclass
from enum import StrEnum

from .hmac import RequestFingerprint


class RunawayDecision(StrEnum):
    ALLOW = "ALLOW"
    OPENED = "OPENED"
    BLOCKED = "BLOCKED"


@dataclass(slots=True)
class _Window:
    arrivals: deque[int]
    open_until_ms: int | None = None


class RunawayDetector:
    """Count every arrival, including duplicate references, within a short window."""

    def __init__(
        self,
        *,
        threshold: int = 5,
        window_ms: int = 30_000,
        cooldown_ms: int = 120_000,
        maximum_fingerprints_per_session: int = 256,
    ) -> None:
        if threshold < 2:
            raise ValueError("runaway threshold must be at least two")
        if min(window_ms, cooldown_ms, maximum_fingerprints_per_session) <= 0:
            raise ValueError("runaway bounds must be positive")
        self.threshold = threshold
        self.window_ms = window_ms
        self.cooldown_ms = cooldown_ms
        self.maximum_fingerprints_per_session = maximum_fingerprints_per_session
        self._sessions: dict[str, OrderedDict[tuple[int, int, bytes], _Window]] = {}

    def record_arrival(
        self,
        *,
        session_id: str,
        fingerprint: RequestFingerprint,
        now_ms: int,
    ) -> RunawayDecision:
        if not session_id:
            raise ValueError("session_id is required")
        tracked = self._sessions.setdefault(session_id, OrderedDict())
        key = fingerprint.key
        window = tracked.get(key)
        if window is None:
            if len(tracked) >= self.maximum_fingerprints_per_session:
                tracked.popitem(last=False)
            window = _Window(deque())
            tracked[key] = window
        else:
            tracked.move_to_end(key)

        if window.open_until_ms is not None:
            if now_ms < window.open_until_ms:
                return RunawayDecision.BLOCKED
            window.open_until_ms = None
            window.arrivals.clear()

        cutoff = now_ms - self.window_ms
        while window.arrivals and window.arrivals[0] <= cutoff:
            window.arrivals.popleft()
        window.arrivals.append(now_ms)
        if len(window.arrivals) >= self.threshold:
            window.open_until_ms = now_ms + self.cooldown_ms
            return RunawayDecision.OPENED
        return RunawayDecision.ALLOW

    def retry_after_ms(
        self,
        *,
        session_id: str,
        fingerprint: RequestFingerprint,
        now_ms: int,
    ) -> int | None:
        tracked = self._sessions.get(session_id)
        if tracked is None:
            return None
        window = tracked.get(fingerprint.key)
        if window is None or window.open_until_ms is None or window.open_until_ms <= now_ms:
            return None
        return window.open_until_ms - now_ms

    def forget_session(self, session_id: str) -> None:
        self._sessions.pop(session_id, None)

    @property
    def tracked_fingerprints(self) -> int:
        return sum(len(entries) for entries in self._sessions.values())
