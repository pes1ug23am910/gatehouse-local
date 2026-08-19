"""Value objects for the provider-neutral feed watcher."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from gatehouse.config import FeedSetConfig

type JsonScalar = str | int | float | bool | None
type JsonValue = JsonScalar | list[JsonValue] | dict[str, JsonValue]


class ScanStatus(StrEnum):
    STARTED = "STARTED"
    ALREADY_RUNNING = "ALREADY_RUNNING"
    OUTSIDE_SCHEDULE = "OUTSIDE_SCHEDULE"


class BudgetStatus(StrEnum):
    ACCEPTED = "ACCEPTED"
    NOT_RUNNING = "NOT_RUNNING"
    STALE_FENCE = "STALE_FENCE"
    DURATION_EXCEEDED = "DURATION_EXCEEDED"
    REQUEST_LIMIT = "REQUEST_LIMIT"
    CREDIT_LIMIT = "CREDIT_LIMIT"
    PAGE_LIMIT = "PAGE_LIMIT"


class CursorCommitStatus(StrEnum):
    COMMITTED = "COMMITTED"
    STALE_VERSION = "STALE_VERSION"
    NON_MONOTONIC = "NON_MONOTONIC"
    UNKNOWN_FEED_SET = "UNKNOWN_FEED_SET"


@dataclass(frozen=True, slots=True)
class TargetRequest:
    operation: str
    url: str


@dataclass(frozen=True, slots=True)
class AuthorizedTarget:
    operation: str
    normalized_url: str
    matched_host: str
    matched_path_regex: str


@dataclass(frozen=True, slots=True)
class ScheduleDecision:
    allowed: bool
    evaluated_at_ms: int
    timezone: str
    window_start_ms: int | None = None
    window_end_ms: int | None = None
    in_grace: bool = False


@dataclass(frozen=True, slots=True)
class RunFence:
    watcher_run_id: str
    lease_id: str
    generation: int
    feed_set_id: str
    owner_session_id: str
    expires_at_ms: int


@dataclass(frozen=True, slots=True)
class BudgetUsage:
    requests: int
    credit_micros: int
    pages: int


@dataclass(frozen=True, slots=True)
class BudgetChargeResult:
    status: BudgetStatus
    usage: BudgetUsage

    @property
    def accepted(self) -> bool:
        return self.status is BudgetStatus.ACCEPTED


@dataclass(frozen=True, slots=True)
class CursorState:
    feed_set_id: str
    cursor_value: str | None
    version: int
    sequence: int
    committed_at_ms: int | None


@dataclass(frozen=True, slots=True)
class CursorCommitResult:
    status: CursorCommitStatus
    cursor: CursorState | None

    @property
    def committed(self) -> bool:
        return self.status is CursorCommitStatus.COMMITTED


@dataclass(frozen=True, slots=True)
class ScanFeedSetResult:
    status: ScanStatus
    feed_set: FeedSetConfig
    schedule: ScheduleDecision
    targets: tuple[AuthorizedTarget, ...]
    fence: RunFence | None = None
    active_run_id: str | None = None
