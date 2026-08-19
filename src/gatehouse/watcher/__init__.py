"""Provider-neutral, allowlisted, budgeted feed watcher primitives."""

from .feedsets import (
    FeedSetRegistry,
    FeedSetResolutionError,
    TargetNotAllowedError,
    authorize_target,
)
from .models import (
    AuthorizedTarget,
    BudgetChargeResult,
    BudgetStatus,
    CursorCommitResult,
    CursorCommitStatus,
    CursorState,
    RunFence,
    ScanFeedSetResult,
    ScanStatus,
    ScheduleDecision,
    TargetRequest,
)
from .schedule import ScheduleTimezoneError, evaluate_schedule
from .service import WatcherService
from .store import (
    CREDIT_MICROS_PER_CREDIT,
    RESERVED_LANE,
    RESERVED_POOL_ALIAS,
    FeedSetLookupError,
    ReservedRouteError,
    StaleRunFenceError,
    SummaryMetadataError,
    WatcherPersistenceError,
    WatcherStore,
    credits_to_micros,
)

__all__ = [
    "CREDIT_MICROS_PER_CREDIT",
    "RESERVED_LANE",
    "RESERVED_POOL_ALIAS",
    "AuthorizedTarget",
    "BudgetChargeResult",
    "BudgetStatus",
    "CursorCommitResult",
    "CursorCommitStatus",
    "CursorState",
    "FeedSetLookupError",
    "FeedSetRegistry",
    "FeedSetResolutionError",
    "ReservedRouteError",
    "RunFence",
    "ScanFeedSetResult",
    "ScanStatus",
    "ScheduleDecision",
    "ScheduleTimezoneError",
    "StaleRunFenceError",
    "SummaryMetadataError",
    "TargetNotAllowedError",
    "TargetRequest",
    "WatcherPersistenceError",
    "WatcherService",
    "WatcherStore",
    "authorize_target",
    "credits_to_micros",
    "evaluate_schedule",
]
