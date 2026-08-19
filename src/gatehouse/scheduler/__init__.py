"""Bounded, session-fair scheduling primitives."""

from .fair import (
    BoundedFairScheduler,
    CancellationResult,
    DispatchPermit,
    DuplicateRequest,
    PriorityClass,
    QueueCapacityExceeded,
    QueueExpired,
    QueueTicket,
    RequestCancelled,
    SchedulerLimits,
    SchedulerSnapshot,
    ServiceLimits,
    UnknownService,
    WorkItem,
)

__all__ = [
    "BoundedFairScheduler",
    "CancellationResult",
    "DispatchPermit",
    "DuplicateRequest",
    "PriorityClass",
    "QueueCapacityExceeded",
    "QueueExpired",
    "QueueTicket",
    "RequestCancelled",
    "SchedulerLimits",
    "SchedulerSnapshot",
    "ServiceLimits",
    "UnknownService",
    "WorkItem",
]
