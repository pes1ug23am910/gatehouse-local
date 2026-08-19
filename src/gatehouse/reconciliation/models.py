"""Provider-neutral quota reconciliation value objects."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from enum import StrEnum


class OwnershipMode(StrEnum):
    EXCLUSIVE = "EXCLUSIVE"
    SHARED = "SHARED"
    UNKNOWN = "UNKNOWN"


class ReconciliationState(StrEnum):
    MATCHED = "MATCHED"
    WITHIN_PENDING = "WITHIN_PENDING"
    MISMATCH = "MISMATCH"
    STALE = "STALE"
    UNKNOWN = "UNKNOWN"
    RESET_DETECTED = "RESET_DETECTED"


class ReconciliationAction(StrEnum):
    NONE = "NONE"
    MONITOR = "MONITOR"
    HOLD_ROUTING = "HOLD_ROUTING"
    INVESTIGATE = "INVESTIGATE"
    QUARANTINE_LOCAL = "QUARANTINE_LOCAL"


@dataclass(frozen=True, slots=True)
class UsageSnapshot:
    quota_scope_id: str
    unit: str
    captured_at_ms: int
    remaining_units: int | None = None
    used_units: int | None = None
    plan_total_units: int | None = None
    period_start_ms: int | None = None
    period_end_ms: int | None = None
    reset_marker: str | None = None
    snapshot_id: str | None = None

    def __post_init__(self) -> None:
        if not self.quota_scope_id or not self.unit:
            raise ValueError("snapshot scope and unit are required")
        if self.captured_at_ms < 0:
            raise ValueError("snapshot capture time must be non-negative")
        if self.remaining_units is None and self.used_units is None:
            raise ValueError("snapshot requires a remaining or used counter")
        for value in (self.remaining_units, self.used_units, self.plan_total_units):
            if value is not None and value < 0:
                raise ValueError("snapshot counters must be non-negative")
        if (
            self.period_start_ms is not None
            and self.period_end_ms is not None
            and self.period_end_ms <= self.period_start_ms
        ):
            raise ValueError("snapshot period end must follow its start")


@dataclass(frozen=True, slots=True)
class LedgerWindow:
    settled_units: int
    pending_reserved_units: int = 0
    manual_adjustment_units: int = 0

    def __post_init__(self) -> None:
        if self.settled_units < 0 or self.pending_reserved_units < 0:
            raise ValueError("ledger usage and pending reservations must be non-negative")


@dataclass(frozen=True, slots=True)
class ReconciliationPolicy:
    absolute_tolerance_units: int
    relative_tolerance: Decimal
    consecutive_mismatches_for_incident: int = 2
    maximum_snapshot_age_ms: int = 3_600_000

    def __post_init__(self) -> None:
        if self.absolute_tolerance_units < 0:
            raise ValueError("absolute tolerance must be non-negative")
        if not Decimal(0) <= self.relative_tolerance <= Decimal(1):
            raise ValueError("relative tolerance must be between zero and one")
        if self.consecutive_mismatches_for_incident <= 0:
            raise ValueError("incident threshold must be positive")
        if self.maximum_snapshot_age_ms <= 0:
            raise ValueError("snapshot age limit must be positive")


@dataclass(frozen=True, slots=True)
class ReconciliationDecision:
    state: ReconciliationState
    action: ReconciliationAction
    ownership: OwnershipMode
    provider_delta_units: int | None
    ledger_settled_units: int
    pending_reserved_units: int
    manual_adjustment_units: int
    unexplained_delta_units: int | None
    allowed_tolerance_units: int
    consecutive_mismatches: int
    preserve_pending_reservations: bool
    incident_required: bool
    quarantine_local: bool
    reason: str


@dataclass(frozen=True, slots=True)
class RecordedReconciliation:
    reconciliation_id: str
    item_id: str
    decision: ReconciliationDecision
    alert_id: str | None = None
