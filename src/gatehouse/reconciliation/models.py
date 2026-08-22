"""Provider-neutral quota reconciliation value objects."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from decimal import Decimal
from enum import StrEnum

from gatehouse.core.provider_numbers import (
    MAX_PROVIDER_FIXED_POINT_CHARS,
    MAX_PROVIDER_SIGNIFICANT_DIGITS,
    ExactProviderNumber,
    compatibility_sqlite_int,
    parse_canonical_allowed_tolerance,
    parse_canonical_provider_delta,
    parse_canonical_provider_number,
    parse_canonical_reconciliation_delta,
    project_routing_units,
    require_sqlite_int64,
)


def _significant_decimal_digits(value: Decimal) -> int:
    digits = list(value.as_tuple().digits)
    while len(digits) > 1 and digits[0] == 0:
        digits.pop(0)
    while len(digits) > 1 and digits[-1] == 0:
        digits.pop()
    return max(1, len(digits))


def _validated_observation(
    *,
    projected: int | None,
    observed: str | None,
    field: str,
) -> str | None:
    if projected is None:
        if observed is not None:
            raise ValueError(f"{field} observation requires a projected value")
        return None
    require_sqlite_int64(projected, field=field, minimum=0)
    if observed is None:
        # Compatibility is deliberately limited to new in-memory objects. Durable
        # readers must reject a missing observation before calling this constructor.
        return str(projected)
    if type(observed) is not str:
        raise ValueError(f"{field} observation must be canonical text")
    try:
        exact = parse_canonical_provider_number(
            observed,
            maximum_fixed_point_chars=MAX_PROVIDER_FIXED_POINT_CHARS,
        )
    except (TypeError, ValueError):
        raise ValueError(f"{field} observation must be canonical text") from None
    if project_routing_units(exact) != projected:
        raise ValueError(f"{field} projection does not match its exact observation")
    return observed


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


def _validate_delta_pair(
    *,
    compatibility: int | None,
    exact_text: str | None,
    field: str,
    parser: Callable[[str], ExactProviderNumber],
) -> None:
    if exact_text is None:
        if compatibility is not None:
            raise ValueError(f"{field} compatibility value requires exact text")
        return
    if type(exact_text) is not str:
        raise ValueError(f"{field} exact value must be canonical text")
    try:
        exact = parser(exact_text)
    except (TypeError, ValueError):
        raise ValueError(f"{field} exact value must be canonical text") from None
    if compatibility is not None:
        require_sqlite_int64(compatibility, field=f"{field} compatibility value")
    if compatibility != compatibility_sqlite_int(exact):
        raise ValueError(f"{field} exact and compatibility values differ")


def _validate_allowed_tolerance(*, compatibility: int, exact_text: str) -> None:
    if type(compatibility) is not int or compatibility < 0:
        raise ValueError("allowed tolerance must be a strict nonnegative integer")
    if type(exact_text) is not str:
        raise ValueError("allowed tolerance exact value must be canonical text")
    try:
        exact = parse_canonical_allowed_tolerance(exact_text)
    except (TypeError, ValueError):
        raise ValueError("allowed tolerance exact value must be canonical text") from None
    expected = exact.coefficient * 10**exact.exponent
    if compatibility != expected:
        raise ValueError("allowed tolerance exact and integer values differ")


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
    observed_remaining_units_decimal: str | None = None
    observed_plan_total_units_decimal: str | None = None

    def __post_init__(self) -> None:
        if not self.quota_scope_id or not self.unit:
            raise ValueError("snapshot scope and unit are required")
        require_sqlite_int64(self.captured_at_ms, field="snapshot capture time", minimum=0)
        if self.remaining_units is None and self.used_units is None:
            raise ValueError("snapshot requires a remaining or used counter")
        if self.used_units is not None:
            require_sqlite_int64(self.used_units, field="used counter", minimum=0)
        remaining_observation = _validated_observation(
            projected=self.remaining_units,
            observed=self.observed_remaining_units_decimal,
            field="remaining counter",
        )
        plan_observation = _validated_observation(
            projected=self.plan_total_units,
            observed=self.observed_plan_total_units_decimal,
            field="plan total counter",
        )
        object.__setattr__(
            self,
            "observed_remaining_units_decimal",
            remaining_observation,
        )
        object.__setattr__(
            self,
            "observed_plan_total_units_decimal",
            plan_observation,
        )
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
        require_sqlite_int64(self.settled_units, field="settled usage", minimum=0)
        require_sqlite_int64(
            self.pending_reserved_units,
            field="pending reservations",
            minimum=0,
        )
        require_sqlite_int64(self.manual_adjustment_units, field="manual adjustment")


@dataclass(frozen=True, slots=True)
class ReconciliationPolicy:
    absolute_tolerance_units: int
    relative_tolerance: Decimal | float
    consecutive_mismatches_for_incident: int = 2
    maximum_snapshot_age_ms: int = 3_600_000

    def __post_init__(self) -> None:
        require_sqlite_int64(
            self.absolute_tolerance_units,
            field="absolute tolerance",
            minimum=0,
        )
        if isinstance(self.relative_tolerance, bool) or not isinstance(
            self.relative_tolerance,
            (Decimal, float),
        ):
            raise ValueError("relative tolerance must be a Decimal or float")
        relative_tolerance = (
            self.relative_tolerance
            if isinstance(self.relative_tolerance, Decimal)
            else Decimal(str(self.relative_tolerance))
        )
        if not relative_tolerance.is_finite():
            raise ValueError("relative tolerance must be finite")
        if not Decimal(0) <= relative_tolerance <= Decimal(1):
            raise ValueError("relative tolerance must be between zero and one")
        if _significant_decimal_digits(relative_tolerance) > MAX_PROVIDER_SIGNIFICANT_DIGITS:
            raise ValueError("relative tolerance has too many significant digits")
        object.__setattr__(self, "relative_tolerance", relative_tolerance)
        require_sqlite_int64(
            self.consecutive_mismatches_for_incident,
            field="incident threshold",
            minimum=1,
        )
        require_sqlite_int64(
            self.maximum_snapshot_age_ms,
            field="snapshot age limit",
            minimum=1,
        )


@dataclass(frozen=True, slots=True)
class ReconciliationDecision:
    state: ReconciliationState
    action: ReconciliationAction
    ownership: OwnershipMode
    provider_delta_units: int | None
    provider_delta_units_decimal: str | None
    ledger_settled_units: int
    pending_reserved_units: int
    manual_adjustment_units: int
    unexplained_delta_units: int | None
    unexplained_delta_units_decimal: str | None
    allowed_tolerance_units: int
    allowed_tolerance_units_decimal: str
    consecutive_mismatches: int
    preserve_pending_reservations: bool
    incident_required: bool
    quarantine_local: bool
    reason: str

    def __post_init__(self) -> None:
        if not isinstance(self.state, ReconciliationState):
            raise ValueError("reconciliation state is invalid")
        if not isinstance(self.action, ReconciliationAction):
            raise ValueError("reconciliation action is invalid")
        if not isinstance(self.ownership, OwnershipMode):
            raise ValueError("reconciliation ownership is invalid")
        _validate_delta_pair(
            compatibility=self.provider_delta_units,
            exact_text=self.provider_delta_units_decimal,
            field="provider delta",
            parser=parse_canonical_provider_delta,
        )
        _validate_delta_pair(
            compatibility=self.unexplained_delta_units,
            exact_text=self.unexplained_delta_units_decimal,
            field="unexplained delta",
            parser=parse_canonical_reconciliation_delta,
        )
        indeterminate = self.state in {
            ReconciliationState.STALE,
            ReconciliationState.UNKNOWN,
            ReconciliationState.RESET_DETECTED,
        }
        exact_deltas_are_null = (
            self.provider_delta_units is None
            and self.provider_delta_units_decimal is None
            and self.unexplained_delta_units is None
            and self.unexplained_delta_units_decimal is None
        )
        exact_deltas_are_complete = (
            self.provider_delta_units_decimal is not None
            and self.unexplained_delta_units_decimal is not None
        )
        if (indeterminate and not exact_deltas_are_null) or (
            not indeterminate and not exact_deltas_are_complete
        ):
            raise ValueError("reconciliation delta fields do not match the decision state")
        _validate_allowed_tolerance(
            compatibility=self.allowed_tolerance_units,
            exact_text=self.allowed_tolerance_units_decimal,
        )


@dataclass(frozen=True, slots=True)
class RecordedReconciliation:
    reconciliation_id: str
    item_id: str
    decision: ReconciliationDecision
    alert_id: str | None = None
