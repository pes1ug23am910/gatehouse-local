"""Pure, reset-aware quota reconciliation policy."""

from __future__ import annotations

from decimal import ROUND_CEILING, Decimal

from .models import (
    LedgerWindow,
    OwnershipMode,
    ReconciliationAction,
    ReconciliationDecision,
    ReconciliationPolicy,
    ReconciliationState,
    UsageSnapshot,
)


def _period_changed(previous: UsageSnapshot, current: UsageSnapshot) -> bool:
    if previous.reset_marker is not None or current.reset_marker is not None:
        if previous.reset_marker != current.reset_marker:
            return True
    for previous_value, current_value in (
        (previous.period_start_ms, current.period_start_ms),
        (previous.period_end_ms, current.period_end_ms),
    ):
        if (
            previous_value is not None
            and current_value is not None
            and previous_value != current_value
        ):
            return True
    return False


def _provider_delta(
    previous: UsageSnapshot,
    current: UsageSnapshot,
) -> tuple[int | None, ReconciliationState | None, str]:
    if previous.quota_scope_id != current.quota_scope_id or previous.unit != current.unit:
        return None, ReconciliationState.UNKNOWN, "snapshot_scope_or_unit_changed"
    if current.captured_at_ms <= previous.captured_at_ms:
        return None, ReconciliationState.UNKNOWN, "snapshot_order_is_not_monotonic"
    if _period_changed(previous, current):
        return None, ReconciliationState.RESET_DETECTED, "billing_period_or_reset_marker_changed"
    if (
        previous.plan_total_units is not None
        and current.plan_total_units is not None
        and previous.plan_total_units != current.plan_total_units
    ):
        return None, ReconciliationState.UNKNOWN, "plan_total_changed_within_period"

    used_delta: int | None = None
    remaining_delta: int | None = None
    if previous.used_units is not None and current.used_units is not None:
        used_delta = current.used_units - previous.used_units
        if used_delta < 0:
            return None, ReconciliationState.RESET_DETECTED, "used_counter_decreased"
    if previous.remaining_units is not None and current.remaining_units is not None:
        remaining_delta = previous.remaining_units - current.remaining_units
        if remaining_delta < 0:
            return None, ReconciliationState.RESET_DETECTED, "remaining_counter_increased"
    if used_delta is not None and remaining_delta is not None and used_delta != remaining_delta:
        return None, ReconciliationState.UNKNOWN, "remaining_and_used_counters_disagree"
    if used_delta is not None:
        return used_delta, None, "used_counter_delta"
    if remaining_delta is not None:
        return remaining_delta, None, "remaining_counter_delta"
    return None, ReconciliationState.UNKNOWN, "no_comparable_counter"


def _allowed_tolerance(
    provider_delta: int,
    expected_high: int,
    policy: ReconciliationPolicy,
) -> int:
    relative_base = max(abs(provider_delta), abs(expected_high))
    relative = int(
        (Decimal(relative_base) * policy.relative_tolerance).to_integral_value(ROUND_CEILING)
    )
    return max(policy.absolute_tolerance_units, relative)


def reconcile_usage(
    *,
    previous: UsageSnapshot | None,
    current: UsageSnapshot | None,
    ledger: LedgerWindow,
    ownership: OwnershipMode,
    policy: ReconciliationPolicy,
    prior_consecutive_mismatches: int,
    now_ms: int,
    observation_is_new: bool = True,
) -> ReconciliationDecision:
    """Compare provider counters with a ledger interval without guessing through resets."""

    if prior_consecutive_mismatches < 0:
        raise ValueError("prior mismatch count must be non-negative")
    if previous is None or current is None:
        return _indeterminate_decision(
            state=ReconciliationState.UNKNOWN,
            reason="two_snapshots_are_required",
            ledger=ledger,
            ownership=ownership,
            prior_consecutive_mismatches=prior_consecutive_mismatches,
        )
    if (
        current.captured_at_ms > now_ms
        or now_ms - current.captured_at_ms > policy.maximum_snapshot_age_ms
    ):
        return _indeterminate_decision(
            state=ReconciliationState.STALE,
            reason="latest_snapshot_is_stale_or_future_dated",
            ledger=ledger,
            ownership=ownership,
            prior_consecutive_mismatches=prior_consecutive_mismatches,
        )
    provider_delta, indeterminate_state, reason = _provider_delta(previous, current)
    if provider_delta is None:
        return _indeterminate_decision(
            state=indeterminate_state or ReconciliationState.UNKNOWN,
            reason=reason,
            ledger=ledger,
            ownership=ownership,
            prior_consecutive_mismatches=prior_consecutive_mismatches,
        )

    expected_low = ledger.settled_units + ledger.manual_adjustment_units
    expected_high = expected_low + ledger.pending_reserved_units
    tolerance = _allowed_tolerance(provider_delta, expected_high, policy)
    within_low = provider_delta >= expected_low - tolerance
    within_high = provider_delta <= expected_high + tolerance
    if within_low and within_high:
        direct_match = abs(provider_delta - expected_low) <= tolerance
        state = ReconciliationState.MATCHED if direct_match else ReconciliationState.WITHIN_PENDING
        consecutive = 0 if direct_match else prior_consecutive_mismatches
        return ReconciliationDecision(
            state=state,
            action=(ReconciliationAction.NONE if direct_match else ReconciliationAction.MONITOR),
            ownership=ownership,
            provider_delta_units=provider_delta,
            ledger_settled_units=ledger.settled_units,
            pending_reserved_units=ledger.pending_reserved_units,
            manual_adjustment_units=ledger.manual_adjustment_units,
            unexplained_delta_units=0,
            allowed_tolerance_units=tolerance,
            consecutive_mismatches=consecutive,
            preserve_pending_reservations=ledger.pending_reserved_units > 0,
            incident_required=False,
            quarantine_local=False,
            reason=("within_tolerance" if direct_match else "covered_by_pending_reservations"),
        )

    unexplained = (
        provider_delta - expected_high
        if provider_delta > expected_high
        else provider_delta - expected_low
    )
    consecutive = prior_consecutive_mismatches + int(observation_is_new)
    threshold_reached = consecutive >= policy.consecutive_mismatches_for_incident
    quarantine = observation_is_new and threshold_reached and ownership is OwnershipMode.EXCLUSIVE
    incident = observation_is_new and threshold_reached
    if quarantine:
        action = ReconciliationAction.QUARANTINE_LOCAL
    elif threshold_reached and ownership is OwnershipMode.SHARED:
        action = ReconciliationAction.INVESTIGATE
    elif threshold_reached:
        action = ReconciliationAction.HOLD_ROUTING
    else:
        action = ReconciliationAction.MONITOR
    return ReconciliationDecision(
        state=ReconciliationState.MISMATCH,
        action=action,
        ownership=ownership,
        provider_delta_units=provider_delta,
        ledger_settled_units=ledger.settled_units,
        pending_reserved_units=ledger.pending_reserved_units,
        manual_adjustment_units=ledger.manual_adjustment_units,
        unexplained_delta_units=unexplained,
        allowed_tolerance_units=tolerance,
        consecutive_mismatches=consecutive,
        preserve_pending_reservations=ledger.pending_reserved_units > 0,
        incident_required=incident,
        quarantine_local=quarantine,
        reason=(
            "provider_delta_outside_ledger_and_pending_range"
            if observation_is_new
            else "duplicate_snapshot_pair_not_counted"
        ),
    )


def _indeterminate_decision(
    *,
    state: ReconciliationState,
    reason: str,
    ledger: LedgerWindow,
    ownership: OwnershipMode,
    prior_consecutive_mismatches: int,
) -> ReconciliationDecision:
    return ReconciliationDecision(
        state=state,
        action=ReconciliationAction.HOLD_ROUTING,
        ownership=ownership,
        provider_delta_units=None,
        ledger_settled_units=ledger.settled_units,
        pending_reserved_units=ledger.pending_reserved_units,
        manual_adjustment_units=ledger.manual_adjustment_units,
        unexplained_delta_units=None,
        allowed_tolerance_units=0,
        consecutive_mismatches=prior_consecutive_mismatches,
        preserve_pending_reservations=True,
        incident_required=False,
        quarantine_local=False,
        reason=reason,
    )
