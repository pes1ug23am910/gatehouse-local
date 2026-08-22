"""Pure, reset-aware quota reconciliation policy."""

from __future__ import annotations

from decimal import (
    MAX_EMAX,
    MIN_EMIN,
    ROUND_CEILING,
    Context,
    Decimal,
    Inexact,
    Rounded,
    localcontext,
)

from gatehouse.core.provider_numbers import (
    DECIMAL_WORK_PRECISION,
    MAX_ALLOWED_TOLERANCE_DECIMAL_CHARS,
    MAX_ALLOWED_TOLERANCE_SIGNIFICANT_DIGITS,
    MAX_PROVIDER_DELTA_SIGNIFICANT_DIGITS,
    MAX_RECONCILIATION_DECIMAL_CHARS,
    MAX_RECONCILIATION_SIGNIFICANT_DIGITS,
    ExactProviderNumber,
    canonicalize_decimal,
    compare_provider_numbers,
    compatibility_sqlite_int,
    parse_canonical_allowed_tolerance,
    parse_canonical_provider_delta,
    parse_canonical_provider_number,
    parse_canonical_reconciliation_delta,
    subtract_provider_numbers,
)

from .models import (
    LedgerWindow,
    OwnershipMode,
    ReconciliationAction,
    ReconciliationDecision,
    ReconciliationPolicy,
    ReconciliationState,
    UsageSnapshot,
)

_DECIMAL_WORK_CONTEXT = Context(
    prec=DECIMAL_WORK_PRECISION,
    Emin=MIN_EMIN,
    Emax=MAX_EMAX,
)
_DECIMAL_WORK_CONTEXT.traps[Inexact] = True
_DECIMAL_WORK_CONTEXT.traps[Rounded] = True
_DECIMAL_WORK_ETINY = MIN_EMIN - DECIMAL_WORK_PRECISION + 1


def _exact_observation(value: str) -> ExactProviderNumber:
    # UsageSnapshot has already applied the same strict parser. Repeating it at
    # the arithmetic boundary keeps the exact-number operations explicit.
    return parse_canonical_provider_number(value)


def _provider_delta_fields(value: Decimal) -> tuple[int | None, str]:
    rendered = canonicalize_decimal(
        value,
        maximum_significant_digits=MAX_PROVIDER_DELTA_SIGNIFICANT_DIGITS,
        maximum_fixed_point_chars=MAX_RECONCILIATION_DECIMAL_CHARS,
    )
    return compatibility_sqlite_int(parse_canonical_provider_delta(rendered)), rendered


def _reconciliation_delta_fields(value: Decimal) -> tuple[int | None, str]:
    rendered = canonicalize_decimal(
        value,
        maximum_significant_digits=MAX_RECONCILIATION_SIGNIFICANT_DIGITS,
        maximum_fixed_point_chars=MAX_RECONCILIATION_DECIMAL_CHARS,
    )
    return compatibility_sqlite_int(parse_canonical_reconciliation_delta(rendered)), rendered


def _canonical_allowed_tolerance(value: Decimal) -> str:
    rendered = canonicalize_decimal(
        value,
        maximum_significant_digits=MAX_ALLOWED_TOLERANCE_SIGNIFICANT_DIGITS,
        maximum_fixed_point_chars=MAX_ALLOWED_TOLERANCE_DECIMAL_CHARS,
    )
    parse_canonical_allowed_tolerance(rendered)
    return rendered


def _normalized_unsigned_decimal(value: Decimal) -> tuple[Decimal, int, int]:
    parts = value.as_tuple()
    exponent = parts.exponent
    if not isinstance(exponent, int):  # pragma: no cover - callers require finite values
        raise TypeError("decimal operand must be finite")
    digits = parts.digits
    first = 0
    while first < len(digits) and digits[first] == 0:
        first += 1
    if first == len(digits):
        return Decimal(0), 0, 0
    if parts.sign:
        raise ValueError("decimal operand must be non-negative")
    last = len(digits)
    while digits[last - 1] == 0:
        last -= 1
        exponent += 1
    normalized_digits = digits[first:last]
    coefficient = 0
    for digit in normalized_digits:
        coefficient = coefficient * 10 + digit
    return Decimal((0, normalized_digits, exponent)), coefficient, exponent


def _ceil_exact_tolerance_product(base: Decimal, tolerance: Decimal) -> Decimal:
    normalized_base, base_coefficient, base_exponent = _normalized_unsigned_decimal(base)
    normalized_tolerance, tolerance_coefficient, tolerance_exponent = _normalized_unsigned_decimal(
        tolerance
    )
    product_coefficient = base_coefficient * tolerance_coefficient
    if product_coefficient == 0:
        return Decimal(0)

    product_exponent = base_exponent + tolerance_exponent
    if product_exponent < _DECIMAL_WORK_ETINY:
        # Decimal can represent policy inputs below every legal Context Etiny.
        # The exact positive product is then strictly between zero and one, so
        # its mathematical ceiling is one without an inexact Decimal operation.
        return Decimal(1)

    exact_relative = normalized_base * normalized_tolerance
    # This is the sole intentional rounding operation. Multiplication above is
    # exact under the trapped 512-digit work context.
    return exact_relative.to_integral_value(rounding=ROUND_CEILING)


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
) -> tuple[Decimal | None, ReconciliationState | None, str]:
    if previous.quota_scope_id != current.quota_scope_id or previous.unit != current.unit:
        return None, ReconciliationState.UNKNOWN, "snapshot_scope_or_unit_changed"
    if current.captured_at_ms <= previous.captured_at_ms:
        return None, ReconciliationState.UNKNOWN, "snapshot_order_is_not_monotonic"
    if _period_changed(previous, current):
        return None, ReconciliationState.RESET_DETECTED, "billing_period_or_reset_marker_changed"
    if (
        previous.observed_plan_total_units_decimal is not None
        and current.observed_plan_total_units_decimal is not None
        and compare_provider_numbers(
            _exact_observation(previous.observed_plan_total_units_decimal),
            _exact_observation(current.observed_plan_total_units_decimal),
        )
        != 0
    ):
        return None, ReconciliationState.UNKNOWN, "plan_total_changed_within_period"

    used_delta: Decimal | None = None
    remaining_delta: Decimal | None = None
    with localcontext(_DECIMAL_WORK_CONTEXT):
        if previous.used_units is not None and current.used_units is not None:
            used_delta = Decimal(current.used_units) - Decimal(previous.used_units)
            if used_delta < 0:
                return None, ReconciliationState.RESET_DETECTED, "used_counter_decreased"
        if (
            previous.observed_remaining_units_decimal is not None
            and current.observed_remaining_units_decimal is not None
        ):
            exact_remaining_delta = subtract_provider_numbers(
                _exact_observation(previous.observed_remaining_units_decimal),
                _exact_observation(current.observed_remaining_units_decimal),
            )
            if exact_remaining_delta.coefficient < 0:
                return None, ReconciliationState.RESET_DETECTED, "remaining_counter_increased"
            remaining_delta = exact_remaining_delta.to_decimal()
    if used_delta is not None and remaining_delta is not None and used_delta != remaining_delta:
        return None, ReconciliationState.UNKNOWN, "remaining_and_used_counters_disagree"
    if used_delta is not None:
        return used_delta, None, "used_counter_delta"
    if remaining_delta is not None:
        return remaining_delta, None, "remaining_counter_delta"
    return None, ReconciliationState.UNKNOWN, "no_comparable_counter"


def _allowed_tolerance(
    provider_delta: Decimal,
    expected_high: Decimal,
    policy: ReconciliationPolicy,
) -> Decimal:
    relative_tolerance = policy.relative_tolerance
    if not isinstance(relative_tolerance, Decimal):  # pragma: no cover - normalized by the model
        raise TypeError("relative tolerance was not normalized")
    with localcontext(_DECIMAL_WORK_CONTEXT):
        relative_base = max(abs(provider_delta), abs(expected_high))
        rounded_relative = _ceil_exact_tolerance_product(relative_base, relative_tolerance)
        return max(Decimal(policy.absolute_tolerance_units), rounded_relative)


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

    with localcontext(_DECIMAL_WORK_CONTEXT):
        expected_low = Decimal(ledger.settled_units) + Decimal(ledger.manual_adjustment_units)
        expected_high = expected_low + Decimal(ledger.pending_reserved_units)
        tolerance = _allowed_tolerance(provider_delta, expected_high, policy)
        within_low = provider_delta >= expected_low - tolerance
        within_high = provider_delta <= expected_high + tolerance
    provider_delta_units, provider_delta_text = _provider_delta_fields(provider_delta)
    allowed_tolerance_text = _canonical_allowed_tolerance(tolerance)
    if within_low and within_high:
        with localcontext(_DECIMAL_WORK_CONTEXT):
            direct_match = abs(provider_delta - expected_low) <= tolerance
        state = ReconciliationState.MATCHED if direct_match else ReconciliationState.WITHIN_PENDING
        consecutive = 0 if direct_match else prior_consecutive_mismatches
        return ReconciliationDecision(
            state=state,
            action=(ReconciliationAction.NONE if direct_match else ReconciliationAction.MONITOR),
            ownership=ownership,
            provider_delta_units=provider_delta_units,
            provider_delta_units_decimal=provider_delta_text,
            ledger_settled_units=ledger.settled_units,
            pending_reserved_units=ledger.pending_reserved_units,
            manual_adjustment_units=ledger.manual_adjustment_units,
            unexplained_delta_units=0,
            unexplained_delta_units_decimal="0",
            allowed_tolerance_units=int(tolerance),
            allowed_tolerance_units_decimal=allowed_tolerance_text,
            consecutive_mismatches=consecutive,
            preserve_pending_reservations=ledger.pending_reserved_units > 0,
            incident_required=False,
            quarantine_local=False,
            reason=("within_tolerance" if direct_match else "covered_by_pending_reservations"),
        )

    with localcontext(_DECIMAL_WORK_CONTEXT):
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
    unexplained_delta_units, unexplained_delta_text = _reconciliation_delta_fields(unexplained)
    return ReconciliationDecision(
        state=ReconciliationState.MISMATCH,
        action=action,
        ownership=ownership,
        provider_delta_units=provider_delta_units,
        provider_delta_units_decimal=provider_delta_text,
        ledger_settled_units=ledger.settled_units,
        pending_reserved_units=ledger.pending_reserved_units,
        manual_adjustment_units=ledger.manual_adjustment_units,
        unexplained_delta_units=unexplained_delta_units,
        unexplained_delta_units_decimal=unexplained_delta_text,
        allowed_tolerance_units=int(tolerance),
        allowed_tolerance_units_decimal=allowed_tolerance_text,
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
        provider_delta_units_decimal=None,
        ledger_settled_units=ledger.settled_units,
        pending_reserved_units=ledger.pending_reserved_units,
        manual_adjustment_units=ledger.manual_adjustment_units,
        unexplained_delta_units=None,
        unexplained_delta_units_decimal=None,
        allowed_tolerance_units=0,
        allowed_tolerance_units_decimal="0",
        consecutive_mismatches=prior_consecutive_mismatches,
        preserve_pending_reservations=True,
        incident_required=False,
        quarantine_local=False,
        reason=reason,
    )
