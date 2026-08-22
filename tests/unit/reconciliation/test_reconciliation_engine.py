from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
from decimal import MIN_EMIN, MIN_ETINY, Decimal, getcontext

import pytest

from gatehouse.core.provider_numbers import (
    DECIMAL_WORK_PRECISION,
    SQLITE_INT64_MAX,
    SQLITE_INT64_MIN,
    parse_canonical_provider_number,
)
from gatehouse.reconciliation import (
    LedgerWindow,
    OwnershipMode,
    ReconciliationAction,
    ReconciliationDecision,
    ReconciliationPolicy,
    ReconciliationState,
    UsageSnapshot,
    reconcile_usage,
)

POLICY = ReconciliationPolicy(
    absolute_tolerance_units=2,
    relative_tolerance=Decimal("0.05"),
    consecutive_mismatches_for_incident=2,
    maximum_snapshot_age_ms=100,
)


def _snapshot(
    captured_at_ms: int,
    *,
    remaining: int | None = None,
    used: int | None = None,
    period_start: int = 0,
    reset_marker: str = "period-a",
) -> UsageSnapshot:
    return UsageSnapshot(
        quota_scope_id="quota",
        unit="credits",
        captured_at_ms=captured_at_ms,
        remaining_units=remaining,
        used_units=used,
        plan_total_units=100,
        period_start_ms=period_start,
        period_end_ms=1_000,
        reset_marker=reset_marker,
    )


def _exact_snapshot(
    captured_at_ms: int,
    remaining: str,
    *,
    plan: str | None = "100",
) -> UsageSnapshot:
    remaining_exact = parse_canonical_provider_number(remaining)
    plan_exact = None if plan is None else parse_canonical_provider_number(plan)
    return UsageSnapshot(
        quota_scope_id="quota",
        unit="credits",
        captured_at_ms=captured_at_ms,
        remaining_units=remaining_exact.routing_units,
        plan_total_units=None if plan_exact is None else plan_exact.routing_units,
        observed_remaining_units_decimal=remaining_exact.canonical,
        observed_plan_total_units_decimal=(None if plan_exact is None else plan_exact.canonical),
        period_start_ms=0,
        period_end_ms=1_000,
        reset_marker="period-a",
    )


def _matched_decision() -> ReconciliationDecision:
    return reconcile_usage(
        previous=_exact_snapshot(10, "2", plan=None),
        current=_exact_snapshot(20, "1", plan=None),
        ledger=LedgerWindow(settled_units=1),
        ownership=OwnershipMode.EXCLUSIVE,
        policy=ReconciliationPolicy(0, Decimal("0")),
        prior_consecutive_mismatches=0,
        now_ms=20,
    )


def test_remaining_and_used_counters_match_ledger_with_combined_tolerance() -> None:
    decision = reconcile_usage(
        previous=_snapshot(10, remaining=100, used=0),
        current=_snapshot(20, remaining=90, used=10),
        ledger=LedgerWindow(settled_units=9),
        ownership=OwnershipMode.EXCLUSIVE,
        policy=POLICY,
        prior_consecutive_mismatches=1,
        now_ms=20,
    )
    assert decision.state is ReconciliationState.MATCHED
    assert decision.allowed_tolerance_units == 2
    assert decision.consecutive_mismatches == 0
    assert decision.action is ReconciliationAction.NONE


def test_pending_reservation_range_prevents_false_mismatch_but_stays_held() -> None:
    decision = reconcile_usage(
        previous=_snapshot(10, remaining=100),
        current=_snapshot(20, remaining=85),
        ledger=LedgerWindow(settled_units=0, pending_reserved_units=20),
        ownership=OwnershipMode.EXCLUSIVE,
        policy=POLICY,
        prior_consecutive_mismatches=1,
        now_ms=20,
    )
    assert decision.state is ReconciliationState.WITHIN_PENDING
    assert decision.preserve_pending_reservations
    assert decision.consecutive_mismatches == 1
    assert not decision.incident_required


def test_consecutive_exclusive_mismatch_quarantines_but_shared_only_investigates() -> None:
    previous = _snapshot(10, remaining=100)
    current = _snapshot(20, remaining=70)
    ledger = LedgerWindow(settled_units=0)
    exclusive = reconcile_usage(
        previous=previous,
        current=current,
        ledger=ledger,
        ownership=OwnershipMode.EXCLUSIVE,
        policy=POLICY,
        prior_consecutive_mismatches=1,
        now_ms=20,
    )
    shared = reconcile_usage(
        previous=previous,
        current=current,
        ledger=ledger,
        ownership=OwnershipMode.SHARED,
        policy=POLICY,
        prior_consecutive_mismatches=1,
        now_ms=20,
    )
    assert exclusive.action is ReconciliationAction.QUARANTINE_LOCAL
    assert exclusive.incident_required and exclusive.quarantine_local
    assert shared.action is ReconciliationAction.INVESTIGATE
    assert shared.incident_required and not shared.quarantine_local


def test_reset_and_stale_snapshots_are_unknown_without_erasing_prior_mismatch() -> None:
    reset = reconcile_usage(
        previous=_snapshot(10, remaining=5, reset_marker="old"),
        current=_snapshot(20, remaining=100, reset_marker="new"),
        ledger=LedgerWindow(settled_units=0, pending_reserved_units=7),
        ownership=OwnershipMode.EXCLUSIVE,
        policy=POLICY,
        prior_consecutive_mismatches=1,
        now_ms=20,
    )
    stale = reconcile_usage(
        previous=_snapshot(10, used=0),
        current=_snapshot(20, used=1),
        ledger=LedgerWindow(settled_units=1),
        ownership=OwnershipMode.EXCLUSIVE,
        policy=POLICY,
        prior_consecutive_mismatches=1,
        now_ms=121,
    )
    assert reset.state is ReconciliationState.RESET_DETECTED
    assert stale.state is ReconciliationState.STALE
    for decision in (reset, stale):
        assert decision.action is ReconciliationAction.HOLD_ROUTING
        assert decision.consecutive_mismatches == 1
        assert decision.preserve_pending_reservations
        assert not decision.quarantine_local


def test_disagreeing_remaining_and_used_counters_fail_conservatively() -> None:
    decision = reconcile_usage(
        previous=_snapshot(10, remaining=100, used=0),
        current=_snapshot(20, remaining=90, used=7),
        ledger=LedgerWindow(settled_units=10),
        ownership=OwnershipMode.UNKNOWN,
        policy=POLICY,
        prior_consecutive_mismatches=0,
        now_ms=20,
    )
    assert decision.state is ReconciliationState.UNKNOWN
    assert decision.provider_delta_units is None
    assert decision.provider_delta_units_decimal is None
    assert decision.unexplained_delta_units_decimal is None
    assert decision.allowed_tolerance_units_decimal == "0"
    assert decision.action is ReconciliationAction.HOLD_ROUTING


@pytest.mark.parametrize(
    ("previous", "current", "expected"),
    [
        ("0.25", "-0.75", "1"),
        ("-1.25", "-3.75", "2.5"),
        ("1.9", "1.1", "0.8"),
    ],
)
def test_remaining_delta_uses_exact_observations(
    previous: str,
    current: str,
    expected: str,
) -> None:
    decision = reconcile_usage(
        previous=_exact_snapshot(10, previous),
        current=_exact_snapshot(20, current),
        ledger=LedgerWindow(settled_units=0),
        ownership=OwnershipMode.EXCLUSIVE,
        policy=ReconciliationPolicy(0, Decimal("0")),
        prior_consecutive_mismatches=0,
        now_ms=20,
    )
    assert decision.provider_delta_units_decimal == expected


def test_fractional_match_and_mismatch_keep_exact_and_compatibility_fields_distinct() -> None:
    matched = reconcile_usage(
        previous=_exact_snapshot(10, "-1.25"),
        current=_exact_snapshot(20, "-3.75"),
        ledger=LedgerWindow(settled_units=2),
        ownership=OwnershipMode.EXCLUSIVE,
        policy=ReconciliationPolicy(1, Decimal("0")),
        prior_consecutive_mismatches=0,
        now_ms=20,
    )
    assert matched.state is ReconciliationState.MATCHED
    assert matched.provider_delta_units is None
    assert matched.provider_delta_units_decimal == "2.5"
    assert matched.unexplained_delta_units == 0
    assert matched.unexplained_delta_units_decimal == "0"

    mismatched = reconcile_usage(
        previous=_exact_snapshot(10, "1.9"),
        current=_exact_snapshot(20, "1.1"),
        ledger=LedgerWindow(settled_units=2),
        ownership=OwnershipMode.EXCLUSIVE,
        policy=ReconciliationPolicy(0, Decimal("0")),
        prior_consecutive_mismatches=0,
        now_ms=20,
    )
    assert mismatched.state is ReconciliationState.MISMATCH
    assert mismatched.provider_delta_units is None
    assert mismatched.provider_delta_units_decimal == "0.8"
    assert mismatched.unexplained_delta_units is None
    assert mismatched.unexplained_delta_units_decimal == "-1.2"


def test_exact_increase_and_plan_change_are_indeterminate_even_when_projections_tie() -> None:
    reset = reconcile_usage(
        previous=_exact_snapshot(10, "1.1"),
        current=_exact_snapshot(20, "1.9"),
        ledger=LedgerWindow(settled_units=0),
        ownership=OwnershipMode.EXCLUSIVE,
        policy=POLICY,
        prior_consecutive_mismatches=0,
        now_ms=20,
    )
    plan_change = reconcile_usage(
        previous=_exact_snapshot(10, "10", plan="1.1"),
        current=_exact_snapshot(20, "9", plan="1.9"),
        ledger=LedgerWindow(settled_units=1),
        ownership=OwnershipMode.EXCLUSIVE,
        policy=POLICY,
        prior_consecutive_mismatches=0,
        now_ms=20,
    )
    assert reset.state is ReconciliationState.RESET_DETECTED
    assert reset.reason == "remaining_counter_increased"
    assert plan_change.state is ReconciliationState.UNKNOWN
    assert plan_change.reason == "plan_total_changed_within_period"
    for decision in (reset, plan_change):
        assert decision.provider_delta_units is None
        assert decision.provider_delta_units_decimal is None
        assert decision.unexplained_delta_units is None
        assert decision.unexplained_delta_units_decimal is None


def test_saturated_observations_still_reconcile_their_exact_change() -> None:
    previous = str(SQLITE_INT64_MAX + 100)
    current = str(SQLITE_INT64_MAX + 99)
    decision = reconcile_usage(
        previous=_exact_snapshot(10, previous),
        current=_exact_snapshot(20, current),
        ledger=LedgerWindow(settled_units=1),
        ownership=OwnershipMode.EXCLUSIVE,
        policy=ReconciliationPolicy(0, Decimal("0")),
        prior_consecutive_mismatches=0,
        now_ms=20,
    )
    assert decision.state is ReconciliationState.MATCHED
    assert decision.provider_delta_units == 1
    assert decision.provider_delta_units_decimal == "1"


def test_maximum_provider_difference_preserves_all_383_significant_digits() -> None:
    large = "9" * 128
    tiny_negative = "-0." + "0" * 127 + "1" * 128
    decision = reconcile_usage(
        previous=_exact_snapshot(10, large, plan=None),
        current=_exact_snapshot(20, tiny_negative, plan="-0.5"),
        ledger=LedgerWindow(settled_units=0),
        ownership=OwnershipMode.EXCLUSIVE,
        policy=ReconciliationPolicy(0, Decimal("0")),
        prior_consecutive_mismatches=0,
        now_ms=20,
    )
    rendered = decision.provider_delta_units_decimal
    assert rendered is not None
    assert len(rendered) == 384
    assert len(rendered.replace(".", "").lstrip("0").rstrip("0")) == 383
    assert decision.provider_delta_units is None


def test_signed_int64_adjustment_preserves_384_digit_unexplained_delta_exactly() -> None:
    before = getcontext().copy()
    integer_part = "9" * 128
    fractional_part = "0" * 127 + "9" * 128
    previous = integer_part
    current = "-0." + fractional_part
    expected_provider = integer_part + "." + fractional_part
    expected_unexplained = "1" + "0" * 109 + str(2**63 - 1) + "." + fractional_part

    decision = reconcile_usage(
        previous=_exact_snapshot(10, previous, plan=None),
        current=_exact_snapshot(20, current, plan=None),
        ledger=LedgerWindow(
            settled_units=0,
            pending_reserved_units=0,
            manual_adjustment_units=SQLITE_INT64_MIN,
        ),
        ownership=OwnershipMode.EXCLUSIVE,
        policy=ReconciliationPolicy(0, Decimal("0")),
        prior_consecutive_mismatches=0,
        now_ms=20,
    )

    assert decision.state is ReconciliationState.MISMATCH
    assert decision.provider_delta_units_decimal == expected_provider
    assert decision.unexplained_delta_units_decimal == expected_unexplained
    assert len(expected_provider.replace(".", "")) == 383
    assert len(expected_unexplained.replace(".", "")) == 384
    assert len(expected_provider) == 384
    assert len(expected_unexplained) == 385
    assert decision.provider_delta_units is None
    assert decision.unexplained_delta_units is None
    after = getcontext()
    assert (after.prec, after.Emin, after.Emax, after.rounding, after.capitals, after.clamp) == (
        before.prec,
        before.Emin,
        before.Emax,
        before.rounding,
        before.capitals,
        before.clamp,
    )
    assert after.traps == before.traps
    assert after.flags == before.flags


def test_missing_plan_in_either_snapshot_remains_not_comparable() -> None:
    decision = reconcile_usage(
        previous=_exact_snapshot(10, "10", plan=None),
        current=_exact_snapshot(20, "9", plan="-0.5"),
        ledger=LedgerWindow(settled_units=1),
        ownership=OwnershipMode.EXCLUSIVE,
        policy=ReconciliationPolicy(0, Decimal("0")),
        prior_consecutive_mismatches=0,
        now_ms=20,
    )
    assert decision.state is ReconciliationState.MATCHED
    assert decision.provider_delta_units_decimal == "1"


def test_exact_tolerance_can_exceed_sqlite_int_without_changing_global_context() -> None:
    before_precision = getcontext().prec
    huge = "1" + "0" * 127
    decision = reconcile_usage(
        previous=_exact_snapshot(10, huge),
        current=_exact_snapshot(20, "0"),
        ledger=LedgerWindow(settled_units=0),
        ownership=OwnershipMode.EXCLUSIVE,
        policy=ReconciliationPolicy(0, Decimal("1")),
        prior_consecutive_mismatches=0,
        now_ms=20,
    )
    assert decision.allowed_tolerance_units > SQLITE_INT64_MAX
    assert decision.allowed_tolerance_units_decimal == huge
    assert decision.provider_delta_units is None
    assert decision.provider_delta_units_decimal == huge
    assert getcontext().prec == before_precision


def test_allowed_tolerance_supports_the_129_digit_opposite_sign_observation_bound() -> None:
    maximum = "9" * 128
    expected = str(2 * 10**128 - 2)
    decision = reconcile_usage(
        previous=_exact_snapshot(10, maximum, plan=None),
        current=_exact_snapshot(20, "-" + maximum, plan=None),
        ledger=LedgerWindow(settled_units=0),
        ownership=OwnershipMode.EXCLUSIVE,
        policy=ReconciliationPolicy(0, Decimal("1")),
        prior_consecutive_mismatches=0,
        now_ms=20,
    )

    assert len(expected) == 129
    assert decision.provider_delta_units_decimal == expected
    assert decision.allowed_tolerance_units == int(expected)
    assert decision.allowed_tolerance_units_decimal == expected


def test_tiny_relative_tolerance_uses_wide_local_context_without_mutating_global_context() -> None:
    before = getcontext().copy()
    decision = reconcile_usage(
        previous=_exact_snapshot(10, "2"),
        current=_exact_snapshot(20, "1"),
        ledger=LedgerWindow(settled_units=1),
        ownership=OwnershipMode.EXCLUSIVE,
        policy=ReconciliationPolicy(0, Decimal("1e-2000000")),
        prior_consecutive_mismatches=0,
        now_ms=20,
    )

    assert decision.allowed_tolerance_units == 1
    assert decision.allowed_tolerance_units_decimal == "1"
    after = getcontext()
    assert (after.prec, after.Emin, after.Emax, after.rounding, after.capitals, after.clamp) == (
        before.prec,
        before.Emin,
        before.Emax,
        before.rounding,
        before.capitals,
        before.clamp,
    )
    assert after.traps == before.traps
    assert after.flags == before.flags


def test_minimum_decimal_exponent_tolerance_has_an_exact_mathematical_ceiling() -> None:
    before = getcontext().copy()
    decision = reconcile_usage(
        previous=_exact_snapshot(10, "2"),
        current=_exact_snapshot(20, "1"),
        ledger=LedgerWindow(settled_units=1),
        ownership=OwnershipMode.EXCLUSIVE,
        policy=ReconciliationPolicy(0, Decimal((0, (1,), MIN_ETINY))),
        prior_consecutive_mismatches=0,
        now_ms=20,
    )

    assert decision.allowed_tolerance_units == 1
    assert decision.allowed_tolerance_units_decimal == "1"
    after = getcontext()
    assert (after.prec, after.Emin, after.Emax, after.rounding, after.capitals, after.clamp) == (
        before.prec,
        before.Emin,
        before.Emax,
        before.rounding,
        before.capitals,
        before.clamp,
    )
    assert after.traps == before.traps
    assert after.flags == before.flags


@pytest.mark.parametrize("product_exponent_offset", [-1, 0])
def test_tolerance_product_is_exact_at_the_work_context_etiny_boundary(
    product_exponent_offset: int,
) -> None:
    maximum = "9" * 128
    minimum = "-0." + "0" * 127 + "1" * 128
    work_etiny = MIN_EMIN - DECIMAL_WORK_PRECISION + 1
    # This maximum provider difference has a normalized exponent of -255.
    tolerance_exponent = work_etiny + 255 + product_exponent_offset
    decision = reconcile_usage(
        previous=_exact_snapshot(10, maximum, plan=None),
        current=_exact_snapshot(20, minimum, plan=None),
        ledger=LedgerWindow(settled_units=0),
        ownership=OwnershipMode.EXCLUSIVE,
        policy=ReconciliationPolicy(0, Decimal((0, (1,), tolerance_exponent))),
        prior_consecutive_mismatches=0,
        now_ms=20,
    )

    assert decision.allowed_tolerance_units == 1
    assert decision.allowed_tolerance_units_decimal == "1"


def test_relative_tolerance_multiplication_preserves_the_full_511_digit_product() -> None:
    maximum = "9" * 128
    minimum = "-0." + "0" * 127 + "1" * 128
    tolerance_digits = "9" * 128
    decision = reconcile_usage(
        previous=_exact_snapshot(10, maximum, plan=None),
        current=_exact_snapshot(20, minimum, plan=None),
        ledger=LedgerWindow(settled_units=0),
        ownership=OwnershipMode.EXCLUSIVE,
        policy=ReconciliationPolicy(0, Decimal("0." + tolerance_digits)),
        prior_consecutive_mismatches=0,
        now_ms=20,
    )

    provider_delta = decision.provider_delta_units_decimal
    assert provider_delta is not None
    integer_part, _, fractional_part = provider_delta.partition(".")
    provider_coefficient = int(integer_part + fractional_part)
    product_coefficient = provider_coefficient * int(tolerance_digits)
    assert len(str(product_coefficient)) == 511
    product_scale = len(fractional_part) + len(tolerance_digits)
    divisor = 10**product_scale
    quotient, remainder = divmod(product_coefficient, divisor)
    expected_ceiling = quotient + int(remainder != 0)
    assert decision.allowed_tolerance_units == expected_ceiling
    assert decision.allowed_tolerance_units_decimal == str(expected_ceiling)


def test_compatibility_fields_are_independently_nullable() -> None:
    decision = reconcile_usage(
        previous=_exact_snapshot(10, "0"),
        current=_exact_snapshot(20, "0"),
        ledger=LedgerWindow(settled_units=0, manual_adjustment_units=-(2**63)),
        ownership=OwnershipMode.EXCLUSIVE,
        policy=ReconciliationPolicy(0, Decimal("0")),
        prior_consecutive_mismatches=0,
        now_ms=20,
    )
    assert decision.provider_delta_units == 0
    assert decision.provider_delta_units_decimal == "0"
    assert decision.unexplained_delta_units is None
    assert decision.unexplained_delta_units_decimal == str(2**63)


def test_reconciliation_decision_rejects_inconsistent_exact_compatibility_pairs() -> None:
    decision = _matched_decision()
    invalid_mutations: tuple[Callable[[ReconciliationDecision], ReconciliationDecision], ...] = (
        lambda value: replace(value, provider_delta_units=2),
        lambda value: replace(
            value,
            provider_delta_units=1,
            provider_delta_units_decimal="1.5",
        ),
        lambda value: replace(value, provider_delta_units=True),
        lambda value: replace(value, unexplained_delta_units=1),
        lambda value: replace(
            value,
            provider_delta_units=None,
            provider_delta_units_decimal="9" * 384,
        ),
        lambda value: replace(
            value,
            unexplained_delta_units=None,
            unexplained_delta_units_decimal="9" * 385,
        ),
    )

    for mutation in invalid_mutations:
        with pytest.raises(ValueError):
            mutation(decision)


def test_reconciliation_decision_rejects_missing_or_state_inconsistent_delta_pairs() -> None:
    decision = _matched_decision()
    invalid_mutations: tuple[Callable[[ReconciliationDecision], ReconciliationDecision], ...] = (
        lambda value: replace(
            value,
            provider_delta_units=None,
            provider_delta_units_decimal=None,
        ),
        lambda value: replace(
            value,
            unexplained_delta_units=None,
            unexplained_delta_units_decimal=None,
        ),
    )
    for mutation in invalid_mutations:
        with pytest.raises(ValueError):
            mutation(decision)

    indeterminate = reconcile_usage(
        previous=None,
        current=None,
        ledger=LedgerWindow(settled_units=0),
        ownership=OwnershipMode.UNKNOWN,
        policy=ReconciliationPolicy(0, Decimal("0")),
        prior_consecutive_mismatches=0,
        now_ms=20,
    )
    with pytest.raises(ValueError):
        replace(
            indeterminate,
            provider_delta_units=0,
            provider_delta_units_decimal="0",
        )
    with pytest.raises(ValueError):
        replace(indeterminate, provider_delta_units=0)


def test_reconciliation_decision_rejects_invalid_or_mismatched_allowed_tolerance() -> None:
    decision = _matched_decision()
    for invalid in ("-1", "0.1", "1.0", "9" * 130):
        with pytest.raises(ValueError):
            replace(decision, allowed_tolerance_units_decimal=invalid)
    with pytest.raises(ValueError):
        replace(
            decision,
            allowed_tolerance_units=2,
            allowed_tolerance_units_decimal="1",
        )
    with pytest.raises(ValueError):
        replace(
            decision,
            allowed_tolerance_units=True,
            allowed_tolerance_units_decimal="1",
        )


def test_reconciliation_decision_accepts_role_specific_boundary_pairs() -> None:
    decision = _matched_decision()

    fractional = replace(
        decision,
        provider_delta_units=None,
        provider_delta_units_decimal="1.5",
    )
    out_of_range = replace(
        decision,
        provider_delta_units=None,
        provider_delta_units_decimal=str(2**63),
    )
    maximum_tolerance = "9" * 129
    tolerance = replace(
        decision,
        allowed_tolerance_units=int(maximum_tolerance),
        allowed_tolerance_units_decimal=maximum_tolerance,
    )

    assert fractional.provider_delta_units is None
    assert out_of_range.provider_delta_units is None
    assert tolerance.allowed_tolerance_units_decimal == maximum_tolerance


def test_policy_and_snapshot_validation_are_strict_and_exact() -> None:
    float_policy = ReconciliationPolicy(0, 0.1)
    assert float_policy.relative_tolerance == Decimal("0.1")
    for invalid in (Decimal("NaN"), Decimal("Infinity"), Decimal("-0.1"), Decimal("1.1")):
        with pytest.raises(ValueError):
            ReconciliationPolicy(0, invalid)
    with pytest.raises(ValueError):
        ReconciliationPolicy(False, Decimal("0"))
    with pytest.raises(ValueError):
        ReconciliationPolicy(SQLITE_INT64_MAX + 1, Decimal("0"))
    with pytest.raises(ValueError):
        ReconciliationPolicy(0, Decimal("0." + "1" * 129))

    with pytest.raises(ValueError):
        UsageSnapshot(
            quota_scope_id="quota",
            unit="credits",
            captured_at_ms=1,
            remaining_units=1,
            observed_remaining_units_decimal="1.0",
        )
    with pytest.raises(ValueError):
        UsageSnapshot(
            quota_scope_id="quota",
            unit="credits",
            captured_at_ms=1,
            remaining_units=1,
            observed_remaining_units_decimal="2.5",
        )
    compatible = UsageSnapshot("quota", "credits", 1, remaining_units=7, plan_total_units=10)
    assert compatible.observed_remaining_units_decimal == "7"
    assert compatible.observed_plan_total_units_decimal == "10"
