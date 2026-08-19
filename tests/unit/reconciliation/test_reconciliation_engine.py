from __future__ import annotations

from decimal import Decimal

from gatehouse.reconciliation import (
    LedgerWindow,
    OwnershipMode,
    ReconciliationAction,
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
    assert decision.action is ReconciliationAction.HOLD_ROUTING
