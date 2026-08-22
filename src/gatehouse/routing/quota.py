"""Atomic quota reservation selection and conservative settlement."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from gatehouse.core.clock import require_utc_ms
from gatehouse.core.ids import QuotaScopeId, RequestId
from gatehouse.core.provider_numbers import require_sqlite_int64
from gatehouse.database.repository import (
    QuotaReservationResult,
    QuotaReservationStatus,
)

from .models import RouteCandidate, RoutingPlan


class ReservationState(StrEnum):
    ACTIVE = "ACTIVE"
    RECONCILED = "RECONCILED"
    PENDING_RECONCILIATION = "PENDING_RECONCILIATION"


class QuotaReservationRepository(Protocol):
    """Short, synchronous transaction boundary; implementations must commit on return."""

    def reserve_quota(
        self,
        *,
        request_id: str,
        quota_scope_id: str,
        amount_units: int,
        unit: str,
        now_ms: int,
        expires_at_ms: int,
        reservation_id: str | None = None,
        metadata: dict[str, object] | None = None,
    ) -> QuotaReservationResult: ...

    def reconcile_quota_reservation(
        self,
        *,
        reservation_id: str,
        actual_units: int | None,
        now_ms: int,
        outcome_known: bool,
    ) -> bool: ...

    def replace_quota_reservation(
        self,
        *,
        old_reservation_id: str,
        request_id: str,
        quota_scope_id: str,
        amount_units: int,
        unit: str,
        now_ms: int,
        expires_at_ms: int,
        reservation_id: str | None = None,
        metadata: dict[str, object] | None = None,
    ) -> QuotaReservationResult: ...


@dataclass(frozen=True, slots=True)
class QuotaReservation:
    reservation_id: str
    request_id: RequestId
    quota_scope_id: QuotaScopeId
    amount_units: int
    unit: str
    created_at_ms: int
    expires_at_ms: int
    state: ReservationState = ReservationState.ACTIVE
    actual_units: int | None = None

    def __post_init__(self) -> None:
        if not self.reservation_id or not self.unit:
            raise ValueError("reservation identifier and unit are required")
        require_sqlite_int64(self.amount_units, field="reservation amount", minimum=0)
        if self.amount_units == 0:
            raise ValueError("reservation amount must be positive")
        require_utc_ms(self.created_at_ms)
        require_utc_ms(self.expires_at_ms)
        if self.expires_at_ms <= self.created_at_ms:
            raise ValueError("reservation expiration must follow creation")
        if self.actual_units is not None:
            require_sqlite_int64(
                self.actual_units,
                field="actual quota usage",
                minimum=0,
            )
        if self.state is ReservationState.ACTIVE and self.actual_units is not None:
            raise ValueError("an active reservation cannot contain settled usage")


@dataclass(frozen=True, slots=True)
class ReservationGrant:
    reservation: QuotaReservation | None
    selected: RouteCandidate
    same_scope_candidates: tuple[RouteCandidate, ...]

    def __post_init__(self) -> None:
        if not self.same_scope_candidates or self.same_scope_candidates[0] != self.selected:
            raise ValueError("selected candidate must lead the same-scope candidates")
        for candidate in self.same_scope_candidates:
            if (
                self.reservation is not None
                and candidate.scope.quota_scope_id != self.reservation.quota_scope_id
            ):
                raise ValueError("reservation candidates must share one quota scope")


class QuotaUnavailableError(RuntimeError):
    def __init__(self, statuses: Mapping[QuotaScopeId, QuotaReservationStatus]) -> None:
        self.statuses = dict(statuses)
        super().__init__("no quota scope in the selected pool could reserve capacity")


class QuotaReservationManager:
    """Try each eligible scope once, in the deterministic order from a route plan."""

    def __init__(self, repository: QuotaReservationRepository) -> None:
        self.repository = repository

    def reserve(
        self,
        *,
        plan: RoutingPlan,
        request_id: RequestId,
        now_ms: int,
        expires_at_ms: int,
        exclude_scope_ids: Iterable[QuotaScopeId] = (),
    ) -> ReservationGrant:
        require_sqlite_int64(
            plan.estimated_cost_units,
            field="estimated cost",
            minimum=0,
        )
        require_utc_ms(now_ms)
        require_utc_ms(expires_at_ms)
        if expires_at_ms <= now_ms:
            raise ValueError("reservation expiration must be in the future")
        excluded = set(exclude_scope_ids)
        if plan.estimated_cost_units == 0:
            selected = next(
                (
                    candidate
                    for candidate in plan.candidates
                    if candidate.scope.quota_scope_id not in excluded
                ),
                None,
            )
            if selected is None:
                raise QuotaUnavailableError({})
            same_scope = tuple(
                item
                for item in plan.candidates
                if item.scope.quota_scope_id == selected.scope.quota_scope_id
            )
            return ReservationGrant(
                reservation=None,
                selected=selected,
                same_scope_candidates=same_scope,
            )
        statuses: dict[QuotaScopeId, QuotaReservationStatus] = {}
        tried: set[QuotaScopeId] = set()
        for candidate in plan.candidates:
            scope_id = candidate.scope.quota_scope_id
            if scope_id in tried or scope_id in excluded:
                continue
            tried.add(scope_id)
            result = self.repository.reserve_quota(
                request_id=str(request_id),
                quota_scope_id=str(scope_id),
                amount_units=plan.estimated_cost_units,
                unit=plan.unit,
                now_ms=now_ms,
                expires_at_ms=expires_at_ms,
                metadata={
                    "pool_id": str(plan.pool_id),
                    "pool_name": plan.pool_name,
                    "operation": plan.operation,
                },
            )
            statuses[scope_id] = result.status
            if not result.reserved or result.reservation_id is None:
                if not plan.automatic_failover_within_pool:
                    break
                continue
            same_scope = tuple(
                item for item in plan.candidates if item.scope.quota_scope_id == scope_id
            )
            return ReservationGrant(
                reservation=QuotaReservation(
                    reservation_id=result.reservation_id,
                    request_id=request_id,
                    quota_scope_id=scope_id,
                    amount_units=plan.estimated_cost_units,
                    unit=plan.unit,
                    created_at_ms=now_ms,
                    expires_at_ms=expires_at_ms,
                ),
                selected=same_scope[0],
                same_scope_candidates=same_scope,
            )
        raise QuotaUnavailableError(statuses)

    def replace_expired(
        self,
        reservation: QuotaReservation,
        *,
        plan: RoutingPlan,
        request_id: RequestId,
        now_ms: int,
        expires_at_ms: int,
        exclude_scope_ids: Iterable[QuotaScopeId] = (),
    ) -> ReservationGrant:
        """Atomically replace one expired pre-dispatch reservation."""

        require_sqlite_int64(
            plan.estimated_cost_units,
            field="estimated cost",
            minimum=0,
        )
        require_utc_ms(now_ms)
        require_utc_ms(expires_at_ms)
        if reservation.request_id != request_id:
            raise ValueError("replacement request does not own the reservation")
        if reservation.state is not ReservationState.ACTIVE:
            raise ValueError("only an active reservation can be replaced")
        if reservation.expires_at_ms > now_ms:
            raise ValueError("only an expired reservation can be replaced")
        if expires_at_ms <= now_ms:
            raise ValueError("replacement expiration must be in the future")
        if plan.estimated_cost_units <= 0:
            raise ValueError("zero-cost plans do not have replaceable reservations")

        excluded = set(exclude_scope_ids)
        statuses: dict[QuotaScopeId, QuotaReservationStatus] = {}
        tried: set[QuotaScopeId] = set()
        for candidate in plan.candidates:
            scope_id = candidate.scope.quota_scope_id
            if scope_id in tried or scope_id in excluded:
                continue
            tried.add(scope_id)
            result = self.repository.replace_quota_reservation(
                old_reservation_id=reservation.reservation_id,
                request_id=str(request_id),
                quota_scope_id=str(scope_id),
                amount_units=plan.estimated_cost_units,
                unit=plan.unit,
                now_ms=now_ms,
                expires_at_ms=expires_at_ms,
                metadata={
                    "pool_id": str(plan.pool_id),
                    "pool_name": plan.pool_name,
                    "operation": plan.operation,
                    "replaces_reservation_id": reservation.reservation_id,
                },
            )
            statuses[scope_id] = result.status
            if not result.reserved or result.reservation_id is None:
                if not plan.automatic_failover_within_pool:
                    break
                continue
            same_scope = tuple(
                item for item in plan.candidates if item.scope.quota_scope_id == scope_id
            )
            return ReservationGrant(
                reservation=QuotaReservation(
                    reservation_id=result.reservation_id,
                    request_id=request_id,
                    quota_scope_id=scope_id,
                    amount_units=plan.estimated_cost_units,
                    unit=plan.unit,
                    created_at_ms=now_ms,
                    expires_at_ms=expires_at_ms,
                ),
                selected=same_scope[0],
                same_scope_candidates=same_scope,
            )
        raise QuotaUnavailableError(statuses)

    def reconcile_known(
        self,
        reservation: QuotaReservation,
        *,
        actual_units: int,
        now_ms: int,
    ) -> QuotaReservation:
        actual_units = require_sqlite_int64(
            actual_units,
            field="actual quota usage",
            minimum=0,
        )
        if reservation.state not in {
            ReservationState.ACTIVE,
            ReservationState.PENDING_RECONCILIATION,
        }:
            raise ValueError("only an active or pending reservation can be reconciled")
        require_utc_ms(now_ms)
        if not self.repository.reconcile_quota_reservation(
            reservation_id=reservation.reservation_id,
            actual_units=actual_units,
            now_ms=now_ms,
            outcome_known=True,
        ):
            raise RuntimeError("quota reservation could not be reconciled")
        return QuotaReservation(
            reservation_id=reservation.reservation_id,
            request_id=reservation.request_id,
            quota_scope_id=reservation.quota_scope_id,
            amount_units=reservation.amount_units,
            unit=reservation.unit,
            created_at_ms=reservation.created_at_ms,
            expires_at_ms=reservation.expires_at_ms,
            state=ReservationState.RECONCILED,
            actual_units=actual_units,
        )

    def hold_for_reconciliation(
        self,
        reservation: QuotaReservation,
        *,
        now_ms: int,
    ) -> QuotaReservation:
        if reservation.state is not ReservationState.ACTIVE:
            raise ValueError("only an active reservation can be held")
        require_utc_ms(now_ms)
        if not self.repository.reconcile_quota_reservation(
            reservation_id=reservation.reservation_id,
            actual_units=None,
            now_ms=now_ms,
            outcome_known=False,
        ):
            raise RuntimeError("quota reservation could not be retained")
        return QuotaReservation(
            reservation_id=reservation.reservation_id,
            request_id=reservation.request_id,
            quota_scope_id=reservation.quota_scope_id,
            amount_units=reservation.amount_units,
            unit=reservation.unit,
            created_at_ms=reservation.created_at_ms,
            expires_at_ms=reservation.expires_at_ms,
            state=ReservationState.PENDING_RECONCILIATION,
        )
