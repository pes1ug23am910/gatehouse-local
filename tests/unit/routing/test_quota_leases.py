from __future__ import annotations

from collections.abc import Callable

import pytest

from gatehouse.core.ids import (
    CredentialId,
    LeaseId,
    PoolId,
    PrincipalId,
    QuotaScopeId,
    RequestId,
)
from gatehouse.database.repository import (
    LeaseResult,
    LeaseStatus,
    QuotaReservationResult,
    QuotaReservationStatus,
)
from gatehouse.routing import (
    CredentialLeaseManager,
    CredentialLeaseUnavailableError,
    NamedPool,
    NamedPoolRouter,
    PoolMember,
    PoolSelectionStrategy,
    QuotaReservationManager,
    QuotaScopeSnapshot,
    ReservationState,
    RoutingCredential,
)

_A = "00000000000000000000000001"
_B = "00000000000000000000000002"


def named_pool() -> NamedPool:
    members = []
    for suffix in (_A, _B):
        principal = PrincipalId(f"prn_{suffix}")
        scope = QuotaScopeId(f"quota_{suffix}")
        members.append(
            PoolMember(
                QuotaScopeSnapshot(
                    scope,
                    principal,
                    "service",
                    "credits",
                    last_known_remaining_units=100,
                    configured_floor_units=10,
                ),
                (RoutingCredential(CredentialId(f"cred_{suffix}"), principal, scope),),
                cost_rank=1 if suffix == _A else 2,
            )
        )
    return NamedPool(
        PoolId(f"pool_{_A}"),
        "default",
        "service",
        PoolSelectionStrategy.CHEAPEST_FIRST,
        tuple(members),
        minimum_remaining_floor_units=10,
    )


class QuotaRepository:
    def __init__(self) -> None:
        self.reserve_calls: list[str] = []
        self.reconcile_calls: list[tuple[str, int | None, bool]] = []

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
    ) -> QuotaReservationResult:
        del request_id, amount_units, unit, now_ms, expires_at_ms, reservation_id, metadata
        self.reserve_calls.append(quota_scope_id)
        if quota_scope_id == f"quota_{_A}":
            return QuotaReservationResult(
                QuotaReservationStatus.EXHAUSTED,
                None,
                0,
                0,
            )
        return QuotaReservationResult(
            QuotaReservationStatus.RESERVED,
            "reservation-b",
            90,
            85,
        )

    def reconcile_quota_reservation(
        self,
        *,
        reservation_id: str,
        actual_units: int | None,
        now_ms: int,
        outcome_known: bool,
    ) -> bool:
        del now_ms
        self.reconcile_calls.append((reservation_id, actual_units, outcome_known))
        return True

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
    ) -> QuotaReservationResult:
        del old_reservation_id, request_id, amount_units, unit, now_ms
        del expires_at_ms, reservation_id, metadata
        self.reserve_calls.append(quota_scope_id)
        return QuotaReservationResult(
            QuotaReservationStatus.RESERVED,
            "reservation-replacement",
            90,
            85,
        )


def test_reservation_tries_each_scope_once_and_reconciles_known_usage() -> None:
    plan = NamedPoolRouter([named_pool()]).plan(
        service_id="service",
        operation="service.read",
        pool_name="default",
        estimated_cost_units=5,
        unit="credits",
        now_ms=10,
    )
    repository = QuotaRepository()
    manager = QuotaReservationManager(repository)

    grant = manager.reserve(
        plan=plan,
        request_id=RequestId(f"req_{_A}"),
        now_ms=10,
        expires_at_ms=100,
    )
    assert repository.reserve_calls == [f"quota_{_A}", f"quota_{_B}"]
    assert grant.reservation is not None
    assert grant.reservation.quota_scope_id == QuotaScopeId(f"quota_{_B}")

    settled = manager.reconcile_known(grant.reservation, actual_units=3, now_ms=20)
    assert settled.state is ReservationState.RECONCILED
    assert settled.actual_units == 3
    assert repository.reconcile_calls == [("reservation-b", 3, True)]


def test_unknown_usage_is_held_and_zero_cost_skips_repository() -> None:
    repository = QuotaRepository()
    manager = QuotaReservationManager(repository)
    plan = NamedPoolRouter([named_pool()]).plan(
        service_id="service",
        operation="service.status",
        pool_name="default",
        estimated_cost_units=0,
        unit="credits",
        now_ms=10,
    )

    grant = manager.reserve(
        plan=plan,
        request_id=RequestId(f"req_{_A}"),
        now_ms=10,
        expires_at_ms=100,
    )

    assert grant.reservation is None
    assert repository.reserve_calls == []


class LeaseRepository:
    def __init__(self, status: LeaseStatus) -> None:
        self.status = status
        self.released: list[str] = []
        self.acquire_calls: list[dict[str, object]] = []

    def acquire_credential_lease(
        self,
        *,
        credential_id: str,
        credential_generation: int,
        quota_scope_id: str,
        pool_id: str,
        owner_id: str,
        now_ms: int,
        expires_at_ms: int,
        exact_affinity: bool = False,
        lease_id: str | None = None,
        metadata: dict[str, object] | None = None,
    ) -> LeaseResult:
        self.acquire_calls.append(
            {
                "credential_id": credential_id,
                "credential_generation": credential_generation,
                "quota_scope_id": quota_scope_id,
                "pool_id": pool_id,
                "owner_id": owner_id,
                "now_ms": now_ms,
                "exact_affinity": exact_affinity,
                "metadata": metadata,
            }
        )
        return LeaseResult(
            self.status,
            lease_id if self.status is LeaseStatus.ACQUIRED else None,
            None,
            expires_at_ms if self.status is LeaseStatus.ACQUIRED else None,
        )

    def release_lease(
        self,
        *,
        lease_id: str,
        owner_id: str,
        now_ms: int,
    ) -> bool:
        del owner_id, now_ms
        self.released.append(lease_id)
        return True


def lease_factory() -> LeaseId:
    return LeaseId(f"lease_{_A}")


def test_logical_credential_lease_is_typed_and_owner_released() -> None:
    repository = LeaseRepository(LeaseStatus.ACQUIRED)
    manager = CredentialLeaseManager(repository, id_factory=lease_factory)
    candidate = (
        NamedPoolRouter([named_pool()])
        .plan(
            service_id="service",
            operation="service.read",
            pool_name="default",
            estimated_cost_units=1,
            unit="credits",
            now_ms=1,
        )
        .candidates[0]
    )

    lease = manager.acquire(
        candidate=candidate,
        request_id=RequestId(f"req_{_A}"),
        now_ms=1,
        expires_at_ms=10,
    )
    assert lease.lease_id == LeaseId(f"lease_{_A}")
    assert repository.acquire_calls == [
        {
            "credential_id": f"cred_{_A}",
            "credential_generation": 1,
            "quota_scope_id": f"quota_{_A}",
            "pool_id": f"pool_{_A}",
            "owner_id": f"req_{_A}",
            "now_ms": 1,
            "exact_affinity": False,
            "metadata": None,
        }
    ]
    assert manager.release(lease, now_ms=2)
    assert repository.released == [str(lease.lease_id)]

    busy: Callable[[], LeaseId] = lease_factory
    with pytest.raises(
        CredentialLeaseUnavailableError,
        match="^credential lease is unavailable$",
    ):
        CredentialLeaseManager(
            LeaseRepository(LeaseStatus.BUSY),
            id_factory=busy,
        ).acquire(
            candidate=candidate,
            request_id=RequestId(f"req_{_A}"),
            now_ms=1,
            expires_at_ms=10,
        )


def test_logical_credential_lease_forwards_exact_affinity_and_hides_ineligibility() -> None:
    candidate = (
        NamedPoolRouter([named_pool()])
        .plan(
            service_id="service",
            operation="service.status",
            pool_name="default",
            estimated_cost_units=0,
            unit="credits",
            now_ms=1,
        )
        .candidates[0]
    )
    repository = LeaseRepository(LeaseStatus.INELIGIBLE)
    manager = CredentialLeaseManager(repository, id_factory=lease_factory)

    with pytest.raises(
        CredentialLeaseUnavailableError,
        match="^credential lease is unavailable$",
    ):
        manager.acquire(
            candidate=candidate,
            request_id=RequestId(f"req_{_A}"),
            now_ms=1,
            expires_at_ms=10,
            exact_affinity=True,
        )

    assert repository.acquire_calls[0]["exact_affinity"] is True
