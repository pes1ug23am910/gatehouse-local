"""Deterministic, fail-closed selection inside one explicitly named pool."""

from __future__ import annotations

from collections.abc import Iterable
from itertools import islice

from gatehouse.core.clock import require_utc_ms
from gatehouse.core.provider_numbers import require_sqlite_int64
from gatehouse.core.states import CredentialState

from .affinity import ResourceAffinity
from .models import (
    NamedPool,
    PoolMember,
    PoolSelectionStrategy,
    QuotaScopeState,
    RouteCandidate,
    RoutingPlan,
    require_route_candidate_limit,
)
from .retry import BreakerKey, BreakerScopeType, CircuitBreakerRegistry


class RoutingError(RuntimeError):
    """Base class for safe named-pool routing failures."""


class NoEligiblePoolError(RoutingError):
    pass


class NoEligibleCredentialError(RoutingError):
    pass


class AffinityUnavailableError(RoutingError):
    pass


class NamedPoolRouter:
    """Create an immutable route plan without consulting any unselected pool."""

    def __init__(
        self,
        pools: Iterable[NamedPool],
        *,
        circuit_breakers: CircuitBreakerRegistry | None = None,
        maximum_route_candidates: int = 32,
    ) -> None:
        self._maximum_route_candidates = require_route_candidate_limit(maximum_route_candidates)
        indexed: dict[tuple[str, str], NamedPool] = {}
        for pool in pools:
            key = (pool.service_id, pool.name)
            if key in indexed:
                raise ValueError("pool names must be unique within a service")
            indexed[key] = pool
        if not indexed:
            raise ValueError("at least one named pool is required")
        self._pools = indexed
        self._circuit_breakers = circuit_breakers

    def plan(
        self,
        *,
        service_id: str,
        operation: str,
        pool_name: str,
        estimated_cost_units: int,
        unit: str,
        now_ms: int,
        affinity: ResourceAffinity | None = None,
        automatic: bool = True,
        reconciliation: bool = False,
    ) -> RoutingPlan:
        estimated_cost_units = require_sqlite_int64(
            estimated_cost_units,
            field="estimated cost",
            minimum=0,
        )
        require_utc_ms(now_ms)
        if not service_id or not operation or not pool_name or not unit:
            raise ValueError("routing identifiers and unit are required")
        if reconciliation and (affinity is None or estimated_cost_units != 0):
            raise ValueError(
                "resource reconciliation requires exact affinity and zero estimated cost"
            )
        pool = self._pools.get((service_id, pool_name))
        if pool is None or (automatic and not pool.automatic_use):
            raise NoEligiblePoolError("the selected named pool is unavailable")

        if affinity is not None:
            if affinity.service_id != service_id or affinity.pool_id != pool.pool_id:
                raise AffinityUnavailableError(
                    "resource affinity does not belong to the selected named pool"
                )

        eligible_members = list(
            islice(
                (
                    member
                    for member in pool.members
                    if self._member_eligible(
                        member,
                        pool=pool,
                        operation=operation,
                        estimated_cost_units=estimated_cost_units,
                        unit=unit,
                        now_ms=now_ms,
                        affinity=affinity,
                        reconciliation=reconciliation,
                    )
                ),
                self._maximum_route_candidates + 1,
            )
        )
        if len(eligible_members) > self._maximum_route_candidates:
            raise NoEligiblePoolError("the selected named pool exceeds the candidate limit")
        ordered_members = self._rank_members(pool, eligible_members)
        candidates: list[RouteCandidate] = []
        for member in ordered_members:
            credentials = sorted(
                islice(
                    (
                        credential
                        for credential in member.credentials
                        if (
                            credential.eligible_at(now_ms)
                            if affinity is None
                            else (
                                credential.credential_id == affinity.credential_id
                                and credential.generation == affinity.credential_generation
                                and credential.state
                                in {CredentialState.HEALTHY, CredentialState.DRAINING}
                                and (
                                    credential.expires_at_ms is None
                                    or credential.expires_at_ms > now_ms
                                )
                            )
                        )
                        and (
                            reconciliation
                            or self._breaker_available(
                                BreakerScopeType.CREDENTIAL,
                                str(credential.credential_id),
                                now_ms=now_ms,
                            )
                        )
                        and (
                            affinity is None
                            or (
                                credential.principal_id == affinity.principal_id
                                and credential.quota_scope_id == affinity.quota_scope_id
                            )
                        )
                    ),
                    self._maximum_route_candidates - len(candidates) + 1,
                ),
                key=lambda credential: (
                    credential.credential_id
                    != (affinity.credential_id if affinity is not None else None),
                    -credential.generation,
                    str(credential.credential_id),
                ),
            )
            if len(candidates) + len(credentials) > self._maximum_route_candidates:
                raise NoEligiblePoolError("the selected named pool exceeds the candidate limit")
            candidates.extend(
                RouteCandidate(
                    pool_id=pool.pool_id,
                    pool_name=pool.name,
                    service_id=pool.service_id,
                    scope=member.scope,
                    credential=credential,
                    priority=member.priority,
                    cost_rank=member.cost_rank,
                )
                for credential in credentials
            )

        if not candidates:
            if affinity is not None:
                raise AffinityUnavailableError(
                    "no credential can satisfy the persisted resource affinity"
                )
            raise NoEligibleCredentialError("the selected named pool has no eligible credential")
        return RoutingPlan(
            pool_id=pool.pool_id,
            pool_name=pool.name,
            service_id=pool.service_id,
            operation=operation,
            estimated_cost_units=estimated_cost_units,
            unit=unit,
            automatic_failover_within_pool=pool.automatic_failover_within_pool,
            candidates=tuple(candidates),
        )

    def _member_eligible(
        self,
        member: PoolMember,
        *,
        pool: NamedPool,
        operation: str,
        estimated_cost_units: int,
        unit: str,
        now_ms: int,
        affinity: ResourceAffinity | None,
        reconciliation: bool,
    ) -> bool:
        if not member.enabled or member.balance_authority_corrupt:
            return False
        scope = member.scope
        if affinity is not None and (
            scope.principal_id != affinity.principal_id
            or scope.quota_scope_id != affinity.quota_scope_id
        ):
            return False
        if reconciliation:
            if scope.unit != unit or scope.state in {
                QuotaScopeState.DISABLED,
                QuotaScopeState.QUARANTINED,
            }:
                return False
            return True
        if not scope.eligible_for(
            amount_units=estimated_cost_units,
            unit=unit,
            now_ms=now_ms,
            floor_units=pool.minimum_remaining_floor_units,
        ):
            return False
        return all(
            (
                self._breaker_available(
                    BreakerScopeType.SERVICE,
                    pool.service_id,
                    now_ms=now_ms,
                ),
                self._breaker_available(
                    BreakerScopeType.PROVIDER_OPERATION,
                    operation,
                    now_ms=now_ms,
                ),
                self._breaker_available(
                    BreakerScopeType.QUOTA_SCOPE,
                    str(scope.quota_scope_id),
                    now_ms=now_ms,
                ),
            )
        )

    def _breaker_available(
        self,
        scope_type: BreakerScopeType,
        scope_id: str,
        *,
        now_ms: int,
    ) -> bool:
        if self._circuit_breakers is None:
            return True
        return self._circuit_breakers.is_available(
            BreakerKey(scope_type, scope_id),
            now_ms=now_ms,
        )

    @staticmethod
    def _rank_members(pool: NamedPool, members: list[PoolMember]) -> list[PoolMember]:
        if pool.selection_strategy is PoolSelectionStrategy.CHEAPEST_FIRST:
            return sorted(
                members,
                key=lambda member: (
                    member.cost_rank,
                    member.priority,
                    str(member.scope.quota_scope_id),
                ),
            )
        if pool.selection_strategy is PoolSelectionStrategy.FILL_FIRST:
            return sorted(
                members,
                key=lambda member: (
                    member.priority,
                    member.cost_rank,
                    str(member.scope.quota_scope_id),
                ),
            )
        return sorted(members, key=lambda member: str(member.scope.quota_scope_id))
