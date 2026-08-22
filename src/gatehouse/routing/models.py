"""Immutable routing inputs and plans for explicitly named resource pools."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Literal

from gatehouse.core.clock import require_utc_ms
from gatehouse.core.ids import CredentialId, PoolId, PrincipalId, QuotaScopeId
from gatehouse.core.provider_numbers import require_sqlite_int64
from gatehouse.core.states import CredentialState


class PoolSelectionStrategy(StrEnum):
    """Deterministic strategies supported by named pools."""

    CHEAPEST_FIRST = "cheapest_first"
    FILL_FIRST = "fill_first"
    PINNED = "pinned"


class QuotaScopeState(StrEnum):
    """Eligibility state for a shared provider billing or rate-limit scope."""

    HEALTHY = "HEALTHY"
    COOLDOWN = "COOLDOWN"
    EXHAUSTED = "EXHAUSTED"
    DISABLED = "DISABLED"
    QUARANTINED = "QUARANTINED"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True, slots=True)
class RoutingCredential:
    credential_id: CredentialId
    principal_id: PrincipalId
    quota_scope_id: QuotaScopeId
    state: CredentialState = CredentialState.HEALTHY
    generation: int = 1
    expires_at_ms: int | None = None

    def __post_init__(self) -> None:
        if self.generation <= 0:
            raise ValueError("credential generation must be positive")
        if self.expires_at_ms is not None:
            require_utc_ms(self.expires_at_ms)

    def eligible_at(self, now_ms: int) -> bool:
        require_utc_ms(now_ms)
        return self.state is CredentialState.HEALTHY and (
            self.expires_at_ms is None or self.expires_at_ms > now_ms
        )


@dataclass(frozen=True, slots=True)
class QuotaScopeSnapshot:
    quota_scope_id: QuotaScopeId
    principal_id: PrincipalId
    service_id: str
    unit: str
    state: QuotaScopeState = QuotaScopeState.HEALTHY
    last_known_remaining_units: int | None = None
    configured_floor_units: int = 0
    active_reserved_units: int = 0
    cooldown_until_ms: int | None = None

    def __post_init__(self) -> None:
        if not self.service_id or not self.unit:
            raise ValueError("service_id and unit are required")
        for name, value in (
            ("last_known_remaining_units", self.last_known_remaining_units),
            ("configured_floor_units", self.configured_floor_units),
            ("active_reserved_units", self.active_reserved_units),
        ):
            if value is not None:
                require_sqlite_int64(value, field=name, minimum=0)
        if self.cooldown_until_ms is not None:
            require_utc_ms(self.cooldown_until_ms)

    def available_units(self, *, floor_units: int | None = None) -> int | None:
        if floor_units is not None:
            require_sqlite_int64(floor_units, field="floor_units", minimum=0)
        if self.last_known_remaining_units is None:
            return None
        effective_floor = max(
            self.configured_floor_units,
            self.configured_floor_units if floor_units is None else floor_units,
        )
        return max(
            0,
            self.last_known_remaining_units - self.active_reserved_units - effective_floor,
        )

    def eligible_for(
        self,
        *,
        amount_units: int,
        unit: str,
        now_ms: int,
        floor_units: int,
    ) -> bool:
        require_sqlite_int64(amount_units, field="amount_units", minimum=0)
        require_sqlite_int64(floor_units, field="floor_units", minimum=0)
        require_utc_ms(now_ms)
        if self.state is not QuotaScopeState.HEALTHY or self.unit != unit:
            return False
        if self.cooldown_until_ms is not None and self.cooldown_until_ms > now_ms:
            return False
        available = self.available_units(floor_units=floor_units)
        return available is not None and available >= amount_units


@dataclass(frozen=True, slots=True)
class PoolMember:
    scope: QuotaScopeSnapshot
    credentials: tuple[RoutingCredential, ...]
    priority: int = 100
    cost_rank: int = 100
    enabled: bool = True
    balance_authority_corrupt: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.balance_authority_corrupt, bool):
            raise TypeError("balance-authority corruption marker must be a boolean")
        if self.priority < 0 or self.cost_rank < 0:
            raise ValueError("pool member priority and cost rank cannot be negative")
        if not self.credentials:
            raise ValueError("a pool member must contain at least one credential")
        identifiers = [credential.credential_id for credential in self.credentials]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("credential identifiers must be unique within a member")
        for credential in self.credentials:
            if credential.principal_id != self.scope.principal_id:
                raise ValueError("credential and quota scope principals must match")
            if credential.quota_scope_id != self.scope.quota_scope_id:
                raise ValueError("credential must belong to the member quota scope")


@dataclass(frozen=True, slots=True)
class NamedPool:
    pool_id: PoolId
    name: str
    service_id: str
    selection_strategy: PoolSelectionStrategy
    members: tuple[PoolMember, ...]
    automatic_failover_within_pool: bool = True
    automatic_failover_outside_pool: Literal[False] = False
    automatic_use: bool = True
    minimum_remaining_floor_units: int = 0

    def __post_init__(self) -> None:
        if not self.name or not self.service_id:
            raise ValueError("pool name and service are required")
        if self.automatic_failover_outside_pool is not False:
            raise ValueError("automatic failover outside a named pool is forbidden")
        require_sqlite_int64(
            self.minimum_remaining_floor_units,
            field="pool remaining floor",
            minimum=0,
        )
        if not self.members:
            raise ValueError("a named pool must contain at least one member")
        scope_ids = [member.scope.quota_scope_id for member in self.members]
        if len(scope_ids) != len(set(scope_ids)):
            raise ValueError("quota scopes must be unique within a named pool")
        for member in self.members:
            if member.scope.service_id != self.service_id:
                raise ValueError("pool members must belong to the pool service")
            if member.scope.configured_floor_units < self.minimum_remaining_floor_units:
                raise ValueError("the durable quota-scope floor must cover the pool minimum floor")
        if self.selection_strategy is PoolSelectionStrategy.PINNED and len(self.members) != 1:
            raise ValueError("a pinned pool must contain exactly one quota scope")


@dataclass(frozen=True, slots=True)
class RouteCandidate:
    pool_id: PoolId
    pool_name: str
    service_id: str
    scope: QuotaScopeSnapshot
    credential: RoutingCredential
    priority: int
    cost_rank: int


@dataclass(frozen=True, slots=True)
class RoutingPlan:
    pool_id: PoolId
    pool_name: str
    service_id: str
    operation: str
    estimated_cost_units: int
    unit: str
    automatic_failover_within_pool: bool
    candidates: tuple[RouteCandidate, ...]

    def __post_init__(self) -> None:
        if not self.pool_name or not self.service_id or not self.operation or not self.unit:
            raise ValueError("routing plan identifiers and unit are required")
        require_sqlite_int64(
            self.estimated_cost_units,
            field="estimated cost",
            minimum=0,
        )
        if not self.candidates:
            raise ValueError("routing plan must contain an eligible candidate")
        seen: set[CredentialId] = set()
        for candidate in self.candidates:
            if (
                candidate.pool_id != self.pool_id
                or candidate.pool_name != self.pool_name
                or candidate.service_id != self.service_id
            ):
                raise ValueError("routing plan candidates cannot cross pool boundaries")
            if candidate.credential.credential_id in seen:
                raise ValueError("routing plan credentials must be unique")
            seen.add(candidate.credential.credential_id)

    def remaining_after(self, credential_id: CredentialId) -> tuple[RouteCandidate, ...]:
        for index, candidate in enumerate(self.candidates):
            if candidate.credential.credential_id == credential_id:
                if not self.automatic_failover_within_pool:
                    return ()
                return self.candidates[index + 1 :]
        raise ValueError("credential does not belong to the routing plan")
