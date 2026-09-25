"""Bounded local route assessment without dispatch or readiness claims.

The planner remains responsible for facts absent from its returned plan, including
member enablement, pool policy, balance authority, and circuit-breaker availability.
This helper validates only represented routing, credential, and quota facts.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from gatehouse.core.clock import MAX_UTC_MS, MIN_UTC_MS
from gatehouse.core.ids import CredentialId, OpaqueId, PoolId, PrincipalId, QuotaScopeId
from gatehouse.core.provider_numbers import SQLITE_INT64_MAX
from gatehouse.core.states import CredentialState
from gatehouse.providers.base import OperationSpec
from gatehouse.providers.firecrawl.adapter import FirecrawlAdapter

from .affinity import ResourceAffinity
from .models import (
    MAXIMUM_ROUTE_CANDIDATES,
    QuotaScopeSnapshot,
    QuotaScopeState,
    RouteCandidate,
    RoutingCredential,
    RoutingPlan,
)
from .router import NoEligibleCredentialError, NoEligiblePoolError

_MAXIMUM_REQUIREMENTS = 32
_POOL_PATTERN = re.compile(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*")
_NEW_WORK_OPERATIONS = frozenset(
    {
        "firecrawl.search",
        "firecrawl.scrape",
        "firecrawl.map",
        "firecrawl.crawl.start",
    }
)
_INVALID_INPUT = "local route assessment inputs are invalid"


class LocalRouteStatus(StrEnum):
    ELIGIBLE = "eligible"
    INELIGIBLE = "ineligible"
    UNVERIFIED = "unverified"


class LocalRouteReason(StrEnum):
    LOCAL_ROUTE_AVAILABLE = "local_route_available"
    POOL_REFUSED = "pool_refused"
    ROUTE_REFUSED = "route_refused"
    ASSESSMENT_UNVERIFIED = "assessment_unverified"


@dataclass(frozen=True, slots=True)
class WorkloadRouteRequirement:
    pool_name: str
    operation: str


@dataclass(frozen=True, slots=True)
class LocalRouteResult:
    requirement: WorkloadRouteRequirement
    status: LocalRouteStatus
    reason: LocalRouteReason


@dataclass(frozen=True, slots=True)
class LocalRouteAssessment:
    observed_at_ms: int
    results: tuple[LocalRouteResult, ...]

    @property
    def status(self) -> LocalRouteStatus:
        if type(self.results) is not tuple or not 1 <= len(self.results) <= _MAXIMUM_REQUIREMENTS:
            return LocalRouteStatus.UNVERIFIED
        statuses: list[LocalRouteStatus] = []
        for result in self.results:
            if type(result) is not LocalRouteResult or type(result.status) is not LocalRouteStatus:
                return LocalRouteStatus.UNVERIFIED
            if result.status is LocalRouteStatus.UNVERIFIED:
                return LocalRouteStatus.UNVERIFIED
            statuses.append(result.status)
        if LocalRouteStatus.INELIGIBLE in statuses:
            return LocalRouteStatus.INELIGIBLE
        return LocalRouteStatus.ELIGIBLE


class LocalRoutePlanner(Protocol):
    """The existing routing plan signature, without importing invocation wiring."""

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
    ) -> RoutingPlan: ...


def _integer(value: object, *, minimum: int = 0, maximum: int = SQLITE_INT64_MAX) -> bool:
    return type(value) is int and minimum <= value <= maximum


def _timestamp(value: object) -> bool:
    return _integer(value, minimum=MIN_UTC_MS, maximum=MAX_UTC_MS)


def _valid_inputs(requirements: object, now_ms: object) -> bool:
    if (
        not _timestamp(now_ms)
        or type(requirements) is not tuple
        or len(requirements) > _MAXIMUM_REQUIREMENTS
    ):
        return False
    seen: set[tuple[str, str]] = set()
    for requirement in requirements:
        if (
            type(requirement) is not WorkloadRouteRequirement
            or type(requirement.pool_name) is not str
            or not 1 <= len(requirement.pool_name) <= 100
            or _POOL_PATTERN.fullmatch(requirement.pool_name) is None
            or requirement.pool_name == "emergency-locked"
            or type(requirement.operation) is not str
            or not 1 <= len(requirement.operation) <= 80
            or requirement.operation not in _NEW_WORK_OPERATIONS
        ):
            return False
        key = (requirement.pool_name, requirement.operation)
        if key in seen:
            return False
        seen.add(key)
    return True


def _operation_cost(operation: str) -> int:
    spec = FirecrawlAdapter.operation_spec(operation)
    if (
        type(spec) is not OperationSpec
        or type(spec.name) is not str
        or spec.name != operation
        or type(spec.cost_unit) is not str
        or spec.cost_unit != "credits"
    ):
        raise ValueError("local operation specification is unavailable")
    cost = spec.default_estimated_cost
    if type(cost) is int:
        valid = 1 <= cost <= SQLITE_INT64_MAX
    elif type(cost) is float:
        valid = math.isfinite(cost) and cost.is_integer() and 1 <= cost <= SQLITE_INT64_MAX
    else:
        valid = False
    if not valid:
        raise ValueError("local operation cost is unavailable")
    return int(cost)


def _typed_id(value: object, kind: type[OpaqueId]) -> bool:
    if type(value) is not kind:
        return False
    identifier = value
    return 0 < len(identifier) <= 64 and kind(str(identifier)) == identifier


def _valid_candidate(
    candidate: object,
    plan: RoutingPlan,
    *,
    cost: int,
    now_ms: int,
) -> bool:
    if (
        type(candidate) is not RouteCandidate
        or not _typed_id(candidate.pool_id, PoolId)
        or candidate.pool_id != plan.pool_id
        or type(candidate.pool_name) is not str
        or candidate.pool_name != plan.pool_name
        or type(candidate.service_id) is not str
        or candidate.service_id != "firecrawl"
        or not _integer(candidate.priority)
        or not _integer(candidate.cost_rank)
        or type(candidate.scope) is not QuotaScopeSnapshot
        or type(candidate.credential) is not RoutingCredential
    ):
        return False
    scope = candidate.scope
    credential = candidate.credential
    if (
        not _typed_id(scope.quota_scope_id, QuotaScopeId)
        or not _typed_id(scope.principal_id, PrincipalId)
        or type(scope.service_id) is not str
        or scope.service_id != "firecrawl"
        or type(scope.unit) is not str
        or scope.unit != "credits"
        or type(scope.state) is not QuotaScopeState
        or (
            scope.last_known_remaining_units is not None
            and not _integer(scope.last_known_remaining_units)
        )
        or not _integer(scope.configured_floor_units)
        or not _integer(scope.active_reserved_units)
        or (scope.cooldown_until_ms is not None and not _timestamp(scope.cooldown_until_ms))
        or not _typed_id(credential.credential_id, CredentialId)
        or not _typed_id(credential.principal_id, PrincipalId)
        or not _typed_id(credential.quota_scope_id, QuotaScopeId)
        or credential.principal_id != scope.principal_id
        or credential.quota_scope_id != scope.quota_scope_id
        or type(credential.state) is not CredentialState
        or not _integer(credential.generation, minimum=1)
        or (credential.expires_at_ms is not None and not _timestamp(credential.expires_at_ms))
    ):
        return False
    return credential.eligible_at(now_ms) and scope.eligible_for(
        amount_units=cost,
        unit="credits",
        now_ms=now_ms,
        floor_units=scope.configured_floor_units,
    )


def _valid_plan(
    plan: object,
    requirement: WorkloadRouteRequirement,
    *,
    cost: int,
    now_ms: int,
) -> bool:
    if (
        type(plan) is not RoutingPlan
        or not _typed_id(plan.pool_id, PoolId)
        or type(plan.pool_name) is not str
        or plan.pool_name != requirement.pool_name
        or type(plan.service_id) is not str
        or plan.service_id != "firecrawl"
        or type(plan.operation) is not str
        or plan.operation != requirement.operation
        or type(plan.estimated_cost_units) is not int
        or plan.estimated_cost_units != cost
        or type(plan.unit) is not str
        or plan.unit != "credits"
        or type(plan.automatic_failover_within_pool) is not bool
        or type(plan.candidates) is not tuple
        or not 1 <= len(plan.candidates) <= MAXIMUM_ROUTE_CANDIDATES
    ):
        return False
    credentials: set[CredentialId] = set()
    scopes: dict[QuotaScopeId, QuotaScopeSnapshot] = {}
    for candidate in plan.candidates:
        if not _valid_candidate(candidate, plan, cost=cost, now_ms=now_ms):
            return False
        credential_id = candidate.credential.credential_id
        scope = candidate.scope
        if credential_id in credentials:
            return False
        if scope.quota_scope_id in scopes and scopes[scope.quota_scope_id] != scope:
            return False
        credentials.add(credential_id)
        scopes[scope.quota_scope_id] = scope
    return True


def assess_local_routes(
    planner: LocalRoutePlanner,
    requirements: tuple[WorkloadRouteRequirement, ...],
    *,
    now_ms: int,
) -> LocalRouteAssessment:
    """Assess explicit new-work routes using local planner facts at the supplied time.

    No provider call, reservation, dispatch, health update, or automatic pool
    selection follows from this assessment. All requirements are checked first.
    Batch and candidate limits do not impose a deadline on a synchronous planner.
    Each requirement is assessed independently: the shared observation time does
    not establish a coherent database snapshot or capacity for joint execution.
    """

    try:
        valid_inputs = _valid_inputs(requirements, now_ms)
    except Exception:
        valid_inputs = False
    if not valid_inputs:
        raise ValueError(_INVALID_INPUT)
    results: list[LocalRouteResult] = []
    for requirement in requirements:
        status = LocalRouteStatus.UNVERIFIED
        reason = LocalRouteReason.ASSESSMENT_UNVERIFIED
        try:
            cost = _operation_cost(requirement.operation)
        except Exception:
            results.append(LocalRouteResult(requirement, status, reason))
            continue
        try:
            plan = planner.plan(
                service_id="firecrawl",
                operation=requirement.operation,
                pool_name=requirement.pool_name,
                estimated_cost_units=cost,
                unit="credits",
                now_ms=now_ms,
                affinity=None,
                automatic=True,
                reconciliation=False,
            )
        except NoEligiblePoolError:
            status, reason = LocalRouteStatus.INELIGIBLE, LocalRouteReason.POOL_REFUSED
        except NoEligibleCredentialError:
            status, reason = LocalRouteStatus.INELIGIBLE, LocalRouteReason.ROUTE_REFUSED
        except Exception:
            status, reason = LocalRouteStatus.UNVERIFIED, LocalRouteReason.ASSESSMENT_UNVERIFIED
        else:
            try:
                valid_plan = _valid_plan(plan, requirement, cost=cost, now_ms=now_ms)
            except Exception:
                valid_plan = False
            if valid_plan:
                status, reason = LocalRouteStatus.ELIGIBLE, LocalRouteReason.LOCAL_ROUTE_AVAILABLE
        results.append(LocalRouteResult(requirement, status, reason))
    return LocalRouteAssessment(observed_at_ms=now_ms, results=tuple(results))
