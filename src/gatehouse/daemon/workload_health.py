"""Bounded, read-only coverage of configured ordinary new-work routes.

This projection describes independent local routing opportunities, not approval
of a specific request, shared capacity, watcher readiness, or provider liveness.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass

from gatehouse.admin.control import ControlWorkloadReadiness
from gatehouse.config import ClientProfileConfig
from gatehouse.core.clock import MAX_UTC_MS, MIN_UTC_MS
from gatehouse.database import transaction
from gatehouse.policy import Decision, WorkspacePolicy
from gatehouse.policy.engine import PurposeRule
from gatehouse.routing import SqliteRoutingCatalog
from gatehouse.routing.eligibility import (
    LocalRouteStatus,
    WorkloadRouteRequirement,
    _operation_cost,
    _valid_inputs,
    assess_local_routes,
)

from .configuration import SynchronizedConfiguration

_MAXIMUM_CONFIGURATIONS = 64
_MAXIMUM_BINDINGS = 256
_MAXIMUM_ROUTES = 32
_MAXIMUM_POLICY_CHECKS = 4096
_OPERATIONS = {
    "firecrawl.search": "search",
    "firecrawl.scrape": "scrape",
    "firecrawl.map": "map",
    "firecrawl.crawl.start": "crawl",
}


@dataclass(frozen=True, slots=True)
class WorkloadBinding:
    client_id: str
    workspace_id: str
    purpose: str | None
    requirement: WorkloadRouteRequirement


@dataclass(frozen=True, slots=True)
class WorkloadCoverage:
    bindings: tuple[WorkloadBinding, ...]
    requirements: tuple[WorkloadRouteRequirement, ...]
    verified: bool


_UNVERIFIED_COVERAGE = WorkloadCoverage((), (), False)


def _allowed_operation(
    policy: WorkspacePolicy,
    *,
    purpose: str | None,
    operation: str,
    cost: int,
) -> bool:
    family = _OPERATIONS[operation]
    rule = policy.purpose_rules.get(purpose, {}).get(family) if purpose is not None else None
    if rule is not None and type(rule) is not PurposeRule:
        raise ValueError("workload purpose rule is invalid")
    decision = policy.default_decision if rule is None else rule.decision
    if type(decision) is not Decision:
        raise ValueError("workload purpose decision is invalid")
    if decision is not Decision.ALLOW:
        return False
    if rule is not None and rule.maximum_cost is not None and rule.maximum_cost < cost:
        return False
    if policy.maximum_requests_per_root_run < 1 or policy.maximum_credits_per_root_run < cost:
        return False
    if family == "search" and policy.maximum_search_results < 1:
        return False
    if family == "map" and policy.maximum_map_results < 1:
        return False
    return not (
        family == "crawl" and (policy.maximum_crawl_pages < 1 or policy.maximum_crawl_depth < 0)
    )


def derive_workload_coverage(synchronized: SynchronizedConfiguration) -> WorkloadCoverage:
    """Freeze effective ALLOW bindings without inventing a generic default route.

    A missing explicit workspace binding grants no ordinary launch authority.
    Unattended clients require feed and schedule checks, which this projection
    does not assess. ASK requests and resource-bound continuations are excluded.
    None denotes the policy default for purposes without an explicit rule.
    """

    try:
        return _derive_workload_coverage(synchronized)
    except Exception:
        return _UNVERIFIED_COVERAGE


def _derive_workload_coverage(synchronized: SynchronizedConfiguration) -> WorkloadCoverage:
    if any(
        len(mapping) > _MAXIMUM_CONFIGURATIONS
        for mapping in (
            synchronized.clients_by_id,
            synchronized.client_ids_by_name,
            synchronized.policies_by_workspace_id,
            synchronized.workspace_ids_by_name,
        )
    ):
        return _UNVERIFIED_COVERAGE
    bindings: list[WorkloadBinding] = []
    requirements: dict[tuple[str, str], WorkloadRouteRequirement] = {}
    policy_checks = 0
    costs = {operation: _operation_cost(operation) for operation in _OPERATIONS}
    for client_id, profile in sorted(synchronized.clients_by_id.items()):
        if (
            type(profile) is not ClientProfileConfig
            or synchronized.client_ids_by_name.get(profile.client.id) != client_id
        ):
            return _UNVERIFIED_COVERAGE
        if profile.workspaces is None or profile.client.unattended:
            continue
        if len(profile.workspaces.allow) > _MAXIMUM_CONFIGURATIONS:
            return _UNVERIFIED_COVERAGE
        if len(profile.capabilities.allow) > 128:
            return _UNVERIFIED_COVERAGE
        operations = tuple(
            operation for operation in _OPERATIONS if operation in profile.capabilities.allow
        )
        if not operations:
            continue
        for workspace_name in sorted(profile.workspaces.allow):
            workspace_id = synchronized.workspace_ids_by_name.get(workspace_name)
            policy = synchronized.policies_by_workspace_id.get(workspace_id or "")
            if (
                type(policy) is not WorkspacePolicy
                or policy.workspace_id != workspace_id
                or policy.policy_id != workspace_name
            ):
                return _UNVERIFIED_COVERAGE
            if policy.service != "firecrawl":
                continue
            pool = profile.pools.bindings.get("firecrawl")
            if pool is None:
                return _UNVERIFIED_COVERAGE
            if len(policy.purpose_rules) > _MAXIMUM_CONFIGURATIONS:
                return _UNVERIFIED_COVERAGE
            purposes: tuple[str | None, ...] = tuple(sorted(policy.purpose_rules))
            if policy.default_decision is Decision.ALLOW:
                purposes += (None,)
            for purpose in purposes:
                for operation in operations:
                    policy_checks += 1
                    if policy_checks > _MAXIMUM_POLICY_CHECKS:
                        return _UNVERIFIED_COVERAGE
                    if not _allowed_operation(
                        policy,
                        purpose=purpose,
                        operation=operation,
                        cost=costs[operation],
                    ):
                        continue
                    key = (pool, operation)
                    requirement = requirements.setdefault(key, WorkloadRouteRequirement(*key))
                    bindings.append(
                        WorkloadBinding(client_id, policy.workspace_id, purpose, requirement)
                    )
                    if len(bindings) > _MAXIMUM_BINDINGS or len(requirements) > _MAXIMUM_ROUTES:
                        return _UNVERIFIED_COVERAGE
    ordered_requirements = tuple(requirements[key] for key in sorted(requirements))
    if not _valid_inputs(ordered_requirements, MIN_UTC_MS):
        return _UNVERIFIED_COVERAGE
    return WorkloadCoverage(tuple(bindings), ordered_requirements, True)


class SqliteWorkloadHealth:
    """Assess actual catalog routes in one owned synchronous SQLite read transaction."""

    def __init__(
        self,
        connection: sqlite3.Connection,
        catalog: SqliteRoutingCatalog,
        coverage: WorkloadCoverage,
        *,
        mode: str,
    ) -> None:
        if mode not in {"disabled", "scripted", "live"}:
            raise ValueError("workload health mode is invalid")
        self._connection = connection
        self._catalog = catalog
        self._coverage = coverage
        self._mode = mode

    def __call__(self, now_ms: int) -> ControlWorkloadReadiness:
        if type(now_ms) is not int or not MIN_UTC_MS <= now_ms <= MAX_UTC_MS:
            return ControlWorkloadReadiness(status="UNVERIFIED")
        if self._mode == "disabled":
            return ControlWorkloadReadiness(status="DISABLED", checked_at_ms=now_ms)
        coverage = self._coverage
        if not coverage.verified:
            return ControlWorkloadReadiness(status="UNVERIFIED", checked_at_ms=now_ms)
        if not coverage.requirements:
            return ControlWorkloadReadiness(status="UNCONFIGURED", checked_at_ms=now_ms)
        try:
            if self._connection.in_transaction:
                return ControlWorkloadReadiness(status="UNVERIFIED", checked_at_ms=now_ms)
            # No await, reservations, provider calls, or breaker permits occur here.
            # An existing caller transaction is never adopted or committed.
            with transaction(self._connection, "DEFERRED"):
                assessment = assess_local_routes(
                    self._catalog,
                    coverage.requirements,
                    now_ms=now_ms,
                )
            eligible = sum(row.status is LocalRouteStatus.ELIGIBLE for row in assessment.results)
            ineligible = sum(
                row.status is LocalRouteStatus.INELIGIBLE for row in assessment.results
            )
            unverified = len(assessment.results) - eligible - ineligible
            return ControlWorkloadReadiness(
                status="UNVERIFIED" if unverified else "DEGRADED" if ineligible else "READY",
                ready=not unverified and not ineligible,
                checked_at_ms=now_ms,
                binding_count=len(coverage.bindings),
                required_routes=len(coverage.requirements),
                eligible_routes=eligible,
                ineligible_routes=ineligible,
                unverified_routes=unverified,
            )
        except Exception:
            return ControlWorkloadReadiness(status="UNVERIFIED", checked_at_ms=now_ms)
