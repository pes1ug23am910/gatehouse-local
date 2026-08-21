from __future__ import annotations

from dataclasses import replace

import pytest

from gatehouse.core.ids import (
    CredentialId,
    PoolId,
    PrincipalId,
    QuotaScopeId,
    RequestId,
    RootRunId,
    SessionId,
    WorkspaceId,
)
from gatehouse.core.states import CredentialState
from gatehouse.routing import (
    AffinityUnavailableError,
    NamedPool,
    NamedPoolRouter,
    NoEligibleCredentialError,
    NoEligiblePoolError,
    PoolMember,
    PoolSelectionStrategy,
    QuotaScopeSnapshot,
    QuotaScopeState,
    ResourceAffinity,
    RoutingCredential,
)

_A = "00000000000000000000000001"
_B = "00000000000000000000000002"
_C = "00000000000000000000000003"


def credential(
    suffix: str,
    principal: PrincipalId,
    scope: QuotaScopeId,
    *,
    state: CredentialState = CredentialState.HEALTHY,
) -> RoutingCredential:
    return RoutingCredential(
        CredentialId(f"cred_{suffix}"),
        principal,
        scope,
        state=state,
    )


def member(
    suffix: str,
    *,
    remaining: int | None = 1_000,
    floor: int = 100,
    reserved: int = 0,
    cooldown_until_ms: int | None = None,
    cost_rank: int = 100,
    credential_state: CredentialState = CredentialState.HEALTHY,
) -> PoolMember:
    principal = PrincipalId(f"prn_{suffix}")
    scope = QuotaScopeId(f"quota_{suffix}")
    return PoolMember(
        scope=QuotaScopeSnapshot(
            scope,
            principal,
            "service",
            "credits",
            last_known_remaining_units=remaining,
            configured_floor_units=floor,
            active_reserved_units=reserved,
            cooldown_until_ms=cooldown_until_ms,
        ),
        credentials=(credential(suffix, principal, scope, state=credential_state),),
        cost_rank=cost_rank,
    )


def pool(*members: PoolMember, automatic_use: bool = True) -> NamedPool:
    return NamedPool(
        PoolId(f"pool_{_A}"),
        "interactive-default",
        "service",
        PoolSelectionStrategy.CHEAPEST_FIRST,
        tuple(members),
        automatic_use=automatic_use,
        minimum_remaining_floor_units=100,
    )


def test_cheapest_first_is_deterministic_regardless_of_config_order() -> None:
    expensive = member(_A, cost_rank=20)
    cheapest_b = member(_B, cost_rank=10)
    cheapest_c = member(_C, cost_rank=10)

    first = NamedPoolRouter([pool(expensive, cheapest_c, cheapest_b)]).plan(
        service_id="service",
        operation="service.read",
        pool_name="interactive-default",
        estimated_cost_units=5,
        unit="credits",
        now_ms=100,
    )
    second = NamedPoolRouter([pool(cheapest_b, expensive, cheapest_c)]).plan(
        service_id="service",
        operation="service.read",
        pool_name="interactive-default",
        estimated_cost_units=5,
        unit="credits",
        now_ms=100,
    )

    expected = [f"quota_{_B}", f"quota_{_C}", f"quota_{_A}"]
    assert [str(item.scope.quota_scope_id) for item in first.candidates] == expected
    assert [str(item.scope.quota_scope_id) for item in second.candidates] == expected


def test_floor_unknown_balance_cooldown_and_credential_state_are_ineligible() -> None:
    below_floor = member(_A, remaining=120, floor=100, reserved=10)
    unknown = member(_B, remaining=None)
    cooling = member(_C, cooldown_until_ms=500)
    usable = member(
        "00000000000000000000000004",
        remaining=200,
        credential_state=CredentialState.HEALTHY,
    )

    plan = NamedPoolRouter([pool(below_floor, unknown, cooling, usable)]).plan(
        service_id="service",
        operation="service.read",
        pool_name="interactive-default",
        estimated_cost_units=20,
        unit="credits",
        now_ms=100,
    )

    assert [item.scope.quota_scope_id for item in plan.candidates] == [usable.scope.quota_scope_id]


def test_locked_pool_is_never_selected_automatically() -> None:
    locked = pool(member(_A), automatic_use=False)
    router = NamedPoolRouter([locked])

    with pytest.raises(NoEligiblePoolError):
        router.plan(
            service_id="service",
            operation="service.read",
            pool_name="interactive-default",
            estimated_cost_units=1,
            unit="credits",
            now_ms=1,
        )

    assert (
        router.plan(
            service_id="service",
            operation="service.read",
            pool_name="interactive-default",
            estimated_cost_units=1,
            unit="credits",
            now_ms=1,
            automatic=False,
        ).pool_id
        == locked.pool_id
    )


def test_resource_affinity_requires_exact_credential_generation() -> None:
    principal = PrincipalId(f"prn_{_A}")
    scope = QuotaScopeId(f"quota_{_A}")
    original = credential(_A, principal, scope, state=CredentialState.DRAINING)
    replacement = credential(_B, principal, scope)
    bound_member = PoolMember(
        QuotaScopeSnapshot(
            scope,
            principal,
            "service",
            "credits",
            last_known_remaining_units=500,
            configured_floor_units=100,
        ),
        (original, replacement),
    )
    unrelated = member(_C)
    named_pool = pool(unrelated, bound_member)
    affinity = ResourceAffinity(
        service_id="service",
        resource_type="job",
        provider_resource_id="provider-job",
        principal_id=principal,
        quota_scope_id=scope,
        credential_id=original.credential_id,
        credential_generation=original.generation,
        pool_id=named_pool.pool_id,
        creating_request_id=RequestId(f"req_{_A}"),
        owner_session_id=SessionId(f"ses_{_A}"),
        owner_workspace_id=WorkspaceId(f"ws_{_A}"),
        owner_root_run_id=RootRunId(f"run_{_A}"),
        bound_at_ms=1,
    )

    plan = NamedPoolRouter([named_pool]).plan(
        service_id="service",
        operation="service.job.status",
        pool_name="interactive-default",
        estimated_cost_units=0,
        unit="credits",
        now_ms=2,
        affinity=affinity,
    )

    assert [item.credential.credential_id for item in plan.candidates] == [original.credential_id]

    stale_generation = replace(affinity, credential_generation=original.generation + 1)
    with pytest.raises(AffinityUnavailableError):
        NamedPoolRouter([named_pool]).plan(
            service_id="service",
            operation="service.job.status",
            pool_name="interactive-default",
            estimated_cost_units=0,
            unit="credits",
            now_ms=2,
            affinity=stale_generation,
        )

    disabled_pool = replace(
        named_pool,
        members=(
            unrelated,
            replace(
                bound_member,
                credentials=(
                    replace(original, state=CredentialState.DISABLED),
                    replacement,
                ),
            ),
        ),
    )
    with pytest.raises(AffinityUnavailableError):
        NamedPoolRouter([disabled_pool]).plan(
            service_id="service",
            operation="service.job.status",
            pool_name="interactive-default",
            estimated_cost_units=0,
            unit="credits",
            now_ms=2,
            affinity=affinity,
        )

    wrong_pool = replace(affinity, pool_id=PoolId(f"pool_{_B}"))
    with pytest.raises(AffinityUnavailableError):
        NamedPoolRouter([named_pool]).plan(
            service_id="service",
            operation="service.job.status",
            pool_name="interactive-default",
            estimated_cost_units=0,
            unit="credits",
            now_ms=2,
            affinity=wrong_pool,
        )


def test_exact_zero_cost_reconciliation_bypasses_quota_health_not_kill_switches() -> None:
    exhausted = member(_A, remaining=0)
    exhausted = replace(
        exhausted,
        scope=replace(exhausted.scope, state=QuotaScopeState.EXHAUSTED),
    )
    named_pool = pool(exhausted)
    affinity = ResourceAffinity(
        service_id="service",
        resource_type="job",
        provider_resource_id="provider-job",
        principal_id=exhausted.scope.principal_id,
        quota_scope_id=exhausted.scope.quota_scope_id,
        credential_id=exhausted.credentials[0].credential_id,
        credential_generation=exhausted.credentials[0].generation,
        pool_id=named_pool.pool_id,
        creating_request_id=RequestId(f"req_{_A}"),
        owner_session_id=SessionId(f"ses_{_A}"),
        owner_workspace_id=WorkspaceId(f"ws_{_A}"),
        owner_root_run_id=RootRunId(f"run_{_A}"),
        bound_at_ms=1,
    )
    router = NamedPoolRouter([named_pool])

    with pytest.raises(AffinityUnavailableError):
        router.plan(
            service_id="service",
            operation="service.job.status",
            pool_name="interactive-default",
            estimated_cost_units=0,
            unit="credits",
            now_ms=2,
            affinity=affinity,
        )
    reconciled = router.plan(
        service_id="service",
        operation="service.job.status",
        pool_name="interactive-default",
        estimated_cost_units=0,
        unit="credits",
        now_ms=2,
        affinity=affinity,
        reconciliation=True,
    )
    assert reconciled.candidates[0].scope.state is QuotaScopeState.EXHAUSTED

    quarantined = replace(
        exhausted,
        scope=replace(exhausted.scope, state=QuotaScopeState.QUARANTINED),
    )
    with pytest.raises(AffinityUnavailableError):
        NamedPoolRouter([pool(quarantined)]).plan(
            service_id="service",
            operation="service.job.status",
            pool_name="interactive-default",
            estimated_cost_units=0,
            unit="credits",
            now_ms=2,
            affinity=affinity,
            reconciliation=True,
        )
    with pytest.raises(ValueError, match="exact affinity"):
        router.plan(
            service_id="service",
            operation="service.job.status",
            pool_name="interactive-default",
            estimated_cost_units=0,
            unit="credits",
            now_ms=2,
            reconciliation=True,
        )


def test_pool_rejects_an_outside_failover_flag_and_underconfigured_floor() -> None:
    with pytest.raises(ValueError, match="outside"):
        NamedPool(
            PoolId(f"pool_{_A}"),
            "default",
            "service",
            PoolSelectionStrategy.CHEAPEST_FIRST,
            (member(_A),),
            automatic_failover_outside_pool=True,  # type: ignore[arg-type]
        )

    with pytest.raises(ValueError, match="durable"):
        NamedPool(
            PoolId(f"pool_{_A}"),
            "default",
            "service",
            PoolSelectionStrategy.CHEAPEST_FIRST,
            (member(_A, floor=10),),
            minimum_remaining_floor_units=100,
        )


def test_nonhealthy_scope_is_ineligible() -> None:
    base = member(_A)
    unhealthy = PoolMember(
        QuotaScopeSnapshot(
            base.scope.quota_scope_id,
            base.scope.principal_id,
            "service",
            "credits",
            state=QuotaScopeState.EXHAUSTED,
            last_known_remaining_units=1_000,
            configured_floor_units=100,
        ),
        base.credentials,
    )
    with pytest.raises(NoEligibleCredentialError):
        NamedPoolRouter([pool(unhealthy)]).plan(
            service_id="service",
            operation="service.read",
            pool_name="interactive-default",
            estimated_cost_units=1,
            unit="credits",
            now_ms=1,
        )
