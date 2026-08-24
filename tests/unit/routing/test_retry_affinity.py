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
from gatehouse.core.states import CircuitBreakerState
from gatehouse.providers import OperationSpec, ProviderErrorClass, RetrySafety, SideEffectClass
from gatehouse.routing import (
    BreakerKey,
    BreakerScopeType,
    CircuitBreakerPolicy,
    CircuitBreakerRegistry,
    InMemoryResourceAffinityStore,
    ResourceAffinity,
    ResourceAffinityConflictError,
    RetryAction,
    RetryDecision,
    RetryPolicy,
)

_A = "00000000000000000000000001"
_B = "00000000000000000000000002"


def operation(retry_safety: RetrySafety = RetrySafety.SAFE) -> OperationSpec:
    return OperationSpec(
        "service.read",
        SideEffectClass.METERED_READ,
        retry_safety,
        coalescible=True,
        asynchronous=False,
        default_estimated_cost=1,
    )


def test_circuit_breaker_opens_and_admits_only_one_half_open_probe() -> None:
    registry = CircuitBreakerRegistry(
        CircuitBreakerPolicy(
            failures_to_open=2,
            observation_window_ms=100,
            default_open_duration_ms=50,
            half_open_probe_count=1,
        )
    )
    key = BreakerKey(BreakerScopeType.QUOTA_SCOPE, "scope")
    registry.record_failure(
        key,
        now_ms=10,
        error_class=ProviderErrorClass.TRANSIENT,
    )
    opened = registry.record_failure(
        key,
        now_ms=20,
        error_class=ProviderErrorClass.TRANSIENT,
    )

    assert opened.state is CircuitBreakerState.OPEN
    assert not registry.is_available(key, now_ms=69)
    assert registry.is_available(key, now_ms=70)
    permit = registry.try_acquire(key, now_ms=70)
    assert permit is not None
    assert not registry.try_acquire(key, now_ms=70)

    assert registry.release(permit)
    closed = registry.record_success(key)
    assert closed.state is CircuitBreakerState.CLOSED
    assert closed.failure_count == 0


def test_abandoned_half_open_permit_is_exactly_once_and_reusable() -> None:
    registry = CircuitBreakerRegistry(
        CircuitBreakerPolicy(
            failures_to_open=1,
            default_open_duration_ms=10,
            half_open_probe_count=1,
        )
    )
    key = BreakerKey(BreakerScopeType.SERVICE, "service")
    registry.record_failure(
        key,
        now_ms=1,
        error_class=ProviderErrorClass.TRANSIENT,
    )
    first = registry.try_acquire(key, now_ms=11)
    assert first is not None

    assert registry.release(first)
    assert not registry.release(first)
    replacement = registry.try_acquire(key, now_ms=11)
    assert replacement is not None
    assert replacement.permit_id != first.permit_id
    assert registry.release(replacement)


def test_retry_policy_never_replays_possible_submission_or_permission_failure() -> None:
    policy = RetryPolicy(maximum_attempts=3, jitter=False)

    ambiguous = policy.decide(
        operation=operation(),
        error_class=ProviderErrorClass.TIMEOUT,
        attempt_number=1,
        submission_may_have_occurred=True,
    )
    permission = policy.decide(
        operation=operation(),
        error_class=ProviderErrorClass.PERMISSION_DENIED,
        attempt_number=1,
        submission_may_have_occurred=False,
        has_pool_failover=True,
    )
    exhausted = policy.decide(
        operation=operation(),
        error_class=ProviderErrorClass.QUOTA_EXHAUSTED,
        attempt_number=policy.maximum_attempts,
        submission_may_have_occurred=False,
        has_pool_failover=True,
    )
    unauthorized_same_scope = policy.decide(
        operation=operation(),
        error_class=ProviderErrorClass.UNAUTHORIZED,
        attempt_number=policy.maximum_attempts,
        submission_may_have_occurred=False,
        has_same_scope_failover=True,
        has_pool_failover=True,
    )
    unauthorized_other_scope_only = policy.decide(
        operation=operation(),
        error_class=ProviderErrorClass.UNAUTHORIZED,
        attempt_number=1,
        submission_may_have_occurred=False,
        has_pool_failover=True,
    )
    transient = policy.decide(
        operation=operation(),
        error_class=ProviderErrorClass.TRANSIENT,
        attempt_number=1,
        submission_may_have_occurred=False,
    )
    unsafe = policy.decide(
        operation=operation(RetrySafety.RECONCILE_FIRST),
        error_class=ProviderErrorClass.TRANSIENT,
        attempt_number=1,
        submission_may_have_occurred=False,
    )

    assert ambiguous.action is RetryAction.UNKNOWN
    assert permission.action is RetryAction.FAIL
    assert exhausted.action is RetryAction.FAILOVER_WITHIN_POOL
    assert unauthorized_same_scope.action is RetryAction.FAILOVER_WITHIN_QUOTA_SCOPE
    assert unauthorized_other_scope_only.action is RetryAction.FAIL
    assert transient == policy.decide(
        operation=operation(),
        error_class=ProviderErrorClass.TRANSIENT,
        attempt_number=1,
        submission_may_have_occurred=False,
    )
    assert transient.delay_ms == 1_000
    assert unsafe.action is RetryAction.FAIL


def test_rate_limit_spills_only_when_same_account_retry_would_fail() -> None:
    policy = RetryPolicy(maximum_attempts=3, jitter=False)

    within_budget = policy.decide(
        operation=operation(),
        error_class=ProviderErrorClass.RATE_LIMITED,
        attempt_number=1,
        submission_may_have_occurred=False,
        retry_after_seconds=2,
        has_pool_failover=True,
        remaining_time_ms=2_001,
    )
    deadline_would_fail = policy.decide(
        operation=operation(),
        error_class=ProviderErrorClass.RATE_LIMITED,
        attempt_number=1,
        submission_may_have_occurred=False,
        retry_after_seconds=2,
        has_pool_failover=True,
        remaining_time_ms=2_000,
    )
    long_hint_within_budget = policy.decide(
        operation=operation(),
        error_class=ProviderErrorClass.RATE_LIMITED,
        attempt_number=1,
        submission_may_have_occurred=False,
        retry_after_seconds=120,
        has_pool_failover=True,
        remaining_time_ms=120_001,
    )
    long_hint_would_fail = policy.decide(
        operation=operation(),
        error_class=ProviderErrorClass.RATE_LIMITED,
        attempt_number=1,
        submission_may_have_occurred=False,
        retry_after_seconds=120,
        has_pool_failover=True,
        remaining_time_ms=120_000,
    )
    attempts_exhausted = policy.decide(
        operation=operation(),
        error_class=ProviderErrorClass.RATE_LIMITED,
        attempt_number=policy.maximum_attempts,
        submission_may_have_occurred=False,
        has_pool_failover=True,
    )
    reset_unknown = policy.decide(
        operation=operation(),
        error_class=ProviderErrorClass.RATE_LIMITED,
        attempt_number=1,
        submission_may_have_occurred=False,
        has_pool_failover=True,
    )
    no_backup = policy.decide(
        operation=operation(),
        error_class=ProviderErrorClass.RATE_LIMITED,
        attempt_number=policy.maximum_attempts,
        submission_may_have_occurred=False,
    )
    unsafe = policy.decide(
        operation=operation(RetrySafety.RECONCILE_FIRST),
        error_class=ProviderErrorClass.RATE_LIMITED,
        attempt_number=policy.maximum_attempts,
        submission_may_have_occurred=False,
        has_pool_failover=True,
    )
    ambiguous = policy.decide(
        operation=operation(),
        error_class=ProviderErrorClass.RATE_LIMITED,
        attempt_number=policy.maximum_attempts,
        submission_may_have_occurred=True,
        has_pool_failover=True,
    )

    assert within_budget == RetryDecision(
        RetryAction.RETRY_SAME_CREDENTIAL,
        delay_ms=2_000,
    )
    assert deadline_would_fail.action is RetryAction.FAILOVER_WITHIN_POOL
    assert long_hint_within_budget == RetryDecision(
        RetryAction.RETRY_SAME_CREDENTIAL,
        delay_ms=120_000,
    )
    assert long_hint_would_fail.action is RetryAction.FAILOVER_WITHIN_POOL
    assert attempts_exhausted.action is RetryAction.FAILOVER_WITHIN_POOL
    assert reset_unknown.action is RetryAction.FAILOVER_WITHIN_POOL
    assert no_backup.action is RetryAction.FAIL
    assert unsafe.action is RetryAction.FAIL
    assert ambiguous.action is RetryAction.UNKNOWN


@pytest.mark.asyncio
async def test_affinity_store_is_idempotent_and_rejects_rebinding() -> None:
    store = InMemoryResourceAffinityStore(maximum_entries=1)
    affinity = ResourceAffinity(
        service_id="service",
        resource_type="job",
        provider_resource_id="provider-job",
        principal_id=PrincipalId(f"prn_{_A}"),
        quota_scope_id=QuotaScopeId(f"quota_{_A}"),
        credential_id=CredentialId(f"cred_{_A}"),
        credential_generation=1,
        pool_id=PoolId(f"pool_{_A}"),
        creating_request_id=RequestId(f"req_{_A}"),
        owner_session_id=SessionId(f"ses_{_A}"),
        owner_workspace_id=WorkspaceId(f"ws_{_A}"),
        owner_root_run_id=RootRunId(f"run_{_A}"),
        bound_at_ms=1,
    )

    assert await store.bind(affinity) == affinity
    assert await store.bind(affinity) == affinity
    assert (
        await store.get(
            service_id="service",
            resource_type="job",
            provider_resource_id="provider-job",
            owner_session_id=affinity.owner_session_id,
            owner_workspace_id=affinity.owner_workspace_id,
            owner_root_run_id=affinity.owner_root_run_id,
        )
        == affinity
    )
    assert (
        await store.get_by_request(
            service_id="service",
            resource_type="job",
            creating_request_id=affinity.creating_request_id,
            owner_session_id=affinity.owner_session_id,
            owner_workspace_id=affinity.owner_workspace_id,
            owner_root_run_id=affinity.owner_root_run_id,
        )
        == affinity
    )
    assert (
        await store.get(
            service_id="service",
            resource_type="job",
            provider_resource_id="provider-job",
            owner_session_id=SessionId(f"ses_{_B}"),
            owner_workspace_id=affinity.owner_workspace_id,
            owner_root_run_id=affinity.owner_root_run_id,
        )
        is None
    )

    conflicting = ResourceAffinity(
        service_id="service",
        resource_type="job",
        provider_resource_id="provider-job",
        principal_id=PrincipalId(f"prn_{_B}"),
        quota_scope_id=QuotaScopeId(f"quota_{_B}"),
        credential_id=CredentialId(f"cred_{_B}"),
        credential_generation=1,
        pool_id=PoolId(f"pool_{_B}"),
        creating_request_id=RequestId(f"req_{_B}"),
        owner_session_id=SessionId(f"ses_{_B}"),
        owner_workspace_id=WorkspaceId(f"ws_{_B}"),
        owner_root_run_id=RootRunId(f"run_{_B}"),
        bound_at_ms=2,
    )
    with pytest.raises(ResourceAffinityConflictError):
        await store.bind(conflicting)
    with pytest.raises(ResourceAffinityConflictError):
        await store.bind(replace(affinity, resource_type="other-job-type"))
