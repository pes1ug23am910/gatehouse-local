from __future__ import annotations

import asyncio
from collections.abc import Mapping

import httpx
import pytest

from gatehouse.core.clock import SystemUtcClock
from gatehouse.core.ids import (
    ClientId,
    CredentialId,
    LeaseId,
    PoolId,
    PrincipalId,
    QuotaScopeId,
    RequestId,
    RootRunId,
    SessionId,
    WorkspaceId,
)
from gatehouse.core.states import InvocationState
from gatehouse.credentials import CredentialMetadata, InMemoryKeyStore
from gatehouse.database.repository import QuotaReservationResult, QuotaReservationStatus
from gatehouse.fingerprint import FingerprintService, SingleFlightCoordinator
from gatehouse.fingerprint.hmac import RequestFingerprint
from gatehouse.invocations import (
    ApprovalResolution,
    AttemptEvent,
    DefaultFingerprintGateway,
    DefaultSensitiveInspector,
    FirecrawlOperationGateway,
    InMemoryBudgetGateway,
    InvocationCoordinator,
    InvocationRequest,
    InvocationSession,
    InvocationStartEvent,
    InvocationStateEvent,
    InvocationValidatedEvent,
)
from gatehouse.policy import ClientClass, Decision, PolicyContext, PolicyResult
from gatehouse.providers.transport import FIRECRAWL_ORIGIN, HttpxProviderTransport
from gatehouse.routing import (
    CircuitBreakerRegistry,
    CredentialDispatchLease,
    InMemoryResourceAffinityStore,
    NamedPool,
    NamedPoolRouter,
    PoolMember,
    PoolSelectionStrategy,
    QuotaReservationManager,
    QuotaScopeSnapshot,
    RouteCandidate,
    RoutingCredential,
)
from gatehouse.scheduler import BoundedFairScheduler, SchedulerLimits, ServiceLimits
from gatehouse.testing import ProviderScriptStep, ScriptedProviderASGI, ScriptMode

_A = "00000000000000000000000001"
_B = "00000000000000000000000002"


class _Sessions:
    def __init__(self, session: InvocationSession) -> None:
        self._session = session

    async def authenticate(self, request: InvocationRequest) -> InvocationSession:
        assert request.access_token == "test-access-token"
        return self._session


class _AllowPolicy:
    def evaluate(self, context: PolicyContext) -> PolicyResult:
        assert context.operation == "firecrawl.search"
        return PolicyResult(Decision.ALLOW, "acceptance", "allowed", "test", "1")


class _UnusedApprovals:
    async def resolve(
        self,
        *,
        request: InvocationRequest,
        session: InvocationSession,
        fingerprint: RequestFingerprint,
        policy: PolicyResult,
        pool_name: str,
        estimated_cost_units: int,
    ) -> ApprovalResolution:
        del request, session, fingerprint, policy, pool_name, estimated_cost_units
        raise AssertionError("an ALLOW policy must not consult approvals")


class _QuotaRepository:
    def __init__(self) -> None:
        self.reserve_calls = 0
        self.reconcile_calls = 0

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
        del request_id, unit, now_ms, expires_at_ms, reservation_id, metadata
        self.reserve_calls += 1
        return QuotaReservationResult(
            QuotaReservationStatus.RESERVED,
            f"reservation-{self.reserve_calls}-{quota_scope_id}",
            100,
            100 - amount_units,
        )

    def reconcile_quota_reservation(
        self,
        *,
        reservation_id: str,
        actual_units: int | None,
        now_ms: int,
        outcome_known: bool,
    ) -> bool:
        del reservation_id, actual_units, now_ms, outcome_known
        self.reconcile_calls += 1
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
        del old_reservation_id, request_id, unit, now_ms, expires_at_ms
        del reservation_id, metadata
        self.reserve_calls += 1
        self.reconcile_calls += 1
        return QuotaReservationResult(
            QuotaReservationStatus.RESERVED,
            f"reservation-{self.reserve_calls}-{quota_scope_id}",
            100,
            100 - amount_units,
        )


class _CredentialLeases:
    def __init__(self) -> None:
        self.acquire_calls = 0
        self.release_calls = 0

    def acquire(
        self,
        *,
        candidate: RouteCandidate,
        request_id: RequestId,
        now_ms: int,
        expires_at_ms: int,
    ) -> CredentialDispatchLease:
        del now_ms
        self.acquire_calls += 1
        return CredentialDispatchLease(
            LeaseId(f"lease_{_A}"),
            candidate.credential.credential_id,
            request_id,
            candidate.credential.generation,
            expires_at_ms,
        )

    def release(self, lease: CredentialDispatchLease, *, now_ms: int) -> bool:
        del lease, now_ms
        self.release_calls += 1
        return True


class _InvocationRepository:
    def __init__(self) -> None:
        self.states: list[InvocationStateEvent] = []
        self.attempts: list[AttemptEvent] = []
        self.validated: list[InvocationValidatedEvent] = []

    @property
    def transaction_active(self) -> bool:
        return False

    async def begin_invocation(self, event: InvocationStartEvent) -> None:
        self.states.append(
            InvocationStateEvent(
                request_id=event.request_id,
                state=InvocationState.RECEIVED,
                occurred_at_ms=event.occurred_at_ms,
            )
        )

    async def record_validated(self, event: InvocationValidatedEvent) -> None:
        self.validated.append(event)

    async def record_state(self, event: InvocationStateEvent) -> None:
        self.states.append(event)

    async def record_attempt(self, event: AttemptEvent) -> None:
        self.attempts.append(event)


def _pool(credential_id: CredentialId) -> NamedPool:
    principal_id = PrincipalId(f"prn_{_A}")
    quota_scope_id = QuotaScopeId(f"quota_{_A}")
    return NamedPool(
        PoolId(f"pool_{_A}"),
        "interactive-default",
        "firecrawl",
        PoolSelectionStrategy.FILL_FIRST,
        (
            PoolMember(
                QuotaScopeSnapshot(
                    quota_scope_id,
                    principal_id,
                    "firecrawl",
                    "credits",
                    last_known_remaining_units=100,
                ),
                (RoutingCredential(credential_id, principal_id, quota_scope_id),),
            ),
        ),
    )


def _request(suffix: str, *, deadline_ms: int) -> InvocationRequest:
    payload: Mapping[str, object] = {
        "query": "same graduate roles",
        "limit": 5,
        "purpose": "career_discovery",
        "data_classification": ["public_web_query"],
    }
    return InvocationRequest(
        RequestId(f"req_{suffix}"),
        "test-access-token",
        RootRunId(f"run_{_A}"),
        "firecrawl",
        "firecrawl.search",
        payload,
        "career_discovery",
        frozenset({"public_web_query"}),
        deadline_ms,
    )


async def _public_resolver(_host: str) -> tuple[str, ...]:
    return ("93.184.216.34",)


@pytest.mark.asyncio
async def test_concurrent_coordinator_duplicates_admit_and_dispatch_once() -> None:
    clock = SystemUtcClock()
    root_run_id = RootRunId(f"run_{_A}")
    credential_id = CredentialId(f"cred_{_A}")
    session = InvocationSession(
        SessionId(f"ses_{_A}"),
        ClientId(f"client_{_A}"),
        root_run_id,
        WorkspaceId(f"ws_{_A}"),
        ClientClass.INTERACTIVE,
        frozenset({"firecrawl.search"}),
        {"firecrawl": "interactive-default"},
        request_count_remaining=10,
        credit_budget_remaining_units=100,
    )
    budgets = InMemoryBudgetGateway({root_run_id: 100})
    quota_repository = _QuotaRepository()
    credential_leases = _CredentialLeases()
    repository = _InvocationRepository()
    app = ScriptedProviderASGI()
    app.script(
        "POST",
        "/v2/search",
        [
            ProviderScriptStep(
                mode=ScriptMode.DELAY,
                delay_ms=100,
                json_data={"success": True, "creditsUsed": 1},
            )
        ],
    )
    key_store = InMemoryKeyStore()
    await key_store.put(
        CredentialMetadata(
            str(credential_id),
            str(PrincipalId(f"prn_{_A}")),
            str(QuotaScopeId(f"quota_{_A}")),
            "acceptance",
        ),
        b"COORDINATOR_ACCEPTANCE_SECRET_123456",
    )
    client = httpx.AsyncClient(
        base_url=FIRECRAWL_ORIGIN,
        transport=httpx.ASGITransport(app=app),
    )
    transport = HttpxProviderTransport(
        key_store=key_store,
        network_enabled=True,
        client=client,
        resolver=_public_resolver,
    )
    coordinator = InvocationCoordinator(
        clock=clock,
        sessions=_Sessions(session),
        operations=FirecrawlOperationGateway(),
        fingerprints=DefaultFingerprintGateway(FingerprintService(b"f" * 32)),
        sensitive=DefaultSensitiveInspector(),
        policy=_AllowPolicy(),
        approvals=_UnusedApprovals(),
        budgets=budgets,
        router=NamedPoolRouter([_pool(credential_id)]),
        quota=QuotaReservationManager(quota_repository),
        scheduler=BoundedFairScheduler(
            limits=SchedulerLimits(
                global_maximum_in_flight=2,
                global_maximum_queued=4,
                per_session_maximum_in_flight=2,
                per_session_maximum_queued=4,
                services={"firecrawl": ServiceLimits(2, 4)},
            ),
            now_ms=clock.now_ms,
        ),
        credential_leases=credential_leases,
        repository=repository,
        transport=transport,
        affinities=InMemoryResourceAffinityStore(maximum_entries=10),
        circuit_breakers=CircuitBreakerRegistry(),
        singleflight=SingleFlightCoordinator(maximum_waiters_per_group=4),
    )
    deadline_ms = clock.now_ms() + 5_000
    leader_request = _request(_A, deadline_ms=deadline_ms)
    duplicate_request = _request(_B, deadline_ms=deadline_ms)

    leader = asyncio.create_task(coordinator.invoke(leader_request))
    for _ in range(100):
        if app.observations:
            break
        await asyncio.sleep(0.001)
    assert len(app.observations) == 1
    duplicate = asyncio.create_task(coordinator.invoke(duplicate_request))
    try:
        leader_result, duplicate_result = await asyncio.gather(leader, duplicate)
    finally:
        await client.aclose()

    assert leader_result.state is InvocationState.SUCCEEDED
    assert duplicate_result.state is InvocationState.SUCCEEDED
    assert duplicate_result.data == {"success": True, "creditsUsed": 1}
    assert len(app.observations) == 1
    assert quota_repository.reserve_calls == 1
    assert quota_repository.reconcile_calls == 1
    assert credential_leases.acquire_calls == 1
    assert credential_leases.release_calls == 1
    assert await budgets.remaining(root_run_id) == 99
    duplicate_states = [
        event.state
        for event in repository.states
        if event.request_id == duplicate_request.request_id
    ]
    assert InvocationState.DUPLICATE_IN_FLIGHT in duplicate_states
    assert duplicate_states[-1] is InvocationState.SUCCEEDED
