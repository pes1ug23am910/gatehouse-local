from __future__ import annotations

import asyncio
import sqlite3
from collections import deque
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, replace

import pytest

from gatehouse.core.errors import ErrorCode
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
from gatehouse.core.states import ApprovalState, InvocationState
from gatehouse.database.repository import QuotaReservationResult, QuotaReservationStatus
from gatehouse.fingerprint import (
    FingerprintService,
    RequestFingerprint,
    RunawayDecision,
    RunawayDetector,
    SingleFlightCoordinator,
)
from gatehouse.invocations import (
    ApprovalResolution,
    BudgetReservation,
    CanonicalOperation,
    ClassifiedProviderOutcome,
    DefaultFingerprintGateway,
    DefaultSensitiveInspector,
    FirecrawlOperationGateway,
    InvocationCoordinator,
    InvocationRequest,
    InvocationRequestLimitExceeded,
    InvocationSession,
    ValidatedOperation,
)
from gatehouse.invocations.models import (
    AttemptEvent,
    InvocationStartEvent,
    InvocationStateEvent,
    InvocationValidatedEvent,
)
from gatehouse.policy import (
    ClientClass,
    Decision,
    InspectionResult,
    PolicyContext,
    PolicyResult,
)
from gatehouse.policy.targets import TargetValidationError
from gatehouse.providers import ProviderErrorClass, ProviderRequest, ProviderResponse
from gatehouse.providers.transport import ProviderNetworkDisabledError
from gatehouse.routing import (
    BreakerKey,
    BreakerScopeType,
    CircuitBreakerRegistry,
    CredentialDispatchLease,
    CredentialLeaseUnavailableError,
    InMemoryResourceAffinityStore,
    NamedPool,
    NamedPoolRouter,
    PoolMember,
    PoolSelectionStrategy,
    QuotaReservationManager,
    QuotaScopeSnapshot,
    ResourceAffinity,
    RetryPolicy,
    RouteCandidate,
    RoutingCredential,
)
from gatehouse.scheduler import (
    BoundedFairScheduler,
    DispatchPermit,
    QueueTicket,
    SchedulerLimits,
    SchedulerSnapshot,
    ServiceLimits,
    WorkItem,
)

_A = "00000000000000000000000001"
_B = "00000000000000000000000002"
_C = "00000000000000000000000003"


@dataclass
class ManualClock:
    value_ms: int

    def now_ms(self) -> int:
        return self.value_ms

    async def sleep(self, seconds: float) -> None:
        self.value_ms += round(seconds * 1_000)


class SessionGateway:
    def __init__(self, session: InvocationSession, log: list[str]) -> None:
        self.session = session
        self.log = log

    async def authenticate(self, request: InvocationRequest) -> InvocationSession:
        del request
        self.log.append("session")
        return self.session


class Operations(FirecrawlOperationGateway):
    def __init__(self, log: list[str]) -> None:
        super().__init__()
        self.log = log

    def validate(
        self,
        service_id: str,
        operation: str,
        payload: object,
    ) -> ValidatedOperation:
        self.log.append("validate")
        return super().validate(service_id, operation, payload)

    def canonicalize(self, validated: ValidatedOperation) -> CanonicalOperation:
        self.log.append("canonicalize")
        return super().canonicalize(validated)


class RaisingClassifier(Operations):
    def __init__(self, log: list[str], error: BaseException) -> None:
        super().__init__(log)
        self.error = error

    def classify_response(
        self,
        operation: str,
        response: ProviderResponse,
    ) -> ClassifiedProviderOutcome:
        del operation, response
        raise self.error


class Fingerprints(DefaultFingerprintGateway):
    def __init__(self, log: list[str]) -> None:
        super().__init__(FingerprintService(b"f" * 32))
        self.log = log

    def calculate(
        self,
        *,
        session: InvocationSession,
        request: InvocationRequest,
        canonical: CanonicalOperation,
    ) -> RequestFingerprint:
        self.log.append("fingerprint")
        return super().calculate(
            session=session,
            request=request,
            canonical=canonical,
        )


class Sensitive(DefaultSensitiveInspector):
    def __init__(self, log: list[str]) -> None:
        self.log = log

    def inspect(self, payload: object) -> InspectionResult:
        self.log.append("sensitive")
        return super().inspect(payload)


class Policy:
    def __init__(self, log: list[str], decision: Decision = Decision.ALLOW) -> None:
        self.log = log
        self.decision = decision

    def evaluate(self, context: PolicyContext) -> PolicyResult:
        del context
        self.log.append("policy")
        return PolicyResult(
            self.decision,
            "test-rule",
            "test",
            "test-policy",
            "1",
        )


class Approvals:
    def __init__(
        self,
        log: list[str],
        resolution: ApprovalResolution | None = None,
    ) -> None:
        self.log = log
        self.resolution = resolution or ApprovalResolution(
            ApprovalState.APPROVED,
            "approval",
        )

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
        self.log.append("approval")
        return self.resolution


class Budgets:
    def __init__(self, log: list[str]) -> None:
        self.log = log
        self.reconciled: list[tuple[int | None, bool]] = []

    async def reserve(
        self,
        *,
        request: InvocationRequest,
        session: InvocationSession,
        amount_units: int,
        unit: str,
    ) -> BudgetReservation:
        del request, session
        self.log.append("budget")
        return BudgetReservation(
            "budget",
            amount_units,
            unit,
        )

    async def reconcile(
        self,
        reservation: BudgetReservation,
        *,
        actual_units: int | None,
        outcome_known: bool,
    ) -> None:
        del reservation
        self.reconciled.append((actual_units, outcome_known))


class QuotaRepository:
    def __init__(
        self,
        log: list[str],
        *,
        available: bool = True,
        replacement_available: bool = True,
        replacement_unavailable_scope_ids: frozenset[str] = frozenset(),
    ) -> None:
        self.log = log
        self.available = available
        self.replacement_available = replacement_available
        self.replacement_unavailable_scope_ids = replacement_unavailable_scope_ids
        self.sequence = 0
        self.reconciled: list[tuple[str, int | None, bool]] = []

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
        self.log.append("quota")
        if not self.available:
            return QuotaReservationResult(
                QuotaReservationStatus.EXHAUSTED,
                None,
                0,
                0,
            )
        self.sequence += 1
        return QuotaReservationResult(
            QuotaReservationStatus.RESERVED,
            f"reservation-{self.sequence}-{quota_scope_id}",
            1_000,
            1_000 - amount_units,
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
        self.reconciled.append((reservation_id, actual_units, outcome_known))
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
        del request_id, unit, now_ms, expires_at_ms, reservation_id, metadata
        self.log.append("quota")
        if (
            not self.replacement_available
            or quota_scope_id in self.replacement_unavailable_scope_ids
        ):
            return QuotaReservationResult(
                QuotaReservationStatus.EXHAUSTED,
                None,
                0,
                0,
            )
        self.reconciled.append((old_reservation_id, 0, True))
        self.sequence += 1
        return QuotaReservationResult(
            QuotaReservationStatus.RESERVED,
            f"reservation-{self.sequence}-{quota_scope_id}",
            1_000,
            1_000 - amount_units,
        )


class Scheduler:
    def __init__(self, clock: ManualClock, log: list[str]) -> None:
        self.log = log
        self.enqueued: list[WorkItem] = []
        self._scheduler = BoundedFairScheduler(
            limits=SchedulerLimits(
                global_maximum_in_flight=4,
                global_maximum_queued=20,
                per_session_maximum_in_flight=4,
                per_session_maximum_queued=20,
                services={"firecrawl": ServiceLimits(4, 20)},
            ),
            now_ms=clock.now_ms,
        )

    async def enqueue(self, item: WorkItem) -> QueueTicket:
        self.log.append("queue")
        self.enqueued.append(item)
        return await self._scheduler.enqueue(item)

    async def release(self, permit: DispatchPermit) -> bool:
        return await self._scheduler.release(permit)

    async def snapshot(self) -> SchedulerSnapshot:
        return await self._scheduler.snapshot()


class CredentialLeases:
    def __init__(
        self,
        log: list[str],
        *,
        unavailable_credential_ids: frozenset[str] = frozenset(),
        reject_release_once: bool = False,
    ) -> None:
        self.log = log
        self.unavailable_credential_ids = unavailable_credential_ids
        self.attempted: list[str] = []
        self.reject_release_once = reject_release_once
        self.sequence = 0
        self.active: set[LeaseId] = set()
        self.released: list[LeaseId] = []

    def acquire(
        self,
        *,
        candidate: RouteCandidate,
        request_id: RequestId,
        now_ms: int,
        expires_at_ms: int,
    ) -> CredentialDispatchLease:
        del now_ms
        self.log.append("credential_lease")
        credential_id = str(candidate.credential.credential_id)
        self.attempted.append(credential_id)
        if credential_id in self.unavailable_credential_ids:
            raise CredentialLeaseUnavailableError("injected lease contention")
        self.sequence += 1
        suffix = _A if self.sequence == 1 else _B
        lease = CredentialDispatchLease(
            LeaseId(f"lease_{suffix}"),
            candidate.credential.credential_id,
            request_id,
            candidate.credential.generation,
            expires_at_ms,
        )
        self.active.add(lease.lease_id)
        return lease

    def release(self, lease: CredentialDispatchLease, *, now_ms: int) -> bool:
        del now_ms
        self.released.append(lease.lease_id)
        if self.reject_release_once:
            self.reject_release_once = False
            return False
        if lease.lease_id not in self.active:
            return False
        self.active.remove(lease.lease_id)
        return True


class Repository:
    def __init__(
        self,
        *,
        transaction_active: bool = False,
        fail_state_once: InvocationState | None = None,
        fail_attempt_state_once: InvocationState | None = None,
        block_state: InvocationState | None = None,
        block_attempt_state: InvocationState | None = None,
    ) -> None:
        self.states: list[InvocationStateEvent] = []
        self.attempts: list[AttemptEvent] = []
        self.validated: list[InvocationValidatedEvent] = []
        self._transaction_active = transaction_active
        self.fail_state_once = fail_state_once
        self.fail_attempt_state_once = fail_attempt_state_once
        self.block_state = block_state
        self.block_attempt_state = block_attempt_state
        self.state_started = asyncio.Event()
        self.state_release = asyncio.Event()
        self.attempt_started = asyncio.Event()
        self.attempt_release = asyncio.Event()

    @property
    def transaction_active(self) -> bool:
        return self._transaction_active

    async def begin_invocation(self, event: InvocationStartEvent) -> None:
        received = InvocationStateEvent(
            request_id=event.request_id,
            state=InvocationState.RECEIVED,
            occurred_at_ms=event.occurred_at_ms,
        )
        if received.state is self.fail_state_once:
            self.fail_state_once = None
            raise RuntimeError("injected state persistence failure")
        self.states.append(received)

    async def record_validated(self, event: InvocationValidatedEvent) -> None:
        self.validated.append(event)

    async def record_state(self, event: InvocationStateEvent) -> None:
        if event.state is self.fail_state_once:
            self.fail_state_once = None
            raise RuntimeError("injected state persistence failure")
        if event.state is self.block_state:
            self.state_started.set()
            await self.state_release.wait()
        self.states.append(event)

    async def record_attempt(self, event: AttemptEvent) -> None:
        if event.state is self.fail_attempt_state_once:
            self.fail_attempt_state_once = None
            raise RuntimeError("injected attempt persistence failure")
        if event.state is self.block_attempt_state:
            self.attempt_started.set()
            await self.attempt_release.wait()
        self.attempts.append(event)


class _SimulatedProcessCrash(BaseException):
    pass


class FailingAffinityStore(InMemoryResourceAffinityStore):
    def __init__(self, error: BaseException) -> None:
        super().__init__()
        self.error = error
        self.bind_calls = 0

    async def bind(self, affinity: ResourceAffinity) -> ResourceAffinity:
        del affinity
        self.bind_calls += 1
        raise self.error


class RequestLimitRepository(Repository):
    async def begin_invocation(self, event: InvocationStartEvent) -> None:
        del event
        raise InvocationRequestLimitExceeded("request allowance exhausted")


class Transport:
    def __init__(
        self,
        log: list[str],
        responses: Iterable[ProviderResponse],
        *,
        blocked: bool = False,
    ) -> None:
        self.log = log
        self.responses = deque(responses)
        self.requests: list[ProviderRequest] = []
        self.started = asyncio.Event()
        self.release_event = asyncio.Event()
        if not blocked:
            self.release_event.set()

    async def send(self, request: ProviderRequest) -> ProviderResponse:
        self.log.append("dispatch")
        self.requests.append(request)
        self.started.set()
        await self.release_event.wait()
        return self.responses.popleft()


class UnsafeTargetTransport(Transport):
    def __init__(self, log: list[str]) -> None:
        super().__init__(log, [])
        self.network_calls = 0

    async def send(self, request: ProviderRequest) -> ProviderResponse:
        del request
        self.log.append("dispatch")
        raise TargetValidationError("resolved_address_is_not_public")


class NetworkDisabledTransport(Transport):
    async def send(self, request: ProviderRequest) -> ProviderResponse:
        del request
        self.log.append("dispatch")
        raise ProviderNetworkDisabledError("provider networking is disabled")


class RecordingRunaway:
    def __init__(self) -> None:
        self.delegate = RunawayDetector(threshold=10)
        self.arrivals = 0

    def record_arrival(
        self,
        *,
        session_id: str,
        fingerprint: RequestFingerprint,
        now_ms: int,
    ) -> RunawayDecision:
        self.arrivals += 1
        return self.delegate.record_arrival(
            session_id=session_id,
            fingerprint=fingerprint,
            now_ms=now_ms,
        )

    def retry_after_ms(
        self,
        *,
        session_id: str,
        fingerprint: RequestFingerprint,
        now_ms: int,
    ) -> int | None:
        return self.delegate.retry_after_ms(
            session_id=session_id,
            fingerprint=fingerprint,
            now_ms=now_ms,
        )


@dataclass
class Harness:
    coordinator: InvocationCoordinator
    transport: Transport
    repository: Repository
    quota_repository: QuotaRepository
    budgets: Budgets
    affinities: InMemoryResourceAffinityStore
    runaway: RecordingRunaway
    scheduler: Scheduler
    credential_leases: CredentialLeases
    singleflight: SingleFlightCoordinator
    log: list[str]
    clock: ManualClock


def session() -> InvocationSession:
    return InvocationSession(
        SessionId(f"ses_{_A}"),
        ClientId(f"client_{_A}"),
        RootRunId(f"run_{_A}"),
        WorkspaceId(f"ws_{_A}"),
        ClientClass.INTERACTIVE,
        frozenset(
            {
                "firecrawl.search",
                "firecrawl.scrape",
                "firecrawl.crawl.start",
                "firecrawl.crawl.status",
            }
        ),
        {"firecrawl": "interactive-default"},
        20,
        1_000,
    )


def named_pool() -> NamedPool:
    members = []
    for index, suffix in enumerate((_A, _B), start=1):
        principal = PrincipalId(f"prn_{suffix}")
        scope = QuotaScopeId(f"quota_{suffix}")
        members.append(
            PoolMember(
                QuotaScopeSnapshot(
                    scope,
                    principal,
                    "firecrawl",
                    "credits",
                    last_known_remaining_units=1_000,
                ),
                (RoutingCredential(CredentialId(f"cred_{suffix}"), principal, scope),),
                cost_rank=index,
            )
        )
    return NamedPool(
        PoolId(f"pool_{_A}"),
        "interactive-default",
        "firecrawl",
        PoolSelectionStrategy.CHEAPEST_FIRST,
        tuple(members),
    )


def request(
    suffix: str = _A,
    *,
    operation: str = "firecrawl.search",
    queue_deadline_ms: int = 100_000,
    root_run_id: RootRunId | None = None,
) -> InvocationRequest:
    payload: Mapping[str, object]
    if operation == "firecrawl.search":
        payload = {
            "query": "graduate roles",
            "limit": 5,
            "purpose": "career_discovery",
            "data_classification": ["public_web_query"],
        }
    elif operation == "firecrawl.scrape":
        payload = {
            "url": "https://example.com/jobs",
            "purpose": "career_site_research",
            "data_classification": ["public_web"],
        }
    elif operation == "firecrawl.crawl.start":
        payload = {
            "url": "https://example.com/jobs",
            "include_paths": [r"^/jobs/.*$"],
            "maximum_pages": 5,
            "maximum_depth": 2,
            "purpose": "multi_page_job_extraction",
            "data_classification": ["public_web"],
        }
    else:
        payload = {"provider_job_id": "provider-job"}
    return InvocationRequest(
        RequestId(f"req_{suffix}"),
        "access-token",
        root_run_id or RootRunId(f"run_{_A}"),
        "firecrawl",
        operation,
        payload,
        "career_discovery",
        frozenset({"public_web_query"}),
        queue_deadline_ms,
    )


def harness(
    responses: Iterable[ProviderResponse],
    *,
    blocked_transport: bool = False,
    transaction_active: bool = False,
    fail_state_once: InvocationState | None = None,
    fail_attempt_state_once: InvocationState | None = None,
    block_state: InvocationState | None = None,
    block_attempt_state: InvocationState | None = None,
    reservation_ttl_ms: int = 900_000,
    quota_available: bool = True,
    replacement_available: bool = True,
    replacement_unavailable_scope_ids: frozenset[str] = frozenset(),
    unavailable_credential_ids: frozenset[str] = frozenset(),
    reject_credential_release_once: bool = False,
    decision: Decision = Decision.ALLOW,
    transport: Transport | None = None,
) -> Harness:
    log: list[str] = []
    clock = ManualClock(1_000)
    breakers = CircuitBreakerRegistry()
    pool = named_pool()
    quota_repository = QuotaRepository(
        log,
        available=quota_available,
        replacement_available=replacement_available,
        replacement_unavailable_scope_ids=replacement_unavailable_scope_ids,
    )
    repository = Repository(
        transaction_active=transaction_active,
        fail_state_once=fail_state_once,
        fail_attempt_state_once=fail_attempt_state_once,
        block_state=block_state,
        block_attempt_state=block_attempt_state,
    )
    budgets = Budgets(log)
    resolved_transport = transport or Transport(log, responses, blocked=blocked_transport)
    affinities = InMemoryResourceAffinityStore()
    runaway = RecordingRunaway()
    scheduler = Scheduler(clock, log)
    credential_leases = CredentialLeases(
        log,
        unavailable_credential_ids=unavailable_credential_ids,
        reject_release_once=reject_credential_release_once,
    )
    singleflight = SingleFlightCoordinator()
    coordinator = InvocationCoordinator(
        clock=clock,
        sessions=SessionGateway(session(), log),
        operations=Operations(log),
        fingerprints=Fingerprints(log),
        sensitive=Sensitive(log),
        policy=Policy(log, decision),
        approvals=Approvals(log),
        budgets=budgets,
        router=NamedPoolRouter([pool], circuit_breakers=breakers),
        quota=QuotaReservationManager(quota_repository),
        scheduler=scheduler,
        credential_leases=credential_leases,
        repository=repository,
        transport=resolved_transport,
        affinities=affinities,
        circuit_breakers=breakers,
        retry_policy=RetryPolicy(maximum_attempts=3, jitter=False),
        singleflight=singleflight,
        runaway=runaway,
        sleeper=clock.sleep,
        reservation_ttl_ms=reservation_ttl_ms,
    )
    return Harness(
        coordinator,
        resolved_transport,
        repository,
        quota_repository,
        budgets,
        affinities,
        runaway,
        scheduler,
        credential_leases,
        singleflight,
        log,
        clock,
    )


async def occupy_scheduler(item: Harness) -> list[DispatchPermit]:
    permits: list[DispatchPermit] = []
    for index in range(4):
        ticket = await item.scheduler.enqueue(
            WorkItem(
                request_id=f"blocker-{index}",
                session_id=f"blocker-session-{index}",
                service_id="firecrawl",
                priority=session().priority,
                enqueued_at_ms=1_000,
                deadline_ms=100_000,
            )
        )
        permits.append(await ticket.wait())
    return permits


async def wait_for_scheduler_queue(item: Harness, expected: int) -> None:
    for _ in range(100):
        if (await item.scheduler.snapshot()).queued_total == expected:
            return
        await asyncio.sleep(0)
    pytest.fail(f"scheduler queue did not reach {expected}")


async def wait_for_state(
    item: Harness,
    request_id: RequestId,
    state: InvocationState,
) -> None:
    for _ in range(100):
        if any(
            event.request_id == request_id and event.state is state
            for event in item.repository.states
        ):
            return
        await asyncio.sleep(0)
    pytest.fail(f"request {request_id} did not reach {state.value}")


@pytest.mark.asyncio
async def test_pipeline_order_and_success_without_real_provider_call() -> None:
    item = harness(
        [
            ProviderResponse(
                200,
                data={"success": True, "creditsUsed": 1, "data": []},
            )
        ]
    )

    result = await item.coordinator.invoke(request())

    assert result.state is InvocationState.SUCCEEDED, item.log
    expected = [
        "validate",
        "canonicalize",
        "fingerprint",
        "sensitive",
        "policy",
        "budget",
        "quota",
        "queue",
        "credential_lease",
        "dispatch",
    ]
    assert [entry for entry in item.log if entry in expected] == expected
    assert [event.state for event in item.repository.states] == [
        InvocationState.RECEIVED,
        InvocationState.VALIDATING,
        InvocationState.POLICY_CHECK,
        InvocationState.DEDUPLICATION,
        InvocationState.QUOTA_RESERVED,
        InvocationState.QUEUED,
        InvocationState.DISPATCHING,
        InvocationState.RUNNING,
        InvocationState.SUCCEEDED,
    ]
    assert item.quota_repository.reconciled[0][1:] == (1, True)
    assert item.budgets.reconciled == [(1, True)]


@pytest.mark.asyncio
async def test_authenticated_entrypoint_uses_trusted_session_without_bearer_reauthentication() -> (
    None
):
    item = harness([ProviderResponse(200, data={"creditsUsed": 1})])
    trusted_request = replace(request(), access_token=None)

    result = await item.coordinator.invoke_authenticated(trusted_request, session())

    assert result.state is InvocationState.SUCCEEDED
    assert "session" not in item.log
    assert item.repository.states[0].state is InvocationState.RECEIVED
    assert item.repository.validated[0].fingerprint == result.fingerprint
    with pytest.raises(ValueError, match="requires an access token"):
        await item.coordinator.invoke(trusted_request)


@pytest.mark.asyncio
async def test_durable_request_limit_rejection_is_a_public_budget_error() -> None:
    item = harness([])
    item.coordinator.repository = RequestLimitRepository()

    result = await item.coordinator.invoke(request())

    assert result.state is InvocationState.DENIED
    assert result.error is not None
    assert result.error.code is ErrorCode.BUDGET_EXHAUSTED
    assert item.transport.requests == []


@pytest.mark.asyncio
async def test_internal_reconciliation_flag_is_restricted_to_resource_operations() -> None:
    item = harness([])
    internal_session = replace(session(), internal_resource_reconciliation=True)

    with pytest.raises(ValueError, match="resource-bound"):
        await item.coordinator.invoke_authenticated(
            replace(request(), access_token=None),
            internal_session,
        )

    assert item.repository.states == []


@pytest.mark.asyncio
async def test_initial_quota_exhaustion_never_fabricates_a_queue_state() -> None:
    item = harness([], quota_available=False)

    result = await item.coordinator.invoke(request())

    assert result.state is InvocationState.QUOTA_EXHAUSTED
    assert [event.state for event in item.repository.states] == [
        InvocationState.RECEIVED,
        InvocationState.VALIDATING,
        InvocationState.POLICY_CHECK,
        InvocationState.DEDUPLICATION,
        InvocationState.QUOTA_EXHAUSTED,
    ]
    assert "queue" not in item.log
    assert "credential_lease" not in item.log
    assert "dispatch" not in item.log


@pytest.mark.asyncio
async def test_concurrent_duplicate_has_one_dispatch_and_both_arrivals_count() -> None:
    item = harness(
        [ProviderResponse(200, data={"creditsUsed": 1})],
        blocked_transport=True,
    )
    leader = asyncio.create_task(item.coordinator.invoke(request(_A)))
    await item.transport.started.wait()
    duplicate = asyncio.create_task(item.coordinator.invoke(request(_B)))
    await asyncio.sleep(0)
    item.transport.release_event.set()
    leader_result, duplicate_result = await asyncio.gather(leader, duplicate)

    assert leader_result.state is InvocationState.SUCCEEDED
    assert duplicate_result.state is InvocationState.SUCCEEDED
    assert duplicate_result.data == {"creditsUsed": 1}
    assert len(item.transport.requests) == 1
    assert item.log.count("budget") == 1
    assert item.log.count("quota") == 1
    assert item.runaway.arrivals == 2


@pytest.mark.asyncio
async def test_leader_caller_cancellation_promotes_waiter_and_keeps_one_execution() -> None:
    item = harness(
        [ProviderResponse(200, data={"creditsUsed": 1, "data": ["stable"]})],
        blocked_transport=True,
    )
    leader_request = request(_A)
    waiter_request = request(_B)
    leader = asyncio.create_task(item.coordinator.invoke(leader_request))
    await item.transport.started.wait()
    waiter = asyncio.create_task(item.coordinator.invoke(waiter_request))
    await wait_for_state(item, waiter_request.request_id, InvocationState.DUPLICATE_IN_FLIGHT)

    leader.cancel()
    with pytest.raises(asyncio.CancelledError):
        await leader
    item.transport.release_event.set()
    waiter_result = await waiter

    assert waiter_result.request_id == waiter_request.request_id
    assert waiter_result.state is InvocationState.SUCCEEDED
    assert waiter_result.data == {"creditsUsed": 1, "data": ["stable"]}
    assert len(item.transport.requests) == 1
    assert item.singleflight.active_groups == 0
    waiter_events = [
        event for event in item.repository.states if event.request_id == waiter_request.request_id
    ]
    assert waiter_events[-1].state is InvocationState.SUCCEEDED
    assert waiter_events[-1].metadata["coalesced_from_request_id"] == str(leader_request.request_id)


@pytest.mark.asyncio
async def test_cancelled_waiter_detaches_and_replacement_can_join() -> None:
    item = harness(
        [ProviderResponse(200, data={"creditsUsed": 1})],
        blocked_transport=True,
    )
    singleflight = SingleFlightCoordinator(maximum_waiters_per_group=1)
    item.singleflight = singleflight
    item.coordinator.singleflight = singleflight
    leader = asyncio.create_task(item.coordinator.invoke(request(_A)))
    await item.transport.started.wait()
    cancelled_request = request(_B)
    cancelled = asyncio.create_task(item.coordinator.invoke(cancelled_request))
    await wait_for_state(
        item,
        cancelled_request.request_id,
        InvocationState.DUPLICATE_IN_FLIGHT,
    )

    cancelled.cancel()
    with pytest.raises(asyncio.CancelledError):
        await cancelled
    replacement_request = request(_C)
    replacement = asyncio.create_task(item.coordinator.invoke(replacement_request))
    await wait_for_state(
        item,
        replacement_request.request_id,
        InvocationState.DUPLICATE_IN_FLIGHT,
    )
    item.transport.release_event.set()
    leader_result, replacement_result = await asyncio.gather(leader, replacement)

    assert leader_result.state is InvocationState.SUCCEEDED
    assert replacement_result.state is InvocationState.SUCCEEDED
    assert len(item.transport.requests) == 1
    assert item.singleflight.active_groups == 0
    cancelled_events = [
        event.state
        for event in item.repository.states
        if event.request_id == cancelled_request.request_id
    ]
    assert cancelled_events[-1] is InvocationState.CANCELLED


@pytest.mark.asyncio
async def test_coalesced_waiter_deadline_detaches_without_stopping_leader() -> None:
    item = harness(
        [ProviderResponse(200, data={"creditsUsed": 1})],
        blocked_transport=True,
    )
    leader = asyncio.create_task(item.coordinator.invoke(request(_A)))
    await item.transport.started.wait()

    timed_out = await item.coordinator.invoke(request(_B, queue_deadline_ms=1_001))

    assert timed_out.state is InvocationState.CAPACITY_EXCEEDED
    assert timed_out.error is not None
    assert timed_out.error.code is ErrorCode.CAPACITY_EXCEEDED
    assert item.singleflight.active_groups == 1
    item.transport.release_event.set()
    assert (await leader).state is InvocationState.SUCCEEDED
    assert item.singleflight.active_groups == 0


@pytest.mark.asyncio
async def test_noncoalescible_async_creates_dispatch_independently() -> None:
    item = harness(
        [
            ProviderResponse(200, data={"id": "provider-job-one", "creditsUsed": 1}),
            ProviderResponse(200, data={"id": "provider-job-two", "creditsUsed": 1}),
        ],
        blocked_transport=True,
    )
    first = asyncio.create_task(
        item.coordinator.invoke(request(_A, operation="firecrawl.crawl.start"))
    )
    second = asyncio.create_task(
        item.coordinator.invoke(request(_B, operation="firecrawl.crawl.start"))
    )
    for _ in range(100):
        if len(item.transport.requests) == 2:
            break
        await asyncio.sleep(0)
    assert len(item.transport.requests) == 2

    item.transport.release_event.set()
    first_result, second_result = await asyncio.gather(first, second)

    assert first_result.state is InvocationState.SUCCEEDED
    assert second_result.state is InvocationState.SUCCEEDED
    assert {
        first_result.provider_resource_id,
        second_result.provider_resource_id,
    } == {"provider-job-one", "provider-job-two"}
    assert item.log.count("budget") == 2
    assert item.log.count("quota") == 2


@pytest.mark.asyncio
async def test_async_success_checkpoint_is_persisted_before_affinity_bind() -> None:
    item = harness([ProviderResponse(200, data={"id": "provider-job-crash"})])
    crashing_affinities = FailingAffinityStore(_SimulatedProcessCrash())
    item.coordinator.affinities = crashing_affinities

    with pytest.raises(_SimulatedProcessCrash):
        await item.coordinator.invoke(request(_A, operation="firecrawl.crawl.start"))

    assert crashing_affinities.bind_calls == 1
    checkpoint = item.repository.attempts[-1]
    assert checkpoint.state is InvocationState.SUCCEEDED
    assert checkpoint.resource_type == "crawl"
    assert checkpoint.provider_resource_id == "provider-job-crash"
    assert checkpoint.credential_generation == 1
    assert checkpoint.pool_id == f"pool_{_A}"
    assert item.repository.states[-1].state is InvocationState.RUNNING


@pytest.mark.asyncio
async def test_online_affinity_bind_failure_is_durable_unknown_without_replay() -> None:
    item = harness([ProviderResponse(200, data={"id": "provider-job-conflict", "creditsUsed": 7})])
    failing_affinities = FailingAffinityStore(
        sqlite3.OperationalError("injected affinity persistence failure")
    )
    item.coordinator.affinities = failing_affinities

    result = await item.coordinator.invoke(request(_A, operation="firecrawl.crawl.start"))

    assert result.state is InvocationState.UNKNOWN
    assert result.error is not None
    assert result.error.code is ErrorCode.UNCERTAIN_OUTCOME
    assert len(item.transport.requests) == 1
    checkpoint = item.repository.attempts[-1]
    assert checkpoint.state is InvocationState.SUCCEEDED
    assert checkpoint.provider_resource_id == "provider-job-conflict"
    terminal = item.repository.states[-1]
    assert terminal.state is InvocationState.UNKNOWN
    assert terminal.metadata == {"provider_handoff": True}
    assert item.quota_repository.reconciled[0][1:] == (None, False)
    assert item.budgets.reconciled == [(None, False)]


@pytest.mark.asyncio
async def test_async_checkpoint_precedes_credential_lease_release_failure() -> None:
    item = harness(
        [ProviderResponse(200, data={"id": "provider-job-release", "creditsUsed": 5})],
        reject_credential_release_once=True,
    )

    result = await item.coordinator.invoke(request(_A, operation="firecrawl.crawl.start"))

    assert result.state is InvocationState.UNKNOWN
    assert len(item.transport.requests) == 1
    checkpoint = item.repository.attempts[-1]
    assert checkpoint.state is InvocationState.SUCCEEDED
    assert checkpoint.provider_resource_id == "provider-job-release"
    assert item.repository.states[-1].metadata == {"provider_handoff": True}
    assert item.quota_repository.reconciled[0][1:] == (None, False)
    assert item.budgets.reconciled == [(None, False)]
    assert not item.credential_leases.active


@pytest.mark.asyncio
async def test_invalid_async_provider_identifier_is_never_bound_or_retried() -> None:
    item = harness([ProviderResponse(200, data={"id": "invalid/provider-job"})])

    result = await item.coordinator.invoke(request(_A, operation="firecrawl.crawl.start"))

    assert result.state is InvocationState.UNKNOWN
    assert result.error is not None
    assert result.error.code is ErrorCode.UNCERTAIN_OUTCOME
    assert len(item.transport.requests) == 1
    attempt = item.repository.attempts[-1]
    assert attempt.state is InvocationState.UNKNOWN
    assert attempt.provider_resource_id is None
    assert item.quota_repository.reconciled[0][1:] == (None, False)
    assert item.budgets.reconciled == [(None, False)]


@pytest.mark.asyncio
async def test_oversized_async_usage_keeps_resource_checkpoint_and_holds_accounting() -> None:
    item = harness([ProviderResponse(200, data={"id": "valid-provider-job", "creditsUsed": 1e20})])

    result = await item.coordinator.invoke(request(_A, operation="firecrawl.crawl.start"))

    assert result.state is InvocationState.SUCCEEDED
    checkpoint = item.repository.attempts[-1]
    assert checkpoint.state is InvocationState.SUCCEEDED
    assert checkpoint.provider_resource_id == "valid-provider-job"
    assert checkpoint.actual_cost_units is None
    assert item.quota_repository.reconciled[0][1:] == (None, False)
    assert item.budgets.reconciled == [(None, False)]


@pytest.mark.asyncio
async def test_explicit_exhaustion_fails_over_only_inside_selected_pool() -> None:
    item = harness(
        [
            ProviderResponse(402),
            ProviderResponse(200, data={"creditsUsed": 1}),
        ]
    )

    result = await item.coordinator.invoke(request())

    assert result.state is InvocationState.SUCCEEDED
    assert [call.credential_id for call in item.transport.requests] == [
        f"cred_{_A}",
        f"cred_{_B}",
    ]
    assert item.log.count("quota") == 2
    assert len(item.quota_repository.reconciled) == 2


@pytest.mark.asyncio
async def test_possible_submission_is_unknown_and_reservation_is_held() -> None:
    item = harness(
        [
            ProviderResponse(
                None,
                transport_error="ambiguous_transport_failure",
                submission_may_have_occurred=True,
            )
        ]
    )

    result = await item.coordinator.invoke(request())

    assert result.state is InvocationState.UNKNOWN
    assert result.error is not None
    assert result.error.code is ErrorCode.UNCERTAIN_OUTCOME
    assert len(item.transport.requests) == 1
    assert item.quota_repository.reconciled[0][1:] == (None, False)
    assert item.budgets.reconciled == [(None, False)]


@pytest.mark.asyncio
async def test_rate_limit_honors_retry_after_before_bounded_retry() -> None:
    item = harness(
        [
            ProviderResponse(429, headers={"retry-after": "2"}),
            ProviderResponse(200, data={"creditsUsed": 1}),
        ]
    )

    result = await item.coordinator.invoke(request())

    assert result.state is InvocationState.SUCCEEDED
    assert len(item.transport.requests) == 2
    assert item.log.count("queue") == 2


@pytest.mark.asyncio
async def test_permission_failure_does_not_spray_other_pool_members() -> None:
    item = harness([ProviderResponse(403)])

    result = await item.coordinator.invoke(request())

    assert result.state is InvocationState.FAILED
    assert result.error is not None
    assert result.error.code is ErrorCode.PROVIDER_PERMISSION_DENIED
    assert len(item.transport.requests) == 1


@pytest.mark.asyncio
async def test_pending_approval_stops_before_budget_and_dispatch() -> None:
    item = harness([], decision=Decision.ASK)
    item.coordinator.approvals = Approvals(
        item.log,
        ApprovalResolution(ApprovalState.PENDING),
    )

    result = await item.coordinator.invoke(request())

    assert result.state is InvocationState.WAITING_APPROVAL
    assert result.error is not None
    assert result.error.code is ErrorCode.APPROVAL_PENDING
    assert "approval" in item.log
    assert "budget" not in item.log
    assert "dispatch" not in item.log


@pytest.mark.asyncio
async def test_open_transaction_blocks_transport_dispatch() -> None:
    item = harness([ProviderResponse(200)], transaction_active=True)

    result = await item.coordinator.invoke(request())

    assert result.state is InvocationState.FAILED
    assert result.error is not None
    assert result.error.code is ErrorCode.DAEMON_DEGRADED
    assert item.transport.requests == []


@pytest.mark.asyncio
async def test_late_target_failure_is_nonretryable_invalid_target() -> None:
    item = harness([])
    unsafe = UnsafeTargetTransport(item.log)
    item.coordinator.transport = unsafe

    result = await item.coordinator.invoke(request(operation="firecrawl.scrape"))

    assert result.state is InvocationState.FAILED
    assert result.error is not None
    assert result.error.code is ErrorCode.INVALID_TARGET
    assert not result.error.retryable
    assert unsafe.network_calls == 0


@pytest.mark.asyncio
async def test_network_disabled_is_known_not_submitted_and_releases_admission() -> None:
    item = harness([])
    disabled = NetworkDisabledTransport(item.log, [])
    item.coordinator.transport = disabled

    result = await item.coordinator.invoke(request())

    assert result.state is InvocationState.FAILED
    assert result.error is not None
    assert result.error.code is ErrorCode.DAEMON_DEGRADED
    assert item.quota_repository.reconciled[0][1:] == (0, True)
    assert item.budgets.reconciled == [(0, True)]
    assert (await item.scheduler.snapshot()).running_total == 0
    assert item.credential_leases.active == set()
    assert len(item.credential_leases.released) == 1
    assert item.repository.attempts[-1].state is InvocationState.FAILED


@pytest.mark.asyncio
async def test_cancellation_while_queued_releases_budget_quota_and_ticket() -> None:
    item = harness([])
    blockers = await occupy_scheduler(item)
    invocation = asyncio.create_task(item.coordinator.invoke(request()))
    await wait_for_scheduler_queue(item, 1)

    invocation.cancel()
    with pytest.raises(asyncio.CancelledError):
        await invocation

    snapshot = await item.scheduler.snapshot()
    assert snapshot.queued_total == 0
    assert snapshot.running_total == len(blockers)
    assert item.quota_repository.reconciled[0][1:] == (0, True)
    assert item.budgets.reconciled == [(0, True)]
    assert item.singleflight.active_groups == 0
    assert item.repository.states[-1].state is InvocationState.CANCELLED
    for permit in blockers:
        assert await item.scheduler.release(permit)


@pytest.mark.asyncio
async def test_expired_quota_reservation_is_replaced_after_queue_wait() -> None:
    item = harness(
        [ProviderResponse(200, data={"creditsUsed": 1})],
        reservation_ttl_ms=10,
    )
    blockers = await occupy_scheduler(item)
    invocation = asyncio.create_task(item.coordinator.invoke(request()))
    await wait_for_scheduler_queue(item, 1)

    item.clock.value_ms += 10
    assert await item.scheduler.release(blockers.pop())
    result = await invocation

    assert result.state is InvocationState.SUCCEEDED
    assert item.log.count("quota") == 2
    assert [entry[1:] for entry in item.quota_repository.reconciled] == [
        (0, True),
        (1, True),
    ]


@pytest.mark.asyncio
async def test_expired_replacement_on_new_scope_requeues_under_new_scope() -> None:
    item = harness(
        [ProviderResponse(200, data={"creditsUsed": 1})],
        reservation_ttl_ms=10,
        replacement_unavailable_scope_ids=frozenset({f"quota_{_A}"}),
    )
    blockers = await occupy_scheduler(item)
    invocation = asyncio.create_task(item.coordinator.invoke(request()))
    await wait_for_scheduler_queue(item, 1)

    item.clock.value_ms += 10
    assert await item.scheduler.release(blockers.pop())
    result = await invocation

    invocation_items = [
        queued for queued in item.scheduler.enqueued if queued.request_id == str(result.request_id)
    ]
    assert result.state is InvocationState.SUCCEEDED
    assert [queued.quota_scope_id for queued in invocation_items] == [
        f"quota_{_A}",
        f"quota_{_B}",
    ]
    assert [entry[1:] for entry in item.quota_repository.reconciled] == [
        (0, True),
        (1, True),
    ]
    assert (await item.scheduler.snapshot()).running_by_quota_scope == {}
    for permit in blockers:
        assert await item.scheduler.release(permit)


@pytest.mark.asyncio
async def test_lease_failover_to_new_scope_requeues_under_new_scope() -> None:
    item = harness(
        [ProviderResponse(200, data={"creditsUsed": 1})],
        unavailable_credential_ids=frozenset({f"cred_{_A}"}),
    )

    result = await item.coordinator.invoke(request())

    invocation_items = [
        queued for queued in item.scheduler.enqueued if queued.request_id == str(result.request_id)
    ]
    assert result.state is InvocationState.SUCCEEDED
    assert item.credential_leases.attempted == [f"cred_{_A}", f"cred_{_B}"]
    assert [queued.quota_scope_id for queued in invocation_items] == [
        f"quota_{_A}",
        f"quota_{_B}",
    ]
    assert [entry[1:] for entry in item.quota_repository.reconciled] == [
        (0, True),
        (1, True),
    ]
    assert (await item.scheduler.snapshot()).running_by_quota_scope == {}


@pytest.mark.asyncio
async def test_expired_quota_replacement_failure_releases_permit_and_budget() -> None:
    item = harness(
        [],
        reservation_ttl_ms=10,
        replacement_available=False,
    )
    blockers = await occupy_scheduler(item)
    invocation = asyncio.create_task(item.coordinator.invoke(request()))
    await wait_for_scheduler_queue(item, 1)

    item.clock.value_ms += 10
    assert await item.scheduler.release(blockers.pop())
    result = await invocation

    assert result.state is InvocationState.QUOTA_EXHAUSTED
    assert item.quota_repository.reconciled[0][1:] == (0, True)
    assert item.budgets.reconciled == [(0, True)]
    assert "credential_lease" not in item.log
    assert "dispatch" not in item.log
    snapshot = await item.scheduler.snapshot()
    assert snapshot.queued_total == 0
    assert snapshot.running_total == len(blockers)
    for permit in blockers:
        assert await item.scheduler.release(permit)


@pytest.mark.asyncio
async def test_quota_expiring_during_running_persistence_never_reaches_transport() -> None:
    item = harness(
        [],
        reservation_ttl_ms=10,
        block_state=InvocationState.RUNNING,
    )
    invocation = asyncio.create_task(item.coordinator.invoke(request()))
    await item.repository.state_started.wait()

    item.clock.value_ms += 10
    item.repository.state_release.set()
    result = await invocation

    assert result.state is InvocationState.QUOTA_EXHAUSTED
    assert item.transport.requests == []
    assert item.quota_repository.reconciled[0][1:] == (0, True)
    assert item.budgets.reconciled == [(0, True)]
    assert not item.credential_leases.active
    assert len(item.credential_leases.released) == 1
    snapshot = await item.scheduler.snapshot()
    assert snapshot.queued_total == 0
    assert snapshot.running_total == 0


@pytest.mark.asyncio
async def test_quota_is_rechecked_after_running_attempt_persistence() -> None:
    item = harness(
        [],
        reservation_ttl_ms=10,
        block_attempt_state=InvocationState.RUNNING,
    )
    invocation = asyncio.create_task(item.coordinator.invoke(request()))
    await item.repository.attempt_started.wait()

    item.clock.value_ms += 10
    item.repository.attempt_release.set()
    result = await invocation

    assert result.state is InvocationState.QUOTA_EXHAUSTED
    assert item.transport.requests == []
    assert [event.state for event in item.repository.attempts] == [
        InvocationState.DISPATCHING,
        InvocationState.RUNNING,
        InvocationState.FAILED,
    ]
    assert item.quota_repository.reconciled[0][1:] == (0, True)
    assert item.budgets.reconciled == [(0, True)]
    assert (await item.scheduler.snapshot()).running_total == 0


@pytest.mark.asyncio
async def test_cancellation_during_attempt_persistence_is_known_not_submitted() -> None:
    item = harness(
        [],
        block_attempt_state=InvocationState.DISPATCHING,
    )
    invocation = asyncio.create_task(item.coordinator.invoke(request()))
    await item.repository.attempt_started.wait()

    invocation.cancel()
    with pytest.raises(asyncio.CancelledError):
        await invocation

    assert item.transport.requests == []
    assert item.quota_repository.reconciled[0][1:] == (0, True)
    assert item.budgets.reconciled == [(0, True)]
    assert (await item.scheduler.snapshot()).running_total == 0
    assert item.credential_leases.active == set()
    assert item.repository.states[-1].state is InvocationState.CANCELLED


@pytest.mark.asyncio
async def test_permit_handoff_state_failure_releases_all_admission() -> None:
    item = harness(
        [],
        fail_state_once=InvocationState.QUOTA_RESERVED,
    )

    result = await item.coordinator.invoke(request())

    assert result.state is InvocationState.FAILED
    assert result.error is not None
    assert result.error.code is ErrorCode.DAEMON_DEGRADED
    assert item.transport.requests == []
    assert item.quota_repository.reconciled[0][1:] == (0, True)
    assert item.budgets.reconciled == [(0, True)]
    assert (await item.scheduler.snapshot()).running_total == 0
    assert item.credential_leases.active == set()
    assert item.repository.states[-1].state is InvocationState.FAILED


@pytest.mark.asyncio
async def test_cancellation_during_provider_send_holds_ambiguous_admission() -> None:
    item = harness(
        [ProviderResponse(200, data={"creditsUsed": 1})],
        blocked_transport=True,
    )
    invocation = asyncio.create_task(item.coordinator.invoke(request()))
    await item.transport.started.wait()

    invocation.cancel()
    with pytest.raises(asyncio.CancelledError):
        await invocation

    assert item.quota_repository.reconciled[0][1:] == (None, False)
    assert item.budgets.reconciled == [(None, False)]
    assert (await item.scheduler.snapshot()).running_total == 0
    assert item.credential_leases.active == set()
    assert item.repository.states[-1].state is InvocationState.UNKNOWN
    assert item.singleflight.active_groups == 0


@pytest.mark.asyncio
async def test_provider_cancellation_returns_exact_half_open_breaker_probe() -> None:
    item = harness(
        [ProviderResponse(200, data={"creditsUsed": 1})],
        blocked_transport=True,
    )
    key = BreakerKey(BreakerScopeType.SERVICE, "firecrawl")
    item.coordinator.circuit_breakers.record_failure(
        key,
        now_ms=900,
        error_class=ProviderErrorClass.TRANSIENT,
        open_until_ms=1_000,
        force_open=True,
    )
    invocation = asyncio.create_task(item.coordinator.invoke(request()))
    await item.transport.started.wait()
    assert item.coordinator.circuit_breakers.snapshot(key, now_ms=1_000).half_open_in_flight == 1

    invocation.cancel()
    with pytest.raises(asyncio.CancelledError):
        await invocation

    snapshot = item.coordinator.circuit_breakers.snapshot(key, now_ms=1_000)
    assert snapshot.half_open_in_flight == 0
    replacement = item.coordinator.circuit_breakers.try_acquire(key, now_ms=1_000)
    assert replacement is not None
    assert item.coordinator.circuit_breakers.release(replacement)


@pytest.mark.asyncio
async def test_cancellation_during_response_classification_holds_admission() -> None:
    item = harness([ProviderResponse(200, data={"creditsUsed": 1})])
    item.coordinator.operations = RaisingClassifier(item.log, asyncio.CancelledError())

    with pytest.raises(asyncio.CancelledError):
        await item.coordinator.invoke(request())

    assert item.quota_repository.reconciled[0][1:] == (None, False)
    assert item.budgets.reconciled == [(None, False)]
    assert (await item.scheduler.snapshot()).running_total == 0
    assert item.credential_leases.active == set()
    assert item.repository.states[-1].state is InvocationState.UNKNOWN


@pytest.mark.asyncio
async def test_post_response_persistence_failure_settles_known_usage_safely() -> None:
    item = harness(
        [ProviderResponse(200, data={"creditsUsed": 1})],
        fail_attempt_state_once=InvocationState.SUCCEEDED,
    )

    result = await item.coordinator.invoke(request())

    assert result.state is InvocationState.UNKNOWN
    assert result.error is not None
    assert result.error.code is ErrorCode.UNCERTAIN_OUTCOME
    assert item.quota_repository.reconciled[0][1:] == (1, True)
    assert item.budgets.reconciled == [(1, True)]
    assert (await item.scheduler.snapshot()).running_total == 0
    assert item.credential_leases.active == set()
    assert item.repository.states[-1].state is InvocationState.UNKNOWN


@pytest.mark.asyncio
async def test_canonical_target_failure_is_invalid_target_before_admission() -> None:
    item = harness([])
    unsafe_request = InvocationRequest(
        RequestId(f"req_{_A}"),
        "access-token",
        RootRunId(f"run_{_A}"),
        "firecrawl",
        "firecrawl.scrape",
        {
            "url": "http://127.0.0.1/private",
            "purpose": "career_site_research",
            "data_classification": ["public_web"],
        },
        "career_site_research",
        frozenset({"public_web"}),
        100_000,
    )

    result = await item.coordinator.invoke(unsafe_request)

    assert result.state is InvocationState.DENIED
    assert result.error is not None
    assert result.error.code is ErrorCode.INVALID_TARGET
    assert "budget" not in item.log
    assert "dispatch" not in item.log


@pytest.mark.asyncio
async def test_existing_async_resource_forces_original_pool_principal_and_scope() -> None:
    item = harness([ProviderResponse(200, data={"status": "scraping"})])
    await item.affinities.bind(
        ResourceAffinity(
            service_id="firecrawl",
            resource_type="crawl",
            provider_resource_id="provider-job",
            principal_id=PrincipalId(f"prn_{_B}"),
            quota_scope_id=QuotaScopeId(f"quota_{_B}"),
            credential_id=CredentialId(f"cred_{_B}"),
            credential_generation=1,
            pool_id=PoolId(f"pool_{_A}"),
            creating_request_id=RequestId(f"req_{_C}"),
            owner_session_id=SessionId(f"ses_{_A}"),
            owner_workspace_id=WorkspaceId(f"ws_{_A}"),
            owner_root_run_id=RootRunId(f"run_{_A}"),
            bound_at_ms=1,
        )
    )

    result = await item.coordinator.invoke(request(operation="firecrawl.crawl.status"))

    assert result.state is InvocationState.SUCCEEDED
    assert len(item.transport.requests) == 1
    assert item.transport.requests[0].credential_id == f"cred_{_B}"
    assert item.log.count("budget") == 0
    assert item.log.count("quota") == 0


@pytest.mark.asyncio
async def test_missing_async_resource_is_denied_before_policy_or_admission() -> None:
    item = harness([])

    result = await item.coordinator.invoke(request(operation="firecrawl.crawl.status"))

    assert result.state is InvocationState.DENIED
    assert result.error is not None
    assert result.error.code is ErrorCode.POLICY_DENIED
    assert result.error.policy_rule_id == "resource-ownership"
    assert "policy" not in item.log
    assert "budget" not in item.log
    assert "quota" not in item.log
    assert "dispatch" not in item.log


@pytest.mark.asyncio
async def test_cross_session_resource_guess_is_denied_before_policy_or_admission() -> None:
    item = harness([])
    owner = session()
    await item.affinities.bind(
        ResourceAffinity(
            service_id="firecrawl",
            resource_type="crawl",
            provider_resource_id="provider-job",
            principal_id=PrincipalId(f"prn_{_B}"),
            quota_scope_id=QuotaScopeId(f"quota_{_B}"),
            credential_id=CredentialId(f"cred_{_B}"),
            credential_generation=1,
            pool_id=PoolId(f"pool_{_A}"),
            creating_request_id=RequestId(f"req_{_C}"),
            owner_session_id=owner.session_id,
            owner_workspace_id=owner.workspace_id,
            owner_root_run_id=owner.root_run_id,
            bound_at_ms=1,
        )
    )
    other_root = RootRunId(f"run_{_B}")
    item.coordinator.sessions = SessionGateway(
        InvocationSession(
            session_id=SessionId(f"ses_{_B}"),
            client_id=ClientId(f"client_{_B}"),
            root_run_id=other_root,
            workspace_id=owner.workspace_id,
            client_class=owner.client_class,
            allowed_capabilities=owner.allowed_capabilities,
            pool_bindings=owner.pool_bindings,
            request_count_remaining=owner.request_count_remaining,
            credit_budget_remaining_units=owner.credit_budget_remaining_units,
        ),
        item.log,
    )

    result = await item.coordinator.invoke(
        request(
            suffix=_B,
            operation="firecrawl.crawl.status",
            root_run_id=other_root,
        )
    )

    assert result.state is InvocationState.DENIED
    assert result.error is not None
    assert result.error.code is ErrorCode.POLICY_DENIED
    assert result.error.policy_rule_id == "resource-ownership"
    assert "policy" not in item.log
    assert "budget" not in item.log
    assert "quota" not in item.log
    assert "dispatch" not in item.log


@pytest.mark.asyncio
async def test_malformed_provider_response_is_unknown_and_holds_reservations() -> None:
    item = harness(
        [
            ProviderResponse(
                200,
                transport_error="malformed_response",
            )
        ]
    )

    result = await item.coordinator.invoke(request())

    assert result.state is InvocationState.UNKNOWN
    assert result.error is not None
    assert result.error.code is ErrorCode.UNCERTAIN_OUTCOME
    assert len(item.transport.requests) == 1
    assert item.quota_repository.reconciled[0][1:] == (None, False)
    assert item.budgets.reconciled == [(None, False)]
