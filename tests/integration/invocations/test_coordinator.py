from __future__ import annotations

import asyncio
import sqlite3
from collections import deque
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, replace
from pathlib import Path

import pytest

from gatehouse.admin import (
    AdminAuthManager,
    ControlDaemonStatus,
    LocalControlService,
)
from gatehouse.core.errors import ErrorCode, GatehouseError
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
from gatehouse.core.states import ApprovalState, InvocationState, SessionState
from gatehouse.credentials.emergency import EmergencyUnlockManager
from gatehouse.credentials.memory import InMemoryKeyStore
from gatehouse.database import open_migrated_database
from gatehouse.database.repository import QuotaReservationResult, QuotaReservationStatus
from gatehouse.database.runaway import (
    RunawayAdmission,
    RunawayAdmissionState,
    RunawayBurstPermit,
    RunawayQuarantineState,
)
from gatehouse.fingerprint import (
    FingerprintService,
    RequestFingerprint,
    RunawayDecision,
    RunawayDetector,
    RunawayTrigger,
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
    InvocationResult,
    InvocationSession,
    PendingApprovalProbe,
    PendingApprovalProbeStatus,
    ProviderSubmissionLimitExceeded,
    SqliteInvocationRepository,
    ValidatedOperation,
    VerifiedPendingApproval,
)
from gatehouse.invocations.budget import BudgetUnavailableError
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
from gatehouse.providers import (
    CredentialCustodyKind,
    ProviderErrorClass,
    ProviderRequest,
    ProviderResponse,
)
from gatehouse.providers.transport import (
    ProviderNetworkDisabledError,
    ProviderPreHandoffError,
)
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
    ClientCapacityLimits,
    DispatchPermit,
    QueueTicket,
    SchedulerLimits,
    SchedulerSnapshot,
    ServiceLimits,
    WorkItem,
)
from gatehouse.sessions import (
    InvalidAccessToken,
    SessionManager,
    SqliteSessionPersistence,
)

_A = "00000000000000000000000001"
_B = "00000000000000000000000002"
_C = "00000000000000000000000003"
_D = "00000000000000000000000004"
_E = "00000000000000000000000005"
_F = "00000000000000000000000006"
_POOL_SCOPE_SUFFIXES = (_A, _B, _C, _D, _E)
_EMERGENCY_UNLOCK_ID = "unl_dddddddddddddddddddddddddddddddd"
_SYNTHETIC_EMERGENCY_SECRET = bytearray(b"synthetic-emergency-coordinator-canary")
_BOUNDED_REVOCATION_CONCURRENCY = 8


@pytest.mark.parametrize(
    "credits_used",
    [2**53 - 1, 2**53, 2**53 + 1, (1 << 63) - 1],
)
def test_operation_gateway_preserves_exact_workload_credit_integers(credits_used: int) -> None:
    outcome = FirecrawlOperationGateway().classify_response(
        "firecrawl.search",
        ProviderResponse(status_code=200, data={"creditsUsed": credits_used}),
    )

    assert outcome.actual_cost_units == credits_used
    assert type(outcome.actual_cost_units) is int


def test_operation_gateway_rejects_workload_credit_above_int64() -> None:
    outcome = FirecrawlOperationGateway().classify_response(
        "firecrawl.search",
        ProviderResponse(status_code=200, data={"creditsUsed": 1 << 63}),
    )

    assert outcome.actual_cost_units is None


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
        self.active = True
        self.revalidations = 0
        self.revalidation_results: deque[bool] = deque()

    async def authenticate(self, request: InvocationRequest) -> InvocationSession:
        del request
        self.log.append("session")
        return self.session

    async def revalidate(self, session: InvocationSession) -> bool:
        del session
        self.revalidations += 1
        if self.revalidation_results:
            return self.revalidation_results.popleft()
        return self.active


class _BlockingDurableSessionGateway:
    """Expose the coordinator fence while delegating authority to real SQLite state."""

    def __init__(
        self,
        manager: SessionManager,
        projection: InvocationSession,
    ) -> None:
        self._manager = manager
        self._projection = projection
        self.revalidation_started = asyncio.Event()
        self.allow_revalidation = asyncio.Event()
        self.results: list[bool] = []

    async def authenticate(self, request: InvocationRequest) -> InvocationSession:
        del request
        return self._projection

    async def revalidate(self, session: InvocationSession) -> bool:
        self.revalidation_started.set()
        await self.allow_revalidation.wait()
        active = await self._manager.is_active_epoch(
            session_id=str(session.session_id),
            token_epoch=session.token_epoch,
            revocation_epoch=session.revocation_epoch,
        )
        self.results.append(active)
        return active


class _StaticControlHealth:
    async def readiness(self) -> ControlDaemonStatus:
        return ControlDaemonStatus(
            ready=True,
            status="READY",
            version="test",
            schema_version=1,
            policy_version="policy-v1",
            uptime_seconds=0,
        )


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
        self.contexts: list[PolicyContext] = []

    def evaluate(self, context: PolicyContext) -> PolicyResult:
        self.contexts.append(context)
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


class RecordingPendingApprovalProbe:
    def __init__(
        self,
        log: list[str],
        response: PendingApprovalProbe,
    ) -> None:
        self.log = log
        self.response = response
        self.calls: list[dict[str, object]] = []

    async def probe_pending_approval(
        self,
        *,
        request: InvocationRequest,
        session: InvocationSession,
        fingerprint: RequestFingerprint,
        policy: PolicyResult,
        pool_name: str,
        estimated_cost_units: int,
    ) -> PendingApprovalProbe:
        self.log.append("approval_probe")
        self.calls.append(
            {
                "request": request,
                "session": session,
                "fingerprint": fingerprint,
                "policy": policy,
                "pool_name": pool_name,
                "estimated_cost_units": estimated_cost_units,
            }
        )
        return self.response


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


class UnavailableBudgets(Budgets):
    async def reserve(
        self,
        *,
        request: InvocationRequest,
        session: InvocationSession,
        amount_units: int,
        unit: str,
    ) -> BudgetReservation:
        del request, session, amount_units, unit
        self.log.append("budget")
        raise BudgetUnavailableError("injected budget exhaustion")


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
    def __init__(
        self,
        clock: ManualClock,
        log: list[str],
        *,
        maximum_per_quota_scope: int = 2_147_483_647,
    ) -> None:
        self.log = log
        self.enqueued: list[WorkItem] = []
        self._scheduler = BoundedFairScheduler(
            limits=SchedulerLimits(
                global_maximum_in_flight=4,
                global_maximum_queued=20,
                per_session_maximum_in_flight=4,
                per_session_maximum_queued=20,
                services={
                    "firecrawl": ServiceLimits(
                        4,
                        20,
                        maximum_per_quota_scope=maximum_per_quota_scope,
                    )
                },
                clients={
                    f"client_{suffix}": ClientCapacityLimits(4, 20)
                    for suffix in (_A, _B, _C, _D, _E, _F)
                },
            ),
            now_ms=clock.now_ms,
        )

    async def enqueue(self, item: WorkItem) -> QueueTicket:
        self.log.append("queue")
        self.enqueued.append(item)
        return await self._scheduler.enqueue(item)

    async def enqueue_unless_quota_scope_saturated(self, item: WorkItem) -> QueueTicket:
        self.log.append("queue")
        self.enqueued.append(item)
        return await self._scheduler.enqueue_unless_quota_scope_saturated(item)

    async def release(self, permit: DispatchPermit) -> bool:
        return await self._scheduler.release(permit)

    async def snapshot(self) -> SchedulerSnapshot:
        return await self._scheduler.snapshot()

    async def cancel_session(self, session_id: str) -> tuple[int, int]:
        return await self._scheduler.cancel_session(session_id)


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
        self.exact_affinity_attempts: list[bool] = []
        self.reconciliation_attempts: list[bool] = []
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
        exact_affinity: bool = False,
        reconciliation: bool = False,
    ) -> CredentialDispatchLease:
        del now_ms
        self.log.append("credential_lease")
        credential_id = str(candidate.credential.credential_id)
        self.attempted.append(credential_id)
        self.exact_affinity_attempts.append(exact_affinity)
        self.reconciliation_attempts.append(reconciliation)
        if credential_id in self.unavailable_credential_ids:
            raise CredentialLeaseUnavailableError("injected lease contention")
        self.sequence += 1
        suffix = f"{self.sequence:026d}"
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
        self.started_requests: set[RequestId] = set()
        self.submission_claims: set[RequestId] = set()
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
        self.started_requests.add(event.request_id)
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

    async def claim_provider_submission(
        self,
        request_id: RequestId,
        ordinal: int,
        *,
        occurred_at_ms: int,
    ) -> None:
        del occurred_at_ms
        if request_id in self.submission_claims:
            raise ProviderSubmissionLimitExceeded("provider submission limit reached")
        invocation = next(
            (event for event in reversed(self.states) if event.request_id == request_id),
            None,
        )
        attempt = next(
            (
                event
                for event in reversed(self.attempts)
                if event.request_id == request_id and event.ordinal == ordinal
            ),
            None,
        )
        if (
            request_id not in self.started_requests
            or type(ordinal) is not int
            or not 1 <= ordinal <= 9_223_372_036_854_775_807
            or invocation is None
            or invocation.state is not InvocationState.RUNNING
            or attempt is None
            or attempt.state is not InvocationState.RUNNING
        ):
            raise ValueError("provider submission lacks running authority")
        self.submission_claims.add(request_id)


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


class BlockingAffinityStore(InMemoryResourceAffinityStore):
    def __init__(self, credential_leases: CredentialLeases) -> None:
        super().__init__()
        self.credential_leases = credential_leases
        self.started = asyncio.Event()
        self.release = asyncio.Event()

    async def bind(self, affinity: ResourceAffinity) -> ResourceAffinity:
        assert self.credential_leases.active
        self.started.set()
        await self.release.wait()
        return await super().bind(affinity)


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


class PreHandoffFailureTransport(Transport):
    async def send(self, request: ProviderRequest) -> ProviderResponse:
        del request
        self.log.append("dispatch")
        raise ProviderPreHandoffError("credential is unavailable")


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


class RecordingRunawayQuarantines:
    def __init__(self, admission: RunawayAdmission) -> None:
        self.admission = admission
        self.admissions: list[dict[str, object]] = []
        self.settled: list[str] = []

    async def admit(self, **values: object) -> RunawayAdmission:
        self.admissions.append(dict(values))
        return self.admission

    async def settle_permit(self, permit_id: str, *, now_ms: int) -> bool:
        del now_ms
        self.settled.append(permit_id)
        return True


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


def named_pool(
    *,
    credential_generation: int = 1,
    scope_count: int = 2,
    secondary_credential_on_first_scope: bool = False,
    selection_strategy: PoolSelectionStrategy = PoolSelectionStrategy.CHEAPEST_FIRST,
    automatic_failover_within_pool: bool = False,
) -> NamedPool:
    if not 1 <= scope_count <= len(_POOL_SCOPE_SUFFIXES):
        raise ValueError("scope count is outside the test pool bounds")
    members = []
    for index, suffix in enumerate(_POOL_SCOPE_SUFFIXES[:scope_count], start=1):
        principal = PrincipalId(f"prn_{suffix}")
        scope = QuotaScopeId(f"quota_{suffix}")
        credentials = [
            RoutingCredential(
                CredentialId(f"cred_{suffix}"),
                principal,
                scope,
                generation=credential_generation,
            )
        ]
        if index == 1 and secondary_credential_on_first_scope:
            credentials.append(
                RoutingCredential(
                    CredentialId(f"cred_{_F}"),
                    principal,
                    scope,
                    generation=credential_generation,
                )
            )
        members.append(
            PoolMember(
                QuotaScopeSnapshot(
                    scope,
                    principal,
                    "firecrawl",
                    "credits",
                    last_known_remaining_units=1_000,
                ),
                tuple(credentials),
                cost_rank=index,
            )
        )
    return NamedPool(
        PoolId(f"pool_{_A}"),
        "interactive-default",
        "firecrawl",
        selection_strategy,
        tuple(members),
        automatic_failover_within_pool=automatic_failover_within_pool,
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
    credential_generation: int = 1,
    pool_scope_count: int = 2,
    secondary_credential_on_first_scope: bool = False,
    maximum_per_quota_scope: int = 2_147_483_647,
    pool_selection_strategy: PoolSelectionStrategy = PoolSelectionStrategy.CHEAPEST_FIRST,
    automatic_failover_within_pool: bool = False,
    invocation_session: InvocationSession | None = None,
    emergency: EmergencyUnlockManager | None = None,
    runaway_quarantines: RecordingRunawayQuarantines | None = None,
    pending_approval_probe: RecordingPendingApprovalProbe | None = None,
    maximum_total_provider_attempts: int = 1,
) -> Harness:
    log: list[str] = []
    clock = ManualClock(1_000)
    breakers = CircuitBreakerRegistry()
    pool = named_pool(
        credential_generation=credential_generation,
        scope_count=pool_scope_count,
        secondary_credential_on_first_scope=secondary_credential_on_first_scope,
        selection_strategy=pool_selection_strategy,
        automatic_failover_within_pool=automatic_failover_within_pool,
    )
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
    scheduler = Scheduler(
        clock,
        log,
        maximum_per_quota_scope=maximum_per_quota_scope,
    )
    credential_leases = CredentialLeases(
        log,
        unavailable_credential_ids=unavailable_credential_ids,
        reject_release_once=reject_credential_release_once,
    )
    singleflight = SingleFlightCoordinator()
    coordinator = InvocationCoordinator(
        clock=clock,
        sessions=SessionGateway(invocation_session or session(), log),
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
        pending_approval_probe=pending_approval_probe,
        retry_policy=RetryPolicy(maximum_attempts=3, jitter=False),
        singleflight=singleflight,
        runaway=runaway,
        runaway_quarantines=runaway_quarantines,
        emergency=emergency,
        sleeper=clock.sleep,
        reservation_ttl_ms=reservation_ttl_ms,
        maximum_total_provider_attempts=maximum_total_provider_attempts,
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


async def emergency_harness(
    responses: Iterable[ProviderResponse],
    *,
    invocation_session: InvocationSession | None = None,
    blocked_transport: bool = False,
) -> tuple[Harness, EmergencyUnlockManager]:
    owner = invocation_session or session()
    item = harness(
        responses,
        invocation_session=owner,
        blocked_transport=blocked_transport,
    )
    manager = await _unlock_emergency(item, owner)
    item.coordinator.emergency = manager
    return item, manager


async def _unlock_emergency(
    item: Harness,
    owner: InvocationSession,
) -> EmergencyUnlockManager:
    manager = EmergencyUnlockManager(
        key_store=InMemoryKeyStore(),
        now_ms=item.clock.now_ms,
        unlock_id_factory=lambda: _EMERGENCY_UNLOCK_ID,
        credential_id_factory=lambda: f"cred_{_C}",
        principal_id_factory=lambda: f"prn_{_C}",
        quota_scope_id_factory=lambda: f"quota_{_C}",
        emergency_pool_name="emergency-locked",
        hard_maximum_duration_ms=60_000,
        hard_maximum_requests=3,
        hard_maximum_credits=10,
    )
    await manager.unlock(
        secret=bytearray(_SYNTHETIC_EMERGENCY_SECRET),
        service_id="firecrawl",
        pool_id=f"pool_{_C}",
        pool_name="emergency-locked",
        session_id=str(owner.session_id),
        root_run_id=str(owner.root_run_id),
        interactive=True,
        duration_ms=60_000,
        maximum_requests=3,
        maximum_credits=10,
    )
    return manager


async def occupy_scheduler(item: Harness) -> list[DispatchPermit]:
    permits: list[DispatchPermit] = []
    for index in range(4):
        ticket = await item.scheduler.enqueue(
            WorkItem(
                request_id=f"blocker-{index}",
                session_id=f"blocker-session-{index}",
                client_id=f"client_{_A}",
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


async def wait_for_transport_requests(item: Harness, expected: int) -> None:
    for _ in range(100):
        if len(item.transport.requests) == expected:
            return
        await asyncio.sleep(0)
    pytest.fail(f"transport request count did not reach {expected}")


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
async def test_pending_approval_recovery_verifies_exact_request_without_admission() -> None:
    item = harness([], decision=Decision.ASK)
    probe = RecordingPendingApprovalProbe(
        item.log,
        PendingApprovalProbe(
            PendingApprovalProbeStatus.RECOVERABLE,
            approval_id="approval-recovered",
            root_run_id=RootRunId(f"run_{_B}"),
        ),
    )
    item.coordinator.pending_approval_probe = probe
    invocation = request(operation="firecrawl.crawl.start")

    recovered = await item.coordinator.recover_pending_approval(invocation, session())

    recovered_fingerprint = probe.calls[0]["fingerprint"]
    assert isinstance(recovered_fingerprint, RequestFingerprint)
    assert recovered == VerifiedPendingApproval(
        approval_id="approval-recovered",
        request_id=invocation.request_id,
        root_run_id=RootRunId(f"run_{_B}"),
        fingerprint=recovered_fingerprint,
    )
    assert item.log == [
        "validate",
        "canonicalize",
        "fingerprint",
        "sensitive",
        "policy",
        "approval_probe",
    ]
    assert probe.calls[0]["pool_name"] == "interactive-default"
    assert probe.calls[0]["estimated_cost_units"] == 25
    assert item.repository.states == []
    assert item.repository.validated == []
    assert item.transport.requests == []
    assert item.budgets.reconciled == []
    assert item.quota_repository.reconciled == []
    assert item.runaway.arrivals == 0


@pytest.mark.asyncio
async def test_absent_pending_approval_returns_none_without_creating_state() -> None:
    item = harness([], decision=Decision.ASK)
    probe = RecordingPendingApprovalProbe(
        item.log,
        PendingApprovalProbe(PendingApprovalProbeStatus.ABSENT),
    )
    item.coordinator.pending_approval_probe = probe

    recovered = await item.coordinator.recover_pending_approval(
        request(operation="firecrawl.crawl.start"),
        session(),
    )

    assert recovered is None
    assert len(probe.calls) == 1
    assert item.repository.states == []
    assert item.transport.requests == []
    assert "budget" not in item.log
    assert "quota" not in item.log


@pytest.mark.asyncio
async def test_fresh_explicit_crawl_in_allow_policy_skips_recovery_and_proceeds() -> None:
    item = harness(
        [ProviderResponse(200, data={"id": "provider-job"})],
        decision=Decision.ALLOW,
    )
    probe = RecordingPendingApprovalProbe(
        item.log,
        PendingApprovalProbe(PendingApprovalProbeStatus.ABSENT),
    )
    item.coordinator.pending_approval_probe = probe
    invocation = request(operation="firecrawl.crawl.start")
    owner = session()

    assert await item.coordinator.recover_pending_approval(invocation, owner) is None
    result = await item.coordinator.invoke_authenticated(invocation, owner)

    assert probe.calls == []
    assert result.state is InvocationState.SUCCEEDED
    assert len(item.transport.requests) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status", "expected_code"),
    (
        (PendingApprovalProbeStatus.MISMATCH, ErrorCode.POLICY_DENIED),
        (PendingApprovalProbeStatus.EXPIRED, ErrorCode.APPROVAL_EXPIRED),
        (PendingApprovalProbeStatus.AMBIGUOUS, ErrorCode.UNCERTAIN_OUTCOME),
    ),
)
async def test_pending_approval_probe_failures_map_to_stable_fail_closed_errors(
    status: PendingApprovalProbeStatus,
    expected_code: ErrorCode,
) -> None:
    item = harness([], decision=Decision.ASK)
    probe = RecordingPendingApprovalProbe(item.log, PendingApprovalProbe(status))
    item.coordinator.pending_approval_probe = probe
    original = request(operation="firecrawl.crawl.start")
    changed_payload = replace(
        original,
        input_payload={**original.input_payload, "url": "https://example.com/changed"},
    )

    with pytest.raises(GatehouseError) as raised:
        await item.coordinator.recover_pending_approval(changed_payload, session())

    assert raised.value.detail.code is expected_code
    assert raised.value.detail.request_id == changed_payload.request_id
    assert len(probe.calls) == 1
    assert item.repository.states == []
    assert item.transport.requests == []


@pytest.mark.asyncio
async def test_pending_approval_recovery_requires_interactive_dashboard_ask() -> None:
    non_dashboard = replace(session(), approval_mode="deny_on_ask")
    item = harness([], decision=Decision.ASK, invocation_session=non_dashboard)
    probe = RecordingPendingApprovalProbe(
        item.log,
        PendingApprovalProbe(PendingApprovalProbeStatus.ABSENT),
    )
    item.coordinator.pending_approval_probe = probe

    with pytest.raises(GatehouseError) as raised:
        await item.coordinator.recover_pending_approval(
            request(operation="firecrawl.crawl.start"),
            non_dashboard,
        )

    assert raised.value.detail.code is ErrorCode.POLICY_DENIED
    assert dict(raised.value.detail.details) == {"approval_mode": "deny_on_ask"}
    assert probe.calls == []


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
    assert result.attempts == 1
    assert item.repository.submission_claims == {request().request_id}
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
async def test_durable_runaway_quarantine_blocks_only_with_sanitized_machine_details() -> None:
    gateway = RecordingRunawayQuarantines(
        RunawayAdmission(
            state=RunawayAdmissionState.QUARANTINED,
            quarantine_id="rqu_test",
            quarantine_state=RunawayQuarantineState.OPEN,
            trigger=RunawayTrigger.AGGREGATE_BURST,
            reason_code="operator_authorization_required",
        )
    )
    item = harness(
        [ProviderResponse(200, data={"creditsUsed": 1})],
        runaway_quarantines=gateway,
    )

    result = await item.coordinator.invoke(request())

    assert result.state is InvocationState.FAILED
    assert result.error is not None
    assert result.error.code is ErrorCode.RUNAWAY_SUSPECTED
    assert not result.error.retryable
    assert dict(result.error.details) == {
        "authorization_required": True,
        "quarantine_id": "rqu_test",
        "reason_code": "operator_authorization_required",
        "scope": "session_root_run_service",
        "state": "OPEN",
        "trigger": "AGGREGATE_BURST",
    }
    assert item.transport.requests == []
    assert item.runaway.arrivals == 0
    assert gateway.settled == []


@pytest.mark.asyncio
async def test_bounded_runaway_permit_bypasses_singleflight_and_settles_exactly_once() -> None:
    gateway = RecordingRunawayQuarantines(
        RunawayAdmission(
            state=RunawayAdmissionState.AUTHORIZED,
            quarantine_id="rqu_test",
            quarantine_state=RunawayQuarantineState.AUTHORIZED,
            trigger=RunawayTrigger.REPEATED_EQUIVALENT,
            reason_code="bounded_burst_authorized",
            permit=RunawayBurstPermit(
                permit_id="permit_test",
                quarantine_id="rqu_test",
                authorization_generation=2,
                reserved_credits=1,
            ),
        )
    )
    item = harness(
        [ProviderResponse(200, data={"creditsUsed": 1})],
        runaway_quarantines=gateway,
    )

    result = await item.coordinator.invoke(request())

    assert result.state is InvocationState.SUCCEEDED
    assert gateway.settled == ["permit_test"]
    assert len(item.transport.requests) == 1
    assert item.singleflight.active_groups == 0
    assert item.runaway.arrivals == 0


@pytest.mark.asyncio
async def test_non_dashboard_ask_mode_never_creates_an_approval() -> None:
    item = harness(
        [],
        decision=Decision.ASK,
        invocation_session=replace(session(), approval_mode="deny_on_ask"),
    )

    result = await item.coordinator.invoke(request())

    assert result.state is InvocationState.DENIED
    assert result.error is not None
    assert result.error.code is ErrorCode.POLICY_DENIED
    assert result.error.details == {"approval_mode": "deny_on_ask"}
    assert "approval" not in item.log
    assert item.transport.requests == []


@pytest.mark.asyncio
async def test_selected_credential_generation_reaches_transport() -> None:
    item = harness(
        [ProviderResponse(200, data={"creditsUsed": 1})],
        credential_generation=7,
    )

    result = await item.coordinator.invoke(request())

    assert result.state is InvocationState.SUCCEEDED
    assert len(item.transport.requests) == 1
    assert item.transport.requests[0].credential_generation == 7
    assert item.transport.requests[0].credential_custody is CredentialCustodyKind.PERSISTENT


@pytest.mark.asyncio
async def test_manual_emergency_unlock_routes_only_the_exact_ephemeral_projection() -> None:
    item, manager = await emergency_harness(
        [ProviderResponse(200, data={"success": True, "creditsUsed": 7, "data": []})]
    )
    try:
        result = await item.coordinator.invoke(request())

        assert result.state is InvocationState.SUCCEEDED
        assert len(item.transport.requests) == 1
        assert item.transport.requests[0].credential_id == f"cred_{_C}"
        assert item.transport.requests[0].credential_generation == 1
        assert item.transport.requests[0].credential_custody is CredentialCustodyKind.EMERGENCY
        assert isinstance(item.coordinator.policy, Policy)
        assert item.coordinator.policy.contexts[-1].proposed_pool == "emergency-locked"
        assert not item.coordinator.policy.contexts[-1].automatic_pool_selection
        assert "quota" not in item.log
        assert "credential_lease" not in item.log
        assert item.budgets.reconciled == [(7, True)]
        assert item.repository.attempts
        assert all(
            event.emergency_unlock_id == _EMERGENCY_UNLOCK_ID
            and event.credential_id == f"cred_{_C}"
            and event.quota_scope_id == f"quota_{_C}"
            and event.pool_id == f"pool_{_C}"
            and event.credential_generation is None
            for event in item.repository.attempts
        )
        status = await manager.status()
        assert status.remaining_requests == 2
        assert status.remaining_credits == 3
        assert status.available_concurrency == 1
    finally:
        await manager.close()


@pytest.mark.asyncio
async def test_emergency_request_never_joins_pre_unlock_ordinary_singleflight() -> None:
    owner = session()
    item = harness(
        [
            ProviderResponse(200, data={"creditsUsed": 1}),
            ProviderResponse(200, data={"creditsUsed": 1}),
        ],
        invocation_session=owner,
        blocked_transport=True,
    )
    manager = EmergencyUnlockManager(
        key_store=InMemoryKeyStore(),
        now_ms=item.clock.now_ms,
        unlock_id_factory=lambda: _EMERGENCY_UNLOCK_ID,
        credential_id_factory=lambda: f"cred_{_C}",
        principal_id_factory=lambda: f"prn_{_C}",
        quota_scope_id_factory=lambda: f"quota_{_C}",
        emergency_pool_name="emergency-locked",
        hard_maximum_duration_ms=60_000,
        hard_maximum_requests=3,
        hard_maximum_credits=10,
    )
    item.coordinator.emergency = manager
    ordinary = asyncio.create_task(item.coordinator.invoke(request(_A)))
    await item.transport.started.wait()
    assert len(item.transport.requests) == 1

    await manager.unlock(
        secret=bytearray(_SYNTHETIC_EMERGENCY_SECRET),
        service_id="firecrawl",
        pool_id=f"pool_{_C}",
        pool_name="emergency-locked",
        session_id=str(owner.session_id),
        root_run_id=str(owner.root_run_id),
        interactive=True,
        duration_ms=60_000,
        maximum_requests=3,
        maximum_credits=10,
    )
    emergency = asyncio.create_task(item.coordinator.invoke(request(_B)))
    for _ in range(100):
        if len(item.transport.requests) == 2:
            break
        await asyncio.sleep(0)
    assert [sent.credential_id for sent in item.transport.requests] == [
        f"cred_{_A}",
        f"cred_{_C}",
    ]

    item.transport.release_event.set()
    ordinary_result, emergency_result = await asyncio.gather(ordinary, emergency)
    try:
        assert ordinary_result.state is InvocationState.SUCCEEDED
        assert emergency_result.state is InvocationState.SUCCEEDED
        assert item.log.count("dispatch") == 2
        assert any(event.emergency_unlock_id is None for event in item.repository.attempts)
        assert any(
            event.emergency_unlock_id == _EMERGENCY_UNLOCK_ID for event in item.repository.attempts
        )
    finally:
        await manager.close()


@pytest.mark.asyncio
async def test_post_cancel_ordinary_request_never_joins_inflight_emergency_execution() -> None:
    item, manager = await emergency_harness(
        [
            ProviderResponse(200, data={"creditsUsed": 1}),
            ProviderResponse(200, data={"creditsUsed": 1}),
        ],
        blocked_transport=True,
    )
    emergency = asyncio.create_task(item.coordinator.invoke(request(_A)))
    await item.transport.started.wait()
    assert item.transport.requests[0].credential_id == f"cred_{_C}"

    assert await manager.cancel(_EMERGENCY_UNLOCK_ID)
    ordinary = asyncio.create_task(item.coordinator.invoke(request(_B)))
    for _ in range(100):
        if len(item.transport.requests) == 2:
            break
        await asyncio.sleep(0)
    assert [sent.credential_id for sent in item.transport.requests] == [
        f"cred_{_C}",
        f"cred_{_A}",
    ]

    item.transport.release_event.set()
    emergency_result, ordinary_result = await asyncio.gather(emergency, ordinary)
    try:
        assert emergency_result.state is InvocationState.SUCCEEDED
        assert ordinary_result.state is InvocationState.SUCCEEDED
        assert item.log.count("dispatch") == 2
    finally:
        await manager.close()


@pytest.mark.asyncio
async def test_active_emergency_unlock_never_projects_across_session_or_root() -> None:
    owner = session()
    item, manager = await emergency_harness(
        [ProviderResponse(200, data={"creditsUsed": 1})],
        invocation_session=owner,
    )
    other = replace(
        owner,
        session_id=SessionId(f"ses_{_B}"),
        root_run_id=RootRunId(f"run_{_B}"),
    )
    item.coordinator.sessions = SessionGateway(other, item.log)
    try:
        result = await item.coordinator.invoke(request(_B, root_run_id=other.root_run_id))

        assert result.state is InvocationState.SUCCEEDED
        assert item.transport.requests[0].credential_id == f"cred_{_A}"
        assert item.log.count("quota") == 1
        assert item.log.count("credential_lease") == 1
        assert all(event.emergency_unlock_id is None for event in item.repository.attempts)
        status = await manager.status()
        assert status.remaining_requests == 3
        assert status.remaining_credits == 10
    finally:
        await manager.close()


@pytest.mark.asyncio
async def test_emergency_unlock_denies_async_creation_before_any_admission_or_send() -> None:
    item, manager = await emergency_harness([])
    try:
        result = await item.coordinator.invoke(request(operation="firecrawl.crawl.start"))

        assert result.state is InvocationState.CAPACITY_EXCEEDED
        assert item.transport.requests == []
        assert "budget" not in item.log
        assert "quota" not in item.log
        assert "credential_lease" not in item.log
        assert item.repository.attempts == []
        status = await manager.status()
        assert status.remaining_requests == 3
        assert status.remaining_credits == 10
        assert status.available_concurrency == 1
    finally:
        await manager.close()


@pytest.mark.asyncio
async def test_emergency_budget_denial_releases_concurrency_and_reserved_credit() -> None:
    item, manager = await emergency_harness([])
    item.coordinator.budgets = UnavailableBudgets(item.log)
    try:
        result = await item.coordinator.invoke(request())

        assert result.state is InvocationState.FAILED
        assert result.error is not None
        assert result.error.code is ErrorCode.BUDGET_EXHAUSTED
        assert item.transport.requests == []
        status = await manager.status()
        assert status.remaining_requests == 2
        assert status.remaining_credits == 10
        assert status.available_concurrency == 1
    finally:
        await manager.close()


@pytest.mark.asyncio
async def test_emergency_known_provider_failure_never_retries_automatically() -> None:
    item, manager = await emergency_harness(
        [
            ProviderResponse(503, data={"success": False, "error": "synthetic failure"}),
            ProviderResponse(200, data={"creditsUsed": 1}),
        ]
    )
    try:
        result = await item.coordinator.invoke(request())

        assert result.state is InvocationState.FAILED
        assert len(item.transport.requests) == 1
        assert item.log.count("dispatch") == 1
        status = await manager.status()
        assert status.remaining_requests == 2
        assert status.available_concurrency == 1
    finally:
        await manager.close()


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
async def test_distinct_sessions_share_fill_first_scope_then_spill_at_scope_capacity() -> None:
    item = harness(
        [
            ProviderResponse(200, data={"creditsUsed": 1}),
            ProviderResponse(200, data={"creditsUsed": 1}),
            ProviderResponse(200, data={"creditsUsed": 1}),
        ],
        blocked_transport=True,
        maximum_per_quota_scope=2,
        pool_selection_strategy=PoolSelectionStrategy.FILL_FIRST,
        automatic_failover_within_pool=True,
    )
    tasks: list[asyncio.Task[InvocationResult]] = []
    request_ids: set[str] = set()
    try:
        for index, suffix in enumerate((_A, _B, _C), start=1):
            owner = replace(
                session(),
                session_id=SessionId(f"ses_{suffix}"),
                client_id=ClientId(f"client_{suffix}"),
                root_run_id=RootRunId(f"run_{suffix}"),
                workspace_id=WorkspaceId(f"ws_{suffix}"),
            )
            invocation = replace(
                request(suffix, root_run_id=owner.root_run_id),
                access_token=None,
                input_payload={
                    "query": f"graduate roles {index}",
                    "limit": 5,
                    "purpose": "career_discovery",
                    "data_classification": ["public_web_query"],
                },
            )
            request_ids.add(str(invocation.request_id))
            tasks.append(
                asyncio.create_task(item.coordinator.invoke_authenticated(invocation, owner))
            )
            await wait_for_transport_requests(item, index)

        assert [call.credential_id for call in item.transport.requests] == [
            f"cred_{_A}",
            f"cred_{_A}",
            f"cred_{_B}",
        ]
        queued_scopes = [
            queued.quota_scope_id
            for queued in item.scheduler.enqueued
            if queued.request_id in request_ids
        ]
        assert queued_scopes == [
            f"quota_{_A}",
            f"quota_{_A}",
            f"quota_{_A}",
            f"quota_{_B}",
        ]
    finally:
        item.transport.release_event.set()
        results = await asyncio.gather(*tasks)

    assert all(result.state is InvocationState.SUCCEEDED for result in results)
    assert len(item.quota_repository.reconciled) == 4
    assert (
        sum(
            actual == 0 for _reservation, actual, known in item.quota_repository.reconciled if known
        )
        == 1
    )
    assert item.credential_leases.active == set()
    assert (await item.scheduler.snapshot()).running_total == 0


@pytest.mark.asyncio
async def test_capacity_scan_falls_back_to_waiting_on_leading_scope_when_all_are_busy() -> None:
    item = harness(
        [ProviderResponse(200, data={"creditsUsed": 1})],
        blocked_transport=True,
        maximum_per_quota_scope=1,
        pool_selection_strategy=PoolSelectionStrategy.FILL_FIRST,
        automatic_failover_within_pool=True,
    )
    blockers: list[DispatchPermit] = []
    for index, suffix in enumerate((_A, _B), start=1):
        ticket = await item.scheduler.enqueue(
            WorkItem(
                request_id=f"scope-blocker-{index}",
                session_id=f"scope-blocker-session-{index}",
                client_id=f"client_{_A}",
                service_id="firecrawl",
                priority=session().priority,
                enqueued_at_ms=item.clock.now_ms(),
                deadline_ms=100_000,
                quota_scope_id=f"quota_{suffix}",
            )
        )
        blockers.append(await ticket.wait())

    invocation = request(_C)
    task = asyncio.create_task(item.coordinator.invoke(invocation))
    await wait_for_scheduler_queue(item, 1)
    invocation_scopes = [
        queued.quota_scope_id
        for queued in item.scheduler.enqueued
        if queued.request_id == str(invocation.request_id)
    ]
    assert invocation_scopes == [f"quota_{_A}", f"quota_{_B}", f"quota_{_A}"]
    assert item.transport.requests == []

    assert await item.scheduler.release(blockers.pop(0))
    await wait_for_transport_requests(item, 1)
    assert item.transport.requests[0].credential_id == f"cred_{_A}"
    item.transport.release_event.set()
    result = await task

    assert result.state is InvocationState.SUCCEEDED
    assert len(item.quota_repository.reconciled) == 3
    for permit in blockers:
        assert await item.scheduler.release(permit)
    assert (await item.scheduler.snapshot()).running_total == 0


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
async def test_async_affinity_bind_completes_before_credential_lease_release() -> None:
    item = harness([ProviderResponse(200, data={"id": "provider-job-lease-fence"})])
    blocking_affinities = BlockingAffinityStore(item.credential_leases)
    item.coordinator.affinities = blocking_affinities

    invocation = asyncio.create_task(
        item.coordinator.invoke(request(_A, operation="firecrawl.crawl.start"))
    )
    await blocking_affinities.started.wait()

    assert item.credential_leases.active
    assert item.credential_leases.released == []

    blocking_affinities.release.set()
    result = await invocation

    assert result.state is InvocationState.SUCCEEDED
    assert not item.credential_leases.active
    assert len(item.credential_leases.released) == 1


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
    assert result.error is not None
    assert result.error.code is ErrorCode.UNCERTAIN_OUTCOME
    assert len(item.transport.requests) == 1
    checkpoint = item.repository.attempts[-1]
    assert checkpoint.state is InvocationState.SUCCEEDED
    assert checkpoint.provider_resource_id == "provider-job-release"
    assert item.repository.states[-1].metadata == {"provider_handoff": True}
    assert item.quota_repository.reconciled[0][1:] == (None, False)
    assert item.budgets.reconciled == [(None, False)]
    assert not item.credential_leases.active
    assert len(item.credential_leases.released) == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("actual_units", [None, 0, 7])
async def test_invalid_async_provider_identifier_is_never_bound_or_retried(
    actual_units: int | None,
) -> None:
    data: dict[str, object] = {"id": "invalid/provider-job"}
    if actual_units is not None:
        data["creditsUsed"] = actual_units
    item = harness(
        [
            ProviderResponse(200, data=data),
            ProviderResponse(200, data={"id": "unused-provider-job", "creditsUsed": 1}),
        ]
    )

    result = await item.coordinator.invoke(request(_A, operation="firecrawl.crawl.start"))

    assert result.state is InvocationState.UNKNOWN
    assert result.error is not None
    assert result.error.code is ErrorCode.UNCERTAIN_OUTCOME
    assert result.attempts == 1
    assert len(item.transport.requests) == 1
    assert len(item.transport.responses) == 1
    assert item.repository.submission_claims == {result.request_id}
    assert item.affinities.entry_count == 0
    attempt = item.repository.attempts[-1]
    assert attempt.state is InvocationState.UNKNOWN
    assert attempt.provider_resource_id is None
    assert attempt.actual_cost_units == actual_units
    expected = (actual_units, actual_units is not None)
    assert [entry[1:] for entry in item.quota_repository.reconciled] == [expected]
    assert item.budgets.reconciled == [expected]
    assert item.credential_leases.active == set()
    assert (await item.scheduler.snapshot()).running_total == 0


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


@pytest.mark.parametrize("invalid_limit", [0, -1, 2, 32, True, False, 1.0, "1", None])
def test_coordinator_accepts_only_one_total_provider_attempt(invalid_limit: int) -> None:
    with pytest.raises((TypeError, ValueError)):
        harness([], maximum_total_provider_attempts=invalid_limit)


@pytest.mark.asyncio
@pytest.mark.parametrize("actual_units", [None, 0, 7])
async def test_successful_submission_settles_only_explicit_known_usage(
    actual_units: int | None,
) -> None:
    data = {} if actual_units is None else {"creditsUsed": actual_units}
    item = harness(
        [ProviderResponse(200, data=data), ProviderResponse(200, data={"creditsUsed": 1})]
    )

    result = await item.coordinator.invoke(request())

    assert result.state is InvocationState.SUCCEEDED
    assert result.attempts == 1
    assert len(item.transport.requests) == 1
    assert len(item.transport.responses) == 1
    assert item.repository.submission_claims == {result.request_id}
    expected = (actual_units, actual_units is not None)
    assert [entry[1:] for entry in item.quota_repository.reconciled] == [expected]
    assert item.budgets.reconciled == [expected]
    assert item.credential_leases.active == set()
    assert (await item.scheduler.snapshot()).running_total == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("automatic_failover", [False, True])
@pytest.mark.parametrize(
    ("response", "expected_error", "actual_units", "outcome_known"),
    [
        pytest.param(
            ProviderResponse(401),
            ErrorCode.PROVIDER_UNAUTHORIZED,
            None,
            False,
            id="unauthorized-with-same-scope-backup",
        ),
        pytest.param(
            ProviderResponse(402),
            ErrorCode.QUOTA_EXHAUSTED,
            None,
            False,
            id="exhausted-with-other-scope-backups",
        ),
        pytest.param(
            ProviderResponse(403),
            ErrorCode.PROVIDER_PERMISSION_DENIED,
            None,
            False,
            id="permission-denied",
        ),
        pytest.param(
            ProviderResponse(503),
            ErrorCode.PROVIDER_UNAVAILABLE,
            None,
            False,
            id="transient-server-failure",
        ),
        pytest.param(
            ProviderResponse(None, transport_error="connect_error"),
            ErrorCode.PROVIDER_TIMEOUT,
            0,
            True,
            id="proven-connection-failure",
        ),
    ],
)
async def test_provider_failure_consumes_one_submission_without_automatic_retry(
    response: ProviderResponse,
    expected_error: ErrorCode,
    actual_units: int | None,
    outcome_known: bool,
    automatic_failover: bool,
) -> None:
    item = harness(
        [response, ProviderResponse(200, data={"creditsUsed": 1})],
        pool_scope_count=5,
        secondary_credential_on_first_scope=True,
        automatic_failover_within_pool=automatic_failover,
    )

    result = await item.coordinator.invoke(request())

    assert result.state is InvocationState.FAILED
    assert result.error is not None
    assert result.error.code is expected_error
    assert result.attempts == 1
    assert [call.credential_id for call in item.transport.requests] == [f"cred_{_A}"]
    assert len(item.transport.responses) == 1
    assert item.clock.value_ms == 1_000
    assert item.log.count("queue") == 1
    assert item.log.count("quota") == 1
    assert item.log.count("budget") == 1
    assert item.credential_leases.attempted == [f"cred_{_A}"]
    assert len(item.credential_leases.released) == 1
    assert item.credential_leases.active == set()
    assert [entry[1:] for entry in item.quota_repository.reconciled] == [
        (actual_units, outcome_known)
    ]
    assert item.budgets.reconciled == [(actual_units, outcome_known)]
    assert all(event.ordinal == 1 for event in item.repository.attempts)
    assert InvocationState.RETRY_WAIT not in [event.state for event in item.repository.states]
    snapshot = await item.scheduler.snapshot()
    assert snapshot.queued_total == 0
    assert snapshot.running_total == 0


@pytest.mark.asyncio
async def test_exhaustion_checkpoint_finishes_before_failure_without_backup_dispatch() -> None:
    item = harness(
        [ProviderResponse(402), ProviderResponse(200, data={"creditsUsed": 1})],
        block_attempt_state=InvocationState.FAILED,
        automatic_failover_within_pool=True,
    )

    invocation = asyncio.create_task(item.coordinator.invoke(request()))
    try:
        await asyncio.wait_for(item.repository.attempt_started.wait(), timeout=1.0)
        assert not invocation.done()
        assert [call.credential_id for call in item.transport.requests] == [f"cred_{_A}"]
    finally:
        item.repository.attempt_release.set()
        if not invocation.done():
            await asyncio.wait_for(asyncio.shield(invocation), timeout=1.0)
    result = await invocation

    assert result.state is InvocationState.FAILED
    assert result.error is not None
    assert result.error.code is ErrorCode.QUOTA_EXHAUSTED
    assert [call.credential_id for call in item.transport.requests] == [f"cred_{_A}"]
    checkpoint = item.repository.attempts[-1]
    assert checkpoint.state is InvocationState.FAILED
    assert checkpoint.error_class is ProviderErrorClass.QUOTA_EXHAUSTED
    assert item.log.count("quota") == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("actual_units", [0, 7])
@pytest.mark.parametrize("fail_terminal_checkpoint", [False, True])
async def test_failed_submission_settles_explicit_known_usage_once(
    actual_units: int,
    fail_terminal_checkpoint: bool,
) -> None:
    class KnownFailure(Operations):
        def classify_response(
            self,
            operation: str,
            response: ProviderResponse,
        ) -> ClassifiedProviderOutcome:
            del operation, response
            return ClassifiedProviderOutcome(
                error_class=ProviderErrorClass.TRANSIENT,
                actual_cost_units=actual_units,
            )

    item = harness(
        [ProviderResponse(503), ProviderResponse(200, data={"creditsUsed": 1})],
        automatic_failover_within_pool=True,
        fail_attempt_state_once=InvocationState.FAILED if fail_terminal_checkpoint else None,
    )
    item.coordinator.operations = KnownFailure(item.log)

    result = await item.coordinator.invoke(request())

    assert result.state is (
        InvocationState.UNKNOWN if fail_terminal_checkpoint else InvocationState.FAILED
    )
    assert result.error is not None
    assert result.error.code is (
        ErrorCode.UNCERTAIN_OUTCOME if fail_terminal_checkpoint else ErrorCode.PROVIDER_UNAVAILABLE
    )
    assert result.attempts == 1
    assert len(item.transport.requests) == 1
    assert [entry[1:] for entry in item.quota_repository.reconciled] == [(actual_units, True)]
    assert item.budgets.reconciled == [(actual_units, True)]
    if not fail_terminal_checkpoint:
        assert item.repository.attempts[-1].actual_cost_units == actual_units
    assert item.credential_leases.active == set()
    assert (await item.scheduler.snapshot()).running_total == 0


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
@pytest.mark.parametrize("automatic_failover", [False, True])
@pytest.mark.parametrize(
    ("retry_after", "queue_deadline_ms"),
    [(None, 10_000), ("1", 10_000), ("2", 2_000), ("60", 61_001), ("120", 2_000)],
)
async def test_rate_limit_never_waits_or_spills_after_one_submission(
    retry_after: str | None,
    queue_deadline_ms: int,
    automatic_failover: bool,
) -> None:
    headers = {} if retry_after is None else {"retry-after": retry_after}
    item = harness(
        [ProviderResponse(429, headers=headers), ProviderResponse(200, data={"creditsUsed": 1})],
        pool_scope_count=5,
        automatic_failover_within_pool=automatic_failover,
    )

    result = await item.coordinator.invoke(request(queue_deadline_ms=queue_deadline_ms))

    assert result.state is InvocationState.FAILED
    assert result.error is not None
    assert result.error.code is ErrorCode.PROVIDER_RATE_LIMITED
    assert result.attempts == 1
    assert [call.credential_id for call in item.transport.requests] == [f"cred_{_A}"]
    assert len(item.transport.responses) == 1
    assert item.clock.value_ms == 1_000
    assert item.log.count("queue") == 1
    assert item.log.count("quota") == 1
    assert item.credential_leases.attempted == [f"cred_{_A}"]
    assert item.credential_leases.active == set()
    assert [entry[1:] for entry in item.quota_repository.reconciled] == [(None, False)]
    assert item.budgets.reconciled == [(None, False)]
    assert InvocationState.RETRY_WAIT not in [event.state for event in item.repository.states]
    snapshot = await item.scheduler.snapshot()
    assert snapshot.queued_total == 0
    assert snapshot.running_total == 0


@pytest.mark.asyncio
async def test_rate_limit_never_spills_an_ambiguous_side_effecting_operation() -> None:
    item = harness(
        [
            ProviderResponse(429),
            ProviderResponse(200, data={"id": "provider-job"}),
        ]
    )

    result = await item.coordinator.invoke(request(operation="firecrawl.crawl.start"))

    assert result.state is InvocationState.FAILED
    assert result.error is not None
    assert result.error.code is ErrorCode.PROVIDER_RATE_LIMITED
    assert [call.credential_id for call in item.transport.requests] == [f"cred_{_A}"]


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
async def test_credential_fence_failure_is_known_not_submitted_and_releases_admission() -> None:
    item = harness([])
    unavailable = PreHandoffFailureTransport(item.log, [])
    item.coordinator.transport = unavailable

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
async def test_invalidated_session_after_dequeue_never_acquires_a_credential() -> None:
    item = harness([ProviderResponse(200, data={"creditsUsed": 1})])
    gateway = item.coordinator.sessions
    assert isinstance(gateway, SessionGateway)
    gateway.active = False

    result = await item.coordinator.invoke(request())

    assert result.state is InvocationState.CANCELLED
    assert result.attempts == 0
    assert gateway.revalidations == 1
    assert item.transport.requests == []
    assert "credential_lease" not in item.log
    assert item.quota_repository.reconciled[0][1:] == (0, True)
    assert item.budgets.reconciled == [(0, True)]
    assert (await item.scheduler.snapshot()).running_total == 0
    assert item.repository.states[-1].metadata == {
        "provider_handoff": False,
        "session_authority_invalidated": True,
    }


@pytest.mark.asyncio
async def test_final_session_epoch_fence_cancels_a_persisted_attempt_before_send() -> None:
    item = harness([ProviderResponse(200, data={"creditsUsed": 1})])
    gateway = item.coordinator.sessions
    assert isinstance(gateway, SessionGateway)
    gateway.revalidation_results.extend((True, False))

    result = await item.coordinator.invoke(request())

    assert result.state is InvocationState.CANCELLED
    assert result.attempts == 1
    assert gateway.revalidations == 2
    assert item.transport.requests == []
    assert [event.state for event in item.repository.attempts] == [
        InvocationState.DISPATCHING,
        InvocationState.RUNNING,
        InvocationState.CANCELLED,
    ]
    assert item.quota_repository.reconciled[0][1:] == (0, True)
    assert item.budgets.reconciled == [(0, True)]
    assert item.credential_leases.active == set()
    assert (await item.scheduler.snapshot()).running_total == 0


@pytest.mark.asyncio
async def test_session_cancellation_before_claim_coroutine_starts_never_sends() -> None:
    item = harness([ProviderResponse(200, data={"creditsUsed": 1})])

    class CancelAfterFinalCheck(SessionGateway):
        cancellation: asyncio.Task[tuple[int, int]] | None = None

        async def revalidate(self, owner: InvocationSession) -> bool:
            active = await super().revalidate(owner)
            if self.revalidations == 2:
                self.cancellation = asyncio.create_task(
                    item.scheduler.cancel_session(str(owner.session_id))
                )
            return active

    gateway = CancelAfterFinalCheck(session(), item.log)
    item.coordinator.sessions = gateway

    result = await asyncio.wait_for(item.coordinator.invoke(request()), timeout=1)

    assert gateway.cancellation is not None
    assert await gateway.cancellation == (0, 1)
    assert gateway.revalidations == 2
    assert result.state is InvocationState.CANCELLED
    assert item.transport.requests == []
    assert len(item.transport.responses) == 1
    assert item.repository.submission_claims == set()
    assert item.repository.attempts[-1].state is InvocationState.CANCELLED
    assert [entry[1:] for entry in item.quota_repository.reconciled] == [(0, True)]
    assert item.budgets.reconciled == [(0, True)]
    assert item.credential_leases.active == set()
    assert (await item.scheduler.snapshot()).running_total == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("claim_committed", [False, True])
async def test_session_cancellation_while_claim_is_pending_never_sends(
    claim_committed: bool,
) -> None:
    item = harness([ProviderResponse(200, data={"creditsUsed": 1})])
    claim_started = asyncio.Event()
    claim_release = asyncio.Event()

    class BlockingClaimRepository(Repository):
        async def claim_provider_submission(
            self,
            request_id: RequestId,
            ordinal: int,
            *,
            occurred_at_ms: int,
        ) -> None:
            if claim_committed:
                await super().claim_provider_submission(
                    request_id, ordinal, occurred_at_ms=occurred_at_ms
                )
            claim_started.set()
            await claim_release.wait()
            if not claim_committed:
                await super().claim_provider_submission(
                    request_id, ordinal, occurred_at_ms=occurred_at_ms
                )

    repository = BlockingClaimRepository()
    item.repository = repository
    item.coordinator.repository = repository
    invocation = asyncio.create_task(item.coordinator.invoke(request()))
    try:
        await asyncio.wait_for(claim_started.wait(), timeout=1)
        assert item.transport.requests == []
        assert await item.scheduler.cancel_session(f"ses_{_A}") == (0, 1)
        result = await asyncio.wait_for(invocation, timeout=1)
    finally:
        claim_release.set()
        if not invocation.done():
            invocation.cancel()
        await asyncio.gather(invocation, return_exceptions=True)

    assert result.state is InvocationState.CANCELLED
    assert item.transport.requests == []
    assert len(item.transport.responses) == 1
    assert repository.submission_claims == ({result.request_id} if claim_committed else set())
    assert repository.attempts[-1].state is InvocationState.CANCELLED
    assert [entry[1:] for entry in item.quota_repository.reconciled] == [(0, True)]
    assert item.budgets.reconciled == [(0, True)]
    assert item.credential_leases.active == set()
    assert (await item.scheduler.snapshot()).running_total == 0


@pytest.mark.asyncio
async def test_session_cancellation_during_provider_send_is_ambiguous() -> None:
    item = harness(
        [ProviderResponse(200, data={"creditsUsed": 1})],
        blocked_transport=True,
    )
    invocation = asyncio.create_task(item.coordinator.invoke(request()))
    await item.transport.started.wait()

    queued, running = await item.scheduler.cancel_session(f"ses_{_A}")
    result = await asyncio.wait_for(invocation, timeout=1)

    assert (queued, running) == (0, 1)
    assert result.state is InvocationState.UNKNOWN
    assert result.error is not None
    assert result.error.code is ErrorCode.UNCERTAIN_OUTCOME
    assert item.repository.attempts[-1].state is InvocationState.UNKNOWN
    assert item.quota_repository.reconciled[0][1:] == (None, False)
    assert item.budgets.reconciled == [(None, False)]
    assert item.credential_leases.active == set()
    assert (await item.scheduler.snapshot()).running_total == 0


@pytest.mark.asyncio
async def test_real_session_revoke_cancels_bounded_queue_and_fences_dequeued_work(
    tmp_path: Path,
) -> None:
    connection = open_migrated_database(tmp_path / "durable-revocation.db")
    invocation_tasks: list[asyncio.Task[InvocationResult]] = []
    blockers: list[DispatchPermit] = []
    durable_gateway: _BlockingDurableSessionGateway | None = None
    item: Harness | None = None
    try:
        client_id = f"client_{_A}"
        workspace_id = f"ws_{_A}"
        connection.execute(
            """
            INSERT INTO clients(
                client_id, display_name, kind, policy_profile, created_at_ms, updated_at_ms
            ) VALUES (?, 'Revocation client', 'interactive', 'test', 0, 0)
            """,
            (client_id,),
        )
        connection.execute(
            """
            INSERT INTO workspaces(
                workspace_id, display_name, canonical_root, created_at_ms, updated_at_ms
            ) VALUES (?, 'Revocation workspace', 'E:\\RevocationTest', 0, 0)
            """,
            (workspace_id,),
        )

        clock = ManualClock(1_000)
        entropy_counter = 0

        def deterministic_random(length: int) -> bytes:
            nonlocal entropy_counter
            entropy_counter += 1
            return bytes((entropy_counter,)) * length

        persistence = SqliteSessionPersistence(connection)
        sessions = await SessionManager.start(
            persistence=persistence,
            verifier_key=b"s" * 32,
            now_ms=clock.now_ms,
            random_bytes=deterministic_random,
            access_token_ttl_ms=10_000,
            reconnect_grace_ms=20_000,
            stale_after_ms=5_000,
            maximum_access_tokens=16,
        )
        launched = await sessions.create_session(
            client_id=client_id,
            workspace_id=workspace_id,
            identity_assurance="CONTROLLED_INTERACTIVE_LAUNCH",
            policy_version="policy-v1",
            absolute_ttl_ms=60_000,
            budget={"credits": 1_000, "requests": 20},
        )
        issued = await sessions.exchange_bootstrap(
            session_id=launched.session.session_id,
            bootstrap_capability=launched.bootstrap_capability,
        )
        root_run = await sessions.create_root_run(
            access_token=issued.access_token,
            budget={"credits": 1_000, "requests": 20},
        )
        projection = InvocationSession(
            session_id=SessionId(issued.principal.session_id),
            client_id=ClientId(issued.principal.client_id),
            root_run_id=RootRunId(root_run.root_run_id),
            workspace_id=WorkspaceId(workspace_id),
            client_class=ClientClass.INTERACTIVE,
            allowed_capabilities=frozenset({"firecrawl.search"}),
            pool_bindings={"firecrawl": "interactive-default"},
            request_count_remaining=20,
            credit_budget_remaining_units=1_000,
            request_limit=20,
            token_epoch=issued.principal.token_epoch,
            revocation_epoch=issued.principal.revocation_epoch,
        )
        item = harness([], invocation_session=projection)
        durable_gateway = _BlockingDurableSessionGateway(sessions, projection)
        item.coordinator.sessions = durable_gateway
        item.coordinator.repository = SqliteInvocationRepository(connection)
        blockers = await occupy_scheduler(item)

        requests: list[InvocationRequest] = []
        for index in range(_BOUNDED_REVOCATION_CONCURRENCY):
            base = request(
                f"{100 + index:026d}",
                root_run_id=projection.root_run_id,
            )
            requests.append(
                replace(
                    base,
                    input_payload={
                        **dict(base.input_payload),
                        "query": f"bounded revocation query {index}",
                    },
                )
            )
        invocation_tasks = [
            asyncio.create_task(
                item.coordinator.invoke_authenticated(invocation, projection),
                name=f"durable-revocation-{index}",
            )
            for index, invocation in enumerate(requests)
        ]
        await wait_for_scheduler_queue(item, _BOUNDED_REVOCATION_CONCURRENCY)
        queued = await item.scheduler.snapshot()
        assert (
            queued.queued_by_session[str(projection.session_id)] == _BOUNDED_REVOCATION_CONCURRENCY
        )
        assert sum(queued.queued_by_session.values()) == _BOUNDED_REVOCATION_CONCURRENCY

        cancellation_counts: list[tuple[int, int]] = []

        async def dequeue_then_cancel(session_id: str) -> tuple[int, int]:
            durable = await persistence.load_session(session_id)
            assert durable is not None and durable.state is SessionState.REVOKED
            assert durable.revocation_epoch == projection.revocation_epoch + 1
            assert await item.scheduler.release(blockers[0])
            await asyncio.wait_for(durable_gateway.revalidation_started.wait(), timeout=1)
            try:
                result = await item.scheduler.cancel_session(session_id)
                cancellation_counts.append(result)
                return result
            finally:
                durable_gateway.allow_revalidation.set()

        control = LocalControlService(
            sessions=sessions,
            admin_auth=AdminAuthManager(
                verifier_key=b"a" * 32,
                now_ms=clock.now_ms,
                random_bytes=deterministic_random,
            ),
            health=_StaticControlHealth(),
            launch_authorities={},
            shutdown=asyncio.Event(),
            cancel_session=dequeue_then_cancel,
        )
        mutation = await asyncio.wait_for(
            control.revoke_session(str(projection.session_id)),
            timeout=1,
        )
        results = await asyncio.wait_for(asyncio.gather(*invocation_tasks), timeout=1)

        assert mutation.state == SessionState.REVOKED.value
        assert cancellation_counts == [(_BOUNDED_REVOCATION_CONCURRENCY - 1, 1)]
        assert durable_gateway.results == [False]
        result_states = [result.state for result in results]
        assert result_states == [InvocationState.CANCELLED] * _BOUNDED_REVOCATION_CONCURRENCY, [
            (result.state, result.error) for result in results
        ]
        assert all(result.attempts == 0 for result in results)
        assert item.transport.requests == []
        assert item.credential_leases.attempted == []
        assert item.credential_leases.active == set()
        assert len(item.quota_repository.reconciled) == _BOUNDED_REVOCATION_CONCURRENCY
        assert all(
            reconciliation[1:] == (0, True) for reconciliation in item.quota_repository.reconciled
        )
        assert item.budgets.reconciled == [(0, True)] * _BOUNDED_REVOCATION_CONCURRENCY

        durable_session = await persistence.load_session(str(projection.session_id))
        assert durable_session is not None
        assert durable_session.state is SessionState.REVOKED
        assert durable_session.revocation_epoch == projection.revocation_epoch + 1
        assert not await sessions.is_active_epoch(
            session_id=str(projection.session_id),
            token_epoch=projection.token_epoch,
            revocation_epoch=projection.revocation_epoch,
        )
        with pytest.raises(InvalidAccessToken):
            await sessions.authenticate(issued.access_token)

        durable_invocations = connection.execute(
            "SELECT state, metadata_json FROM invocations WHERE session_id = ?",
            (str(projection.session_id),),
        ).fetchall()
        assert len(durable_invocations) == _BOUNDED_REVOCATION_CONCURRENCY
        assert {str(row["state"]) for row in durable_invocations} == {"CANCELLED"}
        assert (
            sum(
                '"session_authority_invalidated":true' in str(row["metadata_json"])
                for row in durable_invocations
            )
            == 1
        )
        assert connection.execute("SELECT COUNT(*) FROM attempts").fetchone()[0] == 0

        for blocker in blockers[1:]:
            assert await item.scheduler.release(blocker)
        final = await item.scheduler.snapshot()
        assert final.queued_total == 0
        assert final.running_total == 0
    finally:
        if durable_gateway is not None:
            durable_gateway.allow_revalidation.set()
        for task in invocation_tasks:
            if not task.done():
                task.cancel()
        if invocation_tasks:
            await asyncio.gather(*invocation_tasks, return_exceptions=True)
        if item is not None:
            for blocker in blockers:
                await item.scheduler.release(blocker)
        connection.close()


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
        automatic_failover_within_pool=True,
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
@pytest.mark.parametrize("automatic_failover", [False, True])
@pytest.mark.parametrize("same_scope_backup", [False, True])
async def test_predispatch_lease_fallback_requires_explicit_pool_permission(
    automatic_failover: bool,
    same_scope_backup: bool,
) -> None:
    item = harness(
        [ProviderResponse(200, data={"creditsUsed": 1})],
        unavailable_credential_ids=frozenset({f"cred_{_A}"}),
        secondary_credential_on_first_scope=same_scope_backup,
        automatic_failover_within_pool=automatic_failover,
    )

    result = await item.coordinator.invoke(request())

    if automatic_failover:
        backup = f"cred_{_F if same_scope_backup else _B}"
        assert result.state is InvocationState.SUCCEEDED
        assert result.attempts == 1
        assert item.credential_leases.attempted == [f"cred_{_A}", backup]
        assert [call.credential_id for call in item.transport.requests] == [backup]
        assert item.repository.submission_claims == {result.request_id}
        expected_quota = [(1, True)] if same_scope_backup else [(0, True), (1, True)]
        assert [entry[1:] for entry in item.quota_repository.reconciled] == expected_quota
        assert item.log.count("quota") == (1 if same_scope_backup else 2)
        assert item.log.count("queue") == (1 if same_scope_backup else 2)
        assert item.budgets.reconciled == [(1, True)]
    else:
        assert result.state is InvocationState.FAILED
        assert result.error is not None
        assert result.error.code is ErrorCode.NO_ELIGIBLE_CREDENTIAL
        assert result.attempts == 0
        assert item.credential_leases.attempted == [f"cred_{_A}"]
        assert item.transport.requests == []
        assert len(item.transport.responses) == 1
        assert item.repository.submission_claims == set()
        assert item.log.count("quota") == 1
        assert item.log.count("queue") == 1
        assert [entry[1:] for entry in item.quota_repository.reconciled] == [(0, True)]
        assert item.budgets.reconciled == [(0, True)]
    assert item.clock.value_ms == 1_000
    assert item.log.count("budget") == 1
    assert item.credential_leases.active == set()
    snapshot = await item.scheduler.snapshot()
    assert snapshot.queued_total == 0
    assert snapshot.running_total == 0


@pytest.mark.asyncio
async def test_lease_failover_to_new_scope_requeues_under_new_scope() -> None:
    item = harness(
        [ProviderResponse(200, data={"creditsUsed": 1})],
        unavailable_credential_ids=frozenset({f"cred_{_A}"}),
        automatic_failover_within_pool=True,
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
async def test_internal_reconciliation_forces_original_pool_principal_and_scope() -> None:
    quarantine = RecordingRunawayQuarantines(
        RunawayAdmission(
            state=RunawayAdmissionState.QUARANTINED,
            quarantine_id="rqu_internal-test",
            quarantine_state=RunawayQuarantineState.OPEN,
            trigger=RunawayTrigger.AGGREGATE_BURST,
            reason_code="operator_authorization_required",
        )
    )
    item = harness(
        [ProviderResponse(200, data={"status": "scraping"})],
        runaway_quarantines=quarantine,
    )
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

    result = await item.coordinator.invoke_authenticated(
        replace(request(operation="firecrawl.crawl.status"), access_token=None),
        replace(session(), internal_resource_reconciliation=True),
    )

    assert result.state is InvocationState.SUCCEEDED
    assert len(item.transport.requests) == 1
    assert item.transport.requests[0].credential_id == f"cred_{_B}"
    assert item.credential_leases.exact_affinity_attempts == [True]
    assert item.credential_leases.reconciliation_attempts == [True]
    assert quarantine.admissions == []
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
