from __future__ import annotations

import asyncio
import sqlite3
from dataclasses import replace

import pytest

from gatehouse.config import ClientProfileConfig
from gatehouse.core.errors import ErrorCode, make_error
from gatehouse.core.ids import (
    ClientId,
    CredentialId,
    JobId,
    PoolId,
    PrincipalId,
    QuotaScopeId,
    RequestId,
    RootRunId,
    SessionId,
    WorkspaceId,
)
from gatehouse.core.states import InvocationState
from gatehouse.invocations import InvocationRequest, InvocationResult, InvocationSession
from gatehouse.jobs import (
    CANCEL_RECONCILIATION_STATUS,
    CoordinatorJobObservationGateway,
    JobObservation,
    JobOwner,
    JobRecord,
    JobState,
    JobSupervisor,
    JobSupervisorPolicy,
    SqliteJobSessionResolver,
)
from gatehouse.policy import ClientClass
from gatehouse.scheduler import PriorityClass

_ID = "00000000000000000000000001"
_SECOND_ID = "00000000000000000000000002"


class MutableClock:
    def __init__(self, now_ms: int) -> None:
        self.value = now_ms

    def now_ms(self) -> int:
        return self.value


def record(
    *,
    suffix: str = _ID,
    state: JobState = JobState.CREATED,
    maximum_runtime_at_ms: int = 10_000,
    cancel_requested_at_ms: int | None = None,
) -> JobRecord:
    return JobRecord(
        job_id=JobId(f"job_{suffix}"),
        request_id=RequestId(f"req_{suffix}"),
        service_id="firecrawl",
        operation="firecrawl.crawl.start",
        state=state,
        provider_resource_id=f"provider-job-{suffix[-1]}",
        resource_type="crawl",
        principal_id=PrincipalId(f"prn_{suffix}"),
        quota_scope_id=QuotaScopeId(f"quota_{suffix}"),
        credential_id=CredentialId(f"cred_{suffix}"),
        credential_generation=1,
        pool_id=PoolId(f"pool_{suffix}"),
        owner=JobOwner(
            session_id=SessionId(f"ses_{suffix}"),
            workspace_id=WorkspaceId(f"ws_{suffix}"),
            root_run_id=RootRunId(f"run_{suffix}"),
        ),
        revision=1,
        provider_status=None,
        provider_status_observed_at_ms=None,
        cancel_requested_at_ms=cancel_requested_at_ms,
        next_poll_at_ms=100,
        maximum_runtime_at_ms=maximum_runtime_at_ms,
        created_at_ms=0,
        completed_at_ms=None,
    )


class MemoryStore:
    def __init__(self, initial: JobRecord) -> None:
        self.current = initial

    async def list_due(
        self,
        *,
        now_ms: int,
        limit: int = 100,
    ) -> tuple[JobRecord, ...]:
        del limit
        if self.current.terminal:
            return ()
        if self.current.next_poll_at_ms is None or self.current.next_poll_at_ms <= now_ms:
            return (self.current,)
        return ()

    async def compare_and_set(
        self,
        *,
        expected: JobRecord,
        owner: JobOwner,
        target_state: JobState,
        observed_at_ms: int,
        provider_status: str | None = None,
        next_poll_at_ms: int | None = None,
    ) -> JobRecord | None:
        if expected != self.current or owner != expected.owner:
            return None
        terminal = target_state in {
            JobState.SUCCEEDED,
            JobState.FAILED,
            JobState.CANCELLED,
            JobState.UNKNOWN,
        }
        self.current = replace(
            expected,
            state=target_state,
            revision=expected.revision + 1,
            provider_status=(
                expected.provider_status if provider_status is None else provider_status
            ),
            provider_status_observed_at_ms=(
                expected.provider_status_observed_at_ms
                if provider_status is None
                else observed_at_ms
            ),
            next_poll_at_ms=None if terminal else next_poll_at_ms,
            completed_at_ms=observed_at_ms if terminal else None,
        )
        return self.current

    async def prepare_settlement(
        self,
        *,
        expected: JobRecord,
        owner: JobOwner,
        target_state: JobState,
        actual_cost_units: int,
        observed_at_ms: int,
        provider_status: str | None = None,
    ) -> JobRecord | None:
        if expected != self.current or owner != expected.owner:
            return None
        self.current = replace(
            expected,
            state=JobState.SETTLING,
            revision=expected.revision + 1,
            provider_status=(
                expected.provider_status if provider_status is None else provider_status
            ),
            provider_status_observed_at_ms=(
                expected.provider_status_observed_at_ms
                if provider_status is None
                else observed_at_ms
            ),
            next_poll_at_ms=observed_at_ms,
            settlement_target_state=target_state,
            settlement_actual_cost_units=actual_cost_units,
            settlement_observed_at_ms=observed_at_ms,
        )
        return self.current

    async def complete_settlement(
        self,
        *,
        expected: JobRecord,
        owner: JobOwner,
    ) -> JobRecord | None:
        if expected != self.current or owner != expected.owner:
            return None
        assert expected.settlement_target_state is not None
        assert expected.settlement_observed_at_ms is not None
        self.current = replace(
            expected,
            state=expected.settlement_target_state,
            revision=expected.revision + 1,
            next_poll_at_ms=None,
            completed_at_ms=expected.settlement_observed_at_ms,
            settlement_target_state=None,
            settlement_actual_cost_units=None,
            settlement_observed_at_ms=None,
        )
        return self.current


class Gateway:
    def __init__(self, observation: JobObservation, clock: MutableClock) -> None:
        self.observation = observation
        self.clock = clock
        self.calls: list[JobRecord] = []

    async def observe(self, job: JobRecord) -> JobObservation:
        self.calls.append(job)
        self.clock.value += 10
        return self.observation


class MultiMemoryStore:
    def __init__(self, *records: JobRecord) -> None:
        self.stores = {item.job_id: MemoryStore(item) for item in records}

    async def list_due(
        self,
        *,
        now_ms: int,
        limit: int = 100,
    ) -> tuple[JobRecord, ...]:
        due: list[JobRecord] = []
        for store in self.stores.values():
            due.extend(await store.list_due(now_ms=now_ms, limit=limit))
        return tuple(due[:limit])

    async def compare_and_set(
        self,
        *,
        expected: JobRecord,
        owner: JobOwner,
        target_state: JobState,
        observed_at_ms: int,
        provider_status: str | None = None,
        next_poll_at_ms: int | None = None,
    ) -> JobRecord | None:
        return await self.stores[expected.job_id].compare_and_set(
            expected=expected,
            owner=owner,
            target_state=target_state,
            observed_at_ms=observed_at_ms,
            provider_status=provider_status,
            next_poll_at_ms=next_poll_at_ms,
        )

    async def prepare_settlement(
        self,
        *,
        expected: JobRecord,
        owner: JobOwner,
        target_state: JobState,
        actual_cost_units: int,
        observed_at_ms: int,
        provider_status: str | None = None,
    ) -> JobRecord | None:
        return await self.stores[expected.job_id].prepare_settlement(
            expected=expected,
            owner=owner,
            target_state=target_state,
            actual_cost_units=actual_cost_units,
            observed_at_ms=observed_at_ms,
            provider_status=provider_status,
        )

    async def complete_settlement(
        self,
        *,
        expected: JobRecord,
        owner: JobOwner,
    ) -> JobRecord | None:
        return await self.stores[expected.job_id].complete_settlement(
            expected=expected,
            owner=owner,
        )


class ConcurrentGateway:
    def __init__(self) -> None:
        self.started: list[JobId] = []
        self.both_started = asyncio.Event()
        self.release = asyncio.Event()

    async def observe(self, job: JobRecord) -> JobObservation:
        self.started.append(job.job_id)
        if len(self.started) == 2:
            self.both_started.set()
        await self.release.wait()
        return JobObservation(target_state=JobState.RUNNING, poll_after_ms=500)


@pytest.mark.asyncio
async def test_supervisor_claims_then_schedules_classified_observation() -> None:
    clock = MutableClock(100)
    store = MemoryStore(record())
    gateway = Gateway(
        JobObservation(
            target_state=JobState.RUNNING,
            provider_status="scraping",
            poll_after_ms=500,
        ),
        clock,
    )
    supervisor = JobSupervisor(
        store=store,
        gateway=gateway,
        clock=clock,
        policy=JobSupervisorPolicy(claim_ttl_ms=1_000),
    )

    assert await supervisor.run_once() == 2
    assert len(gateway.calls) == 1
    assert gateway.calls[0].state is JobState.POLLING
    assert gateway.calls[0].next_poll_at_ms == 1_100
    assert store.current.state is JobState.RUNNING
    assert store.current.provider_status == "scraping"
    assert store.current.next_poll_at_ms == 610
    assert store.current.revision == 3


@pytest.mark.asyncio
async def test_cancellation_intent_survives_a_running_provider_observation() -> None:
    clock = MutableClock(100)
    store = MemoryStore(record(state=JobState.CANCELLING, cancel_requested_at_ms=90))
    gateway = Gateway(
        JobObservation(target_state=JobState.RUNNING, poll_after_ms=500),
        clock,
    )

    assert await JobSupervisor(store=store, gateway=gateway, clock=clock).run_once() == 2
    assert gateway.calls[0].state is JobState.CANCELLING
    assert store.current.state is JobState.CANCELLING
    assert store.current.cancel_requested_at_ms == 90


@pytest.mark.asyncio
async def test_due_jobs_observe_concurrently_within_the_explicit_bound() -> None:
    clock = MutableClock(100)
    store = MultiMemoryStore(record(), record(suffix=_SECOND_ID))
    gateway = ConcurrentGateway()
    task = asyncio.create_task(
        JobSupervisor(
            store=store,
            gateway=gateway,
            clock=clock,
            policy=JobSupervisorPolicy(maximum_in_flight=2),
        ).run_once()
    )

    await asyncio.wait_for(gateway.both_started.wait(), timeout=1)
    assert len(gateway.started) == 2
    gateway.release.set()
    assert await task == 4


@pytest.mark.asyncio
async def test_maximum_runtime_becomes_unknown_without_provider_dispatch() -> None:
    clock = MutableClock(100)
    store = MemoryStore(record(maximum_runtime_at_ms=100))
    gateway = Gateway(JobObservation(target_state=JobState.SUCCEEDED), clock)

    assert await JobSupervisor(store=store, gateway=gateway, clock=clock).run_once() == 1
    assert gateway.calls == []
    assert store.current.state is JobState.UNKNOWN
    assert store.current.completed_at_ms == 100


def test_job_observation_requires_a_bounded_follow_up_for_live_state() -> None:
    with pytest.raises(ValueError, match="poll delay"):
        JobObservation(target_state=JobState.RUNNING)
    with pytest.raises(ValueError, match="terminal"):
        JobObservation(target_state=JobState.CANCELLED, poll_after_ms=1)
    with pytest.raises(ValueError, match="non-terminal"):
        JobObservation(
            target_state=JobState.RUNNING,
            poll_after_ms=1,
            actual_cost_units=1,
        )


def internal_session() -> InvocationSession:
    return InvocationSession(
        session_id=SessionId(f"ses_{_ID}"),
        client_id=ClientId(f"client_{_ID}"),
        root_run_id=RootRunId(f"run_{_ID}"),
        workspace_id=WorkspaceId(f"ws_{_ID}"),
        client_class=ClientClass.INTERACTIVE,
        allowed_capabilities=frozenset({"firecrawl.crawl.status", "firecrawl.crawl.cancel"}),
        pool_bindings={"firecrawl": f"pool_{_ID}"},
        request_count_remaining=1,
        credit_budget_remaining_units=0,
        priority=PriorityClass.INTERACTIVE,
        internal_resource_reconciliation=True,
    )


class Resolver:
    def __init__(self) -> None:
        self.session = internal_session()

    def resolve(self, job: JobRecord) -> InvocationSession:
        del job
        return self.session


class Coordinator:
    def __init__(
        self,
        *outcomes: tuple[InvocationState, object, ErrorCode | None],
    ) -> None:
        self.outcomes = list(outcomes)
        self.calls: list[tuple[InvocationRequest, InvocationSession]] = []

    async def invoke_authenticated(
        self,
        request: InvocationRequest,
        session: InvocationSession,
    ) -> InvocationResult:
        self.calls.append((request, session))
        state, data, error_code = self.outcomes.pop(0)
        error = None
        if error_code is not None:
            error = make_error(
                error_code,
                retryable=True,
                retry_after_seconds=2,
            ).detail
        return InvocationResult(
            request_id=request.request_id,
            state=state,
            attempts=1,
            data=data if error is None else None,
            error=error,
        )


class BlockingCoordinator:
    def __init__(self) -> None:
        self.started = asyncio.Event()
        self.calls: list[InvocationRequest] = []

    async def invoke_authenticated(
        self,
        request: InvocationRequest,
        session: InvocationSession,
    ) -> InvocationResult:
        del session
        self.calls.append(request)
        self.started.set()
        await asyncio.Event().wait()
        raise AssertionError("blocked coordinator unexpectedly returned")


@pytest.mark.asyncio
async def test_coordinator_observer_maps_completed_status_with_internal_authority() -> None:
    coordinator = Coordinator(
        (
            InvocationState.SUCCEEDED,
            {"status": "completed", "creditsUsed": 9},
            None,
        )
    )
    gateway = CoordinatorJobObservationGateway(
        coordinator=coordinator,
        sessions=Resolver(),
        clock=MutableClock(100),
    )

    observed = await gateway.observe(record())

    assert observed == JobObservation(
        target_state=JobState.SUCCEEDED,
        provider_status="completed",
        actual_cost_units=9,
    )
    request, session = coordinator.calls[0]
    assert request.operation == "firecrawl.crawl.status"
    assert request.input_payload == {"provider_job_id": "provider-job-1"}
    assert session.internal_resource_reconciliation


@pytest.mark.parametrize(
    "credits_used",
    [2**53 - 1, 2**53, 2**53 + 1, (1 << 63) - 1],
)
@pytest.mark.asyncio
async def test_job_observation_preserves_exact_workload_credit_integers(
    credits_used: int,
) -> None:
    coordinator = Coordinator(
        (
            InvocationState.SUCCEEDED,
            {"status": "completed", "creditsUsed": credits_used},
            None,
        )
    )
    gateway = CoordinatorJobObservationGateway(
        coordinator=coordinator,
        sessions=Resolver(),
        clock=MutableClock(100),
    )

    observed = await gateway.observe(record())

    assert observed.target_state is JobState.SUCCEEDED
    assert observed.actual_cost_units == credits_used
    assert type(observed.actual_cost_units) is int


@pytest.mark.asyncio
async def test_job_observation_rejects_workload_credit_above_int64() -> None:
    coordinator = Coordinator(
        (
            InvocationState.SUCCEEDED,
            {"status": "completed", "creditsUsed": 1 << 63},
            None,
        )
    )
    gateway = CoordinatorJobObservationGateway(
        coordinator=coordinator,
        sessions=Resolver(),
        clock=MutableClock(100),
    )

    observed = await gateway.observe(record())

    assert observed == JobObservation(
        target_state=JobState.RUNNING,
        provider_status="completed",
        poll_after_ms=30_000,
    )


@pytest.mark.asyncio
async def test_ambiguous_cancel_reconciles_status_before_any_replay() -> None:
    coordinator = Coordinator(
        (InvocationState.FAILED, None, ErrorCode.PROVIDER_UNAVAILABLE),
        (
            InvocationState.SUCCEEDED,
            {"status": "cancelled", "creditsUsed": 4},
            None,
        ),
    )
    gateway = CoordinatorJobObservationGateway(
        coordinator=coordinator,
        sessions=Resolver(),
        clock=MutableClock(100),
    )
    cancelling = record(state=JobState.CANCELLING, cancel_requested_at_ms=90)

    first = await gateway.observe(cancelling)
    assert first == JobObservation(
        target_state=JobState.CANCELLING,
        provider_status="gatehouse.cancel_reconcile",
        poll_after_ms=2_000,
    )
    reconciling = replace(
        cancelling,
        provider_status=first.provider_status,
        provider_status_observed_at_ms=100,
    )
    second = await gateway.observe(reconciling)

    assert second == JobObservation(
        target_state=JobState.CANCELLED,
        provider_status="cancelled",
        actual_cost_units=4,
    )
    assert [call[0].operation for call in coordinator.calls] == [
        "firecrawl.crawl.cancel",
        "firecrawl.crawl.status",
    ]


@pytest.mark.asyncio
async def test_successful_cancel_still_reconciles_usage_through_status() -> None:
    coordinator = Coordinator(
        (InvocationState.SUCCEEDED, {"success": True, "creditsUsed": 4}, None)
    )
    gateway = CoordinatorJobObservationGateway(
        coordinator=coordinator,
        sessions=Resolver(),
        clock=MutableClock(100),
    )

    observed = await gateway.observe(record(state=JobState.CANCELLING, cancel_requested_at_ms=90))

    assert observed == JobObservation(
        target_state=JobState.CANCELLING,
        provider_status="gatehouse.cancel_reconcile",
        poll_after_ms=30_000,
    )


@pytest.mark.asyncio
async def test_terminal_status_without_usage_remains_reconcilable() -> None:
    coordinator = Coordinator((InvocationState.SUCCEEDED, {"status": "completed"}, None))
    gateway = CoordinatorJobObservationGateway(
        coordinator=coordinator,
        sessions=Resolver(),
        clock=MutableClock(100),
    )

    observed = await gateway.observe(record())

    assert observed == JobObservation(
        target_state=JobState.RUNNING,
        provider_status="completed",
        poll_after_ms=30_000,
    )


@pytest.mark.asyncio
async def test_cancel_status_without_usage_never_reopens_delete_dispatch() -> None:
    coordinator = Coordinator(
        (InvocationState.SUCCEEDED, {"status": "cancelled"}, None),
        (
            InvocationState.SUCCEEDED,
            {"status": "cancelled", "creditsUsed": 3},
            None,
        ),
    )
    gateway = CoordinatorJobObservationGateway(
        coordinator=coordinator,
        sessions=Resolver(),
        clock=MutableClock(100),
    )
    reconciling = replace(
        record(state=JobState.CANCELLING, cancel_requested_at_ms=90),
        provider_status=CANCEL_RECONCILIATION_STATUS,
        provider_status_observed_at_ms=100,
    )

    pending = await gateway.observe(reconciling)
    assert pending == JobObservation(
        target_state=JobState.CANCELLING,
        provider_status=CANCEL_RECONCILIATION_STATUS,
        poll_after_ms=30_000,
    )
    settled = await gateway.observe(reconciling)
    assert settled.actual_cost_units == 3
    assert [call[0].operation for call in coordinator.calls] == [
        "firecrawl.crawl.status",
        "firecrawl.crawl.status",
    ]


@pytest.mark.asyncio
async def test_cancel_handoff_is_marked_before_dispatch_and_not_replayed() -> None:
    clock = MutableClock(100)
    store = MemoryStore(
        record(
            state=JobState.CANCELLING,
            maximum_runtime_at_ms=10_000,
            cancel_requested_at_ms=90,
        )
    )
    blocked = BlockingCoordinator()
    first_gateway = CoordinatorJobObservationGateway(
        coordinator=blocked,
        sessions=Resolver(),
        clock=clock,
    )
    first = asyncio.create_task(
        JobSupervisor(
            store=store,
            gateway=first_gateway,
            clock=clock,
            policy=JobSupervisorPolicy(claim_ttl_ms=1_000),
        ).run_once()
    )
    await blocked.started.wait()
    assert blocked.calls[0].operation == "firecrawl.crawl.cancel"
    assert store.current.provider_status == CANCEL_RECONCILIATION_STATUS
    first.cancel()
    with pytest.raises(asyncio.CancelledError):
        await first

    clock.value = 1_100
    recovered_coordinator = Coordinator(
        (
            InvocationState.SUCCEEDED,
            {"status": "running"},
            None,
        )
    )
    recovered_gateway = CoordinatorJobObservationGateway(
        coordinator=recovered_coordinator,
        sessions=Resolver(),
        clock=clock,
    )
    await JobSupervisor(
        store=store,
        gateway=recovered_gateway,
        clock=clock,
        policy=JobSupervisorPolicy(claim_ttl_ms=1_000),
    ).run_once()

    assert recovered_coordinator.calls[0][0].operation == "firecrawl.crawl.status"
    assert store.current.state is JobState.CANCELLING


@pytest.mark.asyncio
async def test_observer_is_bounded_by_the_job_runtime_deadline() -> None:
    clock = MutableClock(100)
    blocked = BlockingCoordinator()
    gateway = CoordinatorJobObservationGateway(
        coordinator=blocked,
        sessions=Resolver(),
        clock=clock,
        request_timeout_ms=30_000,
    )

    observed = await gateway.observe(record(maximum_runtime_at_ms=101))

    assert observed == JobObservation(target_state=JobState.UNKNOWN)
    assert blocked.calls[0].queue_deadline_ms == 101


def test_sqlite_resolver_reconstructs_terminal_root_without_public_budget() -> None:
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    connection.execute(
        "CREATE TABLE sessions(session_id TEXT, client_id TEXT, workspace_id TEXT, "
        "token_epoch INTEGER, revocation_epoch INTEGER)"
    )
    connection.execute("CREATE TABLE root_runs(root_run_id TEXT, session_id TEXT, state TEXT)")
    connection.execute("CREATE TABLE pools(pool_id TEXT, service_id TEXT, alias TEXT)")
    connection.execute(
        "INSERT INTO sessions VALUES (?, ?, ?, ?, ?)",
        (f"ses_{_ID}", f"client_{_ID}", f"ws_{_ID}", 7, 3),
    )
    connection.execute(
        "INSERT INTO root_runs VALUES (?, ?, 'COMPLETED')",
        (f"run_{_ID}", f"ses_{_ID}"),
    )
    connection.execute(
        "INSERT INTO pools VALUES (?, 'firecrawl', 'original-affinity-pool')",
        (f"pool_{_ID}",),
    )
    profile = ClientProfileConfig.model_validate(
        {
            "schema_version": 1,
            "client": {
                "id": "editor",
                "kind": "interactive",
                "unattended": False,
                "approval_mode": "dashboard",
                "default_priority": "interactive",
                "maximum_concurrent_runs": 1,
                "maximum_in_flight": 1,
                "maximum_queued": 1,
                "maximum_run_duration": 60_000,
            },
            "capabilities": {"allow": ["firecrawl.crawl.start"]},
            "pools": {
                "bindings": {"firecrawl": "current-default"},
                "emergency_access": False,
            },
            "lease": {"heartbeat_interval": 1_000, "stale_after": 2_000},
        }
    )

    resolved = SqliteJobSessionResolver(
        connection,
        client_profiles={f"client_{_ID}": profile},
    ).resolve(record())

    assert resolved.token_epoch == 7
    assert resolved.revocation_epoch == 3

    assert resolved.root_run_id == RootRunId(f"run_{_ID}")
    assert resolved.pool_bindings == {"firecrawl": "original-affinity-pool"}
    assert resolved.request_count_remaining == 1
    assert resolved.request_limit is None
    assert resolved.internal_resource_reconciliation
    connection.close()
