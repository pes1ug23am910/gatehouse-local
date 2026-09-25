"""Bounded durable supervision for provider-backed asynchronous jobs."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, replace
from typing import Protocol

from gatehouse.core.clock import SYSTEM_UTC_CLOCK, UtcMsClock, require_utc_ms
from gatehouse.core.task_batches import OwnedTaskBatch

from .models import TERMINAL_JOB_STATES, JobOwner, JobRecord, JobState

CANCEL_RECONCILIATION_STATUS = "gatehouse.cancel_reconcile"


@dataclass(frozen=True, slots=True)
class JobObservation:
    """A classified provider observation with no response-body persistence."""

    target_state: JobState
    provider_status: str | None = None
    poll_after_ms: int | None = None
    actual_cost_units: int | None = None

    def __post_init__(self) -> None:
        permitted = {
            JobState.RUNNING,
            JobState.CANCELLING,
            *TERMINAL_JOB_STATES,
        }
        if self.target_state not in permitted:
            raise ValueError("job observation has an unsupported target state")
        if self.target_state in TERMINAL_JOB_STATES:
            if self.poll_after_ms is not None:
                raise ValueError("terminal job observation cannot request another poll")
        elif self.poll_after_ms is None or self.poll_after_ms <= 0:
            raise ValueError("non-terminal job observation requires a positive poll delay")
        if self.actual_cost_units is not None:
            if (
                isinstance(self.actual_cost_units, bool)
                or not isinstance(self.actual_cost_units, int)
                or self.actual_cost_units < 0
                or self.actual_cost_units >= (1 << 63)
            ):
                raise ValueError("job actual cost must be a non-negative integer")
            if self.target_state not in TERMINAL_JOB_STATES:
                raise ValueError("non-terminal observations cannot settle final job usage")


class JobObservationGateway(Protocol):
    """Reconcile one already-claimed job through its exact provider authority."""

    async def observe(self, job: JobRecord) -> JobObservation: ...


class JobSettlementGateway(Protocol):
    """Settle the creating invocation's held quota and budget idempotently."""

    async def reconcile(self, job: JobRecord, *, actual_units: int) -> None: ...


class JobSupervisorStore(Protocol):
    async def list_due(
        self,
        *,
        now_ms: int,
        limit: int = 100,
    ) -> tuple[JobRecord, ...]: ...

    async def compare_and_set(
        self,
        *,
        expected: JobRecord,
        owner: JobOwner,
        target_state: JobState,
        observed_at_ms: int,
        provider_status: str | None = None,
        next_poll_at_ms: int | None = None,
    ) -> JobRecord | None: ...

    async def prepare_settlement(
        self,
        *,
        expected: JobRecord,
        owner: JobOwner,
        target_state: JobState,
        actual_cost_units: int,
        observed_at_ms: int,
        provider_status: str | None = None,
    ) -> JobRecord | None: ...

    async def complete_settlement(
        self,
        *,
        expected: JobRecord,
        owner: JobOwner,
    ) -> JobRecord | None: ...


@dataclass(frozen=True, slots=True)
class JobSupervisorPolicy:
    """Small, explicit bounds for polling and overlapping-runtime claims."""

    claim_ttl_ms: int = 30_000
    idle_poll_ms: int = 1_000
    maximum_batch_size: int = 100
    maximum_in_flight: int = 8
    cancellation_drain_ms: int = 5_000

    def __post_init__(self) -> None:
        if not 1_000 <= self.claim_ttl_ms <= 300_000:
            raise ValueError("job claim TTL is outside the supported bound")
        if not 10 <= self.idle_poll_ms <= 60_000:
            raise ValueError("job supervisor idle poll is outside the supported bound")
        if not 1 <= self.maximum_batch_size <= 500:
            raise ValueError("job supervisor batch size is outside the supported bound")
        if not 1 <= self.maximum_in_flight <= 64:
            raise ValueError("job supervisor concurrency is outside the supported bound")
        if (
            isinstance(self.cancellation_drain_ms, bool)
            or not isinstance(self.cancellation_drain_ms, int)
            or not 10 <= self.cancellation_drain_ms <= 60_000
        ):
            raise ValueError("job supervisor cancellation drain is outside the supported bound")


class JobSupervisor:
    """Claim, observe, and durably advance due jobs without duplicate dispatch."""

    def __init__(
        self,
        *,
        store: JobSupervisorStore,
        gateway: JobObservationGateway,
        settlements: JobSettlementGateway | None = None,
        clock: UtcMsClock = SYSTEM_UTC_CLOCK,
        policy: JobSupervisorPolicy | None = None,
    ) -> None:
        self._store = store
        self._gateway = gateway
        self._settlements = settlements
        self._clock = clock
        self._policy = policy or JobSupervisorPolicy()
        self._batch = OwnedTaskBatch[int](
            maximum_tasks=self._policy.maximum_batch_size,
            cancellation_drain_ms=self._policy.cancellation_drain_ms,
        )

    @property
    def pending_task_count(self) -> int:
        return self._batch.pending_count

    @property
    def drain_failed(self) -> bool:
        return self._batch.drain_failed

    async def cancel_and_drain(self, *, timeout_ms: int | None = None) -> None:
        await self._batch.cancel_and_drain(timeout_ms=timeout_ms)

    async def run_once(self) -> int:
        """Process one bounded due batch and return committed state changes."""

        async def select() -> tuple[JobRecord, ...]:
            return await self._store.list_due(
                now_ms=self._clock.now_ms(),
                limit=self._policy.maximum_batch_size,
            )

        semaphore = asyncio.Semaphore(self._policy.maximum_in_flight)

        async def process(expected: JobRecord) -> int:
            async with semaphore:
                return await self._process_one(expected)

        return sum(await self._batch.run(select, process))

    async def _process_one(self, expected: JobRecord) -> int:
        if expected.terminal:
            return 0
        if expected.state is JobState.SETTLING:
            return await self._finish_settlement(expected)
        now_ms = self._clock.now_ms()
        if now_ms >= expected.maximum_runtime_at_ms:
            expired = await self._store.compare_and_set(
                expected=expected,
                owner=expected.owner,
                target_state=JobState.UNKNOWN,
                observed_at_ms=now_ms,
            )
            return int(expired is not None)

        claim_until_ms = min(
            expected.maximum_runtime_at_ms,
            require_utc_ms(now_ms + self._policy.claim_ttl_ms),
        )
        claim_state = (
            JobState.CANCELLING if expected.cancel_requested_at_ms is not None else JobState.POLLING
        )
        dispatch_cancel = (
            expected.cancel_requested_at_ms is not None
            and expected.provider_status != CANCEL_RECONCILIATION_STATUS
        )
        claimed = await self._store.compare_and_set(
            expected=expected,
            owner=expected.owner,
            target_state=claim_state,
            observed_at_ms=now_ms,
            provider_status=(CANCEL_RECONCILIATION_STATUS if dispatch_cancel else None),
            next_poll_at_ms=claim_until_ms,
        )
        if claimed is None:
            return 0
        changed = 1

        observation_job = claimed
        if dispatch_cancel:
            # The durable marker is written before DELETE.  This process owns
            # the one dispatch, while any crash/restart sees the marker and
            # performs status reconciliation instead of replaying DELETE.
            observation_job = replace(
                claimed,
                provider_status=None,
                provider_status_observed_at_ms=None,
            )
        observation = await self._gateway.observe(observation_job)
        observed_at_ms = self._clock.now_ms()
        target_state = observation.target_state
        if claimed.cancel_requested_at_ms is not None and target_state is JobState.RUNNING:
            target_state = JobState.CANCELLING

        next_poll_at_ms: int | None = None
        if target_state not in TERMINAL_JOB_STATES:
            assert observation.poll_after_ms is not None
            if observed_at_ms >= claimed.maximum_runtime_at_ms:
                target_state = JobState.UNKNOWN
            else:
                next_poll_at_ms = min(
                    claimed.maximum_runtime_at_ms,
                    require_utc_ms(observed_at_ms + observation.poll_after_ms),
                )
        if observation.actual_cost_units is not None:
            if self._settlements is None:
                raise RuntimeError("job usage cannot be settled without a gateway")
            prepared = await self._store.prepare_settlement(
                expected=claimed,
                owner=claimed.owner,
                target_state=target_state,
                actual_cost_units=observation.actual_cost_units,
                observed_at_ms=observed_at_ms,
                provider_status=observation.provider_status,
            )
            if prepared is None:
                return changed
            changed += 1
            changed += await self._finish_settlement(prepared)
            return changed
        applied = await self._store.compare_and_set(
            expected=claimed,
            owner=claimed.owner,
            target_state=target_state,
            observed_at_ms=observed_at_ms,
            provider_status=observation.provider_status,
            next_poll_at_ms=next_poll_at_ms,
        )
        return changed + int(applied is not None)

    async def _finish_settlement(self, prepared: JobRecord) -> int:
        if prepared.state is not JobState.SETTLING or prepared.settlement_actual_cost_units is None:
            raise RuntimeError("job settlement checkpoint is incomplete")
        if self._settlements is None:
            raise RuntimeError("job usage cannot be settled without a gateway")
        await self._settlements.reconcile(
            prepared,
            actual_units=prepared.settlement_actual_cost_units,
        )
        applied = await self._store.complete_settlement(
            expected=prepared,
            owner=prepared.owner,
        )
        return int(applied is not None)

    async def run(self, stop: asyncio.Event) -> None:
        """Run until shutdown; unexpected observer faults remain task-fatal."""

        while not stop.is_set():
            await self.run_once()
            try:
                await asyncio.wait_for(
                    stop.wait(),
                    timeout=self._policy.idle_poll_ms / 1_000,
                )
            except TimeoutError:
                pass
