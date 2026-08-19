from __future__ import annotations

import asyncio
from collections import Counter

import pytest

from gatehouse.scheduler import (
    BoundedFairScheduler,
    PriorityClass,
    QueueCapacityExceeded,
    QueueTicket,
    SchedulerLimits,
    ServiceLimits,
    WorkItem,
)

_CONTEXTS = 256
_IDENTITIES = 200
_PRODUCERS = 60
_GLOBAL_IN_FLIGHT = 96
_GLOBAL_QUEUE = 300
_PROVIDER_IN_FLIGHT = 8


def _work(
    index: int,
    *,
    service_id: str,
    priority: PriorityClass = PriorityClass.NORMAL_AGENT,
) -> WorkItem:
    return WorkItem(
        request_id=f"request-{index}",
        session_id=f"identity-{index % _IDENTITIES}",
        service_id=service_id,
        priority=priority,
        enqueued_at_ms=1_000,
        deadline_ms=60_000,
    )


def _capacity_scheduler() -> BoundedFairScheduler:
    services = {
        f"provider-{index:02d}": ServiceLimits(
            maximum_in_flight=_PROVIDER_IN_FLIGHT,
            maximum_queued=_GLOBAL_QUEUE,
            reserved_system_in_flight=1 if index == 0 else 0,
            reserved_system_queue=1 if index == 0 else 0,
        )
        for index in range(12)
    }
    return BoundedFairScheduler(
        limits=SchedulerLimits(
            global_maximum_in_flight=_GLOBAL_IN_FLIGHT,
            global_maximum_queued=_GLOBAL_QUEUE,
            per_session_maximum_in_flight=8,
            per_session_maximum_queued=20,
            services=services,
            reserved_system_in_flight=1,
            reserved_system_queue=1,
        ),
        now_ms=lambda: 1_000,
    )


@pytest.mark.asyncio
async def test_256_contexts_200_identities_60_producers_respect_all_capacity_gates() -> None:
    scheduler = _capacity_scheduler()
    tickets: list[tuple[int, QueueTicket]] = []
    ticket_lock = asyncio.Lock()

    async def producer(producer_index: int) -> None:
        for index in range(producer_index, _CONTEXTS, _PRODUCERS):
            ticket = await scheduler.enqueue(_work(index, service_id=f"provider-{index % 12:02d}"))
            async with ticket_lock:
                tickets.append((index, ticket))
            await asyncio.sleep(0)

    await asyncio.gather(*(producer(index) for index in range(_PRODUCERS)))
    snapshot = await scheduler.snapshot()
    assert snapshot.running_total == _GLOBAL_IN_FLIGHT - 1
    assert snapshot.queued_total == _CONTEXTS - (_GLOBAL_IN_FLIGHT - 1)
    assert max(snapshot.running_by_service.values()) <= _PROVIDER_IN_FLIGHT

    watcher = await scheduler.enqueue(
        WorkItem(
            request_id="reserved-watcher",
            session_id="watcher",
            service_id="provider-00",
            priority=PriorityClass.SYSTEM_RESERVED,
            enqueued_at_ms=1_000,
            deadline_ms=60_000,
        )
    )
    assert watcher.ready
    saturated = await scheduler.snapshot()
    assert saturated.running_total == _GLOBAL_IN_FLIGHT
    assert saturated.running_by_service["provider-00"] == _PROVIDER_IN_FLIGHT

    pending = [ticket for _, ticket in tickets]
    pending.append(watcher)
    dispatches = []
    while pending:
        ready = [ticket for ticket in pending if ticket.ready]
        assert ready, "scheduler stopped making progress with queued eligible work"
        for ticket in ready:
            permit = await ticket.wait()
            dispatches.append(permit)
            pending.remove(ticket)
            assert await scheduler.release(permit)

    assert len(dispatches) == _CONTEXTS + 1
    assert len({permit.dispatch_id for permit in dispatches}) == len(dispatches)
    assert {permit.session_id for permit in dispatches if permit.session_id != "watcher"} == {
        f"identity-{index}" for index in range(_IDENTITIES)
    }
    assert Counter(permit.service_id for permit in dispatches)["provider-00"] > 0
    final = await scheduler.snapshot()
    assert final.running_total == 0 and final.queued_total == 0


@pytest.mark.asyncio
async def test_queue_is_bounded_at_300_and_retains_one_reserved_watcher_entry() -> None:
    scheduler = BoundedFairScheduler(
        limits=SchedulerLimits(
            global_maximum_in_flight=1,
            global_maximum_queued=300,
            per_session_maximum_in_flight=1,
            per_session_maximum_queued=2,
            services={
                "provider": ServiceLimits(
                    maximum_in_flight=1,
                    maximum_queued=300,
                    reserved_system_queue=1,
                )
            },
            reserved_system_queue=1,
        ),
        now_ms=lambda: 1_000,
    )
    running = await scheduler.enqueue(_work(10_000, service_id="provider"))
    for index in range(299):
        await scheduler.enqueue(
            WorkItem(
                request_id=f"queued-{index}",
                session_id=f"queue-session-{index}",
                service_id="provider",
                priority=PriorityClass.NORMAL_AGENT,
                enqueued_at_ms=1_000,
                deadline_ms=60_000,
            )
        )
    with pytest.raises(QueueCapacityExceeded, match="reserved"):
        await scheduler.enqueue(
            WorkItem(
                request_id="ordinary-overflow",
                session_id="overflow",
                service_id="provider",
                priority=PriorityClass.NORMAL_AGENT,
                enqueued_at_ms=1_000,
                deadline_ms=60_000,
            )
        )
    await scheduler.enqueue(
        WorkItem(
            request_id="queued-watcher",
            session_id="watcher",
            service_id="provider",
            priority=PriorityClass.SYSTEM_RESERVED,
            enqueued_at_ms=1_000,
            deadline_ms=60_000,
        )
    )
    assert (await scheduler.snapshot()).queued_total == 300
    assert await scheduler.release(await running.wait())


@pytest.mark.asyncio
async def test_round_robin_gives_cold_sessions_progress_under_a_hot_producer() -> None:
    scheduler = BoundedFairScheduler(
        limits=SchedulerLimits(
            global_maximum_in_flight=1,
            global_maximum_queued=100,
            per_session_maximum_in_flight=1,
            per_session_maximum_queued=64,
            services={"provider": ServiceLimits(1, 100)},
        ),
        now_ms=lambda: 1_000,
    )
    blocker = await scheduler.enqueue(_work(20_000, service_id="provider"))
    tickets = []
    for index in range(30):
        tickets.append(
            await scheduler.enqueue(
                WorkItem(
                    request_id=f"hot-{index}",
                    session_id="hot",
                    service_id="provider",
                    priority=PriorityClass.NORMAL_AGENT,
                    enqueued_at_ms=1_000,
                    deadline_ms=60_000,
                )
            )
        )
    for index in range(10):
        tickets.append(
            await scheduler.enqueue(
                WorkItem(
                    request_id=f"cold-{index}",
                    session_id=f"cold-{index}",
                    service_id="provider",
                    priority=PriorityClass.NORMAL_AGENT,
                    enqueued_at_ms=1_000,
                    deadline_ms=60_000,
                )
            )
        )
    assert await scheduler.release(await blocker.wait())
    dispatch_order: list[str] = []
    pending = list(tickets)
    while pending:
        ready = next(ticket for ticket in pending if ticket.ready)
        permit = await ready.wait()
        dispatch_order.append(permit.request_id)
        pending.remove(ready)
        assert await scheduler.release(permit)
    cold_positions = [dispatch_order.index(f"cold-{index}") for index in range(10)]
    assert max(cold_positions) < 21
