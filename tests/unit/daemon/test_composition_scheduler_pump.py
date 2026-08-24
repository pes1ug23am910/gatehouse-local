from __future__ import annotations

import asyncio

import pytest

from gatehouse.daemon import pump_scheduler_until_shutdown
from gatehouse.scheduler import (
    BoundedFairScheduler,
    ClientCapacityLimits,
    PriorityClass,
    QueueExpired,
    SchedulerLimits,
    ServiceLimits,
    WorkItem,
)


class MutableClock:
    def __init__(self) -> None:
        self.value = 0

    def __call__(self) -> int:
        return self.value


@pytest.mark.asyncio
async def test_shared_pump_expires_queue_without_another_scheduler_event() -> None:
    clock = MutableClock()
    scheduler = BoundedFairScheduler(
        limits=SchedulerLimits(
            global_maximum_in_flight=1,
            global_maximum_queued=2,
            per_session_maximum_in_flight=1,
            per_session_maximum_queued=2,
            services={"firecrawl": ServiceLimits(1, 2)},
            clients={"client": ClientCapacityLimits(1, 2)},
        ),
        now_ms=clock,
    )
    first = await scheduler.enqueue(
        WorkItem(
            request_id="first",
            session_id="session-one",
            client_id="client",
            service_id="firecrawl",
            priority=PriorityClass.INTERACTIVE,
            enqueued_at_ms=0,
            deadline_ms=1_000,
        )
    )
    permit = await first.wait()
    expiring = await scheduler.enqueue(
        WorkItem(
            request_id="expiring",
            session_id="session-two",
            client_id="client",
            service_id="firecrawl",
            priority=PriorityClass.NORMAL_AGENT,
            enqueued_at_ms=0,
            deadline_ms=50,
        )
    )
    shutdown = asyncio.Event()
    pump = asyncio.create_task(pump_scheduler_until_shutdown(scheduler, shutdown, interval_ms=10))

    clock.value = 51
    for _ in range(20):
        if expiring.ready:
            break
        await asyncio.sleep(0.005)

    assert expiring.ready
    assert (await scheduler.snapshot()).queued_total == 0
    with pytest.raises(QueueExpired):
        await expiring.wait()

    shutdown.set()
    await asyncio.wait_for(pump, timeout=1)
    assert await scheduler.release(permit)


@pytest.mark.asyncio
async def test_scheduler_pump_interval_is_bounded() -> None:
    shutdown = asyncio.Event()

    class Scheduler:
        async def pump(self) -> int:
            return 0

    with pytest.raises(ValueError, match="outside"):
        await pump_scheduler_until_shutdown(Scheduler(), shutdown, interval_ms=9)
