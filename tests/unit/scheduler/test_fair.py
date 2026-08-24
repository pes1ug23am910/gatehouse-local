from __future__ import annotations

import asyncio

import pytest

from gatehouse.scheduler import (
    BoundedFairScheduler,
    CancellationResult,
    PriorityClass,
    QueueCapacityExceeded,
    QueueExpired,
    QuotaScopeSaturated,
    RequestCancelled,
    SchedulerLimits,
    ServiceLimits,
    WorkItem,
)


class FakeClock:
    def __init__(self, value: int = 0) -> None:
        self.value = value

    def __call__(self) -> int:
        return self.value

    def advance(self, milliseconds: int) -> None:
        self.value += milliseconds


def configured_limits(
    *,
    global_in_flight: int = 2,
    global_queued: int = 8,
    per_session_in_flight: int = 1,
    per_session_queued: int = 4,
    reserved_in_flight: int = 0,
    reserved_queue: int = 0,
    per_quota_scope_in_flight: int = 2_147_483_647,
) -> SchedulerLimits:
    return SchedulerLimits(
        global_maximum_in_flight=global_in_flight,
        global_maximum_queued=global_queued,
        per_session_maximum_in_flight=per_session_in_flight,
        per_session_maximum_queued=per_session_queued,
        reserved_system_in_flight=reserved_in_flight,
        reserved_system_queue=reserved_queue,
        services={
            "provider": ServiceLimits(
                maximum_in_flight=global_in_flight,
                maximum_queued=global_queued,
                reserved_system_in_flight=reserved_in_flight,
                reserved_system_queue=reserved_queue,
                maximum_per_quota_scope=per_quota_scope_in_flight,
            )
        },
    )


def work(
    clock: FakeClock,
    request_id: str,
    *,
    session_id: str = "session",
    priority: PriorityClass = PriorityClass.INTERACTIVE,
    ttl_ms: int = 1_000,
    cost: int = 1,
    quota_scope_id: str | None = None,
) -> WorkItem:
    return WorkItem(
        request_id=request_id,
        session_id=session_id,
        service_id="provider",
        priority=priority,
        enqueued_at_ms=clock(),
        deadline_ms=clock() + ttl_ms,
        cost=cost,
        quota_scope_id=quota_scope_id,
    )


@pytest.mark.asyncio
async def test_shared_quota_scope_has_an_independent_in_flight_cap() -> None:
    clock = FakeClock()
    scheduler = BoundedFairScheduler(
        limits=configured_limits(
            global_in_flight=3,
            per_session_in_flight=3,
            per_quota_scope_in_flight=1,
        ),
        now_ms=clock,
    )

    first = await scheduler.enqueue(
        work(clock, "scope-a-one", session_id="one", quota_scope_id="scope-a")
    )
    blocked = await scheduler.enqueue(
        work(clock, "scope-a-two", session_id="two", quota_scope_id="scope-a")
    )
    independent = await scheduler.enqueue(
        work(clock, "scope-b", session_id="three", quota_scope_id="scope-b")
    )

    first_permit = await first.wait()
    independent_permit = await independent.wait()
    assert not blocked.ready
    snapshot = await scheduler.snapshot()
    assert snapshot.running_by_quota_scope == {
        "provider:scope-a": 1,
        "provider:scope-b": 1,
    }
    assert await scheduler.release(first_permit)
    assert (await blocked.wait()).quota_scope_id == "scope-a"
    assert await scheduler.release(independent_permit)


@pytest.mark.asyncio
async def test_scope_saturation_rejection_is_atomic_and_request_id_is_reusable() -> None:
    clock = FakeClock()
    scheduler = BoundedFairScheduler(
        limits=configured_limits(
            global_in_flight=3,
            per_session_in_flight=3,
            per_quota_scope_in_flight=1,
        ),
        now_ms=clock,
    )
    first = await scheduler.enqueue(
        work(clock, "scope-a-running", session_id="one", quota_scope_id="scope-a")
    )
    first_permit = await first.wait()

    with pytest.raises(QuotaScopeSaturated):
        await scheduler.enqueue_unless_quota_scope_saturated(
            work(clock, "spillable", session_id="two", quota_scope_id="scope-a")
        )

    snapshot = await scheduler.snapshot()
    assert snapshot.queued_total == 0
    replacement = await scheduler.enqueue_unless_quota_scope_saturated(
        work(clock, "spillable", session_id="two", quota_scope_id="scope-b")
    )
    replacement_permit = await replacement.wait()
    assert replacement_permit.quota_scope_id == "scope-b"
    assert await scheduler.release(first_permit)
    assert await scheduler.release(replacement_permit)


@pytest.mark.asyncio
async def test_non_scope_capacity_waits_without_requesting_pool_spill() -> None:
    clock = FakeClock()
    scheduler = BoundedFairScheduler(
        limits=configured_limits(
            global_in_flight=1,
            per_session_in_flight=1,
            per_quota_scope_in_flight=1,
        ),
        now_ms=clock,
    )
    blocker = await scheduler.enqueue(
        work(clock, "blocker", session_id="one", quota_scope_id="scope-b")
    )
    blocker_permit = await blocker.wait()
    waiting = await scheduler.enqueue_unless_quota_scope_saturated(
        work(clock, "waiting", session_id="two", quota_scope_id="scope-a")
    )

    assert not waiting.ready
    assert (await scheduler.snapshot()).queued_total == 1
    assert await scheduler.release(blocker_permit)
    waiting_permit = await waiting.wait()
    assert waiting_permit.quota_scope_id == "scope-a"
    assert await scheduler.release(waiting_permit)


@pytest.mark.asyncio
async def test_queued_spillable_ticket_rejects_if_its_scope_saturates_later() -> None:
    clock = FakeClock()
    scheduler = BoundedFairScheduler(
        limits=configured_limits(
            global_in_flight=2,
            per_session_in_flight=2,
            per_quota_scope_in_flight=1,
        ),
        now_ms=clock,
    )
    first = await scheduler.enqueue(
        work(clock, "blocker-one", session_id="one", quota_scope_id="scope-b")
    )
    second = await scheduler.enqueue(
        work(clock, "blocker-two", session_id="two", quota_scope_id="scope-c")
    )
    first_permit = await first.wait()
    second_permit = await second.wait()
    competitor = await scheduler.enqueue(
        work(clock, "competitor", session_id="three", quota_scope_id="scope-a")
    )
    spillable = await scheduler.enqueue_unless_quota_scope_saturated(
        work(clock, "spillable", session_id="four", quota_scope_id="scope-a")
    )
    assert not competitor.ready
    assert not spillable.ready

    assert await scheduler.release(first_permit)
    competitor_permit = await competitor.wait()
    with pytest.raises(QuotaScopeSaturated):
        await spillable.wait()
    assert (await scheduler.snapshot()).queued_total == 0
    assert await scheduler.release(second_permit)
    assert await scheduler.release(competitor_permit)


@pytest.mark.asyncio
async def test_reserved_provider_slot_cannot_be_consumed_by_ordinary_work() -> None:
    clock = FakeClock()
    scheduler = BoundedFairScheduler(
        limits=configured_limits(reserved_in_flight=1),
        now_ms=clock,
    )

    first = await scheduler.enqueue(work(clock, "ordinary-one", session_id="one"))
    blocked = await scheduler.enqueue(work(clock, "ordinary-two", session_id="two"))
    system = await scheduler.enqueue(
        work(
            clock,
            "system",
            session_id="system-session",
            priority=PriorityClass.SYSTEM_RESERVED,
        )
    )

    first_permit = await first.wait()
    system_permit = await system.wait()
    assert not blocked.ready
    snapshot = await scheduler.snapshot()
    assert snapshot.running_total == 2
    assert snapshot.queued_total == 1

    assert await scheduler.release(first_permit)
    assert (await blocked.wait()).request_id == "ordinary-two"
    assert await scheduler.release(system_permit)


@pytest.mark.asyncio
async def test_reserved_queue_capacity_remains_available_to_system_work() -> None:
    clock = FakeClock()
    scheduler = BoundedFairScheduler(
        limits=configured_limits(
            global_in_flight=1,
            global_queued=2,
            reserved_queue=1,
        ),
        now_ms=clock,
    )
    running = await scheduler.enqueue(work(clock, "running", session_id="running"))
    ordinary = await scheduler.enqueue(work(clock, "ordinary", session_id="ordinary"))

    with pytest.raises(QueueCapacityExceeded, match="reserved"):
        await scheduler.enqueue(work(clock, "rejected", session_id="rejected"))

    system = await scheduler.enqueue(
        work(
            clock,
            "system",
            session_id="system",
            priority=PriorityClass.SYSTEM_RESERVED,
        )
    )
    assert not ordinary.ready
    assert not system.ready
    assert (await scheduler.snapshot()).queued_total == 2
    assert await scheduler.release(await running.wait())


@pytest.mark.asyncio
async def test_queue_ttl_uses_injected_clock_at_exact_deadline() -> None:
    clock = FakeClock()
    scheduler = BoundedFairScheduler(
        limits=configured_limits(global_in_flight=1),
        now_ms=clock,
    )
    running = await scheduler.enqueue(work(clock, "running", session_id="running"))
    expiring = await scheduler.enqueue(work(clock, "expiring", session_id="waiting", ttl_ms=10))

    clock.advance(10)
    assert await scheduler.pump() == 0
    with pytest.raises(QueueExpired, match="deadline"):
        await expiring.wait()
    assert (await scheduler.snapshot()).queued_total == 0
    assert await scheduler.release(await running.wait())


@pytest.mark.asyncio
async def test_quiet_queue_wait_expires_without_an_external_pump() -> None:
    clock = FakeClock()
    scheduler = BoundedFairScheduler(
        limits=configured_limits(global_in_flight=1),
        now_ms=clock,
    )
    running = await scheduler.enqueue(work(clock, "running", session_id="running"))
    running_permit = await running.wait()
    expiring = await scheduler.enqueue(work(clock, "quiet-expiry", session_id="waiting", ttl_ms=1))

    with pytest.raises(QueueExpired):
        await expiring.wait()

    assert (await scheduler.snapshot()).queued_total == 0
    assert await scheduler.release(running_permit)


@pytest.mark.asyncio
async def test_cancellation_distinguishes_queued_and_running_ownership() -> None:
    clock = FakeClock()
    scheduler = BoundedFairScheduler(
        limits=configured_limits(global_in_flight=1),
        now_ms=clock,
    )
    running_ticket = await scheduler.enqueue(work(clock, "running", session_id="running"))
    running = await running_ticket.wait()
    queued = await scheduler.enqueue(work(clock, "queued", session_id="queued"))

    assert await scheduler.cancel("queued") is CancellationResult.QUEUED_CANCELLED
    with pytest.raises(RequestCancelled):
        await queued.wait()
    assert await scheduler.cancel("running") is CancellationResult.RUNNING_SIGNALLED
    assert running.cancel_event.is_set()
    assert await scheduler.cancel("missing") is CancellationResult.NOT_FOUND
    assert await scheduler.release(running)


@pytest.mark.asyncio
async def test_cancelling_ticket_wait_reclaims_the_queued_entry() -> None:
    clock = FakeClock()
    scheduler = BoundedFairScheduler(
        limits=configured_limits(
            global_in_flight=1,
            global_queued=1,
            per_session_queued=1,
        ),
        now_ms=clock,
    )
    running = await scheduler.enqueue(work(clock, "running", session_id="running"))
    running_permit = await running.wait()
    abandoned = await scheduler.enqueue(work(clock, "abandoned", session_id="abandoned"))

    waiter = asyncio.create_task(abandoned.wait())
    await asyncio.sleep(0)
    waiter.cancel()
    with pytest.raises(asyncio.CancelledError):
        await waiter

    snapshot = await scheduler.snapshot()
    assert snapshot.queued_total == 0
    assert snapshot.queued_by_session["abandoned"] == 0

    replacement = await scheduler.enqueue(work(clock, "replacement", session_id="replacement"))
    assert await scheduler.release(running_permit)
    replacement_permit = await replacement.wait()
    assert replacement_permit.request_id == "replacement"
    assert await scheduler.release(replacement_permit)


@pytest.mark.asyncio
async def test_ticket_wait_timeout_reclaims_queue_capacity() -> None:
    clock = FakeClock()
    scheduler = BoundedFairScheduler(
        limits=configured_limits(global_in_flight=1, global_queued=1),
        now_ms=clock,
    )
    running = await scheduler.enqueue(work(clock, "running", session_id="running"))
    permit = await running.wait()
    queued = await scheduler.enqueue(work(clock, "timed-out", session_id="waiting"))

    with pytest.raises(TimeoutError):
        await asyncio.wait_for(queued.wait(), timeout=0.001)

    assert (await scheduler.snapshot()).queued_total == 0
    assert await scheduler.release(permit)


@pytest.mark.asyncio
async def test_cancel_after_dispatch_before_waiter_resume_reclaims_permit() -> None:
    clock = FakeClock()
    scheduler = BoundedFairScheduler(
        limits=configured_limits(global_in_flight=1),
        now_ms=clock,
    )
    running = await scheduler.enqueue(work(clock, "running", session_id="running"))
    running_permit = await running.wait()
    queued = await scheduler.enqueue(work(clock, "handoff", session_id="waiting"))
    waiter = asyncio.create_task(queued.wait())
    await asyncio.sleep(0)

    waiter.cancel()
    assert await scheduler.release(running_permit)
    with pytest.raises(asyncio.CancelledError):
        await waiter

    snapshot = await scheduler.snapshot()
    assert snapshot.queued_total == 0
    assert snapshot.running_total == 0


@pytest.mark.asyncio
async def test_old_ticket_cleanup_cannot_reclaim_reused_request_id() -> None:
    clock = FakeClock()
    scheduler = BoundedFairScheduler(
        limits=configured_limits(global_in_flight=1),
        now_ms=clock,
    )
    running = await scheduler.enqueue(work(clock, "running", session_id="running"))
    running_permit = await running.wait()
    old = await scheduler.enqueue(work(clock, "reused", session_id="old"))
    old_waiter = asyncio.create_task(old.wait())
    await asyncio.sleep(0)

    old_waiter.cancel()
    assert await scheduler.cancel("reused") is CancellationResult.QUEUED_CANCELLED
    replacement = await scheduler.enqueue(work(clock, "reused", session_id="replacement"))
    with pytest.raises(asyncio.CancelledError):
        await old_waiter
    assert (await scheduler.snapshot()).queued_total == 1

    assert await scheduler.release(running_permit)
    replacement_permit = await replacement.wait()
    assert replacement_permit.request_id == "reused"
    assert await scheduler.release(replacement_permit)


@pytest.mark.asyncio
async def test_cancellation_expires_hidden_follower_before_pumping() -> None:
    clock = FakeClock()
    scheduler = BoundedFairScheduler(
        limits=SchedulerLimits(
            global_maximum_in_flight=2,
            global_maximum_queued=4,
            per_session_maximum_in_flight=2,
            per_session_maximum_queued=4,
            services={
                "blocked": ServiceLimits(1, 4),
                "free": ServiceLimits(1, 4),
            },
        ),
        now_ms=clock,
    )

    def item(request_id: str, service_id: str, ttl_ms: int = 1_000) -> WorkItem:
        return WorkItem(
            request_id=request_id,
            session_id="session",
            service_id=service_id,
            priority=PriorityClass.INTERACTIVE,
            enqueued_at_ms=clock(),
            deadline_ms=clock() + ttl_ms,
        )

    running = await scheduler.enqueue(item("running", "blocked"))
    running_permit = await running.wait()
    head = await scheduler.enqueue(item("head", "blocked"))
    follower = await scheduler.enqueue(item("expired-follower", "free", ttl_ms=10))
    assert not head.ready and not follower.ready

    clock.advance(10)
    assert await scheduler.cancel("head") is CancellationResult.QUEUED_CANCELLED
    with pytest.raises(QueueExpired):
        await follower.wait()
    assert (await scheduler.snapshot()).running_total == 1
    assert await scheduler.release(running_permit)


@pytest.mark.asyncio
async def test_queue_ticket_has_exactly_one_wait_owner() -> None:
    clock = FakeClock()
    scheduler = BoundedFairScheduler(
        limits=configured_limits(global_in_flight=1),
        now_ms=clock,
    )
    running = await scheduler.enqueue(work(clock, "running", session_id="running"))
    permit = await running.wait()
    queued = await scheduler.enqueue(work(clock, "queued", session_id="queued"))
    owner = asyncio.create_task(queued.wait())
    await asyncio.sleep(0)

    with pytest.raises(RuntimeError, match="only be awaited once"):
        await queued.wait()
    owner.cancel()
    with pytest.raises(asyncio.CancelledError):
        await owner
    assert await scheduler.release(permit)


@pytest.mark.asyncio
async def test_round_robin_rotates_sessions_within_a_priority_class() -> None:
    clock = FakeClock()
    scheduler = BoundedFairScheduler(
        limits=configured_limits(global_in_flight=1),
        now_ms=clock,
    )
    first = await scheduler.enqueue(work(clock, "a-one", session_id="a"))
    a_two = await scheduler.enqueue(work(clock, "a-two", session_id="a"))
    await scheduler.enqueue(work(clock, "a-three", session_id="a"))
    b_one = await scheduler.enqueue(work(clock, "b-one", session_id="b"))

    assert await scheduler.release(await first.wait())
    a_two_permit = await a_two.wait()
    assert a_two_permit.request_id == "a-two"
    assert await scheduler.release(a_two_permit)
    assert (await b_one.wait()).request_id == "b-one"


@pytest.mark.asyncio
async def test_scheduler_does_not_create_per_request_tasks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden_create_task(*args: object, **kwargs: object) -> None:
        raise AssertionError("the scheduler must not create background tasks")

    monkeypatch.setattr(asyncio, "create_task", forbidden_create_task)
    clock = FakeClock()
    scheduler = BoundedFairScheduler(limits=configured_limits(), now_ms=clock)
    ticket = await scheduler.enqueue(work(clock, "request"))
    permit = await ticket.wait()
    assert await scheduler.release(permit)


@pytest.mark.asyncio
async def test_weighted_deficit_accumulates_for_bounded_high_cost_work() -> None:
    clock = FakeClock()
    scheduler = BoundedFairScheduler(limits=configured_limits(), now_ms=clock)
    ticket = await scheduler.enqueue(
        work(
            clock,
            "costly",
            priority=PriorityClass.MAINTENANCE,
            cost=5,
        )
    )
    assert (await ticket.wait()).request_id == "costly"
