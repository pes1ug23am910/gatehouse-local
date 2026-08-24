from __future__ import annotations

import asyncio

import pytest

from gatehouse.fingerprint import (
    FingerprintContext,
    FingerprintService,
    RequestFingerprint,
    RunawayDecision,
    RunawayDetector,
    RunawayTrigger,
    SingleFlightCapacityExceeded,
    SingleFlightCoordinator,
    SingleFlightRole,
)


def fingerprint() -> RequestFingerprint:
    return FingerprintService(b"f" * 32).calculate(
        FingerprintContext(
            service="firecrawl",
            operation="search",
            normalized_input={"query": "jobs"},
            workspace_scope="workspace",
            data_scope="public_web",
            authorization_scope="public",
            result_format="metadata",
        )
    )


@pytest.mark.asyncio
async def test_same_session_joins_but_other_session_does_not_by_default() -> None:
    coordinator = SingleFlightCoordinator(maximum_groups=4)
    leader = await coordinator.join_or_create(
        session_id="session-a", request_id="request-a", fingerprint=fingerprint()
    )
    waiter = await coordinator.join_or_create(
        session_id="session-a", request_id="request-b", fingerprint=fingerprint()
    )
    other = await coordinator.join_or_create(
        session_id="session-b", request_id="request-c", fingerprint=fingerprint()
    )

    assert leader.role is SingleFlightRole.LEADER
    assert waiter.role is SingleFlightRole.WAITER
    assert waiter.original_request_id == leader.request_id
    assert other.role is SingleFlightRole.LEADER
    assert other.group_id != leader.group_id
    await coordinator.complete(leader.group_id, {"data": [1]})
    assert await leader.wait() == {"data": [1]}
    assert await waiter.wait() == {"data": [1]}


@pytest.mark.asyncio
async def test_leader_cancellation_promotes_waiter_without_cancelling_work() -> None:
    coordinator = SingleFlightCoordinator()
    leader = await coordinator.join_or_create(
        session_id="session", request_id="leader", fingerprint=fingerprint()
    )
    waiter = await coordinator.join_or_create(
        session_id="session", request_id="waiter", fingerprint=fingerprint()
    )

    decision = await coordinator.cancel(leader)
    assert decision.detached
    assert not decision.cancel_underlying
    assert decision.promoted_request_id == "waiter"
    with pytest.raises(asyncio.CancelledError):
        await leader.wait()
    await coordinator.complete(leader.group_id, "done")
    assert await waiter.wait() == "done"


@pytest.mark.asyncio
async def test_waiter_cancellation_does_not_cancel_or_receive_leader_result() -> None:
    coordinator = SingleFlightCoordinator()
    leader = await coordinator.join_or_create(
        session_id="session", request_id="leader", fingerprint=fingerprint()
    )
    waiter = await coordinator.join_or_create(
        session_id="session", request_id="waiter", fingerprint=fingerprint()
    )

    decision = await coordinator.cancel(waiter)
    assert decision.detached
    assert not decision.cancel_underlying
    with pytest.raises(asyncio.CancelledError):
        await waiter.wait()
    await coordinator.complete(leader.group_id, "leader-result")
    assert await leader.wait() == "leader-result"


@pytest.mark.asyncio
async def test_last_participant_cancellation_owns_underlying_cancel() -> None:
    coordinator = SingleFlightCoordinator()
    leader = await coordinator.join_or_create(
        session_id="session", request_id="leader", fingerprint=fingerprint()
    )
    decision = await coordinator.cancel(leader)
    assert decision.cancel_underlying
    with pytest.raises(asyncio.CancelledError):
        await leader.wait()


@pytest.mark.asyncio
async def test_singleflight_capacity_is_bounded() -> None:
    coordinator = SingleFlightCoordinator(maximum_groups=1, maximum_waiters_per_group=1)
    await coordinator.join_or_create(
        session_id="session", request_id="leader", fingerprint=fingerprint()
    )
    await coordinator.join_or_create(
        session_id="session", request_id="waiter", fingerprint=fingerprint()
    )
    with pytest.raises(SingleFlightCapacityExceeded):
        await coordinator.join_or_create(
            session_id="session", request_id="too-many", fingerprint=fingerprint()
        )
    with pytest.raises(SingleFlightCapacityExceeded):
        await coordinator.join_or_create(
            session_id="other", request_id="other", fingerprint=fingerprint()
        )


def test_duplicate_arrivals_open_runaway_breaker_until_explicit_recovery() -> None:
    detector = RunawayDetector(
        threshold=3,
        window_ms=30,
        cooldown_ms=100,
        maximum_fingerprints_per_session=2,
    )
    request = fingerprint()
    assert (
        detector.record_arrival(session_id="session", fingerprint=request, now_ms=0)
        is RunawayDecision.ALLOW
    )
    assert (
        detector.record_arrival(session_id="session", fingerprint=request, now_ms=1)
        is RunawayDecision.ALLOW
    )
    assert (
        detector.record_arrival(session_id="session", fingerprint=request, now_ms=2)
        is RunawayDecision.OPENED
    )
    assert (
        detector.record_arrival(session_id="session", fingerprint=request, now_ms=50)
        is RunawayDecision.BLOCKED
    )
    assert detector.retry_after_ms(session_id="session", fingerprint=request, now_ms=50) is None
    assert (
        detector.record_arrival(session_id="session", fingerprint=request, now_ms=102)
        is RunawayDecision.BLOCKED
    )
    detector.forget_session("session")
    assert (
        detector.record_arrival(session_id="session", fingerprint=request, now_ms=103)
        is RunawayDecision.ALLOW
    )


def test_scheduled_repeat_outside_short_window_does_not_trip_breaker() -> None:
    detector = RunawayDetector(threshold=3, window_ms=30, cooldown_ms=100)
    request = fingerprint()
    for now in (0, 31, 62, 93):
        assert (
            detector.record_arrival(session_id="watcher", fingerprint=request, now_ms=now)
            is RunawayDecision.ALLOW
        )


def test_varied_aggregate_arrivals_open_the_same_bounded_scope() -> None:
    detector = RunawayDetector(threshold=3, aggregate_threshold=3, window_ms=30)
    requests = [RequestFingerprint(bytes([index]) * 32, 1, 1) for index in range(1, 4)]
    assert (
        detector.record_arrival(session_id="session", fingerprint=requests[0], now_ms=0)
        is RunawayDecision.ALLOW
    )
    assert (
        detector.record_arrival(session_id="session", fingerprint=requests[1], now_ms=1)
        is RunawayDecision.ALLOW
    )
    observation = detector.observe_arrival(session_id="session", fingerprint=requests[2], now_ms=2)
    assert observation.decision is RunawayDecision.OPENED
    assert observation.trigger is not None
    assert observation.trigger.value == "AGGREGATE_BURST"


def test_inactive_scopes_age_out_without_timer_healing_an_open_scope() -> None:
    detector = RunawayDetector(
        threshold=2,
        aggregate_threshold=4,
        window_ms=10,
        maximum_sessions=2,
    )
    fingerprint = RequestFingerprint(b"a" * 32, 1, 1)
    assert (
        detector.record_arrival(session_id="stale", fingerprint=fingerprint, now_ms=0)
        is RunawayDecision.ALLOW
    )
    assert (
        detector.record_arrival(session_id="opened", fingerprint=fingerprint, now_ms=1)
        is RunawayDecision.ALLOW
    )
    assert (
        detector.record_arrival(session_id="opened", fingerprint=fingerprint, now_ms=2)
        is RunawayDecision.OPENED
    )

    fresh = detector.observe_arrival(
        session_id="fresh",
        fingerprint=RequestFingerprint(b"b" * 32, 1, 1),
        now_ms=11,
    )
    assert fresh.decision is RunawayDecision.ALLOW
    assert detector.tracked_sessions == 2
    assert detector.trigger_for("opened") is RunawayTrigger.REPEATED_EQUIVALENT
