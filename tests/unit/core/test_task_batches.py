from __future__ import annotations

import asyncio

import pytest

from gatehouse.core.task_batches import (
    OwnedTaskBatch,
    TaskBatchDrainError,
    TaskBatchUnavailableError,
)


@pytest.mark.asyncio
async def test_batch_returns_ordered_results_and_accepts_empty_selection() -> None:
    batch = OwnedTaskBatch[int](maximum_tasks=3)

    async def select() -> tuple[int, ...]:
        return (3, 1, 2)

    async def process(value: int) -> int:
        await asyncio.sleep(0)
        return value * 2

    assert await batch.run(select, process) == (6, 2, 4)
    assert batch.pending_count == 0

    async def empty() -> tuple[int, ...]:
        return ()

    assert await batch.run(empty, process) == ()


@pytest.mark.parametrize("cancel_child", [False, True])
@pytest.mark.asyncio
async def test_child_fault_cancels_sibling_and_joins_its_cleanup(cancel_child: bool) -> None:
    batch = OwnedTaskBatch[int](maximum_tasks=2)
    sibling_started = asyncio.Event()
    cleanup_started = asyncio.Event()
    cleanup_release = asyncio.Event()
    cleanup_finished = asyncio.Event()

    async def select() -> tuple[int, ...]:
        return (0, 1)

    async def process(value: int) -> int:
        if value == 0:
            await sibling_started.wait()
            if cancel_child:
                raise asyncio.CancelledError
            raise RuntimeError("synthetic batch failure")
        sibling_started.set()
        try:
            await asyncio.Event().wait()
        finally:
            cleanup_started.set()
            await cleanup_release.wait()
            cleanup_finished.set()
        return 1

    cycle = asyncio.create_task(batch.run(select, process))
    try:
        await asyncio.wait_for(cleanup_started.wait(), timeout=1)
        assert not cycle.done()
        cleanup_release.set()
        expected = asyncio.CancelledError if cancel_child else RuntimeError
        with pytest.raises(expected):
            await asyncio.wait_for(cycle, timeout=1)
        assert cleanup_finished.is_set()
        assert batch.pending_count == 0
    finally:
        cleanup_release.set()
        if not cycle.done():
            cycle.cancel()
        await asyncio.wait_for(asyncio.gather(cycle, return_exceptions=True), timeout=1)


@pytest.mark.asyncio
async def test_repeated_caller_cancellation_does_not_interrupt_sibling_cleanup() -> None:
    batch = OwnedTaskBatch[int](maximum_tasks=2)
    started = asyncio.Event()
    cleanup_started = asyncio.Event()
    cleanup_release = asyncio.Event()
    cleaned: list[int] = []
    entered: list[int] = []

    async def select() -> tuple[int, ...]:
        return (0, 1)

    async def process(value: int) -> int:
        entered.append(value)
        if len(entered) == 2:
            started.set()
        try:
            await asyncio.Event().wait()
        finally:
            cleanup_started.set()
            await cleanup_release.wait()
            cleaned.append(value)
        return value

    cycle = asyncio.create_task(batch.run(select, process))
    try:
        await asyncio.wait_for(started.wait(), timeout=1)
        cycle.cancel()
        await asyncio.wait_for(cleanup_started.wait(), timeout=1)
        cycle.cancel()
        await asyncio.sleep(0)
        cycle.cancel()
        assert not cycle.done()
        cleanup_release.set()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(cycle, timeout=1)
        assert sorted(cleaned) == [0, 1]
        assert batch.pending_count == 0
    finally:
        cleanup_release.set()
        if not cycle.done():
            cycle.cancel()
        await asyncio.wait_for(asyncio.gather(cycle, return_exceptions=True), timeout=1)


@pytest.mark.parametrize("cancel_caller", [False, True])
@pytest.mark.asyncio
async def test_resistant_child_is_retained_and_failed_drain_fences_new_work(
    cancel_caller: bool,
) -> None:
    batch = OwnedTaskBatch[int](maximum_tasks=2, cancellation_drain_ms=10)
    started = asyncio.Event()
    release = asyncio.Event()
    finished = asyncio.Event()
    calls: list[int] = []

    async def select() -> tuple[int, ...]:
        return (0, 1)

    async def process(value: int) -> int:
        calls.append(value)
        if value == 0:
            await started.wait()
            if cancel_caller:
                await asyncio.Event().wait()
            raise RuntimeError("synthetic batch failure")
        started.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            current = asyncio.current_task()
            assert current is not None
            current.uncancel()
            await release.wait()
        finally:
            finished.set()
        raise RuntimeError("synthetic late failure")

    cycle = asyncio.create_task(batch.run(select, process))
    try:
        await asyncio.wait_for(started.wait(), timeout=1)
        if cancel_caller:
            cycle.cancel()
        with pytest.raises(TaskBatchDrainError) as caught:
            await asyncio.wait_for(cycle, timeout=1)
        assert caught.value.pending_count == 1
        assert batch.pending_count == 1
        assert batch.drain_failed
        assert not finished.is_set()
        with pytest.raises(TaskBatchUnavailableError):
            await batch.run(select, process)
        with pytest.raises(TaskBatchDrainError):
            await batch.cancel_and_drain(timeout_ms=0)
        assert calls == [0, 1]
    finally:
        release.set()
        await asyncio.wait_for(finished.wait(), timeout=1)
        await batch.cancel_and_drain()
        await asyncio.wait_for(asyncio.gather(cycle, return_exceptions=True), timeout=1)
    assert batch.pending_count == 0
    assert batch.drain_failed
    with pytest.raises(TaskBatchUnavailableError):
        await batch.run(select, process)


@pytest.mark.asyncio
async def test_overlapping_cycle_is_rejected_before_selection() -> None:
    batch = OwnedTaskBatch[int](maximum_tasks=1)
    selecting = asyncio.Event()
    release = asyncio.Event()
    selected = 0

    async def select() -> tuple[int, ...]:
        nonlocal selected
        selected += 1
        selecting.set()
        await release.wait()
        return ()

    async def process(value: int) -> int:
        raise AssertionError("empty selection dispatched work")

    cycle = asyncio.create_task(batch.run(select, process))
    try:
        await asyncio.wait_for(selecting.wait(), timeout=1)
        with pytest.raises(TaskBatchUnavailableError):
            await batch.run(select, process)
        assert selected == 1
        with pytest.raises(TaskBatchUnavailableError):
            await batch.cancel_and_drain()
        release.set()
        with pytest.raises(TaskBatchUnavailableError):
            await asyncio.wait_for(cycle, timeout=1)
    finally:
        release.set()
        if not cycle.done():
            cycle.cancel()
        await asyncio.wait_for(asyncio.gather(cycle, return_exceptions=True), timeout=1)
    await batch.cancel_and_drain()


@pytest.mark.asyncio
async def test_selection_overflow_and_closed_batch_do_not_dispatch() -> None:
    batch = OwnedTaskBatch[int](maximum_tasks=1)
    selected = 0

    async def select() -> tuple[int, ...]:
        nonlocal selected
        selected += 1
        return (0, 1)

    async def process(value: int) -> int:
        raise AssertionError("rejected batch dispatched work")

    with pytest.raises(ValueError, match="task bound"):
        await batch.run(select, process)
    assert batch.pending_count == 0
    await batch.cancel_and_drain()
    with pytest.raises(TaskBatchUnavailableError):
        await batch.run(select, process)
    assert selected == 1


@pytest.mark.parametrize("timeout_ms", [True, 0, 9, 60_001])
def test_batch_requires_strict_bounded_cancellation_deadline(timeout_ms: int) -> None:
    with pytest.raises(ValueError, match="drain"):
        OwnedTaskBatch[int](maximum_tasks=1, cancellation_drain_ms=timeout_ms)
