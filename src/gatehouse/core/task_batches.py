"""Fail-fast child ownership with bounded, cancellation-resistant draining."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Sequence


class TaskBatchUnavailableError(RuntimeError):
    """A batch is already active, closed, or fenced by a failed drain."""


class TaskBatchDrainError(RuntimeError):
    """Owned children remain live; their resources must remain owned as well."""

    def __init__(self, pending_count: int) -> None:
        super().__init__("owned task batch did not drain")
        self.pending_count = pending_count


class OwnedTaskBatch[ResultT]:
    """Own every selected child until completion, including after a drain timeout.

    This is cooperative containment: cancellation-resistant children cannot be
    killed here. A failed drain permanently fences new batches and exposes the
    remaining ownership to the resource lifecycle.
    """

    def __init__(self, *, maximum_tasks: int, cancellation_drain_ms: int = 5_000) -> None:
        if (
            isinstance(maximum_tasks, bool)
            or not isinstance(maximum_tasks, int)
            or not 1 <= maximum_tasks <= 1_000
        ):
            raise ValueError("batch task bound is invalid")
        if (
            isinstance(cancellation_drain_ms, bool)
            or not isinstance(cancellation_drain_ms, int)
            or not 10 <= cancellation_drain_ms <= 60_000
        ):
            raise ValueError("batch cancellation drain is outside its bound")
        self._maximum_tasks = maximum_tasks
        self._cancellation_drain_ms = cancellation_drain_ms
        self._tasks: set[asyncio.Task[ResultT]] = set()
        self._cancel_requested: set[asyncio.Task[ResultT]] = set()
        self._running = False
        self._closed = False
        self._aborting = False
        self._drain_failed = False
        self._failure: BaseException | None = None

    @property
    def pending_count(self) -> int:
        return sum(not task.done() for task in self._tasks)

    @property
    def drain_failed(self) -> bool:
        return self._drain_failed

    async def run[ItemT](
        self,
        select: Callable[[], Awaitable[Sequence[ItemT]]],
        operation: Callable[[ItemT], Awaitable[ResultT]],
    ) -> tuple[ResultT, ...]:
        """Select once, then finish or cancel and drain the entire bounded batch."""

        if self._running or self._closed or self._drain_failed or self.pending_count:
            raise TaskBatchUnavailableError("task batch is unavailable")
        self._running = True
        self._aborting = False
        self._failure = None
        tasks: list[asyncio.Task[ResultT]] = []

        async def invoke(item: ItemT) -> ResultT:
            try:
                if self._aborting:
                    raise asyncio.CancelledError
                return await operation(item)
            except BaseException as error:
                if self._running and self._failure is None:
                    self._failure = error
                self._cancel_pending()
                raise

        try:
            items = await select()
            if self._closed:
                raise TaskBatchUnavailableError("task batch is closed")
            if len(items) > self._maximum_tasks:
                raise ValueError("selection exceeds the batch task bound")
            for item in items:
                child = invoke(item)
                try:
                    task = asyncio.create_task(child, name="gatehouse-owned-batch-child")
                except BaseException:
                    child.close()
                    raise
                tasks.append(task)
                self._tasks.add(task)
                task.add_done_callback(self._completed)
            pending = set(tasks)
            while pending:
                done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
                if self._failure is not None:
                    raise self._failure
                for task in done:
                    task.result()
            return tuple(task.result() for task in tasks)
        except BaseException:
            self._cancel_pending()
            await self._drain(self._cancellation_drain_ms)
            raise
        finally:
            self._running = False
            self._failure = None

    async def cancel_and_drain(self, *, timeout_ms: int | None = None) -> None:
        """Close admission and drain children; active cycle callers must be joined.

        A caller that has not yet joined run() receives an explicit failure even
        if its selected children have drained. Resource closure is then unsafe.
        """

        budget_ms = self._cancellation_drain_ms
        if timeout_ms is not None:
            if (
                isinstance(timeout_ms, bool)
                or not isinstance(timeout_ms, int)
                or not 0 <= timeout_ms <= 60_000
            ):
                raise ValueError("batch cancellation drain is outside its bound")
            budget_ms = min(budget_ms, timeout_ms)
        self._closed = True
        self._cancel_pending()
        await self._drain(budget_ms)
        if self._running:
            raise TaskBatchUnavailableError("task batch cycle is still active")

    def _cancel_pending(self) -> None:
        self._aborting = True
        current = asyncio.current_task()
        for task in self._tasks:
            if task is not current and not task.done() and task not in self._cancel_requested:
                self._cancel_requested.add(task)
                if not task.cancelling():
                    task.cancel()

    async def _drain(self, timeout_ms: int) -> None:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout_ms / 1_000
        interrupted = False
        while pending := {task for task in self._tasks if not task.done()}:
            remaining = deadline - loop.time()
            if remaining <= 0:
                self._drain_failed = True
                raise TaskBatchDrainError(len(pending)) from None
            try:
                await asyncio.wait(pending, timeout=remaining)
            except asyncio.CancelledError:
                # Repeated caller cancellation cannot cancel child cleanup or
                # restart the monotonic deadline.
                interrupted = True
        if interrupted:
            raise asyncio.CancelledError

    def _completed(self, task: asyncio.Task[ResultT]) -> None:
        self._tasks.discard(task)
        self._cancel_requested.discard(task)
        if not task.cancelled():
            task.exception()
