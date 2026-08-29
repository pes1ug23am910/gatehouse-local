"""Bounded, provider-free scheduled quota reconciliation."""

from __future__ import annotations

import asyncio
import math
import threading
import time
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path

from gatehouse.core.clock import SYSTEM_UTC_CLOCK, UtcMsClock
from gatehouse.database import (
    DEFAULT_BUSY_TIMEOUT_MS,
    open_compatible_database,
)

from .models import ReconciliationMode, ReconciliationPolicy
from .store import ReconciliationStore

_MAXIMUM_SCOPES_PER_BATCH = 1_000
_MAXIMUM_BATCH_WALL_DURATION_MS = 60_000
_MAXIMUM_POLL_INTERVAL_MS = 24 * 60 * 60 * 1_000


@dataclass(frozen=True, slots=True)
class ReconciliationBatchReport:
    """Non-sensitive accounting for one bounded local database batch."""

    processed_scopes: int
    quick_scopes: int
    full_scopes: int
    scope_limit_reached: bool
    wall_limit_reached: bool
    cancellation_requested: bool


def _validate_batch_bounds(
    *,
    maximum_scopes: int,
    maximum_wall_duration_ms: int,
    busy_timeout_ms: int,
) -> None:
    if (
        isinstance(maximum_scopes, bool)
        or not isinstance(maximum_scopes, int)
        or not 1 <= maximum_scopes <= _MAXIMUM_SCOPES_PER_BATCH
    ):
        raise ValueError("reconciliation scope bound is invalid")
    if (
        isinstance(maximum_wall_duration_ms, bool)
        or not isinstance(maximum_wall_duration_ms, int)
        or not 1 <= maximum_wall_duration_ms <= _MAXIMUM_BATCH_WALL_DURATION_MS
    ):
        raise ValueError("reconciliation wall-duration bound is invalid")
    if (
        isinstance(busy_timeout_ms, bool)
        or not isinstance(busy_timeout_ms, int)
        or not 0 <= busy_timeout_ms <= DEFAULT_BUSY_TIMEOUT_MS
    ):
        raise ValueError("reconciliation busy timeout is invalid")


def _monotonic_value(monotonic: Callable[[], float]) -> float:
    value = monotonic()
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise RuntimeError("reconciliation monotonic clock is invalid")
    normalized = float(value)
    if not math.isfinite(normalized) or normalized < 0:
        raise RuntimeError("reconciliation monotonic clock is invalid")
    return normalized


def run_scheduled_reconciliation_batch(
    database_path: str | Path,
    *,
    policy: ReconciliationPolicy,
    now_ms: int,
    quick_interval_ms: int,
    full_interval_ms: int,
    maximum_scopes: int,
    maximum_wall_duration_ms: int,
    busy_timeout_ms: int = DEFAULT_BUSY_TIMEOUT_MS,
    monotonic: Callable[[], float] = time.monotonic,
    cancellation_event: threading.Event | None = None,
) -> ReconciliationBatchReport:
    """Use one worker-owned connection for a bounded series of scope transactions."""

    _validate_batch_bounds(
        maximum_scopes=maximum_scopes,
        maximum_wall_duration_ms=maximum_wall_duration_ms,
        busy_timeout_ms=busy_timeout_ms,
    )
    ReconciliationStore._validate_schedule_inputs(
        now_ms=now_ms,
        quick_interval_ms=quick_interval_ms,
        full_interval_ms=full_interval_ms,
    )
    started = _monotonic_value(monotonic)
    processed = 0
    quick = 0
    full = 0
    wall_limit_reached = False
    cancellation_requested = False
    connection = open_compatible_database(
        database_path,
        busy_timeout_ms=busy_timeout_ms,
    )
    try:
        store = ReconciliationStore(connection)
        while processed < maximum_scopes:
            if cancellation_event is not None and cancellation_event.is_set():
                cancellation_requested = True
                break
            elapsed_ms = (_monotonic_value(monotonic) - started) * 1_000
            if elapsed_ms >= maximum_wall_duration_ms:
                wall_limit_reached = True
                break
            outcome = store.reconcile_next_due_scope(
                policy=policy,
                now_ms=now_ms,
                quick_interval_ms=quick_interval_ms,
                full_interval_ms=full_interval_ms,
            )
            if outcome is None:
                break
            processed += 1
            if outcome.mode is ReconciliationMode.QUICK:
                quick += 1
            elif outcome.mode is ReconciliationMode.FULL:
                full += 1
            else:  # pragma: no cover - store contract
                raise RuntimeError("scheduled reconciliation returned a manual result")
    finally:
        connection.close()
    return ReconciliationBatchReport(
        processed_scopes=processed,
        quick_scopes=quick,
        full_scopes=full,
        scope_limit_reached=processed == maximum_scopes,
        wall_limit_reached=wall_limit_reached,
        cancellation_requested=cancellation_requested,
    )


async def await_scheduled_reconciliation_batch(
    database_path: str | Path,
    *,
    policy: ReconciliationPolicy,
    now_ms: int,
    quick_interval_ms: int,
    full_interval_ms: int,
    maximum_scopes: int,
    maximum_wall_duration_ms: int,
    busy_timeout_ms: int,
    monotonic: Callable[[], float],
    stop_event: asyncio.Event | None = None,
) -> ReconciliationBatchReport:
    cancellation_event = threading.Event()
    worker = asyncio.create_task(
        asyncio.to_thread(
            run_scheduled_reconciliation_batch,
            database_path,
            policy=policy,
            now_ms=now_ms,
            quick_interval_ms=quick_interval_ms,
            full_interval_ms=full_interval_ms,
            maximum_scopes=maximum_scopes,
            maximum_wall_duration_ms=maximum_wall_duration_ms,
            busy_timeout_ms=busy_timeout_ms,
            monotonic=monotonic,
            cancellation_event=cancellation_event,
        ),
        name="gatehouse-reconciliation-worker",
    )
    stop_waiter: asyncio.Task[bool] | None = None
    try:
        if stop_event is not None:
            stop_waiter = asyncio.create_task(
                stop_event.wait(),
                name="gatehouse-reconciliation-stop-waiter",
            )
            await asyncio.wait(
                (worker, stop_waiter),
                return_when=asyncio.FIRST_COMPLETED,
            )
            if stop_event.is_set() and not worker.done():
                cancellation_event.set()
        return await asyncio.shield(worker)
    except asyncio.CancelledError:
        cancellation_event.set()
        # SQLite busy waits cannot be interrupted from the event-loop thread.
        # Join the bounded worker so its connection is never orphaned.
        while not worker.done():
            with suppress(asyncio.CancelledError):
                await asyncio.shield(worker)
        with suppress(BaseException):
            worker.result()
        raise
    finally:
        if stop_waiter is not None and not stop_waiter.done():
            stop_waiter.cancel()
            with suppress(asyncio.CancelledError):
                await stop_waiter


async def run_scheduled_reconciliation_until_shutdown(
    database_path: str | Path,
    shutdown_event: asyncio.Event,
    *,
    policy: ReconciliationPolicy,
    quick_interval_ms: int,
    full_interval_ms: int,
    maximum_scopes: int,
    maximum_wall_duration_ms: int,
    poll_interval_ms: int = 60_000,
    busy_timeout_ms: int = DEFAULT_BUSY_TIMEOUT_MS,
    clock: UtcMsClock = SYSTEM_UTC_CLOCK,
    monotonic: Callable[[], float] = time.monotonic,
) -> None:
    """Run immediate and periodic bounded batches until daemon shutdown."""

    _validate_batch_bounds(
        maximum_scopes=maximum_scopes,
        maximum_wall_duration_ms=maximum_wall_duration_ms,
        busy_timeout_ms=busy_timeout_ms,
    )
    if (
        isinstance(poll_interval_ms, bool)
        or not isinstance(poll_interval_ms, int)
        or not 10 <= poll_interval_ms <= _MAXIMUM_POLL_INTERVAL_MS
    ):
        raise ValueError("reconciliation poll interval is invalid")
    ReconciliationStore._validate_schedule_inputs(
        now_ms=clock.now_ms(),
        quick_interval_ms=quick_interval_ms,
        full_interval_ms=full_interval_ms,
    )
    resolved_database_path = Path(database_path)
    while not shutdown_event.is_set():
        await await_scheduled_reconciliation_batch(
            resolved_database_path,
            policy=policy,
            now_ms=clock.now_ms(),
            quick_interval_ms=quick_interval_ms,
            full_interval_ms=full_interval_ms,
            maximum_scopes=maximum_scopes,
            maximum_wall_duration_ms=maximum_wall_duration_ms,
            busy_timeout_ms=busy_timeout_ms,
            monotonic=monotonic,
            stop_event=shutdown_event,
        )
        if shutdown_event.is_set():
            break
        try:
            await asyncio.wait_for(
                shutdown_event.wait(),
                timeout=poll_interval_ms / 1_000,
            )
        except TimeoutError:
            continue
