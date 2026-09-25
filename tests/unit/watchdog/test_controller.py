from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from pathlib import Path

import pytest

from gatehouse.database.migrations import open_migrated_database
from gatehouse.watchdog import (
    ProbeResult,
    RestartPolicy,
    WatchdogController,
    WatchdogOutcome,
)
from gatehouse.watchdog.controller import ProbeAttestation


@pytest.fixture
def watchdog_database(tmp_path: Path) -> Iterator[sqlite3.Connection]:
    """Real SQLite accounting in fresh scratch; no retained installation or native lease."""

    connection = open_migrated_database(tmp_path / "watchdog.db")
    try:
        yield connection
    finally:
        connection.close()


@pytest.mark.asyncio
async def test_live_degraded_daemon_is_not_restart_looped(
    watchdog_database: sqlite3.Connection,
) -> None:
    connection = watchdog_database
    restarts = 0

    async def probe() -> ProbeResult:
        return ProbeResult(
            live=True,
            ready=False,
            daemon_state="DEGRADED_NO_PROVIDER",
            agent_status_code=200,
            control_status_code=200,
            attestation=ProbeAttestation.MATCHED,
        )

    async def restart() -> bool:
        nonlocal restarts
        restarts += 1
        return True

    outcome = await WatchdogController(
        connection=connection,
        probe=probe,
        restart=restart,
        owner_id="watchdog-1",
    ).run_once(now_ms=1_000)

    assert outcome is WatchdogOutcome.LIVE_DEGRADED
    assert restarts == 0


@pytest.mark.asyncio
async def test_existing_failed_closed_daemon_is_reported_without_restart(
    watchdog_database: sqlite3.Connection,
) -> None:
    connection = watchdog_database
    restarts = 0

    async def probe() -> ProbeResult:
        return ProbeResult(
            live=True,
            ready=False,
            daemon_state="FAILED_CLOSED",
            agent_status_code=200,
            control_status_code=200,
            attestation=ProbeAttestation.MATCHED,
        )

    async def restart() -> bool:
        nonlocal restarts
        restarts += 1
        return True

    outcome = await WatchdogController(
        connection=connection,
        probe=probe,
        restart=restart,
        owner_id="watchdog-1",
    ).run_once(now_ms=1_000)

    assert outcome is WatchdogOutcome.FAILED_CLOSED
    assert restarts == 0


@pytest.mark.asyncio
async def test_dead_daemon_restarts_once_under_lease(
    watchdog_database: sqlite3.Connection,
) -> None:
    connection = watchdog_database

    async def probe() -> ProbeResult:
        return ProbeResult(live=False, ready=False, attestation=ProbeAttestation.NO_RESPONDER)

    async def restart() -> bool:
        return True

    outcome = await WatchdogController(
        connection=connection,
        probe=probe,
        restart=restart,
        owner_id="watchdog-1",
    ).run_once(now_ms=1_000)

    assert outcome is WatchdogOutcome.RESTARTED
    assert (
        connection.execute(
            "SELECT COUNT(*) FROM alerts WHERE category = 'watchdog_restart'"
        ).fetchone()[0]
        == 1
    )


@pytest.mark.asyncio
async def test_restart_budget_enters_cooldown(watchdog_database: sqlite3.Connection) -> None:
    connection = watchdog_database
    calls = 0

    async def probe() -> ProbeResult:
        return ProbeResult(live=False, ready=False, attestation=ProbeAttestation.NO_RESPONDER)

    async def restart() -> bool:
        nonlocal calls
        calls += 1
        return True

    controller = WatchdogController(
        connection=connection,
        probe=probe,
        restart=restart,
        owner_id="watchdog-1",
        policy=RestartPolicy(
            maximum_restarts=2,
            restart_window_ms=10_000,
            crash_loop_cooldown_ms=20_000,
        ),
    )
    assert await controller.run_once(now_ms=1_000) is WatchdogOutcome.RESTARTED
    assert await controller.run_once(now_ms=2_000) is WatchdogOutcome.RESTARTED
    assert await controller.run_once(now_ms=3_000) is WatchdogOutcome.CRASH_LOOP_COOLDOWN
    assert calls == 2
