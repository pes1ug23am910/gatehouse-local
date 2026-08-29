from __future__ import annotations

from pathlib import Path

import pytest

from gatehouse.database.migrations import open_migrated_database
from gatehouse.watchdog import (
    ProbeResult,
    RestartPolicy,
    WatchdogController,
    WatchdogOutcome,
)


@pytest.mark.asyncio
async def test_live_degraded_daemon_is_not_restart_looped(tmp_path: Path) -> None:
    connection = open_migrated_database(tmp_path / "watchdog.db")
    restarts = 0

    async def probe() -> ProbeResult:
        return ProbeResult(live=True, ready=False, daemon_state="DEGRADED_NO_PROVIDER")

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
    connection.close()


@pytest.mark.asyncio
async def test_existing_failed_closed_daemon_is_reported_without_restart(tmp_path: Path) -> None:
    connection = open_migrated_database(tmp_path / "watchdog.db")
    restarts = 0

    async def probe() -> ProbeResult:
        return ProbeResult(live=True, ready=False, daemon_state="FAILED_CLOSED")

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
    connection.close()


@pytest.mark.asyncio
async def test_dead_daemon_restarts_once_under_lease(tmp_path: Path) -> None:
    connection = open_migrated_database(tmp_path / "watchdog.db")

    async def probe() -> ProbeResult:
        return ProbeResult(live=False, ready=False)

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
    connection.close()


@pytest.mark.asyncio
async def test_restart_budget_enters_cooldown(tmp_path: Path) -> None:
    connection = open_migrated_database(tmp_path / "watchdog.db")
    calls = 0

    async def probe() -> ProbeResult:
        return ProbeResult(live=False, ready=False)

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
    connection.close()
