from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from gatehouse.watchdog import ProbeResult, RestartPolicy, WatchdogOutcome
from gatehouse.watchdog import main as watchdog_main


def _settings(tmp_path: Path, *, port: int = 48_101) -> watchdog_main.WatchdogRuntimeSettings:
    return watchdog_main.WatchdogRuntimeSettings(
        config_path=tmp_path / "config.yaml",
        database_path=tmp_path / "state" / "gatehouse.db",
        agent_port=port,
        readiness_timeout_seconds=1,
        restart_policy=RestartPolicy(),
    )


def test_runtime_settings_follow_validated_config_and_explicit_overrides(
    tmp_path: Path,
) -> None:
    example = Path(__file__).parents[3] / "config" / "config.example.yaml"
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        example.read_text(encoding="utf-8")
        .replace("port: 47621", "port: 48101")
        .replace("readiness_timeout: 30s", "readiness_timeout: 12s")
        .replace("maximum_restarts: 5", "maximum_restarts: 7")
        .replace(
            r"%LOCALAPPDATA%\Gatehouse\state\gatehouse.db",
            "%LOCALAPPDATA%/custom/gatehouse.db",
        ),
        encoding="utf-8",
    )
    overridden_database = tmp_path / "override.db"

    settings = watchdog_main._load_runtime_settings(
        config_path,
        database_path=overridden_database,
        environment={"LOCALAPPDATA": str(tmp_path / "local"), "APPDATA": str(tmp_path)},
    )

    assert settings.config_path == config_path
    assert settings.database_path == overridden_database
    assert settings.agent_port == 48_101
    assert settings.readiness_timeout_seconds == 12
    assert settings.restart_policy.maximum_restarts == 7


@pytest.mark.asyncio
async def test_probe_reads_status_from_degraded_readiness_response(tmp_path: Path) -> None:
    requested_urls: list[str] = []

    def respond(request: httpx.Request) -> httpx.Response:
        requested_urls.append(str(request.url))
        if request.url.path == "/health/live":
            return httpx.Response(200, json={"status": "live"})
        return httpx.Response(503, json={"status": "failed_closed"})

    result = await watchdog_main._probe(
        _settings(tmp_path),
        transport=httpx.MockTransport(respond),
    )

    assert result == ProbeResult(live=True, ready=False, daemon_state="FAILED_CLOSED")
    assert requested_urls == [
        "http://127.0.0.1:48101/health/live",
        "http://127.0.0.1:48101/health/ready",
    ]


@pytest.mark.asyncio
async def test_restart_uses_installed_entry_point_and_requires_observed_liveness(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daemon_executable = tmp_path / "gatehoused.exe"
    daemon_executable.touch()
    spawned: list[tuple[str, ...]] = []

    class FakeProcess:
        returncode: int | None = None

    async def spawn(arguments: tuple[str, ...]) -> FakeProcess:
        spawned.append(arguments)
        return FakeProcess()

    async def live() -> ProbeResult:
        return ProbeResult(live=True, ready=False, daemon_state="RECOVERING")

    monkeypatch.setattr(watchdog_main, "_spawn_daemon", spawn)
    settings = _settings(tmp_path)

    assert await watchdog_main._restart(
        settings,
        daemon_executable=daemon_executable,
        probe=live,
    )
    assert spawned == [
        (str(daemon_executable), "--config", str(settings.config_path)),
    ]


@pytest.mark.asyncio
async def test_restart_does_not_report_success_for_an_alive_but_unreachable_process(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daemon_executable = tmp_path / "gatehoused.exe"
    daemon_executable.touch()

    class FakeProcess:
        returncode: int | None = None

    async def spawn(_: tuple[str, ...]) -> FakeProcess:
        return FakeProcess()

    async def unreachable() -> ProbeResult:
        return ProbeResult(live=False, ready=False)

    monkeypatch.setattr(watchdog_main, "_spawn_daemon", spawn)
    settings = watchdog_main.WatchdogRuntimeSettings(
        config_path=tmp_path / "config.yaml",
        database_path=tmp_path / "gatehouse.db",
        agent_port=48_101,
        readiness_timeout_seconds=0.001,
        restart_policy=RestartPolicy(),
    )

    assert not await watchdog_main._restart(
        settings,
        daemon_executable=daemon_executable,
        probe=unreachable,
    )


def test_degraded_and_lease_busy_checks_are_successful_task_runs() -> None:
    assert watchdog_main._outcome_exit_code(WatchdogOutcome.HEALTHY) == 0
    assert watchdog_main._outcome_exit_code(WatchdogOutcome.LIVE_DEGRADED) == 0
    assert watchdog_main._outcome_exit_code(WatchdogOutcome.LEASE_BUSY) == 0
    assert watchdog_main._outcome_exit_code(WatchdogOutcome.FAILED_CLOSED) == 1
    assert watchdog_main._outcome_exit_code(WatchdogOutcome.RESTART_FAILED) == 1
