from __future__ import annotations

import os
from pathlib import Path

import httpx
import pytest

from gatehouse.database import MIGRATIONS, MigrationDriftError, apply_migrations, connect_database
from gatehouse.state_security import StateDirectorySecurityError
from gatehouse.watchdog import ProbeResult, RestartPolicy, WatchdogOutcome
from gatehouse.watchdog import main as watchdog_main


class _FakeProcess:
    def __init__(self, *, returncode: int | None = None) -> None:
        self.returncode = returncode
        self.terminate_calls = 0
        self.kill_calls = 0

    def terminate(self) -> None:
        self.terminate_calls += 1
        self.returncode = -15

    def kill(self) -> None:
        self.kill_calls += 1
        self.returncode = -9

    async def wait(self) -> int:
        assert self.returncode is not None
        return self.returncode


def _settings(
    tmp_path: Path,
    *,
    port: int = 48_101,
    timeout_seconds: float = 1,
    allow_provider_disabled_state: bool = False,
) -> watchdog_main.WatchdogRuntimeSettings:
    return watchdog_main.WatchdogRuntimeSettings(
        config_path=tmp_path / "config.yaml",
        database_path=tmp_path / "state" / "gatehouse.db",
        agent_port=port,
        readiness_timeout_seconds=timeout_seconds,
        restart_policy=RestartPolicy(),
        allow_provider_disabled_state=allow_provider_disabled_state,
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
    assert settings.allow_provider_disabled_state


def test_runtime_settings_reject_unsafe_database_override_before_resolution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    example = Path(__file__).parents[3] / "config" / "config.example.yaml"
    config_path = tmp_path / "config.yaml"
    config_path.write_text(example.read_text(encoding="utf-8"), encoding="utf-8")
    override = tmp_path / "remote-shaped" / "gatehouse.db"
    observed: list[Path] = []

    def reject_override(path: str | Path) -> Path:
        observed.append(Path(path))
        raise StateDirectorySecurityError("synthetic remote drive")

    monkeypatch.setattr(watchdog_main, "validate_state_path_ancestry", reject_override)

    with pytest.raises(ValueError, match="^watchdog database path is unsafe$"):
        watchdog_main._load_runtime_settings(
            config_path,
            database_path=override,
            environment={"LOCALAPPDATA": str(tmp_path / "local"), "APPDATA": str(tmp_path)},
        )

    assert observed == [override]
    assert not override.parent.exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows path rooting is Windows-specific")
@pytest.mark.parametrize(
    "override",
    (
        Path(r"C:state\gatehouse.db"),
        Path(r"\state\gatehouse.db"),
    ),
)
def test_runtime_settings_reject_drive_or_root_relative_database_override(
    tmp_path: Path,
    override: Path,
) -> None:
    example = Path(__file__).parents[3] / "config" / "config.example.yaml"
    config_path = tmp_path / "config.yaml"
    config_path.write_text(example.read_text(encoding="utf-8"), encoding="utf-8")

    with pytest.raises(ValueError, match="^watchdog database path is unsafe$") as captured:
        watchdog_main._load_runtime_settings(
            config_path,
            database_path=override,
            environment={"LOCALAPPDATA": str(tmp_path / "local"), "APPDATA": str(tmp_path)},
        )

    assert str(override) not in str(captured.value)


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

    assert result == ProbeResult(
        live=True,
        ready=False,
        daemon_state="FAILED_CLOSED",
        readiness_status_code=503,
        readiness_contract_valid=True,
    )
    assert requested_urls == [
        "http://127.0.0.1:48101/health/live",
        "http://127.0.0.1:48101/health/ready",
    ]


@pytest.mark.asyncio
async def test_probe_rejects_http_200_when_readiness_state_is_not_ready(tmp_path: Path) -> None:
    def respond(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/health/live":
            return httpx.Response(200, json={"status": "live"})
        return httpx.Response(200, json={"status": "degraded_no_provider"})

    result = await watchdog_main._probe(
        _settings(tmp_path),
        transport=httpx.MockTransport(respond),
    )

    assert result == ProbeResult(
        live=True,
        ready=False,
        daemon_state="DEGRADED_NO_PROVIDER",
        detail="readiness_status_mismatch",
        readiness_status_code=200,
        readiness_contract_valid=False,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "readiness_body",
    (b"[]", b"null", b'"READY"', b"\xff"),
    ids=("array", "null", "string", "invalid-utf8"),
)
async def test_probe_rejects_non_object_or_undecodable_readiness_bodies(
    tmp_path: Path,
    readiness_body: bytes,
) -> None:
    def respond(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/health/live":
            return httpx.Response(200, json={"status": "live"})
        return httpx.Response(
            503,
            content=readiness_body,
            headers={"content-type": "application/json"},
        )

    result = await watchdog_main._probe(
        _settings(tmp_path),
        transport=httpx.MockTransport(respond),
    )

    assert result == ProbeResult(
        live=True,
        ready=False,
        detail="readiness_state_unavailable",
        readiness_status_code=503,
        readiness_contract_valid=False,
    )


@pytest.mark.asyncio
async def test_probe_preserves_liveness_when_readiness_transport_fails(tmp_path: Path) -> None:
    def respond(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/health/live":
            return httpx.Response(200, json={"status": "live"})
        raise httpx.ConnectError("readiness endpoint disconnected", request=request)

    result = await watchdog_main._probe(
        _settings(tmp_path),
        transport=httpx.MockTransport(respond),
    )

    assert result == ProbeResult(
        live=True,
        ready=False,
        detail="readiness_connection_failed",
    )


@pytest.mark.asyncio
async def test_restart_uses_installed_entry_point_and_requires_explicit_readiness(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daemon_executable = tmp_path / "gatehoused.exe"
    daemon_executable.touch()
    spawned: list[tuple[str, ...]] = []
    process = _FakeProcess()

    async def spawn(arguments: tuple[str, ...]) -> _FakeProcess:
        spawned.append(arguments)
        return process

    async def ready() -> ProbeResult:
        return ProbeResult(
            live=True,
            ready=True,
            daemon_state="READY",
            readiness_status_code=200,
            readiness_contract_valid=True,
        )

    monkeypatch.setattr(watchdog_main, "_spawn_daemon", spawn)
    settings = _settings(tmp_path)

    assert await watchdog_main._restart(
        settings,
        daemon_executable=daemon_executable,
        probe=ready,
    )
    assert spawned == [
        (str(daemon_executable), "--config", str(settings.config_path)),
    ]
    assert process.terminate_calls == 0


@pytest.mark.asyncio
async def test_restart_accepts_disabled_provider_state_only_when_configured(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daemon_executable = tmp_path / "gatehoused.exe"
    daemon_executable.touch()
    accepted_process = _FakeProcess()

    async def spawn(_: tuple[str, ...]) -> _FakeProcess:
        return accepted_process

    async def disabled() -> ProbeResult:
        return ProbeResult(
            live=True,
            ready=False,
            daemon_state="DEGRADED_NO_PROVIDER",
            readiness_status_code=503,
            readiness_contract_valid=True,
        )

    monkeypatch.setattr(watchdog_main, "_spawn_daemon", spawn)

    assert await watchdog_main._restart(
        _settings(tmp_path, allow_provider_disabled_state=True),
        daemon_executable=daemon_executable,
        probe=disabled,
    )
    assert accepted_process.terminate_calls == 0

    rejected_process = _FakeProcess()

    async def respawn(_: tuple[str, ...]) -> _FakeProcess:
        return rejected_process

    monkeypatch.setattr(watchdog_main, "_spawn_daemon", respawn)
    assert not await watchdog_main._restart(
        _settings(tmp_path, timeout_seconds=0.001),
        daemon_executable=daemon_executable,
        probe=disabled,
    )
    assert rejected_process.terminate_calls == 1

    mismatched_process = _FakeProcess()

    async def respawn_mismatched(_: tuple[str, ...]) -> _FakeProcess:
        return mismatched_process

    async def mismatched_disabled() -> ProbeResult:
        return ProbeResult(
            live=True,
            ready=False,
            daemon_state="DEGRADED_NO_PROVIDER",
            detail="readiness_status_mismatch",
            readiness_status_code=200,
            readiness_contract_valid=False,
        )

    monkeypatch.setattr(watchdog_main, "_spawn_daemon", respawn_mismatched)
    assert not await watchdog_main._restart(
        _settings(
            tmp_path,
            timeout_seconds=0.001,
            allow_provider_disabled_state=True,
        ),
        daemon_executable=daemon_executable,
        probe=mismatched_disabled,
    )
    assert mismatched_process.terminate_calls == 1


@pytest.mark.asyncio
async def test_restart_rejects_ready_flag_with_mismatched_daemon_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daemon_executable = tmp_path / "gatehoused.exe"
    daemon_executable.touch()
    process = _FakeProcess()

    async def spawn(_: tuple[str, ...]) -> _FakeProcess:
        return process

    async def mismatched() -> ProbeResult:
        return ProbeResult(live=True, ready=True, daemon_state="STARTING")

    monkeypatch.setattr(watchdog_main, "_spawn_daemon", spawn)
    assert not await watchdog_main._restart(
        _settings(tmp_path, timeout_seconds=0.001),
        daemon_executable=daemon_executable,
        probe=mismatched,
    )
    assert process.terminate_calls == 1


@pytest.mark.asyncio
async def test_restart_terminates_owned_failed_closed_child(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daemon_executable = tmp_path / "gatehoused.exe"
    daemon_executable.touch()
    process = _FakeProcess()

    async def spawn(_: tuple[str, ...]) -> _FakeProcess:
        return process

    async def failed_closed() -> ProbeResult:
        return ProbeResult(live=True, ready=False, daemon_state="FAILED_CLOSED")

    monkeypatch.setattr(watchdog_main, "_spawn_daemon", spawn)

    assert not await watchdog_main._restart(
        _settings(tmp_path),
        daemon_executable=daemon_executable,
        probe=failed_closed,
    )
    assert process.terminate_calls == 1
    assert process.kill_calls == 0


@pytest.mark.asyncio
async def test_restart_does_not_accept_readiness_from_an_exited_child(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daemon_executable = tmp_path / "gatehoused.exe"
    daemon_executable.touch()
    process = _FakeProcess()

    async def spawn(_: tuple[str, ...]) -> _FakeProcess:
        return process

    async def ready_after_exit() -> ProbeResult:
        process.returncode = 1
        return ProbeResult(
            live=True,
            ready=True,
            daemon_state="READY",
            readiness_status_code=200,
            readiness_contract_valid=True,
        )

    monkeypatch.setattr(watchdog_main, "_spawn_daemon", spawn)

    assert not await watchdog_main._restart(
        _settings(tmp_path),
        daemon_executable=daemon_executable,
        probe=ready_after_exit,
    )
    assert process.terminate_calls == 0


@pytest.mark.asyncio
async def test_restart_does_not_report_success_for_an_alive_but_unreachable_process(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daemon_executable = tmp_path / "gatehoused.exe"
    daemon_executable.touch()
    process = _FakeProcess()

    async def spawn(_: tuple[str, ...]) -> _FakeProcess:
        return process

    async def unreachable() -> ProbeResult:
        return ProbeResult(live=False, ready=False)

    monkeypatch.setattr(watchdog_main, "_spawn_daemon", spawn)
    settings = _settings(tmp_path, timeout_seconds=0.001)

    assert not await watchdog_main._restart(
        settings,
        daemon_executable=daemon_executable,
        probe=unreachable,
    )
    assert process.terminate_calls == 1
    assert process.kill_calls == 0


@pytest.mark.asyncio
async def test_watchdog_run_rejects_old_schema_without_migrating(
    tmp_path: Path,
) -> None:
    settings = _settings(tmp_path)
    settings.database_path.parent.mkdir(parents=True)
    connection = connect_database(settings.database_path)
    try:
        assert apply_migrations(connection, migrations=MIGRATIONS[:-1]) == 13
    finally:
        connection.close()

    with pytest.raises(MigrationDriftError):
        await watchdog_main._run(settings)

    inspected = connect_database(settings.database_path)
    try:
        assert inspected.execute("PRAGMA user_version").fetchone()[0] == 13
        assert inspected.execute("SELECT COUNT(*) FROM schema_migrations").fetchone()[0] == 13
    finally:
        inspected.close()


@pytest.mark.asyncio
async def test_watchdog_acl_failure_precedes_database_open_and_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _settings(tmp_path)
    settings.database_path.parent.mkdir(parents=True)
    original = b"synthetic database bytes"
    settings.database_path.write_bytes(original)
    open_calls = 0

    def reject_permissions(path: Path, *, must_exist: bool = False) -> Path:
        assert path == settings.database_path
        assert must_exist
        raise StateDirectorySecurityError("synthetic unsafe state root")

    def forbidden_open(*_args: object, **_kwargs: object) -> None:
        nonlocal open_calls
        open_calls += 1

    monkeypatch.setattr(watchdog_main, "secure_database_state", reject_permissions)
    monkeypatch.setattr(watchdog_main, "open_compatible_database", forbidden_open)

    with pytest.raises(StateDirectorySecurityError, match="unsafe state root"):
        await watchdog_main._run(settings)

    assert open_calls == 0
    assert settings.database_path.read_bytes() == original


def test_degraded_and_lease_busy_checks_are_successful_task_runs() -> None:
    assert watchdog_main._outcome_exit_code(WatchdogOutcome.HEALTHY) == 0
    assert watchdog_main._outcome_exit_code(WatchdogOutcome.LIVE_DEGRADED) == 0
    assert watchdog_main._outcome_exit_code(WatchdogOutcome.LEASE_BUSY) == 0
    assert watchdog_main._outcome_exit_code(WatchdogOutcome.FAILED_CLOSED) == 1
    assert watchdog_main._outcome_exit_code(WatchdogOutcome.RESTART_FAILED) == 1


def test_watchdog_entrypoint_hardens_streams_before_running(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _settings(tmp_path)
    observed: list[str] = []

    def ensure_streams() -> None:
        observed.append("streams")

    def load_settings(*_: object, **__: object) -> watchdog_main.WatchdogRuntimeSettings:
        observed.append("settings")
        return settings

    async def run(_: watchdog_main.WatchdogRuntimeSettings) -> WatchdogOutcome:
        observed.append("run")
        return WatchdogOutcome.HEALTHY

    monkeypatch.setattr(watchdog_main, "ensure_standard_streams", ensure_streams)
    monkeypatch.setattr(watchdog_main, "_load_runtime_settings", load_settings)
    monkeypatch.setattr(watchdog_main, "_run", run)

    with pytest.raises(SystemExit) as raised:
        watchdog_main.main(
            ["--config", str(settings.config_path)],
            environment={"APPDATA": str(tmp_path)},
        )

    assert raised.value.code == 0
    assert observed == ["streams", "settings", "run"]
