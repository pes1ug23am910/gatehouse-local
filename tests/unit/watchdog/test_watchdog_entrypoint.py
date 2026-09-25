from __future__ import annotations

import asyncio
import hashlib
import json
import os
from collections.abc import AsyncIterator, Callable, Coroutine, Mapping
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

from gatehouse.admin.control import CONTROL_CAPABILITY_HEADER
from gatehouse.config import loader as config_loader
from gatehouse.config.loader import parse_main_config
from gatehouse.config.security import ConfigurationDocument, ConfigurationSnapshot, FileIdentity
from gatehouse.daemon.configuration import (
    RuntimeConfiguration,
    require_configuration_snapshot_digest,
)
from gatehouse.database import MIGRATIONS, MigrationDriftError, apply_migrations, connect_database
from gatehouse.state_security import StateDirectorySecurityError
from gatehouse.watchdog import ProbeResult, RestartPolicy, WatchdogOutcome
from gatehouse.watchdog import main as watchdog_main
from gatehouse.watchdog.controller import ProbeAttestation

SYNTHETIC_CAPABILITY = "a" * 43


@pytest.fixture
def adjacent_daemon_interpreter(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        watchdog_main,
        "sys",
        SimpleNamespace(executable=str(tmp_path / "pythonw.exe")),
    )


@pytest.fixture
def watchdog_probe_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Callable[[Path], str]:
    """Derive only this test's synthetic path; never resolve or load native authority."""

    capability_path = tmp_path / "state" / "control-capability.dpapi"

    def paths(database_path: str | Path) -> SimpleNamespace:
        assert Path(database_path) == tmp_path / "state" / "gatehouse.db"
        return SimpleNamespace(control_capability=capability_path)

    def load(path: Path) -> str:
        assert path == capability_path
        return SYNTHETIC_CAPABILITY

    monkeypatch.setattr(watchdog_main, "installation_state_paths", paths)
    return load


def _assert_probe_authority(request: httpx.Request) -> None:
    assert request.method == "GET" and request.url.host == "127.0.0.1"
    if request.url.path == "/health/live":
        assert request.url.port == 48_101
        assert request.headers.get_list(CONTROL_CAPABILITY_HEADER) == []
    else:
        assert request.url.path == "/v1/control/status" and request.url.port == 48_102
        assert request.headers.get_list(CONTROL_CAPABILITY_HEADER) == [SYNTHETIC_CAPABILITY]


def _control_status(state: str, *, ready: bool = False) -> dict[str, object]:
    return {
        "ready": ready,
        "status": state,
        "version": "synthetic",
        "schema_version": 16,
        "policy_version": "synthetic",
        "uptime_seconds": 0,
        "degraded_components": [],
        "config_digest": "a" * 64,
    }


class _SyntheticProbeStream(httpx.AsyncByteStream):
    def __init__(self, body: bytes) -> None:
        assert len(body) <= 65_536
        self._body = body

    async def __aiter__(self) -> AsyncIterator[bytes]:
        yield self._body


def _probe_response(status: int, body: dict[str, object] | bytes) -> httpx.Response:
    raw = body if isinstance(body, bytes) else json.dumps(body, allow_nan=False).encode("utf-8")
    return httpx.Response(
        status,
        stream=_SyntheticProbeStream(raw),
        headers={"content-type": "application/json", "content-length": str(len(raw))},
    )


def _test_digest(path: Path, environment: Mapping[str, str]) -> str:
    return hashlib.sha256(
        path.read_bytes() + repr(tuple(sorted(environment.items()))).encode()
    ).hexdigest()


@pytest.fixture
def watchdog_configuration_snapshot(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Fake snapshot and ancestry trust for fresh test bytes, without native proof."""

    def fresh_ancestry(path: str | Path) -> Path:
        candidate = Path(path)
        assert candidate.is_absolute() and ".." not in candidate.parts
        assert candidate.is_relative_to(tmp_path)
        return candidate

    def capture(
        path: str | Path,
        *,
        environment: Mapping[str, str],
        expected_config_digest: str,
    ) -> RuntimeConfiguration:
        origin = Path(path)
        assert origin == tmp_path / "config.yaml"
        raw = origin.read_bytes()
        bindings = tuple(sorted(environment.items()))
        document = ConfigurationDocument(
            origin.name,
            raw,
            FileIdentity(1, 1),
            hashlib.sha256(raw).hexdigest(),
        )
        snapshot = ConfigurationSnapshot(
            origin,
            origin.name,
            (document,),
            hashlib.sha256(raw + repr(bindings).encode()).hexdigest(),
            bindings,
        )
        require_configuration_snapshot_digest(snapshot, expected_config_digest)
        return RuntimeConfiguration(
            parse_main_config(raw, config_path=origin, environment=environment),
            (),
            (),
            (),
            snapshot,
        )

    monkeypatch.setattr(config_loader, "validate_state_path_ancestry", fresh_ancestry)
    monkeypatch.setattr(watchdog_main, "load_runtime_configuration", capture)


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
        admin_port=port + 1,
        readiness_timeout_seconds=timeout_seconds,
        restart_policy=RestartPolicy(),
        expected_config_digest="a" * 64,
        environment={},
        allow_provider_disabled_state=allow_provider_disabled_state,
    )


@pytest.mark.usefixtures("watchdog_configuration_snapshot")
def test_runtime_settings_follow_verified_config_and_equal_override_assertions(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    example = Path(__file__).parents[3] / "config" / "config.example.yaml"
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        example.read_text(encoding="utf-8")
        .replace("port: 47621", "port: 48101")
        .replace("port: 47622", "port: 48102")
        .replace("readiness_timeout: 30s", "readiness_timeout: 12s")
        .replace("maximum_restarts: 5", "maximum_restarts: 7")
        .replace(
            r"%LOCALAPPDATA%\Gatehouse\state\gatehouse.db",
            "%LOCALAPPDATA%/custom/gatehouse.db",
        ),
        encoding="utf-8",
    )
    overridden_database = tmp_path / "local" / "custom" / "gatehouse.db"
    environment = {"LOCALAPPDATA": str(tmp_path / "local"), "APPDATA": str(tmp_path)}

    def fresh_override_ancestry(path: str | Path) -> Path:
        candidate = Path(path)
        assert candidate == overridden_database
        assert candidate.is_relative_to(tmp_path)
        return candidate

    monkeypatch.setattr(watchdog_main, "validate_state_path_ancestry", fresh_override_ancestry)

    settings = watchdog_main._load_runtime_settings(
        config_path,
        expected_config_digest=_test_digest(config_path, environment),
        database_path=overridden_database,
        agent_port=48_101,
        environment=environment,
    )

    assert settings.config_path == config_path
    assert settings.database_path == overridden_database
    assert settings.agent_port == 48_101
    assert settings.admin_port == 48_102
    assert settings.readiness_timeout_seconds == 12
    assert settings.restart_policy.maximum_restarts == 7
    assert settings.allow_provider_disabled_state


@pytest.mark.usefixtures("watchdog_configuration_snapshot")
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
    environment = {"LOCALAPPDATA": str(tmp_path / "local"), "APPDATA": str(tmp_path)}

    with pytest.raises(ValueError, match="^watchdog database path is unsafe$"):
        watchdog_main._load_runtime_settings(
            config_path,
            expected_config_digest=_test_digest(config_path, environment),
            database_path=override,
            environment=environment,
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
@pytest.mark.usefixtures("watchdog_configuration_snapshot")
def test_runtime_settings_reject_drive_or_root_relative_database_override(
    tmp_path: Path,
    override: Path,
) -> None:
    example = Path(__file__).parents[3] / "config" / "config.example.yaml"
    config_path = tmp_path / "config.yaml"
    config_path.write_text(example.read_text(encoding="utf-8"), encoding="utf-8")
    environment = {"LOCALAPPDATA": str(tmp_path / "local"), "APPDATA": str(tmp_path)}

    with pytest.raises(ValueError, match="^watchdog database path is unsafe$") as captured:
        watchdog_main._load_runtime_settings(
            config_path,
            expected_config_digest=_test_digest(config_path, environment),
            database_path=override,
            environment=environment,
        )

    assert str(override) not in str(captured.value)


@pytest.mark.asyncio
async def test_probe_reads_status_from_authenticated_failed_closed_response(
    tmp_path: Path,
    watchdog_probe_authority: Callable[[Path], str],
) -> None:
    requested_urls: list[str] = []

    def respond(request: httpx.Request) -> httpx.Response:
        _assert_probe_authority(request)
        requested_urls.append(str(request.url))
        if request.url.path == "/health/live":
            return _probe_response(200, {"status": "live"})
        return _probe_response(200, _control_status("FAILED_CLOSED"))

    result = await watchdog_main._probe(
        _settings(tmp_path),
        transport=httpx.MockTransport(respond),
        capability_loader=watchdog_probe_authority,
    )

    assert result == ProbeResult(
        live=True,
        ready=False,
        daemon_state="FAILED_CLOSED",
        agent_status_code=200,
        control_status_code=200,
        attestation=ProbeAttestation.MATCHED,
    )
    assert requested_urls == [
        "http://127.0.0.1:48101/health/live",
        "http://127.0.0.1:48102/v1/control/status",
    ]


@pytest.mark.asyncio
async def test_probe_rejects_incoherent_authenticated_ready_flag(
    tmp_path: Path,
    watchdog_probe_authority: Callable[[Path], str],
) -> None:
    def respond(request: httpx.Request) -> httpx.Response:
        _assert_probe_authority(request)
        if request.url.path == "/health/live":
            return _probe_response(200, {"status": "live"})
        return _probe_response(200, _control_status("DEGRADED_NO_PROVIDER", ready=True))

    result = await watchdog_main._probe(
        _settings(tmp_path),
        transport=httpx.MockTransport(respond),
        capability_loader=watchdog_probe_authority,
    )

    assert result.live and not result.ready
    assert result.agent_status_code == 200
    assert result.attestation is ProbeAttestation.UNVERIFIED
    assert result.control_status_code == 200


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "readiness_body",
    (b"[]", b"null", b'"READY"', b"\xff"),
    ids=("array", "null", "string", "invalid-utf8"),
)
async def test_probe_rejects_non_object_or_undecodable_control_bodies(
    tmp_path: Path,
    readiness_body: bytes,
    watchdog_probe_authority: Callable[[Path], str],
) -> None:
    def respond(request: httpx.Request) -> httpx.Response:
        _assert_probe_authority(request)
        if request.url.path == "/health/live":
            return _probe_response(200, {"status": "live"})
        return _probe_response(200, readiness_body)

    result = await watchdog_main._probe(
        _settings(tmp_path),
        transport=httpx.MockTransport(respond),
        capability_loader=watchdog_probe_authority,
    )

    assert result.live and not result.ready
    assert result.agent_status_code == 200
    assert result.daemon_state is None
    assert result.attestation is ProbeAttestation.UNVERIFIED
    assert result.control_status_code == 200


@pytest.mark.asyncio
async def test_probe_preserves_liveness_when_control_transport_fails(
    tmp_path: Path,
    watchdog_probe_authority: Callable[[Path], str],
) -> None:
    def respond(request: httpx.Request) -> httpx.Response:
        _assert_probe_authority(request)
        if request.url.path == "/health/live":
            return _probe_response(200, {"status": "live"})
        raise httpx.ConnectError("synthetic control endpoint disconnected", request=request)

    result = await watchdog_main._probe(
        _settings(tmp_path),
        transport=httpx.MockTransport(respond),
        capability_loader=watchdog_probe_authority,
    )

    assert result.live and not result.ready
    assert result.agent_status_code == 200
    assert result.control_status_code is None
    assert result.attestation is ProbeAttestation.UNVERIFIED


@pytest.mark.asyncio
@pytest.mark.usefixtures("adjacent_daemon_interpreter")
async def test_restart_uses_installed_entry_point_and_requires_explicit_readiness(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daemon_executable = tmp_path / ("gatehoused.exe" if os.name == "nt" else "gatehoused")
    daemon_executable.touch()
    spawned: list[tuple[str, ...]] = []
    process = _FakeProcess()

    async def spawn(arguments: tuple[str, ...], *, environment: Mapping[str, str]) -> _FakeProcess:
        assert environment == {}
        spawned.append(arguments)
        return process

    async def ready() -> ProbeResult:
        return ProbeResult(
            live=True,
            ready=True,
            daemon_state="READY",
            agent_status_code=200,
            control_status_code=200,
            attestation=ProbeAttestation.MATCHED,
        )

    monkeypatch.setattr(watchdog_main, "_spawn_daemon", spawn)
    settings = _settings(tmp_path)

    assert await watchdog_main._restart(
        settings,
        daemon_executable=daemon_executable,
        probe=ready,
    )
    assert spawned == [
        (
            str(daemon_executable),
            "--config",
            str(settings.config_path),
            "--expected-config-digest",
            "a" * 64,
        ),
    ]
    assert process.terminate_calls == 0


@pytest.mark.asyncio
@pytest.mark.usefixtures("adjacent_daemon_interpreter")
async def test_restart_accepts_disabled_provider_state_only_when_configured(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daemon_executable = tmp_path / ("gatehoused.exe" if os.name == "nt" else "gatehoused")
    daemon_executable.touch()
    accepted_process = _FakeProcess()

    async def spawn(_: tuple[str, ...], *, environment: Mapping[str, str]) -> _FakeProcess:
        return accepted_process

    async def disabled() -> ProbeResult:
        return ProbeResult(
            live=True,
            ready=False,
            daemon_state="DEGRADED_NO_PROVIDER",
            agent_status_code=200,
            control_status_code=200,
            attestation=ProbeAttestation.MATCHED,
        )

    monkeypatch.setattr(watchdog_main, "_spawn_daemon", spawn)

    assert await watchdog_main._restart(
        _settings(tmp_path, allow_provider_disabled_state=True),
        daemon_executable=daemon_executable,
        probe=disabled,
    )
    assert accepted_process.terminate_calls == 0

    rejected_process = _FakeProcess()

    async def respawn(_: tuple[str, ...], *, environment: Mapping[str, str]) -> _FakeProcess:
        return rejected_process

    monkeypatch.setattr(watchdog_main, "_spawn_daemon", respawn)
    assert not await watchdog_main._restart(
        _settings(tmp_path, timeout_seconds=0.001),
        daemon_executable=daemon_executable,
        probe=disabled,
    )
    assert rejected_process.terminate_calls == 1

    mismatched_process = _FakeProcess()

    async def respawn_mismatched(
        _: tuple[str, ...], *, environment: Mapping[str, str]
    ) -> _FakeProcess:
        return mismatched_process

    async def mismatched_disabled() -> ProbeResult:
        return ProbeResult(
            live=True,
            ready=False,
            daemon_state="DEGRADED_NO_PROVIDER",
            agent_status_code=200,
            control_status_code=503,
            attestation=ProbeAttestation.MATCHED,
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
@pytest.mark.usefixtures("adjacent_daemon_interpreter")
async def test_restart_rejects_ready_flag_with_mismatched_daemon_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daemon_executable = tmp_path / ("gatehoused.exe" if os.name == "nt" else "gatehoused")
    daemon_executable.touch()
    process = _FakeProcess()

    async def spawn(_: tuple[str, ...], *, environment: Mapping[str, str]) -> _FakeProcess:
        return process

    async def mismatched() -> ProbeResult:
        return ProbeResult(
            live=True,
            ready=True,
            daemon_state="STARTING",
            agent_status_code=200,
            control_status_code=200,
            attestation=ProbeAttestation.MATCHED,
        )

    monkeypatch.setattr(watchdog_main, "_spawn_daemon", spawn)
    assert not await watchdog_main._restart(
        _settings(tmp_path, timeout_seconds=0.001),
        daemon_executable=daemon_executable,
        probe=mismatched,
    )
    assert process.terminate_calls == 1


@pytest.mark.asyncio
@pytest.mark.usefixtures("adjacent_daemon_interpreter")
async def test_restart_terminates_owned_failed_closed_child(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daemon_executable = tmp_path / ("gatehoused.exe" if os.name == "nt" else "gatehoused")
    daemon_executable.touch()
    process = _FakeProcess()

    async def spawn(_: tuple[str, ...], *, environment: Mapping[str, str]) -> _FakeProcess:
        return process

    async def failed_closed() -> ProbeResult:
        return ProbeResult(
            live=True,
            ready=False,
            daemon_state="FAILED_CLOSED",
            agent_status_code=200,
            control_status_code=200,
            attestation=ProbeAttestation.MATCHED,
        )

    monkeypatch.setattr(watchdog_main, "_spawn_daemon", spawn)

    assert not await watchdog_main._restart(
        _settings(tmp_path),
        daemon_executable=daemon_executable,
        probe=failed_closed,
    )
    assert process.terminate_calls == 1
    assert process.kill_calls == 0


@pytest.mark.asyncio
@pytest.mark.usefixtures("adjacent_daemon_interpreter")
async def test_restart_does_not_accept_readiness_from_an_exited_child(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daemon_executable = tmp_path / ("gatehoused.exe" if os.name == "nt" else "gatehoused")
    daemon_executable.touch()
    process = _FakeProcess()

    async def spawn(_: tuple[str, ...], *, environment: Mapping[str, str]) -> _FakeProcess:
        return process

    async def ready_after_exit() -> ProbeResult:
        process.returncode = 1
        return ProbeResult(
            live=True,
            ready=True,
            daemon_state="READY",
            agent_status_code=200,
            control_status_code=200,
            attestation=ProbeAttestation.MATCHED,
        )

    monkeypatch.setattr(watchdog_main, "_spawn_daemon", spawn)

    assert not await watchdog_main._restart(
        _settings(tmp_path),
        daemon_executable=daemon_executable,
        probe=ready_after_exit,
    )
    assert process.terminate_calls == 0


@pytest.mark.asyncio
@pytest.mark.usefixtures("adjacent_daemon_interpreter")
async def test_restart_does_not_report_success_for_an_alive_but_unreachable_process(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daemon_executable = tmp_path / ("gatehoused.exe" if os.name == "nt" else "gatehoused")
    daemon_executable.touch()
    process = _FakeProcess()

    async def spawn(_: tuple[str, ...], *, environment: Mapping[str, str]) -> _FakeProcess:
        return process

    async def unreachable() -> ProbeResult:
        return ProbeResult(live=False, ready=False, attestation=ProbeAttestation.NO_RESPONDER)

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
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _settings(tmp_path)
    settings.database_path.parent.mkdir(parents=True)
    connection = connect_database(settings.database_path)
    try:
        assert apply_migrations(connection, migrations=MIGRATIONS[:-1]) == MIGRATIONS[-2].version
    finally:
        connection.close()

    def fresh_database_security(path: Path, *, must_exist: bool = False) -> Path:
        assert path == settings.database_path
        assert path.is_relative_to(tmp_path)
        assert must_exist
        return path

    # Schema compatibility uses a fresh database; native ACL enforcement is separate.
    monkeypatch.setattr(watchdog_main, "secure_database_state", fresh_database_security)

    with pytest.raises(MigrationDriftError):
        await watchdog_main._run(settings)

    inspected = connect_database(settings.database_path)
    try:
        assert inspected.execute("PRAGMA user_version").fetchone()[0] == MIGRATIONS[-2].version
        assert (
            inspected.execute("SELECT COUNT(*) FROM schema_migrations").fetchone()[0]
            == len(MIGRATIONS) - 1
        )
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


def test_only_accepted_states_and_lease_busy_are_successful_task_runs() -> None:
    assert watchdog_main._outcome_exit_code(WatchdogOutcome.HEALTHY) == 0
    assert watchdog_main._outcome_exit_code(WatchdogOutcome.PROVIDERS_DISABLED) == 0
    assert watchdog_main._outcome_exit_code(WatchdogOutcome.LEASE_BUSY) == 0
    assert watchdog_main._outcome_exit_code(WatchdogOutcome.LIVE_DEGRADED) == 1
    assert watchdog_main._outcome_exit_code(WatchdogOutcome.CONFIG_MISMATCH) == 1
    assert watchdog_main._outcome_exit_code(WatchdogOutcome.CONFIG_UNVERIFIED) == 1
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

    def run_without_event_loop(
        coroutine: Coroutine[object, object, WatchdogOutcome],
    ) -> WatchdogOutcome:
        assert getattr(coroutine, "cr_code", None) is run.__code__
        try:
            try:
                coroutine.send(None)
            except StopIteration as completed:
                outcome = completed.value
                assert isinstance(outcome, WatchdogOutcome)
                return outcome
            raise AssertionError("the injected entrypoint coroutine must not suspend")
        finally:
            coroutine.close()

    monkeypatch.setattr(watchdog_main, "ensure_standard_streams", ensure_streams)
    monkeypatch.setattr(watchdog_main, "_load_runtime_settings", load_settings)
    monkeypatch.setattr(watchdog_main, "_run", run)
    monkeypatch.setattr(asyncio, "run", run_without_event_loop)

    with pytest.raises(SystemExit) as raised:
        watchdog_main.main(
            ["--config", str(settings.config_path), "--expected-config-digest", "a" * 64],
            environment={"APPDATA": str(tmp_path)},
        )

    assert raised.value.code == 0
    assert observed == ["streams", "settings", "run"]
