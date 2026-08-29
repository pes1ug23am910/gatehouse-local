from __future__ import annotations

import asyncio
from collections.abc import Mapping
from pathlib import Path

import pytest
import uvicorn
from fastapi import FastAPI

import gatehouse.daemon.main as daemon_entrypoint
from gatehouse.config import ConfigLoadError
from gatehouse.config.loader import ConfigLoadStage
from gatehouse.daemon import (
    DaemonApplications,
    DaemonSettings,
    RuntimeHealthProbe,
    serve,
)
from gatehouse.daemon.main import default_config_path

_ROUTINE_SHUTDOWN_SOAK_CYCLES = 32


def test_listener_settings_are_loopback_only_and_separate() -> None:
    with pytest.raises(ValueError, match="127.0.0.1"):
        DaemonSettings(host=".".join(("0", "0", "0", "0")))
    with pytest.raises(ValueError, match="distinct"):
        DaemonSettings(agent_port=47_621, admin_port=47_621)


def test_agent_and_admin_use_distinct_application_objects() -> None:
    agent = FastAPI()
    admin = FastAPI()
    applications = DaemonApplications(agent=agent, admin=admin)
    assert applications.agent is agent
    assert applications.admin is admin
    with pytest.raises(ValueError, match="separate"):
        DaemonApplications(agent=agent, admin=agent)


def test_all_declared_entry_point_modules_resolve() -> None:
    from gatehouse.cli.main import app
    from gatehouse.daemon.main import main as daemon_main
    from gatehouse.mcp.server import main as mcp_main
    from gatehouse.notifier.main import main as notifier_main

    assert app is not None
    assert callable(daemon_main)
    assert callable(mcp_main)
    assert callable(notifier_main)


def test_daemon_default_config_uses_roaming_appdata() -> None:
    assert default_config_path(environment={"APPDATA": r"C:\Users\Y\AppData\Roaming"}) == (
        Path(r"C:\Users\Y\AppData\Roaming") / "Gatehouse" / "config.yaml"
    )


def test_daemon_entrypoint_accepts_explicit_config(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path = (tmp_path / "config.yaml").resolve()
    observed: list[object] = []

    def ensure_streams() -> None:
        observed.append("streams")

    async def run(
        path: str | Path,
        *,
        environment: Mapping[str, str] | None = None,
    ) -> int:
        observed.append(Path(path))
        observed.append(dict(environment or {}))
        return 0

    monkeypatch.setattr(daemon_entrypoint, "ensure_standard_streams", ensure_streams)
    monkeypatch.setattr(daemon_entrypoint, "run_stock_daemon", run)
    daemon_entrypoint.main(
        ["--config", str(config_path)],
        environment={
            "APPDATA": str(tmp_path / "roaming"),
            "PATH": "C:\\Windows",
            "FIRECRAWL_API_KEY": "provider-secret",
        },
    )

    assert observed == [
        "streams",
        config_path,
        {
            "APPDATA": str(tmp_path / "roaming"),
            "PATH": "C:\\Windows",
        },
    ]


def test_daemon_entrypoint_redacts_config_failures_without_a_traceback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path_token = "fc-" + "abcdefghijklmnopqrstuvwxyz123456"
    config_path = tmp_path / f"{path_token}.yaml"

    async def fail(
        path: str | Path,
        *,
        environment: Mapping[str, str] | None = None,
    ) -> int:
        del environment
        raise ConfigLoadError(Path(path), ConfigLoadStage.READ, "file is unavailable")

    monkeypatch.setattr(daemon_entrypoint, "run_stock_daemon", fail)

    with pytest.raises(SystemExit) as captured:
        daemon_entrypoint.main(["--config", str(config_path)], environment={})

    stderr = capsys.readouterr().err
    assert captured.value.code == 2
    assert path_token not in stderr
    assert "[REDACTED:firecrawl_token]" in stderr
    assert "Traceback" not in stderr


@pytest.mark.asyncio
async def test_runtime_health_tracks_lifecycle_and_uptime() -> None:
    health = RuntimeHealthProbe(
        version="0.0.1",
        schema_version=5,
        policy_version="policy-v1",
        now_ms=lambda: 10_000,
        started_at_ms=1_000,
    )
    recovering = await health.readiness()
    assert not recovering.ready
    assert recovering.status == "RECOVERING"
    assert recovering.uptime_seconds == 9

    health.transition("ready")
    assert (await health.readiness()).ready
    health.transition("degraded_no_provider", degraded_components=("credentials",))
    degraded = await health.readiness()
    assert not degraded.ready
    assert degraded.status == "DEGRADED_NO_PROVIDER"
    assert degraded.degraded_components == ["credentials"]


class _FakeServer:
    instances: list[_FakeServer] = []
    all_created: asyncio.Event

    def __init__(self, config: uvicorn.Config) -> None:
        self.config = config
        self._should_exit = False
        self.started = asyncio.Event()
        self.stopped = asyncio.Event()
        self.exit_requested = asyncio.Event()
        self.instances.append(self)
        if len(self.instances) == 2:
            self.all_created.set()

    @property
    def should_exit(self) -> bool:
        return self._should_exit

    @should_exit.setter
    def should_exit(self, value: bool) -> None:
        self._should_exit = value
        if value:
            self.exit_requested.set()

    async def serve(self) -> None:
        self.started.set()
        await self.exit_requested.wait()
        self.stopped.set()


@pytest.mark.asyncio
async def test_shared_shutdown_stops_both_listeners() -> None:
    _FakeServer.instances.clear()
    _FakeServer.all_created = asyncio.Event()
    shutdown = asyncio.Event()
    applications = DaemonApplications(agent=FastAPI(), admin=FastAPI())
    task = asyncio.create_task(
        serve(
            applications,
            DaemonSettings(),
            shutdown_event=shutdown,
            server_factory=_FakeServer,
        )
    )
    await _FakeServer.all_created.wait()
    await asyncio.gather(*(server.started.wait() for server in _FakeServer.instances))
    shutdown.set()
    await asyncio.wait_for(task, timeout=1)
    assert all(server.should_exit and server.stopped.is_set() for server in _FakeServer.instances)
    assert all(server.config.limit_concurrency == 128 for server in _FakeServer.instances)
    assert all(server.config.backlog == 128 for server in _FakeServer.instances)
    assert all(server.config.timeout_keep_alive == 5 for server in _FakeServer.instances)


@pytest.mark.asyncio
async def test_bounded_listener_concurrency_survives_repeated_clean_shutdowns() -> None:
    settings = DaemonSettings(
        maximum_listener_concurrency=7,
        listener_backlog=11,
        keep_alive_timeout_seconds=2,
    )
    applications = DaemonApplications(agent=FastAPI(), admin=FastAPI())
    observed_servers = 0

    for cycle in range(_ROUTINE_SHUTDOWN_SOAK_CYCLES):
        _FakeServer.instances.clear()
        _FakeServer.all_created = asyncio.Event()
        shutdown = asyncio.Event()
        task = asyncio.create_task(
            serve(
                applications,
                settings,
                shutdown_event=shutdown,
                server_factory=_FakeServer,
            ),
            name=f"runtime-shutdown-soak-{cycle}",
        )

        await asyncio.wait_for(_FakeServer.all_created.wait(), timeout=1)
        await asyncio.wait_for(
            asyncio.gather(*(server.started.wait() for server in _FakeServer.instances)),
            timeout=1,
        )
        live_task_names = [candidate.get_name() for candidate in asyncio.all_tasks()]
        assert live_task_names.count("gatehouse-agent-listener") == 1
        assert live_task_names.count("gatehouse-admin-listener") == 1
        assert live_task_names.count("gatehouse-shutdown-signal") == 1
        assert all(
            server.config.limit_concurrency == settings.maximum_listener_concurrency
            for server in _FakeServer.instances
        )
        assert all(
            server.config.backlog == settings.listener_backlog for server in _FakeServer.instances
        )
        observed_servers += len(_FakeServer.instances)

        shutdown.set()
        await asyncio.wait_for(task, timeout=1)
        assert all(
            server.should_exit and server.stopped.is_set() for server in _FakeServer.instances
        )
        assert not any(
            candidate.get_name()
            in {
                "gatehouse-agent-listener",
                "gatehouse-admin-listener",
                "gatehouse-shutdown-signal",
            }
            for candidate in asyncio.all_tasks()
        )

    assert observed_servers == _ROUTINE_SHUTDOWN_SOAK_CYCLES * 2
