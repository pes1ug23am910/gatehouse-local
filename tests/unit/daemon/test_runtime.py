from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from fastapi import FastAPI

import gatehouse.daemon.main as daemon_entrypoint
from gatehouse.daemon import (
    DaemonApplications,
    DaemonSettings,
    RuntimeHealthProbe,
    serve,
)
from gatehouse.daemon.main import default_config_path


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
    observed: list[str | Path] = []

    def ensure_streams() -> None:
        observed.append("streams")

    async def run(path: str | Path) -> int:
        observed.append(Path(path))
        return 0

    monkeypatch.setattr(daemon_entrypoint, "ensure_standard_streams", ensure_streams)
    monkeypatch.setattr(daemon_entrypoint, "run_stock_daemon", run)
    daemon_entrypoint.main(["--config", str(config_path)])

    assert observed == ["streams", config_path]


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

    def __init__(self, config: object) -> None:
        del config
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
