from __future__ import annotations

import asyncio
import sys
from collections.abc import Coroutine, Mapping
from io import StringIO
from pathlib import Path
from types import CoroutineType
from typing import Any

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
_CONFIG_DIGEST = "a" * 64


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
        expected_config_digest: str,
        environment: Mapping[str, str] | None = None,
    ) -> int:
        assert expected_config_digest == _CONFIG_DIGEST
        observed.append(Path(path))
        observed.append(dict(environment or {}))
        return 0

    monkeypatch.setattr(daemon_entrypoint, "ensure_standard_streams", ensure_streams)
    monkeypatch.setattr(daemon_entrypoint, "run_stock_daemon", run)
    daemon_entrypoint.main(
        ["--config", str(config_path), "--expected-config-digest", _CONFIG_DIGEST],
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
        expected_config_digest: str,
        environment: Mapping[str, str] | None = None,
    ) -> int:
        assert expected_config_digest == _CONFIG_DIGEST
        del environment
        raise ConfigLoadError(Path(path), ConfigLoadStage.READ, "file is unavailable")

    monkeypatch.setattr(daemon_entrypoint, "run_stock_daemon", fail)

    with pytest.raises(SystemExit) as captured:
        daemon_entrypoint.main(
            ["--config", str(config_path), "--expected-config-digest", _CONFIG_DIGEST],
            environment={},
        )

    stderr = capsys.readouterr().err
    assert captured.value.code == 2
    assert path_token not in stderr
    assert stderr == "gatehoused: configuration startup was refused\n"
    assert "Traceback" not in stderr


def _run_without_event_loop(coroutine: Coroutine[None, None, int]) -> int:
    try:
        try:
            coroutine.send(None)
        except StopIteration as completed:
            result = completed.value
            assert type(result) is int
            return result
        raise AssertionError("the fake daemon must finish without suspending")
    finally:
        coroutine.close()


@pytest.mark.parametrize(
    "raw_path",
    [
        r"C:\synthetic\config\config.yaml",
        "C:/synthetic/config/./config.yaml",
        r"C:\synthetic\config\..\config.yaml",
        r"C:\synthetic\\config\config.yaml",
    ],
    ids=["absolute-path", "dot-component", "parent-component", "repeated-separator"],
)
def test_h3_daemon_entrypoint_forwards_exact_digest_and_raw_path_without_event_loop(
    monkeypatch: pytest.MonkeyPatch, raw_path: str
) -> None:
    calls: list[str] = []
    received: list[tuple[str, str, dict[str, str]]] = []
    stderr = StringIO()

    async def run(
        path: str | Path,
        *,
        expected_config_digest: str,
        environment: Mapping[str, str] | None = None,
    ) -> int:
        calls.append("daemon")
        assert type(path) is str
        received.append((path, expected_config_digest, dict(environment or {})))
        return 0

    def run_once(coroutine: Coroutine[None, None, int]) -> int:
        calls.append("asyncio.run")
        return _run_without_event_loop(coroutine)

    monkeypatch.setattr(
        daemon_entrypoint, "ensure_standard_streams", lambda: calls.append("streams")
    )
    monkeypatch.setattr(daemon_entrypoint, "run_stock_daemon", run)
    monkeypatch.setattr(asyncio, "run", run_once)
    monkeypatch.setattr(sys, "stderr", stderr)
    daemon_entrypoint.main(
        ["--config", raw_path, "--expected-config-digest", _CONFIG_DIGEST],
        environment={
            "APPDATA": r"C:\synthetic\roaming",
            "LOCALAPPDATA": r"C:\synthetic\local",
            "PATH": r"C:\Windows",
            "FIRECRAWL_API_KEY": "FAKE-ENTRYPOINT-ENV-NOT-A-REAL-KEY",
        },
    )

    assert calls == ["streams", "asyncio.run", "daemon"]
    assert received == [
        (
            raw_path,
            _CONFIG_DIGEST,
            {
                "APPDATA": r"C:\synthetic\roaming",
                "LOCALAPPDATA": r"C:\synthetic\local",
                "PATH": r"C:\Windows",
            },
        )
    ]
    assert stderr.getvalue() == ""


@pytest.mark.parametrize(
    "arguments",
    [
        pytest.param((), id="missing"),
        pytest.param(("--expected-config-digest",), id="missing-value"),
        pytest.param(("--expected-config-digest=",), id="empty"),
        pytest.param(("--expected-config-digest", "a" * 63), id="short"),
        pytest.param(("--expected-config-digest", "a" * 65), id="long"),
        pytest.param(("--expected-config-digest", "A" * 64), id="uppercase"),
        pytest.param(("--expected-config-digest", "g" * 64), id="non-hex"),
        pytest.param(("--expected-config-digest", " " + _CONFIG_DIGEST), id="leading-space"),
        pytest.param(("--expected-config-digest", _CONFIG_DIGEST + " "), id="trailing-space"),
        pytest.param(("--expected-config-digest", _CONFIG_DIGEST + "\n"), id="newline"),
        pytest.param(("--expected-config-digest", "\uff41" * 64), id="non-ascii"),
        pytest.param(
            ("--expected-config-digest", "FAKE-ARGUMENT-CANARY-NOT-A-REAL-KEY"),
            id="private-shaped-value",
        ),
        pytest.param(
            (
                "--expected-config-digest",
                _CONFIG_DIGEST,
                "--expected-config-digest",
                _CONFIG_DIGEST,
            ),
            id="duplicate-identical",
        ),
        pytest.param(
            ("--expected-config-digest", _CONFIG_DIGEST, "--expected-config-digest", "b" * 64),
            id="duplicate-conflicting",
        ),
        pytest.param(("--expected-config-dig", _CONFIG_DIGEST), id="abbreviated-option"),
        pytest.param(
            (
                "--expected-config-digest",
                _CONFIG_DIGEST,
                "--unknown-option",
                "FAKE-ARGUMENT-CANARY-NOT-A-REAL-KEY",
            ),
            id="unknown-option",
        ),
        pytest.param(
            ("--expected-config-digest", _CONFIG_DIGEST, "FAKE-ARGUMENT-CANARY-NOT-A-REAL-KEY"),
            id="unexpected-positional",
        ),
    ],
)
def test_h3_daemon_entrypoint_rejects_digest_arguments_before_runtime_without_echo(
    monkeypatch: pytest.MonkeyPatch, arguments: tuple[str, ...]
) -> None:
    calls: list[str] = []
    stderr = StringIO()
    raw_path = "C:/synthetic/FAKE-PATH-CANARY/config.yaml"

    def forbidden_daemon(*args: object, **kwargs: object) -> None:
        calls.append("daemon")
        raise AssertionError("invalid arguments must not invoke the daemon")

    def forbidden_runner(coroutine: Coroutine[None, None, int]) -> int:
        calls.append("asyncio.run")
        coroutine.close()
        raise AssertionError("invalid arguments must not enter the event-loop runner")

    monkeypatch.setattr(daemon_entrypoint, "ensure_standard_streams", lambda: None)
    monkeypatch.setattr(daemon_entrypoint, "run_stock_daemon", forbidden_daemon)
    monkeypatch.setattr(asyncio, "run", forbidden_runner)
    monkeypatch.setattr(sys, "stderr", stderr)
    with pytest.raises(SystemExit) as captured:
        daemon_entrypoint.main(
            ["--config", raw_path, *arguments],
            environment={"APPDATA": r"C:\synthetic\roaming"},
        )

    rendered = stderr.getvalue()
    assert captured.value.code == 2
    assert calls == []
    assert "daemon startup arguments are invalid" in rendered
    assert "Traceback" not in rendered
    assert raw_path not in rendered
    assert "FAKE-PATH-CANARY" not in rendered
    for argument in arguments:
        if argument and not argument.startswith("--"):
            assert argument not in rendered


def test_h3_daemon_entrypoint_preserves_sanitized_config_error_without_event_loop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path_token = "fc-" + "abcdefghijklmnopqrstuvwxyz123456"
    raw_path = f"C:/synthetic/{path_token}.yaml"
    stderr = StringIO()
    calls: list[str] = []

    async def fail(
        path: str | Path,
        *,
        expected_config_digest: str,
        environment: Mapping[str, str] | None = None,
    ) -> int:
        calls.append("daemon")
        assert path == raw_path
        assert expected_config_digest == _CONFIG_DIGEST
        assert environment == {"APPDATA": r"C:\synthetic\roaming"}
        raise ConfigLoadError(Path(path), ConfigLoadStage.READ, "file is unavailable")

    monkeypatch.setattr(daemon_entrypoint, "ensure_standard_streams", lambda: None)
    monkeypatch.setattr(daemon_entrypoint, "run_stock_daemon", fail)
    monkeypatch.setattr(asyncio, "run", _run_without_event_loop)
    monkeypatch.setattr(sys, "stderr", stderr)
    with pytest.raises(SystemExit) as captured:
        daemon_entrypoint.main(
            ["--config", raw_path, "--expected-config-digest", _CONFIG_DIGEST],
            environment={"APPDATA": r"C:\synthetic\roaming"},
        )

    rendered = stderr.getvalue()
    assert captured.value.code == 2
    assert calls == ["daemon"]
    assert rendered == "gatehoused: configuration startup was refused\n"
    assert "file is unavailable" not in rendered
    assert "[REDACTED:firecrawl_token]" not in rendered
    assert "daemon startup arguments are invalid" not in rendered
    assert path_token not in rendered
    assert raw_path not in rendered
    assert "Traceback" not in rendered


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
        self.task: asyncio.Task[Any] | None = None
        self.serve_calls = 0
        self.cancel_calls = 0
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
        self.task = asyncio.current_task()
        self.serve_calls += 1
        self.started.set()
        try:
            await self.exit_requested.wait()
        except asyncio.CancelledError:
            self.cancel_calls += 1
            raise
        self.stopped.set()

    def release_for_cleanup(self) -> None:
        self.should_exit = True


async def _wait_for_fake_listeners() -> None:
    await asyncio.wait_for(_FakeServer.all_created.wait(), timeout=1)
    await asyncio.wait_for(
        asyncio.gather(*(server.started.wait() for server in _FakeServer.instances)),
        timeout=1,
    )


async def _join_fake_serve(task: asyncio.Task[None]) -> None:
    done, pending = await asyncio.wait({task}, timeout=1)
    assert task in done and not pending, "fake listener lifecycle did not finish"
    task.result()


async def _finish_fake_serve(
    task: asyncio.Task[None],
    shutdown: asyncio.Event,
    *,
    extra_tasks: tuple[asyncio.Task[Any], ...] = (),
) -> None:
    """Release cooperative fakes and join without cancelling the owned lifecycle."""

    shutdown.set()
    for server in _FakeServer.instances:
        server.release_for_cleanup()
    owned = {task, *extra_tasks}
    owned.update(server.task for server in _FakeServer.instances if server.task is not None)
    done, pending = await asyncio.wait(owned, timeout=1)
    for completed in done:
        if not completed.cancelled():
            completed.exception()
    assert not pending, "fake listener cleanup retained unfinished work"


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
    try:
        await _wait_for_fake_listeners()
        shutdown.set()
        await _join_fake_serve(task)
        assert all(
            server.should_exit and server.stopped.is_set() for server in _FakeServer.instances
        )
        assert all(server.config.limit_concurrency == 128 for server in _FakeServer.instances)
        assert all(server.config.backlog == 128 for server in _FakeServer.instances)
        assert all(server.config.timeout_keep_alive == 5 for server in _FakeServer.instances)
    finally:
        await _finish_fake_serve(task, shutdown)


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

        try:
            await _wait_for_fake_listeners()
            live_task_names = [candidate.get_name() for candidate in asyncio.all_tasks()]
            assert live_task_names.count("gatehouse-agent-listener") == 1
            assert live_task_names.count("gatehouse-admin-listener") == 1
            assert live_task_names.count("gatehouse-shutdown-signal") == 1
            assert all(
                server.config.limit_concurrency == settings.maximum_listener_concurrency
                for server in _FakeServer.instances
            )
            assert all(
                server.config.backlog == settings.listener_backlog
                for server in _FakeServer.instances
            )
            observed_servers += len(_FakeServer.instances)

            shutdown.set()
            await _join_fake_serve(task)
            assert all(
                server.should_exit and server.stopped.is_set() for server in _FakeServer.instances
            )
        finally:
            await _finish_fake_serve(task, shutdown)
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


@pytest.mark.asyncio
async def test_cancelling_serve_at_initial_wait_joins_both_listeners() -> None:
    _FakeServer.instances.clear()
    _FakeServer.all_created = asyncio.Event()
    shutdown = asyncio.Event()
    task = asyncio.create_task(
        serve(
            DaemonApplications(agent=FastAPI(), admin=FastAPI()),
            DaemonSettings(),
            shutdown_event=shutdown,
            server_factory=_FakeServer,
        )
    )
    try:
        await _wait_for_fake_listeners()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await _join_fake_serve(task)
        assert task.cancelled()
        assert all(
            server.should_exit and server.stopped.is_set() for server in _FakeServer.instances
        )
        assert all(server.cancel_calls == 0 for server in _FakeServer.instances)
    finally:
        await _finish_fake_serve(task, shutdown)


@pytest.mark.asyncio
async def test_repeated_serve_cancellation_retains_ignoring_listener_until_release() -> None:
    _FakeServer.instances.clear()
    _FakeServer.all_created = asyncio.Event()
    shutdown = asyncio.Event()
    release = asyncio.Event()
    settings = DaemonSettings()

    class IgnoringServer(_FakeServer):
        async def serve(self) -> None:
            if self.config.port != settings.agent_port:
                await super().serve()
                return
            self.task = asyncio.current_task()
            self.serve_calls += 1
            self.started.set()
            try:
                await release.wait()
            except asyncio.CancelledError:
                self.cancel_calls += 1
                raise
            self.stopped.set()

        def release_for_cleanup(self) -> None:
            super().release_for_cleanup()
            release.set()

    task = asyncio.create_task(
        serve(
            DaemonApplications(agent=FastAPI(), admin=FastAPI()),
            settings,
            shutdown_event=shutdown,
            server_factory=IgnoringServer,
        )
    )
    try:
        await _wait_for_fake_listeners()
        agent, admin = _FakeServer.instances
        task.cancel()
        await asyncio.wait_for(agent.exit_requested.wait(), timeout=1)
        await asyncio.wait_for(admin.stopped.wait(), timeout=1)
        assert not task.done() and not agent.stopped.is_set()
        task.cancel()
        await asyncio.sleep(0)
        assert not task.done() and not agent.stopped.is_set()
        assert all(server.cancel_calls == 0 for server in _FakeServer.instances)
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await _join_fake_serve(task)
        assert task.cancelled() and agent.stopped.is_set()
    finally:
        await _finish_fake_serve(task, shutdown)


@pytest.mark.asyncio
async def test_listener_failure_waits_for_ignoring_peer_and_preserves_error() -> None:
    _FakeServer.instances.clear()
    _FakeServer.all_created = asyncio.Event()
    shutdown = asyncio.Event()
    fail = asyncio.Event()
    release = asyncio.Event()
    settings = DaemonSettings()

    class FailingAndIgnoringServer(_FakeServer):
        async def serve(self) -> None:
            self.task = asyncio.current_task()
            self.serve_calls += 1
            self.started.set()
            try:
                if self.config.port == settings.agent_port:
                    await fail.wait()
                    raise RuntimeError("synthetic listener failure")
                await release.wait()
            except asyncio.CancelledError:
                self.cancel_calls += 1
                raise
            finally:
                self.stopped.set()

        def release_for_cleanup(self) -> None:
            super().release_for_cleanup()
            fail.set()
            release.set()

    task = asyncio.create_task(
        serve(
            DaemonApplications(agent=FastAPI(), admin=FastAPI()),
            settings,
            shutdown_event=shutdown,
            server_factory=FailingAndIgnoringServer,
        )
    )
    try:
        await _wait_for_fake_listeners()
        agent, admin = _FakeServer.instances
        fail.set()
        await asyncio.wait_for(admin.exit_requested.wait(), timeout=1)
        assert agent.stopped.is_set()
        assert not task.done() and not admin.stopped.is_set()
        task.cancel()
        await asyncio.sleep(0)
        task.cancel()
        await asyncio.sleep(0)
        assert not task.done() and not admin.stopped.is_set()
        assert all(server.cancel_calls == 0 for server in _FakeServer.instances)
        release.set()
        with pytest.raises(RuntimeError, match="^synthetic listener failure$"):
            await _join_fake_serve(task)
        assert not task.cancelled() and admin.stopped.is_set()
    finally:
        await _finish_fake_serve(task, shutdown)


@pytest.mark.asyncio
@pytest.mark.parametrize("failure_index", (2, 3))
async def test_partial_listener_task_creation_failure_never_starts_server(
    monkeypatch: pytest.MonkeyPatch, failure_index: int
) -> None:
    _FakeServer.instances.clear()
    _FakeServer.all_created = asyncio.Event()
    shutdown = asyncio.Event()
    real_create_task = asyncio.create_task
    created: list[asyncio.Task[Any]] = []
    rejected: list[Coroutine[Any, Any, Any]] = []
    attempts = 0

    def controlled_create_task(
        work: Coroutine[Any, Any, Any], *, name: str | None = None
    ) -> asyncio.Task[Any]:
        nonlocal attempts
        if name in {
            "gatehouse-agent-listener",
            "gatehouse-admin-listener",
            "gatehouse-shutdown-signal",
        }:
            attempts += 1
            if attempts == failure_index:
                rejected.append(work)
                raise RuntimeError("synthetic task creation failure")
            child = real_create_task(work, name=name)
            created.append(child)
            return child
        return real_create_task(work, name=name)

    monkeypatch.setattr(asyncio, "create_task", controlled_create_task)
    task = real_create_task(
        serve(
            DaemonApplications(agent=FastAPI(), admin=FastAPI()),
            DaemonSettings(),
            shutdown_event=shutdown,
            server_factory=_FakeServer,
        )
    )
    try:
        with pytest.raises(RuntimeError, match="^synthetic task creation failure$"):
            await _join_fake_serve(task)
        assert attempts == failure_index
        assert len(created) == failure_index - 1
        assert all(child.done() and not child.cancelled() for child in created)
        assert len(_FakeServer.instances) == 2
        assert all(
            server.serve_calls == 0 and server.task is None for server in _FakeServer.instances
        )
        assert all(server.should_exit for server in _FakeServer.instances)
        assert len(rejected) == 1
        assert isinstance(rejected[0], CoroutineType)
        assert rejected[0].cr_frame is None
    finally:
        await _finish_fake_serve(task, shutdown, extra_tasks=tuple(created))
