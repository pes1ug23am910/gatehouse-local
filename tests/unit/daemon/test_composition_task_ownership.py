from __future__ import annotations

import asyncio
import sqlite3
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest
import uvicorn

from gatehouse.admin import SqliteCredentialLifecycleService
from gatehouse.core import FixedUtcClock, RuntimeAdmissionController
from gatehouse.core.task_batches import TaskBatchDrainError
from gatehouse.daemon import DaemonApplications, DaemonSettings, composition, runtime
from gatehouse.daemon.health import RuntimeHealthProbe
from gatehouse.daemon.lease import InstallationDaemonLease
from gatehouse.database import RetentionPolicy
from gatehouse.jobs import JobSupervisor
from gatehouse.reconciliation import ReconciliationPolicy
from gatehouse.scheduler import BoundedFairScheduler


class FakeConnection:
    def __init__(self, effects: list[str]) -> None:
        self.effects = effects

    def close(self) -> None:
        self.effects.append("database_closed")


class FakeLease:
    def __init__(self, effects: list[str]) -> None:
        self.effects = effects

    def release(self) -> None:
        self.effects.append("lease_released")


class FakeTransport:
    def __init__(self, effects: list[str], name: str) -> None:
        self.effects = effects
        self.name = name

    async def aclose(self) -> None:
        self.effects.append(self.name)

    async def send(self, request: object) -> object:
        raise AssertionError("teardown attempted provider dispatch")


class FakeCredentials:
    def __init__(self, effects: list[str]) -> None:
        self.effects = effects

    async def close_emergency(self) -> None:
        self.effects.append("emergency_closed")


class FakeSupervisor:
    pending_task_count = 0
    drain_failed = False

    async def cancel_and_drain(self, *, timeout_ms: int | None = None) -> None:
        del timeout_ms

    async def run_once(self) -> int:
        return 0

    async def run(self, stop: asyncio.Event) -> None:
        await stop.wait()


def _daemon(monkeypatch: pytest.MonkeyPatch) -> tuple[composition.StockDaemon, list[str]]:
    effects: list[str] = []

    def set_state(connection: object, state: str, *, now_ms: int, clean: bool = False) -> None:
        del connection, now_ms, clean
        effects.append(state)

    monkeypatch.setattr(composition, "_set_system_state", set_state)
    monkeypatch.setattr(composition, "checkpoint_wal", lambda *args, **kwargs: None)
    daemon = object.__new__(composition.StockDaemon)
    daemon.lifecycle_journal = None
    daemon.shutdown_event = asyncio.Event()
    daemon.job_supervisor = cast(JobSupervisor, FakeSupervisor())
    daemon.observation_loop = None
    daemon.approval_notifications = None
    daemon.admission = RuntimeAdmissionController()
    daemon.health = RuntimeHealthProbe(
        version="synthetic",
        schema_version=16,
        policy_version="synthetic",
        now_ms=lambda: 100,
        started_at_ms=100,
    )
    daemon.connection = cast(sqlite3.Connection, FakeConnection(effects))
    daemon.transport = cast(
        composition._ClosableProviderTransport, FakeTransport(effects, "workload_closed")
    )
    daemon.observer_transport = cast(
        composition._ClosableProviderTransport, FakeTransport(effects, "observer_closed")
    )
    daemon.credential_lifecycle = cast(SqliteCredentialLifecycleService, FakeCredentials(effects))
    daemon._clock = FixedUtcClock(100)
    daemon._lease = cast(InstallationDaemonLease, FakeLease(effects))
    daemon._closed = False
    daemon._failed = False
    daemon._operational_status = "READY"
    daemon._operational_degraded_components = ()
    daemon._runtime_tasks = set()
    daemon._runtime_cancel_requested = set()
    daemon._close_task = None
    daemon._close_deadline = None
    daemon._close_cancel_requested = False
    daemon._close_progress = composition._DaemonCloseProgress()
    return daemon, effects


@pytest.mark.asyncio
async def test_direct_close_before_serving_drains_then_releases_resources(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daemon, effects = _daemon(monkeypatch)
    await daemon.close(timeout_ms=100)
    assert daemon._closed
    assert effects == [
        "DRAINING",
        "emergency_closed",
        "observer_closed",
        "workload_closed",
        "STOPPED",
        "database_closed",
        "lease_released",
    ]


@pytest.mark.asyncio
async def test_resistant_owned_task_fences_close_and_retains_database_and_lease(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daemon, effects = _daemon(monkeypatch)
    started = asyncio.Event()
    release = asyncio.Event()

    async def resistant() -> None:
        started.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            await release.wait()

    worker = daemon._own_runtime_task(resistant(), name="synthetic-resistant")
    try:
        await asyncio.wait_for(started.wait(), timeout=1)
        with pytest.raises(composition.DaemonDrainError):
            await daemon.close(timeout_ms=10)
        assert daemon.pending_runtime_task_count == 1
        closed_after_failure = daemon._closed
        assert not closed_after_failure
        assert daemon.health.status == "FAILED_CLOSED"
        assert not any(item.endswith("closed") or item == "lease_released" for item in effects)
        assert "STOPPED" not in effects
    finally:
        release.set()
        await asyncio.wait_for(worker, timeout=1)
        if daemon._close_task is not None:
            await asyncio.wait_for(
                asyncio.gather(daemon._close_task, return_exceptions=True), timeout=1
            )
        await daemon.close(timeout_ms=100)
    assert daemon._closed
    assert effects[-2:] == ["database_closed", "lease_released"]
    assert "STOPPED" not in effects


@pytest.mark.asyncio
async def test_real_serve_retains_listener_ownership_until_close_can_release_resources(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daemon, effects = _daemon(monkeypatch)
    release = asyncio.Event()

    class Listener:
        def __init__(self, name: str) -> None:
            self.name = name
            self.started = asyncio.Event()
            self.task: asyncio.Task[None] | None = None
            self.shutdown_signals = 0
            self.cancellations = 0
            self._should_exit = False

        @property
        def should_exit(self) -> bool:
            return self._should_exit

        @should_exit.setter
        def should_exit(self, value: bool) -> None:
            self._should_exit = value
            self.shutdown_signals += int(value)

        async def serve(self) -> None:
            current = asyncio.current_task()
            assert current is not None
            self.task = current
            self.started.set()
            while not release.is_set():
                try:
                    await release.wait()
                except asyncio.CancelledError:
                    self.cancellations += 1
                    current.uncancel()
            effects.append(f"{self.name}_joined")

    listeners = (Listener("agent_listener"), Listener("admin_listener"))
    applications = cast(DaemonApplications, SimpleNamespace(agent=object(), admin=object()))
    monkeypatch.setattr(
        uvicorn,
        "Config",
        lambda app, **options: SimpleNamespace(app=app, **options),
    )

    def server_factory(config: object) -> Listener:
        app = cast(SimpleNamespace, config).app
        assert app is applications.agent or app is applications.admin
        return listeners[0] if app is applications.agent else listeners[1]

    async def join(tasks: set[asyncio.Task[None]]) -> None:
        done, pending = await asyncio.wait(tasks, timeout=1)
        for task in done:
            if not task.cancelled():
                task.exception()
        assert not pending, "released listener ownership did not finish"

    owned = daemon._own_runtime_task(
        runtime.serve(
            applications,
            DaemonSettings(),
            shutdown_event=daemon.shutdown_event,
            server_factory=server_factory,
        ),
        name="synthetic-listener-runtime",
    )
    try:
        await asyncio.wait_for(
            asyncio.gather(*(listener.started.wait() for listener in listeners)), timeout=1
        )
        for _ in range(2):
            with pytest.raises(composition.DaemonDrainError):
                await daemon.close(timeout_ms=10)
            assert daemon._close_task is not None
            await join({daemon._close_task})
            assert owned in daemon._runtime_tasks and not owned.done()
            assert daemon.pending_runtime_task_count == 1
            closed_after_failure = daemon._closed
            assert not closed_after_failure and daemon.health.status == "FAILED_CLOSED"
            for listener in listeners:
                assert listener.should_exit and listener.shutdown_signals >= 1
                assert listener.cancellations == 0
                assert listener.task is not None and not listener.task.done()
            assert not any(item.endswith("closed") or item == "lease_released" for item in effects)
            assert "STOPPED" not in effects

        release.set()
        await join({owned, *(listener.task for listener in listeners if listener.task is not None)})
        assert owned.cancelled()
        assert daemon.pending_runtime_task_count == 0
        effects.append("runtime_joined")
        await daemon.close(timeout_ms=100)
        assert daemon._closed
        assert effects[-5:] == [
            "emergency_closed",
            "observer_closed",
            "workload_closed",
            "database_closed",
            "lease_released",
        ]
        for listener in listeners:
            assert listener.cancellations == 0
            assert effects.index(f"{listener.name}_joined") < effects.index("runtime_joined")
        assert effects.index("runtime_joined") < effects.index("emergency_closed")
        assert "STOPPED" not in effects
    finally:
        release.set()
        tasks = {owned, *(listener.task for listener in listeners if listener.task is not None)}
        if daemon._close_task is not None:
            tasks.add(daemon._close_task)
        await join(tasks)
        await daemon.close(timeout_ms=100)


@pytest.mark.asyncio
async def test_repeated_close_cancellation_joins_owned_cleanup_before_resource_release(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daemon, effects = _daemon(monkeypatch)
    started = asyncio.Event()
    cleaning = asyncio.Event()
    release = asyncio.Event()

    async def worker() -> None:
        started.set()
        try:
            await asyncio.Event().wait()
        finally:
            cleaning.set()
            await release.wait()
            effects.append("worker_joined")

    owned = daemon._own_runtime_task(worker(), name="synthetic-cooperative")
    await asyncio.wait_for(started.wait(), timeout=1)
    closing = asyncio.create_task(daemon.close(timeout_ms=500))
    try:
        await asyncio.wait_for(cleaning.wait(), timeout=1)
        closing.cancel()
        await asyncio.sleep(0)
        closing.cancel()
        assert "database_closed" not in effects
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(closing, timeout=1)
        assert effects.index("worker_joined") < effects.index("emergency_closed")
        assert daemon._closed
    finally:
        release.set()
        await asyncio.wait_for(asyncio.gather(owned, return_exceptions=True), timeout=1)
        await asyncio.wait_for(asyncio.gather(closing, return_exceptions=True), timeout=1)


@pytest.mark.asyncio
async def test_startup_failure_and_resistant_startup_cancellation_are_owned(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daemon, effects = _daemon(monkeypatch)
    daemon.database_path = Path("synthetic.db")
    daemon.database_busy_timeout_ms = 0
    daemon.database_size_cap = 1
    daemon.retention_policy = RetentionPolicy()
    entered = asyncio.Event()
    release = asyncio.Event()

    async def maintenance(*args: object, **kwargs: object) -> None:
        entered.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            await release.wait()
        raise RuntimeError("synthetic startup failure")

    async def never_serve(*args: object) -> None:
        raise AssertionError("startup failure reached listeners")

    monkeypatch.setattr(composition, "_await_database_maintenance_batch", maintenance)
    serving = asyncio.create_task(
        composition._serve_composed(
            daemon,
            serve_applications=never_serve,
            scheduler_pump_interval_ms=10,
            drain_timeout_ms=10,
        )
    )
    try:
        await asyncio.wait_for(entered.wait(), timeout=1)
        serving.cancel()
        with pytest.raises(composition.DaemonDrainError):
            await asyncio.wait_for(serving, timeout=1)
        with pytest.raises(composition.DaemonDrainError):
            await daemon.close(timeout_ms=10)
        assert "database_closed" not in effects
        assert "lease_released" not in effects
        assert daemon.pending_runtime_task_count == 1
    finally:
        release.set()
        await asyncio.sleep(0)
        if daemon._close_task is not None:
            await asyncio.wait_for(
                asyncio.gather(daemon._close_task, return_exceptions=True), timeout=1
            )
        await daemon.close(timeout_ms=100)


def _runtime_fakes(daemon: composition.StockDaemon, monkeypatch: pytest.MonkeyPatch) -> None:
    daemon.database_path = Path("synthetic.db")
    daemon.database_busy_timeout_ms = 0
    daemon.database_size_cap = 1
    daemon.retention_policy = RetentionPolicy()
    daemon.maintenance_interval_ms = 10
    daemon.reconciliation_policy = ReconciliationPolicy(
        absolute_tolerance_units=0, relative_tolerance=0.0
    )
    daemon.reconciliation_quick_interval_ms = 10
    daemon.reconciliation_full_interval_ms = 10
    daemon.reconciliation_maximum_scopes = 1
    daemon.reconciliation_maximum_wall_duration_ms = 10
    daemon.applications = cast(DaemonApplications, object())
    daemon.settings = cast(DaemonSettings, object())
    daemon.scheduler = cast(BoundedFairScheduler, object())

    async def startup(*args: object, **kwargs: object) -> None:
        pass

    async def periodic(unused: object, stop: asyncio.Event, **kwargs: object) -> None:
        await stop.wait()

    monkeypatch.setattr(composition, "_await_database_maintenance_batch", startup)
    monkeypatch.setattr(composition, "await_scheduled_reconciliation_batch", startup)
    monkeypatch.setattr(composition, "run_database_maintenance_until_shutdown", periodic)
    monkeypatch.setattr(composition, "run_scheduled_reconciliation_until_shutdown", periodic)
    monkeypatch.setattr(composition, "pump_scheduler_until_shutdown", periodic)


@pytest.mark.asyncio
async def test_final_job_pass_timeout_retains_child_and_fences_resource_close(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daemon, effects = _daemon(monkeypatch)
    _runtime_fakes(daemon, monkeypatch)
    final_started = asyncio.Event()
    final_finished = asyncio.Event()
    release = asyncio.Event()

    class Supervisor(FakeSupervisor):
        def __init__(self) -> None:
            self.calls = 0

        async def run_once(self) -> int:
            self.calls += 1
            if self.calls == 1:
                return 0
            final_started.set()
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                current = asyncio.current_task()
                assert current is not None
                current.uncancel()
                await release.wait()
            final_finished.set()
            return 0

    async def serve(unused_apps: object, unused_settings: object, stop: asyncio.Event) -> None:
        stop.set()
        await stop.wait()

    daemon.job_supervisor = cast(JobSupervisor, Supervisor())
    serving = asyncio.create_task(
        composition._serve_composed(
            daemon,
            serve_applications=serve,
            scheduler_pump_interval_ms=10,
            drain_timeout_ms=100,
        )
    )
    try:
        await asyncio.wait_for(final_started.wait(), timeout=1)
        with pytest.raises(composition.DaemonDrainError):
            await asyncio.wait_for(serving, timeout=1)
        assert daemon.pending_runtime_task_count == 1
        assert not final_finished.is_set()
        with pytest.raises(composition.DaemonDrainError):
            await daemon.close(timeout_ms=10)
        assert not final_finished.is_set()
        assert "database_closed" not in effects
        assert "lease_released" not in effects
    finally:
        release.set()
        await asyncio.wait_for(final_finished.wait(), timeout=1)
        if daemon._close_task is not None:
            await asyncio.wait_for(
                asyncio.gather(daemon._close_task, return_exceptions=True), timeout=1
            )
        await daemon.close(timeout_ms=100)
    assert "STOPPED" not in effects


@pytest.mark.asyncio
async def test_required_task_failure_joins_sibling_before_returning(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daemon, effects = _daemon(monkeypatch)
    _runtime_fakes(daemon, monkeypatch)
    supervisor_started = asyncio.Event()
    cleanup_started = asyncio.Event()
    release = asyncio.Event()

    class Supervisor(FakeSupervisor):
        async def run(self, stop: asyncio.Event) -> None:
            supervisor_started.set()
            try:
                await asyncio.Event().wait()
            finally:
                cleanup_started.set()
                await release.wait()
                effects.append("supervisor_joined")

    async def fail_listener(*args: object) -> None:
        await supervisor_started.wait()
        raise RuntimeError("synthetic required task failure")

    daemon.job_supervisor = cast(JobSupervisor, Supervisor())
    serving = asyncio.create_task(
        composition._serve_composed(
            daemon,
            serve_applications=fail_listener,
            scheduler_pump_interval_ms=10,
            drain_timeout_ms=500,
        )
    )
    try:
        await asyncio.wait_for(cleanup_started.wait(), timeout=1)
        assert not serving.done()
        assert "database_closed" not in effects
        release.set()
        with pytest.raises(RuntimeError, match="required daemon runtime task failed"):
            await asyncio.wait_for(serving, timeout=1)
        assert daemon.pending_runtime_task_count == 0
        await daemon.close(timeout_ms=100)
        assert effects.index("supervisor_joined") < effects.index("emergency_closed")
    finally:
        release.set()
        await asyncio.wait_for(asyncio.gather(serving, return_exceptions=True), timeout=1)
        await daemon.close(timeout_ms=100)


@pytest.mark.asyncio
async def test_resistant_resource_close_is_retained_without_repeated_cancellation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daemon, effects = _daemon(monkeypatch)
    entered = asyncio.Event()
    release = asyncio.Event()

    class Transport(FakeTransport):
        async def aclose(self) -> None:
            entered.set()
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                current = asyncio.current_task()
                assert current is not None
                current.uncancel()
                await release.wait()
            self.effects.append(self.name)

    daemon.observer_transport = cast(
        composition._ClosableProviderTransport, Transport(effects, "observer_closed")
    )
    try:
        with pytest.raises(composition.DaemonDrainError):
            await daemon.close(timeout_ms=10)
        await asyncio.wait_for(entered.wait(), timeout=1)
        await asyncio.sleep(0)
        with pytest.raises(composition.DaemonDrainError):
            await daemon.close(timeout_ms=10)
        assert "database_closed" not in effects
        assert "lease_released" not in effects
        assert daemon._close_task is not None and not daemon._close_task.done()
    finally:
        release.set()
        assert daemon._close_task is not None
        await asyncio.wait_for(daemon._close_task, timeout=1)
    assert daemon._closed
    assert "STOPPED" not in effects


@pytest.mark.asyncio
async def test_failed_batch_drain_fences_close_after_runtime_caller_has_exited(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daemon, effects = _daemon(monkeypatch)

    class Supervisor(FakeSupervisor):
        pending_task_count = 1
        drain_failed = True

        async def cancel_and_drain(self, *, timeout_ms: int | None = None) -> None:
            if self.pending_task_count:
                raise TaskBatchDrainError(self.pending_task_count)

    supervisor = Supervisor()
    daemon.job_supervisor = cast(JobSupervisor, supervisor)
    with pytest.raises(TaskBatchDrainError):
        await daemon.close(timeout_ms=100)
    assert daemon.pending_runtime_task_count == 0
    closed_after_failure = daemon._closed
    assert not closed_after_failure
    assert effects == ["DRAINING", "FAILED_CLOSED"]
    supervisor.pending_task_count = 0
    await daemon.close(timeout_ms=100)
    assert daemon._closed
    assert "STOPPED" not in effects


@pytest.mark.asyncio
async def test_resource_close_failure_retains_database_and_lease(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    daemon, effects = _daemon(monkeypatch)

    class Transport(FakeTransport):
        async def aclose(self) -> None:
            raise RuntimeError("synthetic resource close failure")

    daemon.observer_transport = cast(
        composition._ClosableProviderTransport, Transport(effects, "observer_closed")
    )
    with pytest.raises(RuntimeError, match="synthetic resource close failure"):
        await daemon.close(timeout_ms=100)
    closed_after_failure = daemon._closed
    assert not closed_after_failure
    assert "database_closed" not in effects
    assert "lease_released" not in effects
    assert daemon.health.status == "FAILED_CLOSED"
    daemon.observer_transport = cast(
        composition._ClosableProviderTransport, FakeTransport(effects, "observer_closed")
    )
    await daemon.close(timeout_ms=100)
    assert daemon._closed
    assert "STOPPED" not in effects


@pytest.mark.asyncio
@pytest.mark.parametrize("failure_phase", ("database", "lease", "admission"))
async def test_late_close_failure_retries_only_unfinished_phases(
    monkeypatch: pytest.MonkeyPatch,
    failure_phase: str,
) -> None:
    daemon, effects = _daemon(monkeypatch)
    attempts = {
        "drain": 0,
        "checkpoint": 0,
        "database": 0,
        "lease": 0,
        "admission": 0,
        "late_database_access": 0,
    }

    class Connection(FakeConnection):
        finalized = False
        closed = False

        def close(self) -> None:
            assert self.finalized and not self.closed
            assert not lease.released
            attempts["database"] += 1
            if failure_phase == "database" and attempts["database"] == 1:
                raise RuntimeError("synthetic late database failure")
            self.closed = True
            super().close()

    class Lease(FakeLease):
        released = False

        def release(self) -> None:
            assert connection.closed and not self.released
            attempts["lease"] += 1
            if failure_phase == "lease" and attempts["lease"] == 1:
                raise RuntimeError("synthetic late lease failure")
            self.released = True
            super().release()

    class Admission(RuntimeAdmissionController):
        def stop(self) -> None:
            assert lease.released
            attempts["admission"] += 1
            if failure_phase == "admission" and attempts["admission"] == 1:
                raise RuntimeError("synthetic late admission failure")
            super().stop()
            effects.append("admission_stopped")

    class Supervisor(FakeSupervisor):
        async def cancel_and_drain(self, *, timeout_ms: int | None = None) -> None:
            del timeout_ms
            attempts["drain"] += 1

    connection = Connection(effects)
    lease = Lease(effects)
    daemon.connection = cast(sqlite3.Connection, connection)
    daemon._lease = cast(InstallationDaemonLease, lease)
    daemon.admission = Admission()
    daemon.job_supervisor = cast(JobSupervisor, Supervisor())

    def set_state(target: object, state: str, *, now_ms: int, clean: bool = False) -> None:
        del now_ms
        assert target is connection
        if connection.finalized or connection.closed:
            attempts["late_database_access"] += 1
        assert not connection.finalized and not connection.closed
        assert clean is (state == "STOPPED")
        effects.append(state)

    def checkpoint(target: object, *, mode: str) -> None:
        assert target is connection and mode == "TRUNCATE"
        if connection.finalized or connection.closed:
            attempts["late_database_access"] += 1
        assert not connection.finalized and not connection.closed
        connection.finalized = True
        attempts["checkpoint"] += 1
        effects.append("database_finalized")

    monkeypatch.setattr(composition, "_set_system_state", set_state)
    monkeypatch.setattr(composition, "checkpoint_wal", checkpoint)

    with pytest.raises(RuntimeError, match=f"synthetic late {failure_phase} failure"):
        await daemon.close(timeout_ms=100)
    closed_after_failure = daemon._closed
    assert not closed_after_failure
    assert daemon._failed and daemon.health.status == "FAILED_CLOSED"
    assert daemon.connection is cast(sqlite3.Connection, connection)
    assert daemon._lease is cast(InstallationDaemonLease, lease)
    assert daemon._close_progress.database_finalized
    assert daemon._close_progress.database_closed is (failure_phase != "database")
    assert daemon._close_progress.lease_released is (failure_phase == "admission")
    assert not daemon._close_progress.admission_stopped
    # This durable marker covers drained DB finalization, even when later close,
    # lease release, or admission cleanup fails. Memory never reports STOPPED.
    assert effects.count("STOPPED") == 1
    first_effects = tuple(effects)

    await daemon.close(timeout_ms=100)
    expected_retry_effects = {
        "database": ["database_closed", "lease_released", "admission_stopped"],
        "lease": ["lease_released", "admission_stopped"],
        "admission": ["admission_stopped"],
    }
    assert effects == [*first_effects, *expected_retry_effects[failure_phase]]
    assert daemon._closed and daemon.health.status == "FAILED_CLOSED"
    assert attempts == {
        "drain": 1,
        "checkpoint": 1,
        "database": 2 if failure_phase == "database" else 1,
        "lease": 2 if failure_phase == "lease" else 1,
        "admission": 2 if failure_phase == "admission" else 1,
        "late_database_access": 0,
    }
    for phase in ("emergency_closed", "observer_closed", "workload_closed", "STOPPED"):
        assert effects.count(phase) == 1
    completed_effects = tuple(effects)
    await daemon.close(timeout_ms=100)
    assert tuple(effects) == completed_effects
