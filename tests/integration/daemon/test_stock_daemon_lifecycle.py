from __future__ import annotations

import asyncio
import json
import sqlite3
from pathlib import Path
from typing import Any

import httpx
import pytest

from gatehouse.admin import (
    CredentialValidationRequest,
    CredentialValidationUnavailable,
    EmergencyUnlockRequest,
    SqliteCredentialValidationService,
    load_control_capability,
)
from gatehouse.api import GatehouseAgentOperations
from gatehouse.core import FixedUtcClock
from gatehouse.credentials.emergency import EmergencyUnlockError, EmergencyUnlockState
from gatehouse.daemon import (
    DaemonAlreadyRunningError,
    DaemonApplications,
    DaemonSettings,
    FileInstallationDaemonLeaseFactory,
    compose_stock_daemon,
    composition,
    installation_state_paths,
    load_runtime_configuration,
    pump_scheduler_until_shutdown,
    run_stock_daemon,
)
from gatehouse.database import DatabaseFootprintReport, RetentionPolicy
from gatehouse.invocations import InvocationCoordinator
from gatehouse.jobs import JobCorruptionError, JobSupervisor, SqliteJobStore
from gatehouse.providers import ScriptedProviderTransport
from gatehouse.routing import SqliteRoutingCatalog
from gatehouse.scheduler import PriorityClass, WorkItem


class FakeProtector:
    def protect(self, plaintext: bytes) -> bytes:
        return b"protected:" + bytes(item ^ 0xA5 for item in plaintext)

    def unprotect(self, ciphertext: bytes) -> bytearray:
        if not ciphertext.startswith(b"protected:"):
            raise OSError("invalid protected value")
        return bytearray(item ^ 0xA5 for item in ciphertext.removeprefix(b"protected:"))


def _write_configuration(
    tmp_path: Path,
    *,
    provider: str,
    observer: str | None = None,
    include_authority: bool = True,
    include_feed: bool = False,
    interactive_client: bool = False,
) -> tuple[Path, Path]:
    source = Path(__file__).parents[3] / "config"
    config_path = tmp_path / "config.yaml"
    database_path = tmp_path / "state" / "gatehouse.db"
    workspace_root = (tmp_path / "workspace").resolve()
    workspace_root.mkdir()
    main = (source / "config.example.yaml").read_text(encoding="utf-8")
    main = main.replace(
        r"'%LOCALAPPDATA%\Gatehouse\state\gatehouse.db'",
        f"'{database_path.as_posix()}'",
    )
    scoped_workload = "\n".join(
        f"    {line}" for line in provider.replace("provider:", "workload:", 1).splitlines()
    )
    main = main.replace(
        "    workload:\n      mode: disabled\n      network_enabled: false",
        scoped_workload,
    )
    if observer is not None:
        scoped_observer = "\n".join(f"    {line}" for line in observer.splitlines())
        main = main.replace(
            "    observer:\n      mode: disabled\n      network_enabled: false",
            scoped_observer,
        )
    config_path.write_text(main, encoding="utf-8")
    if include_authority:
        clients = tmp_path / "clients"
        policies = tmp_path / "policies"
        clients.mkdir()
        policies.mkdir()
        profile = (source / "clients" / "company-watcher.example.yaml").read_text(encoding="utf-8")
        if interactive_client:
            profile = profile.replace("company-watcher", "editor-one")
            profile = profile.replace("kind: system", "kind: interactive")
            profile = profile.replace("unattended: true", "unattended: false")
            profile = profile.replace("approval_mode: deny_on_ask", "approval_mode: dashboard")
            profile = profile.replace(
                "default_priority: system_reserved",
                "default_priority: interactive",
            )
            profile = profile.replace(
                "    - watcher.scan_feed_set\n"
                "    - watcher.get_cursor\n"
                "    - watcher.commit_cursor\n"
                "    - watcher.get_previous_summary",
                "    - firecrawl.search",
            )
            profile = profile.replace(
                "firecrawl: watcher-reserved",
                "firecrawl: interactive-default",
            )
        (clients / "client.yaml").write_text(profile, encoding="utf-8")
        policy = (source / "policies" / "placement-schedule.example.yaml").read_text(
            encoding="utf-8"
        )
        policy = policy.replace(r"E:\Projects\Placement-Schedule", str(workspace_root))
        (policies / "placement.yaml").write_text(policy, encoding="utf-8")
        if include_feed:
            feeds = tmp_path / "feeds"
            feeds.mkdir()
            feed = (source / "feeds" / "placement-companies-primary.example.yaml").read_text(
                encoding="utf-8"
            )
            feed = feed.replace("timezone: Asia/Kolkata", "timezone: Etc/UTC")
            (feeds / "placement.yaml").write_text(feed, encoding="utf-8")
    return config_path, database_path


def _system_state(database_path: Path) -> tuple[int, str, int | None]:
    connection = sqlite3.connect(database_path)
    try:
        row = connection.execute(
            """
            SELECT token_epoch, daemon_state, last_clean_shutdown_at_ms
              FROM system_state WHERE singleton_id = 1
            """
        ).fetchone()
        assert row is not None
        return int(row[0]), str(row[1]), None if row[2] is None else int(row[2])
    finally:
        connection.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("provider_mode", "network_enabled"),
    (("disabled", False), ("scripted", False), ("live", True)),
)
async def test_credential_validation_composition_isolated_from_workload_transport(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    provider_mode: str,
    network_enabled: bool,
) -> None:
    manifest = tmp_path / "scripted-responses.yaml"
    manifest.write_text("responses: []\n", encoding="utf-8")
    provider = (
        f"provider:\n  mode: {provider_mode}\n  network_enabled: {str(network_enabled).lower()}"
    )
    if provider_mode == "scripted":
        provider += f"\n  scripted_responses_path: '{manifest.as_posix()}'"
    config_path, _ = _write_configuration(tmp_path, provider=provider)
    configuration = load_runtime_configuration(config_path)
    captured: dict[str, Any] = {}

    class NoNetworkTransport:
        def __init__(self) -> None:
            self.send_calls = 0
            self.closed = False

        async def send(self, request: object) -> object:
            del request
            self.send_calls += 1
            raise AssertionError("composition test attempted provider dispatch")

        async def aclose(self) -> None:
            self.closed = True

    workload_transport = NoNetworkTransport()
    observer_transport = NoNetworkTransport()
    original_coordinator = InvocationCoordinator
    original_agent_operations = GatehouseAgentOperations

    def capturing_coordinator(**kwargs: Any) -> InvocationCoordinator:
        coordinator = original_coordinator(**kwargs)
        captured["coordinator"] = coordinator
        captured["pending_approval_probe"] = kwargs.get("pending_approval_probe")
        return coordinator

    def capturing_agent_operations(**kwargs: Any) -> GatehouseAgentOperations:
        captured["pending_approval_recovery"] = kwargs.get("pending_approval_recovery")
        return original_agent_operations(**kwargs)

    class CapturingValidationService(SqliteCredentialValidationService):
        def __init__(self, connection: sqlite3.Connection, **kwargs: Any) -> None:
            captured.update(kwargs)
            captured["service"] = self
            super().__init__(connection, **kwargs)

    async def no_network_provider_transport(*args: object, **kwargs: Any) -> object:
        del args
        captured["provider_persistent_key_store"] = kwargs["persistent_key_store"]
        return workload_transport

    def no_network_observer_transport(*args: object, **kwargs: Any) -> object:
        del args
        captured["observer_persistent_key_store"] = kwargs["persistent_key_store"]
        return observer_transport

    def valid_routing(_catalog: object, *, now_ms: int) -> int:
        del now_ms
        return 1

    monkeypatch.setattr(
        composition,
        "SqliteCredentialValidationService",
        CapturingValidationService,
    )
    monkeypatch.setattr(composition, "_provider_transport", no_network_provider_transport)
    monkeypatch.setattr(composition, "_observer_transport", no_network_observer_transport)
    monkeypatch.setattr(composition, "InvocationCoordinator", capturing_coordinator)
    monkeypatch.setattr(composition, "GatehouseAgentOperations", capturing_agent_operations)
    monkeypatch.setattr(SqliteRoutingCatalog, "validate", valid_routing)

    daemon = await compose_stock_daemon(
        configuration,
        config_path=config_path,
        clock=FixedUtcClock(1_000),
        protector=FakeProtector(),
    )
    try:
        assert captured["transport"] is observer_transport
        assert captured["transport"] is not workload_transport
        assert captured["persistent_key_store"] is captured["provider_persistent_key_store"]
        assert captured["persistent_key_store"] is captured["observer_persistent_key_store"]
        assert captured["provider_mode"] == "disabled"
        assert captured["network_enabled"] is False
        assert captured["repository"].connection is daemon.connection
        assert captured["pending_approval_probe"] is not None
        recovery = captured["pending_approval_recovery"]
        assert isinstance(recovery, composition._PendingApprovalRecoveryAdapter)
        assert recovery._coordinator is captured["coordinator"]
        assert recovery._coordinator.pending_approval_probe is captured["pending_approval_probe"]
        assert daemon.observation_loop is None
        assert daemon.maintenance_interval_ms == 15 * 60 * 1_000
        assert daemon.reconciliation_quick_interval_ms == 6 * 60 * 60 * 1_000
        assert daemon.reconciliation_full_interval_ms == 7 * 24 * 60 * 60 * 1_000
        assert daemon.reconciliation_maximum_scopes == 20
        assert daemon.reconciliation_maximum_wall_duration_ms == 30_000
        assert daemon.reconciliation_policy.absolute_tolerance_units == 5
        assert str(daemon.reconciliation_policy.relative_tolerance) == "0.02"
        assert daemon.reconciliation_policy.maximum_snapshot_age_ms == 30 * 60 * 1_000
        assert daemon.retention_policy.detailed_metadata_age_ms == 60 * 24 * 60 * 60 * 1_000
        assert daemon.retention_policy.feedback_age_ms == 60 * 24 * 60 * 60 * 1_000
        assert daemon.retention_policy.closed_alert_age_ms == 60 * 24 * 60 * 60 * 1_000
        assert daemon.retention_policy.debug_excerpt_age_ms == 72 * 60 * 60 * 1_000
        assert daemon.retention_policy.daily_aggregate_age_ms == 365 * 24 * 60 * 60 * 1_000
        assert daemon.retention_policy.closed_admin_session_age_ms == 7 * 24 * 60 * 60 * 1_000
        assert daemon.retention_policy.completed_approval_age_ms == 180 * 24 * 60 * 60 * 1_000
        service = captured["service"]
        with pytest.raises(CredentialValidationUnavailable):
            await service.validate_credential(
                "cred_no_dispatch",
                CredentialValidationRequest(expected_generation=1),
                "adm_no_dispatch",
            )
        assert workload_transport.send_calls == 0
        assert observer_transport.send_calls == 0
    finally:
        await daemon.close()
    assert workload_transport.closed is True
    assert observer_transport.closed is True


@pytest.mark.asyncio
async def test_close_attempts_every_cleanup_and_preserves_the_first_cancellation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path, database_path = _write_configuration(
        tmp_path,
        provider="provider:\n  mode: disabled\n  network_enabled: false",
    )
    configuration = load_runtime_configuration(config_path)
    cleanup_calls: list[str] = []

    class RecordingTransport:
        def __init__(self, name: str, *, error: BaseException | None = None) -> None:
            self.name = name
            self.error = error
            self.closed = False

        async def send(self, request: object) -> object:
            del request
            raise AssertionError("lifecycle cleanup test attempted provider dispatch")

        async def aclose(self) -> None:
            cleanup_calls.append(self.name)
            self.closed = True
            if self.error is not None:
                raise self.error

    workload_transport = RecordingTransport("workload")
    observer_error = RuntimeError("observer-close-failed")
    observer_transport = RecordingTransport("observer", error=observer_error)

    async def no_network_provider_transport(*args: object, **kwargs: Any) -> object:
        del args, kwargs
        return workload_transport

    def no_network_observer_transport(*args: object, **kwargs: Any) -> object:
        del args, kwargs
        return observer_transport

    monkeypatch.setattr(composition, "_provider_transport", no_network_provider_transport)
    monkeypatch.setattr(composition, "_observer_transport", no_network_observer_transport)
    daemon = await compose_stock_daemon(
        configuration,
        config_path=config_path,
        clock=FixedUtcClock(1_000),
        protector=FakeProtector(),
    )

    first_error = asyncio.CancelledError("emergency-close-cancelled")
    notification_error = RuntimeError("notification-close-failed")

    async def fail_emergency_close(_service: object) -> None:
        cleanup_calls.append("emergency")
        raise first_error

    class FailingNotifications:
        def close(self, *, maximum_wait_seconds: float) -> None:
            assert maximum_wait_seconds == 0.25
            cleanup_calls.append("notification")
            raise notification_error

    checkpoint_calls: list[str] = []

    def record_checkpoint(connection: object, *, mode: str = "PASSIVE") -> tuple[int, int, int]:
        del connection
        checkpoint_calls.append(mode)
        return (0, 0, 0)

    monkeypatch.setattr(
        type(daemon.credential_lifecycle),
        "close_emergency",
        fail_emergency_close,
    )
    failing_notifications: Any = FailingNotifications()
    daemon.approval_notifications = failing_notifications
    monkeypatch.setattr(composition, "checkpoint_wal", record_checkpoint)

    with pytest.raises(asyncio.CancelledError) as captured:
        await daemon.close()

    assert captured.value is first_error
    assert cleanup_calls == ["emergency", "notification", "observer", "workload"]
    assert observer_transport.closed is True
    assert workload_transport.closed is True
    assert checkpoint_calls == []
    assert daemon.admission.state.value == "STOPPED"
    assert daemon._closed is True
    with pytest.raises(sqlite3.ProgrammingError):
        daemon.connection.execute("SELECT 1")
    _, state, clean_shutdown_at_ms = _system_state(database_path)
    assert state == "DRAINING"
    assert clean_shutdown_at_ms is None

    replacement_lease = FileInstallationDaemonLeaseFactory().acquire(
        installation_state_paths(configuration.main.database.path).daemon_lease
    )
    replacement_lease.release()


@pytest.mark.asyncio
async def test_live_observer_uses_persistent_custody_and_a_separate_network_switch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path, _ = _write_configuration(
        tmp_path,
        provider="provider:\n  mode: disabled\n  network_enabled: false",
        observer="observer:\n  mode: live\n  network_enabled: true",
    )
    configuration = load_runtime_configuration(config_path)
    captured: dict[str, Any] = {}

    class NoNetworkTransport:
        def __init__(self) -> None:
            self.closed = False

        async def send(self, request: object) -> object:
            del request
            raise AssertionError("composition test attempted provider dispatch")

        async def aclose(self) -> None:
            self.closed = True

    workload_transport = NoNetworkTransport()
    observer_transport = NoNetworkTransport()

    class CapturingValidationService(SqliteCredentialValidationService):
        def __init__(self, connection: sqlite3.Connection, **kwargs: Any) -> None:
            captured.update(kwargs)
            super().__init__(connection, **kwargs)

    async def no_network_provider_transport(*args: object, **kwargs: Any) -> object:
        del args
        captured["workload_transport_key_store"] = kwargs["transport_key_store"]
        captured["provider_persistent_key_store"] = kwargs["persistent_key_store"]
        return workload_transport

    def no_network_observer_transport(*args: object, **kwargs: Any) -> object:
        del args
        captured["observer_persistent_key_store"] = kwargs["persistent_key_store"]
        return observer_transport

    monkeypatch.setattr(
        composition,
        "SqliteCredentialValidationService",
        CapturingValidationService,
    )
    monkeypatch.setattr(composition, "_provider_transport", no_network_provider_transport)
    monkeypatch.setattr(composition, "_observer_transport", no_network_observer_transport)

    daemon = await compose_stock_daemon(
        configuration,
        config_path=config_path,
        clock=FixedUtcClock(1_000),
        protector=FakeProtector(),
    )
    try:
        assert captured["transport"] is observer_transport
        assert captured["provider_mode"] == "live"
        assert captured["network_enabled"] is True
        assert captured["persistent_key_store"] is captured["observer_persistent_key_store"]
        assert captured["persistent_key_store"] is captured["provider_persistent_key_store"]
        assert captured["persistent_key_store"] is not captured["workload_transport_key_store"]
        assert daemon.observation_loop is not None
    finally:
        await daemon.close()
    assert workload_transport.closed is True
    assert observer_transport.closed is True


@pytest.mark.asyncio
async def test_competing_daemon_fails_before_recovery_provider_or_listener_work(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path, database_path = _write_configuration(
        tmp_path,
        provider="provider:\n  mode: disabled\n  network_enabled: false",
    )
    protector = FakeProtector()
    configuration = load_runtime_configuration(config_path)
    owner = await compose_stock_daemon(
        configuration,
        config_path=config_path,
        protector=protector,
    )
    initial_state = _system_state(database_path)
    assert initial_state[:2] == (1, "RECOVERING")
    forbidden_calls: list[str] = []

    def forbidden_recovery(*args: object, **kwargs: object) -> object:
        del args, kwargs
        forbidden_calls.append("recovery")
        raise AssertionError("competing daemon reached recovery")

    async def forbidden_provider(*args: object, **kwargs: object) -> object:
        del args, kwargs
        forbidden_calls.append("provider")
        raise AssertionError("competing daemon reached provider construction")

    listener_called = False

    async def forbidden_listener(
        applications: DaemonApplications,
        settings: DaemonSettings,
        shutdown: asyncio.Event,
    ) -> None:
        del applications, settings, shutdown
        nonlocal listener_called
        listener_called = True

    try:
        with monkeypatch.context() as scoped:
            scoped.setattr(composition, "recover_startup", forbidden_recovery)
            scoped.setattr(composition, "_provider_transport", forbidden_provider)
            with pytest.raises(DaemonAlreadyRunningError):
                await compose_stock_daemon(
                    configuration,
                    config_path=config_path,
                    protector=protector,
                )
            assert (
                await run_stock_daemon(
                    config_path,
                    protector=protector,
                    serve_applications=forbidden_listener,
                    install_signal_handlers=False,
                )
                == 1
            )
        assert forbidden_calls == []
        assert listener_called is False
        assert _system_state(database_path) == initial_state
    finally:
        await owner.close()

    replacement = await compose_stock_daemon(
        configuration,
        config_path=config_path,
        protector=protector,
    )
    try:
        assert _system_state(database_path)[0] == 2
    finally:
        await replacement.close()


@pytest.mark.asyncio
async def test_composition_failure_releases_the_installation_lease(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path, database_path = _write_configuration(
        tmp_path,
        provider="provider:\n  mode: disabled\n  network_enabled: false",
    )
    configuration = load_runtime_configuration(config_path)

    def fail_recovery(*args: object, **kwargs: object) -> object:
        del args, kwargs
        raise RuntimeError("injected recovery failure")

    monkeypatch.setattr(composition, "recover_startup", fail_recovery)
    with pytest.raises(RuntimeError, match="injected recovery failure"):
        await compose_stock_daemon(
            configuration,
            config_path=config_path,
            protector=FakeProtector(),
        )

    lease = FileInstallationDaemonLeaseFactory().acquire(
        installation_state_paths(database_path).daemon_lease
    )
    lease.release()


@pytest.mark.asyncio
async def test_disabled_stock_daemon_recovers_once_serves_control_and_stops_cleanly(
    tmp_path: Path,
) -> None:
    config_path, database_path = _write_configuration(
        tmp_path,
        provider="provider:\n  mode: disabled\n  network_enabled: false",
    )
    protector = FakeProtector()
    observed_epochs: list[int] = []

    async def inspect_runtime(
        applications: DaemonApplications,
        settings: DaemonSettings,
        shutdown: asyncio.Event,
    ) -> None:
        agent_transport = httpx.ASGITransport(app=applications.agent)
        async with httpx.AsyncClient(
            transport=agent_transport,
            base_url=f"http://127.0.0.1:{settings.agent_port}",
        ) as agent:
            readiness = await agent.get("/health/ready")
        assert readiness.status_code == 503
        assert readiness.json()["status"] == "DEGRADED_NO_PROVIDER"

        paths = installation_state_paths(database_path)
        capability = load_control_capability(
            paths.control_capability,
            protector=protector,
        )
        admin_transport = httpx.ASGITransport(app=applications.admin)
        async with httpx.AsyncClient(
            transport=admin_transport,
            base_url=f"http://127.0.0.1:{settings.admin_port}",
            headers={"x-gatehouse-control-capability": capability},
        ) as admin:
            status = await admin.get("/v1/control/status")
            launched = await admin.post(
                "/v1/control/sessions",
                json={
                    "client": "company-watcher",
                    "workspace": "placement-schedule",
                    "working_directory": str((config_path.parent / "workspace").resolve()),
                    "non_interactive": True,
                },
            )
            assert launched.status_code == 201
            revoked = await admin.post(
                f"/v1/control/sessions/{launched.json()['session_id']}/revoke"
            )
            assert revoked.status_code == 200
            assert revoked.json()["state"] == "REVOKED"
        assert status.status_code == 200
        assert status.json()["status"] == "DEGRADED_NO_PROVIDER"
        connection = sqlite3.connect(database_path)
        try:
            budget = connection.execute(
                "SELECT budget_json FROM sessions WHERE session_id = ?",
                (launched.json()["session_id"],),
            ).fetchone()
            assert budget is not None
            assert json.loads(str(budget[0])) == {"credits": 200, "requests": 30}
        finally:
            connection.close()
        observed_epochs.append(_system_state(database_path)[0])
        task_names = [task.get_name() for task in asyncio.all_tasks() if not task.done()]
        assert task_names.count("gatehouse-scheduler-pump") == 1
        assert task_names.count("gatehouse-job-supervisor") == 1
        assert task_names.count("gatehouse-database-maintenance") == 1
        assert task_names.count("gatehouse-scheduled-reconciliation") == 1
        shutdown.set()

    for expected_epoch in (1, 2):
        assert (
            await run_stock_daemon(
                config_path,
                protector=protector,
                serve_applications=inspect_runtime,
                install_signal_handlers=False,
            )
            == 0
        )
        epoch, state, clean_at = _system_state(database_path)
        assert epoch == expected_epoch
        assert state == "STOPPED"
        assert clean_at is not None

    assert observed_epochs == [1, 2]


@pytest.mark.asyncio
async def test_stock_composition_clean_shutdown_relocks_active_emergency_unlock(
    tmp_path: Path,
) -> None:
    config_path, database_path = _write_configuration(
        tmp_path,
        provider="provider:\n  mode: disabled\n  network_enabled: false",
        interactive_client=True,
    )
    protector = FakeProtector()
    clock = FixedUtcClock(1_800_000_000_000)
    configuration = load_runtime_configuration(config_path)
    first = await compose_stock_daemon(
        configuration,
        config_path=config_path,
        protector=protector,
        clock=clock,
    )
    unlock_id = ""
    credential_id = ""
    principal_id = ""
    quota_scope_id = ""
    session_id = ""
    root_run_id = ""
    pool_id = ""
    try:
        first.mark_recovery_complete()
        capability = load_control_capability(
            installation_state_paths(database_path).control_capability,
            protector=protector,
        )
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=first.applications.admin),
            base_url=f"http://127.0.0.1:{first.settings.admin_port}",
            headers={"x-gatehouse-control-capability": capability},
        ) as admin:
            launched = await admin.post(
                "/v1/control/sessions",
                json={
                    "client": "editor-one",
                    "workspace": "placement-schedule",
                    "working_directory": str((config_path.parent / "workspace").resolve()),
                    "non_interactive": False,
                },
            )
        assert launched.status_code == 201
        session_id = str(launched.json()["session_id"])
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=first.applications.agent),
            base_url=f"http://127.0.0.1:{first.settings.agent_port}",
        ) as agent:
            exchanged = await agent.post(
                "/v1/sessions/exchange",
                json={
                    "session_id": session_id,
                    "bootstrap_capability": launched.json()["bootstrap_capability"],
                    "client_nonce": "stock-emergency-shutdown",
                },
            )
            assert exchanged.status_code == 200
            root_run = await agent.post(
                "/v1/root-runs",
                headers={
                    "authorization": f"Bearer {exchanged.json()['access_token']}",
                },
                json={},
            )
        assert root_run.status_code == 201
        root_run_id = str(root_run.json()["root_run_id"])
        pool = first.connection.execute(
            "SELECT pool_id FROM pools WHERE service_id = ? AND alias = ?",
            ("firecrawl", "emergency-locked"),
        ).fetchone()
        assert pool is not None
        pool_id = str(pool["pool_id"])

        secret = bytearray(b"FAKE-STOCK-EMERGENCY-SHUTDOWN-NOT-A-REAL-KEY-123456")
        secret_length = len(secret)
        unlocked = await first.credential_lifecycle.unlock_emergency(
            EmergencyUnlockRequest(
                mutation_id="mutation-stock-emergency-shutdown-0001",
                service="firecrawl",
                pool_id=pool_id,
                session_id=session_id,
                root_run_id=root_run_id,
                alias="stock-shutdown-emergency",
                reason="synthetic clean-shutdown relock verification",
                duration_ms=60_000,
                maximum_requests=2,
                maximum_credits=2,
                maximum_concurrency=1,
            ),
            secret,
            "synthetic-stock-admin",
        )
        assert secret == bytearray(secret_length)
        assert unlocked.state == "ACTIVE"
        unlock_id = unlocked.unlock_id
        credential_id = unlocked.credential_id
        principal_id = unlocked.principal_id
        quota_scope_id = unlocked.quota_scope_id
        first_manager = first.credential_lifecycle._emergency  # noqa: SLF001
        assert first_manager is not None
        assert (await first_manager.status()).state is EmergencyUnlockState.ACTIVE
    finally:
        await first.close()

    connection = sqlite3.connect(database_path)
    try:
        assert connection.execute(
            "SELECT state FROM emergency_unlock_records WHERE unlock_id = ?",
            (unlock_id,),
        ).fetchone() == ("RELOCKED",)
        assert connection.execute(
            "SELECT COUNT(*) FROM credentials WHERE credential_id = ?",
            (credential_id,),
        ).fetchone() == (0,)
        assert connection.execute(
            "SELECT COUNT(*) FROM principals WHERE principal_id = ?",
            (principal_id,),
        ).fetchone() == (0,)
        assert connection.execute(
            "SELECT COUNT(*) FROM quota_scopes WHERE quota_scope_id = ?",
            (quota_scope_id,),
        ).fetchone() == (0,)
    finally:
        connection.close()

    fresh = await compose_stock_daemon(
        configuration,
        config_path=config_path,
        protector=protector,
        clock=clock,
    )
    try:
        views = await fresh.credential_lifecycle.list_emergency_unlocks(limit=10)
        assert len(views) == 1
        assert views[0].unlock_id == unlock_id
        assert views[0].state == "RELOCKED"
        assert views[0].remaining_requests == 0
        assert views[0].remaining_credits == 0
        assert views[0].remaining_concurrency == 0

        fresh_manager = fresh.credential_lifecycle._emergency  # noqa: SLF001
        assert fresh_manager is not None
        assert (await fresh_manager.status()).state is EmergencyUnlockState.LOCKED
        with pytest.raises(
            EmergencyUnlockError,
            match="emergency unlock is unavailable",
        ):
            await fresh_manager.project(
                service_id="firecrawl",
                pool_name="emergency-locked",
                session_id=session_id,
                root_run_id=root_run_id,
                automatic=False,
            )
    finally:
        await fresh.close()


@pytest.mark.asyncio
async def test_operational_health_waits_for_initial_supervisor_recovery_pass(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path, database_path = _write_configuration(
        tmp_path,
        provider="provider:\n  mode: disabled\n  network_enabled: false",
    )
    original_run_once = JobSupervisor.run_once
    original_maintenance = composition._await_database_maintenance_batch
    observed_states: list[str] = []
    startup_steps: list[str] = []

    async def observe_maintenance(
        database_path_argument: Path,
        *,
        busy_timeout_ms: int,
        now_ms: int,
        policy: RetentionPolicy,
        maximum_database_bytes: int | None = None,
    ) -> DatabaseFootprintReport | None:
        startup_steps.append("maintenance")
        observed_states.append(_system_state(database_path)[1])
        return await original_maintenance(
            database_path_argument,
            busy_timeout_ms=busy_timeout_ms,
            now_ms=now_ms,
            policy=policy,
            maximum_database_bytes=maximum_database_bytes,
        )

    async def observe_recovery(self: JobSupervisor) -> int:
        startup_steps.append("supervisor")
        observed_states.append(_system_state(database_path)[1])
        return await original_run_once(self)

    monkeypatch.setattr(composition, "_await_database_maintenance_batch", observe_maintenance)
    monkeypatch.setattr(JobSupervisor, "run_once", observe_recovery)

    async def inspect_after_recovery(
        applications: DaemonApplications,
        settings: DaemonSettings,
        shutdown: asyncio.Event,
    ) -> None:
        transport = httpx.ASGITransport(app=applications.agent)
        async with httpx.AsyncClient(
            transport=transport,
            base_url=f"http://127.0.0.1:{settings.agent_port}",
        ) as client:
            readiness = await client.get("/health/ready")
        assert readiness.json()["status"] == "DEGRADED_NO_PROVIDER"
        assert observed_states[0] == "RECOVERING"
        assert startup_steps[:2] == ["maintenance", "supervisor"]
        shutdown.set()

    assert (
        await run_stock_daemon(
            config_path,
            protector=FakeProtector(),
            serve_applications=inspect_after_recovery,
            drain_timeout_ms=50,
            install_signal_handlers=False,
        )
        == 0
    )
    assert observed_states[:2] == ["RECOVERING", "RECOVERING"]


@pytest.mark.asyncio
async def test_recovered_due_job_is_reconciled_before_ready_is_advertised(
    tmp_path: Path,
) -> None:
    manifest = tmp_path / "crawl-responses.json"

    def write_manifest(*, status: str) -> None:
        responses: dict[str, list[dict[str, object]]] = {
            "firecrawl.crawl.status": [
                {
                    "status_code": 200,
                    "data": (
                        {"status": "completed", "creditsUsed": 3}
                        if status == "completed"
                        else {"status": status}
                    ),
                }
            ]
        }
        if status != "completed":
            responses["firecrawl.crawl.start"] = [
                {
                    "status_code": 200,
                    "data": {"success": True, "id": "provider-crawl-one"},
                }
            ]
        manifest.write_text(
            json.dumps({"schema_version": 1, "responses": responses}),
            encoding="utf-8",
        )

    write_manifest(status="scraping")
    config_path, database_path = _write_configuration(
        tmp_path,
        provider=(
            "provider:\n"
            "  mode: scripted\n"
            "  network_enabled: false\n"
            f"  scripted_responses_path: '{manifest.as_posix()}'"
        ),
        interactive_client=True,
    )
    client_path = tmp_path / "clients" / "client.yaml"
    client_path.write_text(
        client_path.read_text(encoding="utf-8").replace(
            "    - firecrawl.search",
            "    - firecrawl.crawl.start\n"
            "    - firecrawl.crawl.status\n"
            "    - firecrawl.crawl.cancel\n"
            "    - jobs.status\n"
            "    - jobs.await\n"
            "    - jobs.cancel",
        ),
        encoding="utf-8",
    )
    protector = FakeProtector()
    created_job_ids: list[str] = []
    old_access_tokens: list[str] = []

    async def create_crawl(
        applications: DaemonApplications,
        settings: DaemonSettings,
        shutdown: asyncio.Event,
    ) -> None:
        capability = load_control_capability(
            installation_state_paths(database_path).control_capability,
            protector=protector,
        )
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=applications.admin),
            base_url=f"http://127.0.0.1:{settings.admin_port}",
            headers={"x-gatehouse-control-capability": capability},
        ) as admin:
            launched = await admin.post(
                "/v1/control/sessions",
                json={
                    "client": "editor-one",
                    "workspace": "placement-schedule",
                    "working_directory": str((config_path.parent / "workspace").resolve()),
                    "non_interactive": False,
                },
            )
        assert launched.status_code == 201
        launch = launched.json()
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=applications.agent),
            base_url=f"http://127.0.0.1:{settings.agent_port}",
        ) as agent:
            exchanged = await agent.post(
                "/v1/sessions/exchange",
                json={
                    "session_id": launch["session_id"],
                    "bootstrap_capability": launch["bootstrap_capability"],
                    "client_nonce": "crawl-restart-001",
                },
            )
            old_access_tokens.append(str(exchanged.json()["access_token"]))
            authorization = {"authorization": f"Bearer {old_access_tokens[-1]}"}
            root_run = await agent.post("/v1/root-runs", headers=authorization, json={})
            invocation = await agent.post(
                "/v1/invocations",
                headers=authorization,
                json={
                    "service": "firecrawl",
                    "operation": "crawl.start",
                    "input": {
                        "url": "https://example.com/jobs",
                        "include_paths": ["^/jobs"],
                        "maximum_pages": 2,
                        "maximum_depth": 1,
                        "purpose": "multi_page_job_extraction",
                        "data_classification": ["public_job_data"],
                    },
                    "context": {"root_run_id": root_run.json()["root_run_id"]},
                    "execution": {"wait_up_to_ms": 5_000},
                },
            )
        assert invocation.status_code == 200
        created_job_ids.append(str(invocation.json()["job_id"]))
        shutdown.set()

    assert (
        await run_stock_daemon(
            config_path,
            protector=protector,
            clock=FixedUtcClock(1_000),
            serve_applications=create_crawl,
            drain_timeout_ms=250,
            install_signal_handlers=False,
        )
        == 0
    )
    assert created_job_ids
    connection = sqlite3.connect(database_path)
    try:
        assert (
            connection.execute(
                "SELECT state FROM jobs WHERE job_id = ?",
                (created_job_ids[0],),
            ).fetchone()[0]
            == "RUNNING"
        )
    finally:
        connection.close()

    write_manifest(status="completed")

    async def inspect_recovered(
        applications: DaemonApplications,
        settings: DaemonSettings,
        shutdown: asyncio.Event,
    ) -> None:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=applications.agent),
            base_url=f"http://127.0.0.1:{settings.agent_port}",
        ) as agent:
            readiness = await agent.get("/health/ready")
            stale_heartbeat = await agent.post(
                "/v1/sessions/heartbeat",
                headers={"authorization": f"Bearer {old_access_tokens[0]}"},
                json={},
            )
        assert readiness.status_code == 200
        assert readiness.json()["status"] == "READY"
        assert stale_heartbeat.status_code == 401
        connection = sqlite3.connect(database_path)
        try:
            assert (
                connection.execute(
                    "SELECT state FROM jobs WHERE job_id = ?",
                    (created_job_ids[0],),
                ).fetchone()[0]
                == "SUCCEEDED"
            )
            request_id = connection.execute(
                "SELECT request_id FROM jobs WHERE job_id = ?",
                (created_job_ids[0],),
            ).fetchone()[0]
            assert connection.execute(
                """
                SELECT state, actual_units FROM quota_reservations
                 WHERE request_id = ?
                """,
                (request_id,),
            ).fetchall() == [("RECONCILED", 3)]
            assert connection.execute(
                """
                SELECT state, actual_units FROM budget_reservations
                 WHERE request_id = ?
                """,
                (request_id,),
            ).fetchall() == [("RECONCILED", 3)]
        finally:
            connection.close()
        shutdown.set()

    assert (
        await run_stock_daemon(
            config_path,
            protector=protector,
            clock=FixedUtcClock(31_001),
            serve_applications=inspect_recovered,
            drain_timeout_ms=250,
            install_signal_handlers=False,
        )
        == 0
    )


@pytest.mark.asyncio
async def test_shutdown_bounds_a_stuck_supervisor_drain_and_closes_cleanly(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path, database_path = _write_configuration(
        tmp_path,
        provider="provider:\n  mode: disabled\n  network_enabled: false",
    )
    supervisor_entered = asyncio.Event()
    supervisor_cancelled = asyncio.Event()
    calls = 0
    drain_requested_at: float | None = None

    async def block_after_initial_pass(self: JobSupervisor) -> int:
        del self
        nonlocal calls
        calls += 1
        if calls == 1:
            return 0
        supervisor_entered.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            supervisor_cancelled.set()
            raise
        return 0

    monkeypatch.setattr(JobSupervisor, "run_once", block_after_initial_pass)

    async def request_drain(
        applications: DaemonApplications,
        settings: DaemonSettings,
        stop: asyncio.Event,
    ) -> None:
        del applications, settings
        nonlocal drain_requested_at
        await supervisor_entered.wait()
        drain_requested_at = asyncio.get_running_loop().time()
        stop.set()
        await stop.wait()

    result = await run_stock_daemon(
        config_path,
        protector=FakeProtector(),
        serve_applications=request_drain,
        drain_timeout_ms=50,
        install_signal_handlers=False,
    )
    finished_at = asyncio.get_running_loop().time()

    assert result == 0
    assert drain_requested_at is not None
    assert finished_at - drain_requested_at < 1
    assert supervisor_cancelled.is_set()
    assert _system_state(database_path)[1] == "STOPPED"


@pytest.mark.asyncio
async def test_drain_deadline_bounds_a_nonquiescent_scheduler_and_stops_listener(
    tmp_path: Path,
) -> None:
    config_path, _ = _write_configuration(
        tmp_path,
        provider="provider:\n  mode: disabled\n  network_enabled: false",
    )
    configuration = load_runtime_configuration(config_path)
    daemon = await compose_stock_daemon(
        configuration,
        config_path=config_path,
        protector=FakeProtector(),
        clock=FixedUtcClock(1_000),
    )
    client_row = daemon.connection.execute("SELECT client_id FROM clients LIMIT 1").fetchone()
    assert client_row is not None
    ticket = await daemon.scheduler.enqueue(
        WorkItem(
            request_id="held-through-drain",
            session_id="session-through-drain",
            client_id=str(client_row[0]),
            service_id="firecrawl",
            priority=PriorityClass.INTERACTIVE,
            enqueued_at_ms=1_000,
            deadline_ms=2_000,
        )
    )
    permit = await ticket.wait()
    listener_stopped = asyncio.Event()

    async def request_drain_and_wait_for_stop(
        applications: DaemonApplications,
        settings: DaemonSettings,
        lifecycle: asyncio.Event,
    ) -> None:
        del applications, settings
        try:
            lifecycle.set()
            await lifecycle.wait()
        finally:
            listener_stopped.set()

    started = asyncio.get_running_loop().time()
    try:
        await composition._serve_composed(
            daemon,
            serve_applications=request_drain_and_wait_for_stop,
            scheduler_pump_interval_ms=10,
            drain_timeout_ms=50,
        )
        elapsed = asyncio.get_running_loop().time() - started
        assert elapsed < 1
        assert listener_stopped.is_set()
        assert (await daemon.scheduler.snapshot()).running_total == 1
    finally:
        await daemon.scheduler.release(permit)
        await daemon.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("provider_mode", ("disabled", "scripted", "live"))
async def test_stock_watcher_is_scripted_only_and_executes_configured_order(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    provider_mode: str,
) -> None:
    manifest = tmp_path / "watcher-responses.json"
    manifest.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "responses": {
                    "firecrawl.scrape": [
                        {
                            "status_code": 200,
                            "data": {
                                "success": True,
                                "data": {"markdown": "scripted scrape"},
                                "creditsUsed": 1,
                            },
                            "provider_request_id": "watcher-scripted-scrape",
                        }
                    ],
                    "firecrawl.map": [
                        {
                            "status_code": 200,
                            "data": {
                                "success": True,
                                "links": ["https://jobs.example-ats.com/company-name/opening"],
                                "creditsUsed": 1,
                            },
                            "provider_request_id": "watcher-scripted-map",
                        }
                    ],
                },
            }
        ),
        encoding="utf-8",
    )
    provider = (
        f"provider:\n  mode: {provider_mode}\n"
        f"  network_enabled: {str(provider_mode == 'live').lower()}"
    )
    if provider_mode == "scripted":
        provider += f"\n  scripted_responses_path: '{manifest.as_posix()}'"
    config_path, database_path = _write_configuration(
        tmp_path,
        provider=provider,
        include_feed=True,
    )
    configuration = load_runtime_configuration(config_path)

    class NoNetworkTransport:
        def __init__(self) -> None:
            self.send_calls = 0
            self.closed = False

        async def send(self, request: object) -> object:
            del request
            self.send_calls += 1
            raise AssertionError("non-scripted watcher attempted provider dispatch")

        async def aclose(self) -> None:
            self.closed = True

    live_transport = NoNetworkTransport()
    if provider_mode == "live":

        async def no_network_live_transport(*args: object, **kwargs: object) -> object:
            del args, kwargs
            return live_transport

        def valid_routing(_catalog: object, *, now_ms: int) -> int:
            del now_ms
            return 1

        monkeypatch.setattr(composition, "_provider_transport", no_network_live_transport)
        monkeypatch.setattr(SqliteRoutingCatalog, "validate", valid_routing)

    protector = FakeProtector()
    daemon = await compose_stock_daemon(
        configuration,
        config_path=config_path,
        protector=protector,
        clock=FixedUtcClock(1_000),
    )
    daemon.mark_recovery_complete()
    scheduler_pump = asyncio.create_task(
        pump_scheduler_until_shutdown(
            daemon.scheduler,
            daemon.shutdown_event,
            interval_ms=10,
        ),
        name="test-stock-watcher-scheduler-pump",
    )
    try:
        capability = load_control_capability(
            installation_state_paths(database_path).control_capability,
            protector=protector,
        )
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=daemon.applications.admin),
            base_url=f"http://127.0.0.1:{daemon.settings.admin_port}",
            headers={"x-gatehouse-control-capability": capability},
        ) as admin:
            launched = await admin.post(
                "/v1/control/sessions",
                json={
                    "client": "company-watcher",
                    "workspace": "placement-schedule",
                    "working_directory": str((tmp_path / "workspace").resolve()),
                    "non_interactive": True,
                },
            )
        assert launched.status_code == 201
        launch = launched.json()
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=daemon.applications.agent),
            base_url=f"http://127.0.0.1:{daemon.settings.agent_port}",
        ) as agent:
            exchanged = await agent.post(
                "/v1/sessions/exchange",
                json={
                    "session_id": launch["session_id"],
                    "bootstrap_capability": launch["bootstrap_capability"],
                    "client_nonce": f"stock-watcher-{provider_mode}",
                },
            )
            assert exchanged.status_code == 200
            capabilities = set(exchanged.json()["capabilities"])
            expected_capabilities = (
                {
                    "watcher.scan_feed_set",
                    "watcher.get_cursor",
                    "watcher.commit_cursor",
                    "watcher.get_previous_summary",
                }
                if provider_mode == "scripted"
                else set()
            )
            assert capabilities == expected_capabilities
            assert not any(item.startswith("firecrawl.") for item in capabilities)
            authorization = {
                "authorization": f"Bearer {exchanged.json()['access_token']}",
            }
            root_run = await agent.post("/v1/root-runs", headers=authorization, json={})
            assert root_run.status_code == 201
            root_run_id = str(root_run.json()["root_run_id"])
            scanned = await agent.post(
                "/v1/watcher/feed-sets/placement-companies-primary/scan",
                headers=authorization,
                json={"root_run_id": root_run_id, "cursor": None},
            )

            if provider_mode != "scripted":
                assert scanned.status_code == 403
                assert scanned.json()["error"]["code"] == "policy_denied"
            else:
                assert isinstance(daemon.transport, ScriptedProviderTransport)
                assert scanned.status_code == 200
                result = scanned.json()
                assert result["status"] == "READY_TO_COMMIT"
                assert [item["operation"] for item in result["results"]] == [
                    "scrape",
                    "map",
                ]
                assert [item["url"] for item in result["results"]] == [
                    "https://careers.example.com/jobs",
                    "https://jobs.example-ats.com/company-name/jobs",
                ]
                assert daemon.transport.dispatch_count == 2
                committed = await agent.post(
                    "/v1/watcher/feed-sets/placement-companies-primary/cursor/commit",
                    headers=authorization,
                    json={
                        "root_run_id": root_run_id,
                        "watcher_run_id": result["watcher_run_id"],
                        "expected_version": 0,
                        "cursor_value": "stock-composition-cursor-1",
                        "cursor_sequence": 1,
                    },
                )
                assert committed.status_code == 200
                assert committed.json()["status"] == "COMMITTED"

        invocations = daemon.connection.execute(
            "SELECT operation FROM invocations ORDER BY rowid"
        ).fetchall()
        if provider_mode == "scripted":
            assert [str(row["operation"]) for row in invocations] == [
                "firecrawl.scrape",
                "firecrawl.map",
            ]
            assert (
                daemon.connection.execute("SELECT state FROM watcher_runs").fetchone()["state"]
                == "COMPLETED"
            )
            assert [
                tuple(row)
                for row in daemon.connection.execute(
                    """
                    SELECT DISTINCT p.alias, p.automatic_use
                      FROM attempts AS a
                      JOIN pools AS p ON p.pool_id = a.dispatch_pool_id
                     ORDER BY p.alias
                    """
                ).fetchall()
            ] == [("watcher-reserved", 0)]
        else:
            assert invocations == []
            assert daemon.connection.execute("SELECT COUNT(*) FROM watcher_runs").fetchone()[0] == 0
            if provider_mode == "live":
                assert live_transport.send_calls == 0
    finally:
        await daemon.close()
        await scheduler_pump
    if provider_mode == "live":
        assert live_transport.closed is True


@pytest.mark.asyncio
async def test_scripted_mode_synchronizes_routes_and_becomes_ready_without_sockets(
    tmp_path: Path,
) -> None:
    manifest = tmp_path / "responses.json"
    manifest.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "responses": {
                    "firecrawl.search": [
                        {
                            "status_code": 200,
                            "data": {"success": True, "data": [], "creditsUsed": 1},
                        }
                    ]
                },
            }
        ),
        encoding="utf-8",
    )
    config_path, database_path = _write_configuration(
        tmp_path,
        provider=(
            "provider:\n"
            "  mode: scripted\n"
            "  network_enabled: false\n"
            f"  scripted_responses_path: '{manifest.as_posix()}'"
        ),
        interactive_client=True,
    )

    async def inspect_runtime(
        applications: DaemonApplications,
        settings: DaemonSettings,
        shutdown: asyncio.Event,
    ) -> None:
        transport = httpx.ASGITransport(app=applications.agent)
        async with httpx.AsyncClient(
            transport=transport,
            base_url=f"http://127.0.0.1:{settings.agent_port}",
        ) as client:
            readiness = await client.get("/health/ready")
        assert readiness.status_code == 200
        assert readiness.json()["status"] == "READY"

        capability = load_control_capability(
            installation_state_paths(database_path).control_capability,
            protector=protector,
        )
        admin_transport = httpx.ASGITransport(app=applications.admin)
        async with httpx.AsyncClient(
            transport=admin_transport,
            base_url=f"http://127.0.0.1:{settings.admin_port}",
            headers={"x-gatehouse-control-capability": capability},
        ) as admin:
            launched = await admin.post(
                "/v1/control/sessions",
                json={
                    "client": "editor-one",
                    "workspace": "placement-schedule",
                    "working_directory": str((config_path.parent / "workspace").resolve()),
                    "non_interactive": False,
                },
            )
        assert launched.status_code == 201
        launch = launched.json()
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=applications.agent),
            base_url=f"http://127.0.0.1:{settings.agent_port}",
        ) as agent:
            exchanged = await agent.post(
                "/v1/sessions/exchange",
                json={
                    "session_id": launch["session_id"],
                    "bootstrap_capability": launch["bootstrap_capability"],
                    "client_nonce": "scripted-e2e",
                },
            )
            assert exchanged.status_code == 200
            authorization = {"authorization": f"Bearer {exchanged.json()['access_token']}"}
            root_run = await agent.post("/v1/root-runs", headers=authorization, json={})
            assert root_run.status_code == 201
            invocation = await agent.post(
                "/v1/invocations",
                headers=authorization,
                json={
                    "service": "firecrawl",
                    "operation": "search",
                    "input": {
                        "query": "graduate roles",
                        "limit": 5,
                        "purpose": "career_discovery",
                        "data_classification": ["public_web_query"],
                    },
                    "context": {"root_run_id": root_run.json()["root_run_id"]},
                    "execution": {"wait_up_to_ms": 5_000},
                },
            )
        assert invocation.status_code == 200
        assert invocation.json()["state"] == "SUCCEEDED"
        connection = sqlite3.connect(database_path)
        try:
            assert connection.execute("SELECT COUNT(*) FROM pools").fetchone()[0] == 2
            assert connection.execute(
                "SELECT DISTINCT secret_backend FROM credentials"
            ).fetchall() == [("scripted",)]
            consumed = connection.execute(
                "SELECT consumed_json FROM root_runs WHERE root_run_id = ?",
                (root_run.json()["root_run_id"],),
            ).fetchone()
            assert consumed is not None
            assert json.loads(str(consumed[0]))["credits"] == 1
        finally:
            connection.close()
        shutdown.set()

    protector = FakeProtector()
    assert (
        await run_stock_daemon(
            config_path,
            protector=protector,
            serve_applications=inspect_runtime,
            install_signal_handlers=False,
        )
        == 0
    )


@pytest.mark.asyncio
async def test_legacy_client_without_workspace_binding_starts_but_cannot_launch(
    tmp_path: Path,
) -> None:
    config_path, database_path = _write_configuration(
        tmp_path,
        provider="provider:\n  mode: disabled\n  network_enabled: false",
    )
    client_path = tmp_path / "clients" / "client.yaml"
    profile = client_path.read_text(encoding="utf-8")
    profile = profile.replace("workspaces:\n  allow:\n    - placement-schedule\n", "")
    client_path.write_text(profile, encoding="utf-8")
    observed: list[object] = []
    protector = FakeProtector()

    async def inspect_runtime(
        applications: DaemonApplications,
        settings: DaemonSettings,
        shutdown: asyncio.Event,
    ) -> None:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=applications.agent),
            base_url=f"http://127.0.0.1:{settings.agent_port}",
        ) as agent:
            readiness = await agent.get("/health/ready")
        capability = load_control_capability(
            installation_state_paths(database_path).control_capability,
            protector=protector,
        )
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=applications.admin),
            base_url=f"http://127.0.0.1:{settings.admin_port}",
            headers={"x-gatehouse-control-capability": capability},
        ) as admin:
            launched = await admin.post(
                "/v1/control/sessions",
                json={
                    "client": "company-watcher",
                    "workspace": "placement-schedule",
                    "working_directory": str((tmp_path / "workspace").resolve()),
                    "non_interactive": True,
                },
            )
        observed.extend((readiness.json()["status"], launched.status_code))
        shutdown.set()

    assert (
        await run_stock_daemon(
            config_path,
            protector=protector,
            serve_applications=inspect_runtime,
            install_signal_handlers=False,
        )
        == 0
    )
    assert observed == ["DEGRADED_NO_PROVIDER", 403]
    assert _system_state(database_path)[1] == "STOPPED"


@pytest.mark.asyncio
async def test_job_integrity_failure_serves_health_only_failed_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path, database_path = _write_configuration(
        tmp_path,
        provider="provider:\n  mode: disabled\n  network_enabled: false",
    )
    observed: list[str] = []

    def reject_corrupt_jobs(
        self: SqliteJobStore,
        **_kwargs: object,
    ) -> int:
        del self
        raise JobCorruptionError("nonterminal job has invalid durable authority")

    monkeypatch.setattr(
        SqliteJobStore,
        "validate_startup_integrity",
        reject_corrupt_jobs,
    )

    async def inspect_failure(
        applications: DaemonApplications,
        settings: DaemonSettings,
        shutdown: asyncio.Event,
    ) -> None:
        transport = httpx.ASGITransport(app=applications.agent)
        async with httpx.AsyncClient(
            transport=transport,
            base_url=f"http://127.0.0.1:{settings.agent_port}",
        ) as client:
            response = await client.get("/health/ready")
        assert response.status_code == 503
        observed.append(str(response.json()["status"]))
        await shutdown.wait()
        observed.append("EXPIRED")

    assert (
        await run_stock_daemon(
            config_path,
            protector=FakeProtector(),
            serve_applications=inspect_failure,
            failed_closed_fallback_lifetime_ms=10,
            install_signal_handlers=False,
        )
        == 1
    )
    assert observed == ["FAILED_CLOSED", "EXPIRED"]
    assert _system_state(database_path)[1] == "FAILED_CLOSED"


@pytest.mark.asyncio
async def test_unexpected_database_maintenance_exit_is_fatal_and_not_a_clean_stop(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path, database_path = _write_configuration(
        tmp_path,
        provider="provider:\n  mode: disabled\n  network_enabled: false",
    )

    async def exit_maintenance(*args: object, **kwargs: object) -> None:
        del args, kwargs

    async def await_failed_shutdown(
        applications: DaemonApplications,
        settings: DaemonSettings,
        shutdown: asyncio.Event,
    ) -> None:
        del applications, settings
        await shutdown.wait()

    monkeypatch.setattr(
        composition,
        "run_database_maintenance_until_shutdown",
        exit_maintenance,
    )
    assert (
        await run_stock_daemon(
            config_path,
            protector=FakeProtector(),
            serve_applications=await_failed_shutdown,
            install_signal_handlers=False,
        )
        == 1
    )
    _epoch, state, clean_at = _system_state(database_path)
    assert state == "FAILED_CLOSED"
    assert clean_at is None


@pytest.mark.asyncio
async def test_unexpected_scheduled_reconciliation_exit_is_fatal_and_not_a_clean_stop(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path, database_path = _write_configuration(
        tmp_path,
        provider="provider:\n  mode: disabled\n  network_enabled: false",
    )

    async def exit_reconciliation(*args: object, **kwargs: object) -> None:
        del args, kwargs

    async def await_failed_shutdown(
        applications: DaemonApplications,
        settings: DaemonSettings,
        shutdown: asyncio.Event,
    ) -> None:
        del applications, settings
        await shutdown.wait()

    monkeypatch.setattr(
        composition,
        "run_scheduled_reconciliation_until_shutdown",
        exit_reconciliation,
    )
    assert (
        await run_stock_daemon(
            config_path,
            protector=FakeProtector(),
            serve_applications=await_failed_shutdown,
            install_signal_handlers=False,
        )
        == 1
    )
    _epoch, state, clean_at = _system_state(database_path)
    assert state == "FAILED_CLOSED"
    assert clean_at is None


@pytest.mark.asyncio
async def test_initial_scheduled_reconciliation_failure_prevents_listener_start(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path, database_path = _write_configuration(
        tmp_path,
        provider="provider:\n  mode: disabled\n  network_enabled: false",
    )
    listener_started = False

    async def fail_initial_reconciliation(*args: object, **kwargs: object) -> object:
        del args, kwargs
        raise RuntimeError("injected scheduled reconciliation failure")

    async def unexpected_listener_start(
        applications: DaemonApplications,
        settings: DaemonSettings,
        shutdown: asyncio.Event,
    ) -> None:
        del applications, settings, shutdown
        nonlocal listener_started
        listener_started = True

    monkeypatch.setattr(
        composition,
        "await_scheduled_reconciliation_batch",
        fail_initial_reconciliation,
    )
    assert (
        await run_stock_daemon(
            config_path,
            protector=FakeProtector(),
            serve_applications=unexpected_listener_start,
            install_signal_handlers=False,
        )
        == 1
    )
    assert listener_started is False
    _epoch, state, clean_at = _system_state(database_path)
    assert state == "FAILED_CLOSED"
    assert clean_at is None


@pytest.mark.asyncio
async def test_initial_global_database_cap_prevents_listener_start_and_ready(
    tmp_path: Path,
) -> None:
    config_path, database_path = _write_configuration(
        tmp_path,
        provider="provider:\n  mode: disabled\n  network_enabled: false",
    )
    configured = config_path.read_text(encoding="utf-8")
    configured = configured.replace("database_size_cap: 2GiB", "database_size_cap: 1")
    configured = configured.replace("debug_excerpt_size_cap: 250MiB", "debug_excerpt_size_cap: 1")
    config_path.write_text(configured, encoding="utf-8")
    listener_started = False

    async def unexpected_listener_start(
        applications: DaemonApplications,
        settings: DaemonSettings,
        shutdown: asyncio.Event,
    ) -> None:
        del applications, settings, shutdown
        nonlocal listener_started
        listener_started = True

    assert (
        await run_stock_daemon(
            config_path,
            protector=FakeProtector(),
            serve_applications=unexpected_listener_start,
            install_signal_handlers=False,
        )
        == 1
    )
    assert listener_started is False
    _epoch, state, clean_at = _system_state(database_path)
    assert state == "FAILED_CLOSED"
    assert clean_at is None
    connection = sqlite3.connect(database_path)
    try:
        alert = connection.execute(
            """
            SELECT severity, state, preserve, metadata_json FROM alerts
             WHERE alert_id = 'alert_database_retention_pressure'
            """
        ).fetchone()
    finally:
        connection.close()
    assert alert is not None
    assert tuple(alert[:3]) == ("CRITICAL", "OPEN", 1)
    assert json.loads(str(alert[3])) == {"footprint_status": "CAPACITY_EXHAUSTED"}


@pytest.mark.asyncio
async def test_unexpected_job_supervisor_exit_is_fatal_and_not_a_clean_stop(
    tmp_path: Path,
) -> None:
    config_path, database_path = _write_configuration(
        tmp_path,
        provider="provider:\n  mode: disabled\n  network_enabled: false",
    )

    async def interrupt_supervisor(
        applications: DaemonApplications,
        settings: DaemonSettings,
        shutdown: asyncio.Event,
    ) -> None:
        del applications, settings
        supervisors = [
            task for task in asyncio.all_tasks() if task.get_name() == "gatehouse-job-supervisor"
        ]
        assert len(supervisors) == 1
        supervisors[0].cancel()
        await shutdown.wait()

    assert (
        await run_stock_daemon(
            config_path,
            protector=FakeProtector(),
            serve_applications=interrupt_supervisor,
            install_signal_handlers=False,
        )
        == 1
    )
    _epoch, state, clean_at = _system_state(database_path)
    assert state == "FAILED_CLOSED"
    assert clean_at is None


@pytest.mark.asyncio
async def test_unexpected_credit_observer_exit_is_fatal_and_not_a_clean_stop(
    tmp_path: Path,
) -> None:
    config_path, database_path = _write_configuration(
        tmp_path,
        provider="provider:\n  mode: disabled\n  network_enabled: false",
    )
    configuration = load_runtime_configuration(config_path)
    daemon = await compose_stock_daemon(
        configuration,
        config_path=config_path,
        protector=FakeProtector(),
    )

    class ExitingObserver:
        async def run(self, stop_event: asyncio.Event) -> None:
            del stop_event

    daemon.observation_loop = ExitingObserver()  # type: ignore[assignment]

    async def await_failed_shutdown(
        applications: DaemonApplications,
        settings: DaemonSettings,
        shutdown: asyncio.Event,
    ) -> None:
        del applications, settings
        await shutdown.wait()

    try:
        with pytest.raises(RuntimeError, match="required daemon runtime task failed"):
            await composition._serve_composed(
                daemon,
                serve_applications=await_failed_shutdown,
                scheduler_pump_interval_ms=10,
                drain_timeout_ms=250,
            )
        _epoch, state, clean_at = _system_state(database_path)
        assert state == "FAILED_CLOSED"
        assert clean_at is None
    finally:
        await daemon.close()
