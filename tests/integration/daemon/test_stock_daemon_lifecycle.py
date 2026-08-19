from __future__ import annotations

import asyncio
import json
import sqlite3
from collections.abc import Mapping
from pathlib import Path

import httpx
import pytest

from gatehouse.admin import load_control_capability
from gatehouse.core import FixedUtcClock
from gatehouse.daemon import (
    DaemonAlreadyRunningError,
    DaemonApplications,
    DaemonSettings,
    FileInstallationDaemonLeaseFactory,
    compose_stock_daemon,
    composition,
    installation_state_paths,
    load_runtime_configuration,
    run_stock_daemon,
)
from gatehouse.jobs import JobCorruptionError, JobSupervisor, SqliteJobStore
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
    include_authority: bool = True,
    interactive_client: bool = False,
) -> tuple[Path, Path]:
    source = Path(__file__).parents[3] / "config"
    config_path = tmp_path / "config.yaml"
    database_path = tmp_path / "state" / "gatehouse.db"
    main = (source / "config.example.yaml").read_text(encoding="utf-8")
    main = main.replace(
        r"'%LOCALAPPDATA%\Gatehouse\state\gatehouse.db'",
        f"'{database_path.as_posix()}'",
    )
    main = main.replace(
        "provider:\n  mode: disabled\n  network_enabled: false",
        provider,
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
        (policies / "placement.yaml").write_text(
            (source / "policies" / "placement-schedule.example.yaml").read_text(encoding="utf-8"),
            encoding="utf-8",
        )
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
                    "non_interactive": True,
                },
            )
        assert status.status_code == 200
        assert status.json()["status"] == "DEGRADED_NO_PROVIDER"
        assert launched.status_code == 201
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
async def test_operational_health_waits_for_initial_supervisor_recovery_pass(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path, database_path = _write_configuration(
        tmp_path,
        provider="provider:\n  mode: disabled\n  network_enabled: false",
    )
    original_run_once = JobSupervisor.run_once
    observed_states: list[str] = []

    async def observe_recovery(self: JobSupervisor) -> int:
        observed_states.append(_system_state(database_path)[1])
        return await original_run_once(self)

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
    assert observed_states[0] == "RECOVERING"


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
        await supervisor_entered.wait()
        stop.set()
        await stop.wait()

    started = asyncio.get_running_loop().time()
    result = await run_stock_daemon(
        config_path,
        protector=FakeProtector(),
        serve_applications=request_drain,
        drain_timeout_ms=50,
        install_signal_handlers=False,
    )
    elapsed = asyncio.get_running_loop().time() - started

    assert result == 0
    assert elapsed < 1
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
    ticket = await daemon.scheduler.enqueue(
        WorkItem(
            request_id="held-through-drain",
            session_id="session-through-drain",
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
            assert connection.execute("SELECT COUNT(*) FROM pools").fetchone()[0] == 1
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
async def test_post_config_composition_failure_serves_health_only_failed_closed(
    tmp_path: Path,
) -> None:
    config_path, database_path = _write_configuration(
        tmp_path,
        provider="provider:\n  mode: disabled\n  network_enabled: false",
        include_authority=False,
    )
    observed: list[Mapping[str, object]] = []

    async def inspect_failure(
        applications: DaemonApplications,
        settings: DaemonSettings,
        shutdown: asyncio.Event,
    ) -> None:
        for application, port in (
            (applications.agent, settings.agent_port),
            (applications.admin, settings.admin_port),
        ):
            transport = httpx.ASGITransport(app=application)
            async with httpx.AsyncClient(
                transport=transport,
                base_url=f"http://127.0.0.1:{port}",
            ) as client:
                response = await client.get("/health/ready")
            assert response.status_code == 503
            observed.append(response.json())
        shutdown.set()

    assert (
        await run_stock_daemon(
            config_path,
            protector=FakeProtector(),
            serve_applications=inspect_failure,
            install_signal_handlers=False,
        )
        == 1
    )
    assert [item["status"] for item in observed] == ["FAILED_CLOSED", "FAILED_CLOSED"]
    assert _system_state(database_path)[1] == "FAILED_CLOSED"


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
        shutdown.set()

    assert (
        await run_stock_daemon(
            config_path,
            protector=FakeProtector(),
            serve_applications=inspect_failure,
            install_signal_handlers=False,
        )
        == 1
    )
    assert observed == ["FAILED_CLOSED"]
    assert _system_state(database_path)[1] == "FAILED_CLOSED"


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
