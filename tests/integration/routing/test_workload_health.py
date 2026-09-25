"""Stock workload-health reads against new synthetic SQLite state."""

from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from dataclasses import replace
from pathlib import Path

import httpx
import pytest
import yaml

from gatehouse.admin import load_control_capability
from gatehouse.core.clock import FixedUtcClock
from gatehouse.daemon import (
    compose_stock_daemon,
    installation_state_paths,
    load_runtime_configuration,
)
from gatehouse.daemon.provider import synchronize_scripted_routes
from gatehouse.daemon.workload_health import SqliteWorkloadHealth, WorkloadBinding, WorkloadCoverage
from gatehouse.database import open_migrated_database
from gatehouse.providers import ProviderErrorClass, ScriptedProviderTransport
from gatehouse.routing import SqliteRoutingCatalog
from gatehouse.routing.eligibility import WorkloadRouteRequirement
from gatehouse.routing.retry import BreakerKey, BreakerScopeType, CircuitBreakerRegistry
from gatehouse.state_security import secure_private_directory


def _coverage(*operations: str, pool: str = "configured-pool") -> WorkloadCoverage:
    requirements = tuple(WorkloadRouteRequirement(pool, operation) for operation in operations)
    return WorkloadCoverage(
        bindings=tuple(
            WorkloadBinding("client-a", "workspace-a", "research", item) for item in requirements
        ),
        requirements=requirements,
        verified=True,
    )


def _snapshot(connection: sqlite3.Connection) -> tuple[tuple[object, ...], ...]:
    return (
        tuple(
            tuple(row)
            for row in connection.execute(
                "SELECT type, name, tbl_name, sql FROM sqlite_master ORDER BY type, name"
            )
        )
        + tuple(
            tuple(row)
            for row in connection.execute(
                "SELECT credential_id, state, generation, expires_at_ms "
                "FROM credentials ORDER BY credential_id"
            )
        )
        + tuple(
            tuple(row)
            for row in connection.execute(
                "SELECT quota_scope_id, state, configured_floor_units "
                "FROM quota_scopes ORDER BY quota_scope_id"
            )
        )
    )


def test_health_reassesses_real_routes_and_preserves_database_and_breaker_authority() -> None:
    with closing(open_migrated_database(":memory:")) as connection:
        synchronize_scripted_routes(
            connection,
            pool_aliases=("configured-pool",),
            clock=FixedUtcClock(1),
        )
        breakers = CircuitBreakerRegistry()
        probe = SqliteWorkloadHealth(
            connection,
            SqliteRoutingCatalog(connection, circuit_breakers=breakers),
            _coverage("firecrawl.search", "firecrawl.crawl.start"),
            mode="scripted",
        )
        changes, before = connection.total_changes, _snapshot(connection)
        first = probe(10)
        assert first.ready and first.status == "READY"
        assert first.required_routes == first.eligible_routes == 2
        assert first.checked_at_ms == 10
        assert connection.total_changes == changes and _snapshot(connection) == before
        assert not connection.in_transaction and not breakers._active_permits

        connection.execute("UPDATE credentials SET state = 'DISABLED'")
        changes = connection.total_changes
        blocked = probe(11)
        assert not blocked.ready and blocked.status == "DEGRADED"
        assert blocked.ineligible_routes == 2 and connection.total_changes == changes
        connection.execute("UPDATE credentials SET state = 'HEALTHY'")
        recovered = probe(12)
        assert recovered.ready and recovered.checked_at_ms == 12


@pytest.mark.parametrize("defect", ["expiry", "floor", "scope", "manual_pool", "member"])
def test_route_health_reports_current_local_refusals_without_new_authority(defect: str) -> None:
    with closing(open_migrated_database(":memory:")) as connection:
        synchronize_scripted_routes(
            connection,
            pool_aliases=("configured-pool",),
            clock=FixedUtcClock(1),
        )
        statements = {
            "expiry": "UPDATE credentials SET expires_at_ms = 10",
            "floor": "UPDATE quota_scopes SET configured_floor_units = 1000000",
            "scope": "UPDATE quota_scopes SET state = 'EXHAUSTED'",
            "manual_pool": "UPDATE pools SET automatic_use = 0",
            "member": "UPDATE pool_members SET enabled = 0",
        }
        connection.execute(statements[defect])
        probe = SqliteWorkloadHealth(
            connection,
            SqliteRoutingCatalog(connection),
            _coverage("firecrawl.search"),
            mode="scripted",
        )
        before, changes = _snapshot(connection), connection.total_changes
        status = probe(10)
        assert status.status == "DEGRADED" and not status.ready and status.ineligible_routes == 1
        assert connection.total_changes == changes and _snapshot(connection) == before


def test_health_uses_actual_operation_cost_and_exposes_partial_capacity() -> None:
    with closing(open_migrated_database(":memory:")) as connection:
        synchronize_scripted_routes(
            connection,
            pool_aliases=("configured-pool",),
            clock=FixedUtcClock(1),
        )
        connection.execute("UPDATE quota_scopes SET configured_floor_units = 999999")
        probe = SqliteWorkloadHealth(
            connection,
            SqliteRoutingCatalog(connection),
            _coverage("firecrawl.search", "firecrawl.crawl.start"),
            mode="scripted",
        )
        status = probe(10)
        assert status.status == "DEGRADED"
        assert status.eligible_routes == status.ineligible_routes == 1
        assert status.required_routes == 2 and not status.ready


def test_health_never_commits_or_rolls_back_a_callers_active_transaction() -> None:
    with closing(open_migrated_database(":memory:")) as connection:
        synchronize_scripted_routes(
            connection,
            pool_aliases=("configured-pool",),
            clock=FixedUtcClock(1),
        )
        probe = SqliteWorkloadHealth(
            connection,
            SqliteRoutingCatalog(connection),
            _coverage("firecrawl.search"),
            mode="scripted",
        )
        connection.execute("BEGIN IMMEDIATE")
        connection.execute("UPDATE credentials SET state = 'DISABLED'")
        status = probe(10)
        assert status.status == "UNVERIFIED" and not status.ready
        assert connection.in_transaction
        connection.rollback()
        assert probe(11).ready


@pytest.mark.parametrize(
    "mode,verified,operations,expected",
    [
        ("disabled", True, ("firecrawl.search",), "DISABLED"),
        ("scripted", True, (), "UNCONFIGURED"),
        ("scripted", False, (), "UNVERIFIED"),
    ],
)
def test_disabled_empty_and_unverified_coverage_skip_database_reads(
    mode: str,
    verified: bool,
    operations: tuple[str, ...],
    expected: str,
) -> None:
    with closing(open_migrated_database(":memory:")) as connection:
        coverage = replace(_coverage(*operations), verified=verified)
        probe = SqliteWorkloadHealth(
            connection,
            SqliteRoutingCatalog(connection),
            coverage,
            mode=mode,
        )
        statements: list[str] = []
        connection.set_trace_callback(statements.append)
        status = probe(10)
        assert status.status == expected and not status.ready
        assert statements == []


def test_health_observes_breaker_headroom_without_taking_a_probe() -> None:
    with closing(open_migrated_database(":memory:")) as connection:
        synchronize_scripted_routes(
            connection,
            pool_aliases=("configured-pool",),
            clock=FixedUtcClock(1),
        )
        breakers = CircuitBreakerRegistry()
        key = BreakerKey(BreakerScopeType.PROVIDER_OPERATION, "firecrawl.search")
        breakers.record_failure(
            key,
            now_ms=1,
            error_class=ProviderErrorClass.RATE_LIMITED,
            open_until_ms=100,
            force_open=True,
        )
        probe = SqliteWorkloadHealth(
            connection,
            SqliteRoutingCatalog(connection, circuit_breakers=breakers),
            _coverage("firecrawl.search"),
            mode="scripted",
        )
        assert probe(10).status == "DEGRADED"
        assert probe(100).ready and not breakers._active_permits
        permit = breakers.try_acquire(key, now_ms=100)
        assert permit is not None
        try:
            assert probe(100).status == "DEGRADED"
            assert len(breakers._active_permits) == 1
        finally:
            assert breakers.release(permit)


def test_assessment_error_preserves_control_availability_and_closes_its_own_read_transaction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with closing(open_migrated_database(":memory:")) as connection:
        catalog = SqliteRoutingCatalog(connection)

        def broken(**kwargs: object) -> None:
            del kwargs
            raise RuntimeError("synthetic-private-planner-detail")

        monkeypatch.setattr(catalog, "plan", broken)
        probe = SqliteWorkloadHealth(
            connection,
            catalog,
            _coverage("firecrawl.search"),
            mode="live",
        )
        status = probe(10)
        assert status.status == "UNVERIFIED" and not status.ready
        assert not connection.in_transaction
        assert "synthetic-private-planner-detail" not in status.model_dump_json()


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["disabled", "scripted"])
async def test_real_stock_control_exposes_coverage_and_current_routing_changes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
) -> None:
    source = Path(__file__).parents[3] / "config"
    main = yaml.safe_load((source / "config.example.yaml").read_text(encoding="utf-8"))
    database_path = tmp_path / "state" / "gatehouse.db"
    main["database"]["path"] = str(database_path)
    main["approvals"]["windows_notification"] = False
    workload = {"mode": mode, "network_enabled": False}
    if mode == "scripted":
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
        workload["scripted_responses_path"] = str(manifest)
    main["providers"]["firecrawl"]["workload"] = workload
    config_path = tmp_path / "config.yaml"
    config_path.write_text(json.dumps(main), encoding="utf-8")
    profile = yaml.safe_load(
        (source / "clients" / "company-watcher.example.yaml").read_text(
            encoding="utf-8",
        )
    )
    profile["client"].update(
        {
            "id": "editor-one",
            "kind": "interactive",
            "unattended": False,
            "approval_mode": "dashboard",
            "default_priority": "interactive",
        }
    )
    profile["capabilities"]["allow"] = ["firecrawl.search"]
    profile["pools"]["firecrawl"] = "configured-pool"
    clients = tmp_path / "clients"
    clients.mkdir()
    (clients / "editor.yaml").write_text(json.dumps(profile), encoding="utf-8")
    policy = yaml.safe_load(
        (source / "policies" / "placement-schedule.example.yaml").read_text(
            encoding="utf-8",
        )
    )
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    policy["workspace"]["canonical_root"] = str(workspace.resolve())
    policies = tmp_path / "policies"
    policies.mkdir()
    (policies / "workspace.yaml").write_text(json.dumps(policy), encoding="utf-8")
    # Admit the actual fresh configuration tree through production ACL helpers.
    secure_private_directory(tmp_path, recursive=True, maximum_entries=32, must_exist=True)

    class SyntheticProtector:
        def protect(self, plaintext: bytes) -> bytes:
            return b"synthetic:" + plaintext

        def unprotect(self, ciphertext: bytes) -> bytearray:
            assert ciphertext.startswith(b"synthetic:")
            return bytearray(ciphertext.removeprefix(b"synthetic:"))

    async def forbidden_send(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise AssertionError("health dispatched a provider request")

    monkeypatch.setattr(ScriptedProviderTransport, "send", forbidden_send)
    protector = SyntheticProtector()
    daemon = await compose_stock_daemon(
        load_runtime_configuration(config_path, environment={}),
        config_path=config_path,
        clock=FixedUtcClock(1_000),
        protector=protector,
    )
    try:
        daemon.mark_recovery_complete()
        capability = load_control_capability(
            installation_state_paths(database_path).control_capability,
            protector=protector,
        )
        transport = httpx.ASGITransport(app=daemon.applications.admin)
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://127.0.0.1:47622",
        ) as client:
            rejected = await client.get("/v1/control/status")
            assert rejected.status_code == 401 and "workload" not in rejected.json()
            headers = {"x-gatehouse-control-capability": capability}
            response = await client.get("/v1/control/status", headers=headers)
            assert response.status_code == 200
            status = response.json()
            if mode == "disabled":
                assert status["status"] == "DEGRADED_NO_PROVIDER"
                assert status["workload"]["status"] == "DISABLED"
            else:
                assert status["ready"] and status["workload"]["ready"]
                assert status["workload"]["binding_count"] == 6
                assert status["workload"]["required_routes"] == 1
                daemon.connection.execute("UPDATE credentials SET state = 'DISABLED'")
                changed = await client.get("/v1/control/status", headers=headers)
                assert changed.json()["ready"] and not changed.json()["workload"]["ready"]
                assert changed.json()["workload"]["status"] == "DEGRADED"
    finally:
        await daemon.close()
