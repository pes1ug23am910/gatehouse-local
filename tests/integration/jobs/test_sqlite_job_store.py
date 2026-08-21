from __future__ import annotations

import asyncio
import hashlib
import json
import sqlite3
from dataclasses import replace
from pathlib import Path

import pytest

from gatehouse.core.clock import FixedUtcClock
from gatehouse.core.ids import (
    CredentialId,
    JobId,
    PoolId,
    PrincipalId,
    QuotaScopeId,
    RequestId,
    RootRunId,
    SessionId,
    WorkspaceId,
)
from gatehouse.database import open_migrated_database, recover_startup
from gatehouse.database.repository import GatehouseRepository
from gatehouse.invocations import SqliteBudgetGateway
from gatehouse.jobs import (
    JobConflictError,
    JobCorruptionError,
    JobObservation,
    JobOwner,
    JobRecord,
    JobSettlementError,
    JobState,
    JobSupervisor,
    SqliteJobSettlementGateway,
    SqliteJobStore,
)
from gatehouse.routing import ResourceAffinity, SqliteResourceAffinityStore

_A = "00000000000000000000000001"
_B = "00000000000000000000000002"


class DeterministicEntropy:
    def __init__(self) -> None:
        self.counter = 0

    def __call__(self, length: int) -> bytes:
        self.counter += 1
        seed = hashlib.sha256(f"job-{self.counter}".encode()).digest()
        return seed[:length]


class UnexpectedObservationGateway:
    async def observe(self, job: JobRecord) -> JobObservation:
        del job
        raise AssertionError("a checkpointed settlement must not poll the provider")


def seed_authority(connection: sqlite3.Connection) -> None:
    for suffix in (_A, _B):
        connection.execute(
            """
            INSERT INTO clients(
                client_id, display_name, kind, policy_profile,
                created_at_ms, updated_at_ms
            ) VALUES (?, ?, 'interactive', 'default', 0, 0)
            """,
            (f"client_{suffix}", f"Client {suffix[-1]}"),
        )
        connection.execute(
            """
            INSERT INTO workspaces(
                workspace_id, display_name, canonical_root,
                created_at_ms, updated_at_ms
            ) VALUES (?, ?, ?, 0, 0)
            """,
            (f"ws_{suffix}", f"Workspace {suffix[-1]}", f"E:\\Jobs-{suffix[-1]}"),
        )
        connection.execute(
            """
            INSERT INTO sessions(
                session_id, client_id, workspace_id, bootstrap_verifier,
                bootstrap_version, token_epoch, state, identity_assurance,
                policy_version, created_at_ms, reconnect_until_ms,
                absolute_expires_at_ms
            ) VALUES (?, ?, ?, X'01', 1, 0, 'ACTIVE', 'TEST', 'v1',
                      0, 100000, 100000)
            """,
            (f"ses_{suffix}", f"client_{suffix}", f"ws_{suffix}"),
        )
        connection.execute(
            """
            INSERT INTO root_runs(root_run_id, session_id, state, started_at_ms)
            VALUES (?, ?, 'ACTIVE', 0)
            """,
            (f"run_{suffix}", f"ses_{suffix}"),
        )
        connection.execute(
            """
            INSERT INTO invocations(
                request_id, session_id, root_run_id, service_id, operation,
                request_fingerprint, fingerprint_version,
                canonicalization_version, state, priority_class,
                request_size_bytes, received_at_ms, completed_at_ms
            ) VALUES (?, ?, ?, 'firecrawl', 'firecrawl.crawl.start', ?, 1, 1,
                      'SUCCEEDED', 'INTERACTIVE', 10, 0, 100)
            """,
            (
                f"req_{suffix}",
                f"ses_{suffix}",
                f"run_{suffix}",
                suffix.encode("ascii"),
            ),
        )

    connection.execute(
        """
        INSERT INTO principals(
            principal_id, service_id, alias, created_at_ms, updated_at_ms
        ) VALUES (?, 'firecrawl', 'principal', 0, 0)
        """,
        (f"prn_{_A}",),
    )
    connection.execute(
        """
        INSERT INTO quota_scopes(
            quota_scope_id, principal_id, alias, state, unit,
            configured_floor_units
        ) VALUES (?, ?, 'quota', 'HEALTHY', 'credits', 0)
        """,
        (f"quota_{_A}", f"prn_{_A}"),
    )
    connection.execute(
        """
        INSERT INTO credentials(
            credential_id, principal_id, quota_scope_id, alias,
            secret_backend, secret_reference, state, generation, created_at_ms
        ) VALUES (?, ?, ?, 'credential', 'test', 'reference', 'ACTIVE', 3, 0)
        """,
        (f"cred_{_A}", f"prn_{_A}", f"quota_{_A}"),
    )
    connection.execute(
        """
        INSERT INTO pools(pool_id, service_id, alias, state, selection_strategy)
        VALUES (?, 'firecrawl', 'default', 'ACTIVE', 'CHEAPEST_FIRST')
        """,
        (f"pool_{_A}",),
    )
    connection.execute(
        "INSERT INTO pool_members(pool_id, quota_scope_id) VALUES (?, ?)",
        (f"pool_{_A}", f"quota_{_A}"),
    )


def owner(suffix: str = _A) -> JobOwner:
    return JobOwner(
        session_id=SessionId(f"ses_{suffix}"),
        workspace_id=WorkspaceId(f"ws_{suffix}"),
        root_run_id=RootRunId(f"run_{suffix}"),
    )


def affinity(
    *,
    suffix: str = _A,
    provider_resource_id: str = "provider-job-1",
) -> ResourceAffinity:
    return ResourceAffinity(
        service_id="firecrawl",
        resource_type="crawl",
        provider_resource_id=provider_resource_id,
        principal_id=PrincipalId(f"prn_{_A}"),
        quota_scope_id=QuotaScopeId(f"quota_{_A}"),
        credential_id=CredentialId(f"cred_{_A}"),
        credential_generation=3,
        pool_id=PoolId(f"pool_{_A}"),
        creating_request_id=RequestId(f"req_{suffix}"),
        owner_session_id=SessionId(f"ses_{suffix}"),
        owner_workspace_id=WorkspaceId(f"ws_{suffix}"),
        owner_root_run_id=RootRunId(f"run_{suffix}"),
        bound_at_ms=100,
    )


def seed_successful_attempt(
    connection: sqlite3.Connection,
    fact: ResourceAffinity,
) -> None:
    connection.execute(
        """
        INSERT INTO attempts(
            attempt_id, request_id, ordinal, credential_id, principal_id,
            quota_scope_id, state, error_class, started_at_ms, completed_at_ms,
            resource_type, provider_resource_id, credential_generation, pool_id,
            dispatch_credential_generation, dispatch_pool_id
        ) VALUES (?, ?, 1, ?, ?, ?, 'SUCCEEDED', 'none', 90, 100,
                  ?, ?, ?, ?, ?, ?)
        """,
        (
            f"attempt-{fact.creating_request_id}",
            str(fact.creating_request_id),
            str(fact.credential_id),
            str(fact.principal_id),
            str(fact.quota_scope_id),
            fact.resource_type,
            fact.provider_resource_id,
            fact.credential_generation,
            str(fact.pool_id),
            fact.credential_generation,
            str(fact.pool_id),
        ),
    )


async def create_job(
    connection: sqlite3.Connection,
) -> tuple[SqliteJobStore, ResourceAffinity]:
    fact = affinity()
    seed_successful_attempt(connection, fact)
    await SqliteResourceAffinityStore(
        connection,
        identifier=lambda: "resource-row-1",
    ).bind(fact)
    store = SqliteJobStore(connection, entropy=DeterministicEntropy())
    return store, fact


def seed_alternate_authority(connection: sqlite3.Connection) -> None:
    connection.execute(
        """
        INSERT INTO principals(
            principal_id, service_id, alias, created_at_ms, updated_at_ms
        ) VALUES (?, 'firecrawl', 'principal-alternate', 0, 0)
        """,
        (f"prn_{_B}",),
    )
    connection.execute(
        """
        INSERT INTO quota_scopes(
            quota_scope_id, principal_id, alias, state, unit,
            configured_floor_units
        ) VALUES (?, ?, 'quota-alternate', 'HEALTHY', 'credits', 0)
        """,
        (f"quota_{_B}", f"prn_{_B}"),
    )
    connection.execute(
        """
        INSERT INTO credentials(
            credential_id, principal_id, quota_scope_id, alias,
            secret_backend, secret_reference, state, generation, created_at_ms
        ) VALUES (?, ?, ?, 'credential-alternate', 'test',
                  'reference-alternate', 'ACTIVE', 4, 0)
        """,
        (f"cred_{_B}", f"prn_{_B}", f"quota_{_B}"),
    )
    connection.execute(
        """
        INSERT INTO pools(pool_id, service_id, alias, state, selection_strategy)
        VALUES (?, 'other-service', 'alternate', 'ACTIVE', 'CHEAPEST_FIRST')
        """,
        (f"pool_{_B}",),
    )
    connection.execute(
        "INSERT INTO pool_members(pool_id, quota_scope_id) VALUES (?, ?)",
        (f"pool_{_B}", f"quota_{_A}"),
    )


@pytest.mark.asyncio
async def test_empty_startup_needs_no_client_runtime_authority(tmp_path: Path) -> None:
    connection = open_migrated_database(tmp_path / "empty.db")
    store = SqliteJobStore(connection)

    assert (
        await store.recover_orphaned_resources(
            maximum_runtime_ms_by_client_id={},
            now_ms=100,
        )
        == 0
    )
    assert (
        store.validate_startup_integrity(
            supported_operation_resource_types={"firecrawl.crawl.start": "crawl"}
        )
        == 0
    )
    connection.close()


@pytest.mark.asyncio
async def test_orphan_requires_its_client_runtime_authority(tmp_path: Path) -> None:
    connection = open_migrated_database(tmp_path / "orphan.db")
    seed_authority(connection)
    _store, fact = await create_job(connection)
    store = SqliteJobStore(connection)

    with pytest.raises(JobCorruptionError, match="runtime authority"):
        await store.recover_orphaned_resources(
            maximum_runtime_ms_by_client_id={},
            now_ms=fact.bound_at_ms,
        )
    assert connection.execute("SELECT COUNT(*) FROM jobs").fetchone()[0] == 0
    connection.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "corruption",
    (
        "operation",
        "principal",
        "quota_scope",
        "credential",
        "provider_resource",
        "owner",
        "principal_chain",
        "quota_chain",
        "credential_chain",
        "pool_chain",
    ),
)
async def test_startup_integrity_rejects_semantically_corrupt_live_jobs(
    tmp_path: Path,
    corruption: str,
) -> None:
    connection = open_migrated_database(tmp_path / f"{corruption}.db")
    seed_authority(connection)
    store, fact = await create_job(connection)
    await store.create_from_affinity(
        fact,
        maximum_runtime_at_ms=10_000,
        next_poll_at_ms=200,
    )
    seed_alternate_authority(connection)

    if corruption == "operation":
        connection.execute("UPDATE jobs SET operation = 'firecrawl.crawl.other'")
    elif corruption == "principal":
        connection.execute("UPDATE jobs SET principal_id = ?", (f"prn_{_B}",))
    elif corruption == "quota_scope":
        connection.execute(
            "UPDATE jobs SET quota_scope_id = ?",
            (f"quota_{_B}",),
        )
    elif corruption == "credential":
        connection.execute(
            "UPDATE jobs SET credential_id = ?",
            (f"cred_{_B}",),
        )
    elif corruption == "provider_resource":
        connection.execute("UPDATE jobs SET provider_job_id = 'provider-other'")
    elif corruption == "owner":
        connection.execute(
            """
            UPDATE external_resources
               SET owner_session_id = ?, owner_workspace_id = ?,
                   owner_root_run_id = ?
            """,
            (f"ses_{_B}", f"ws_{_B}", f"run_{_B}"),
        )
    elif corruption == "principal_chain":
        connection.execute(
            "UPDATE principals SET service_id = 'other-service' WHERE principal_id = ?",
            (f"prn_{_A}",),
        )
    elif corruption == "quota_chain":
        connection.execute(
            "UPDATE quota_scopes SET principal_id = ? WHERE quota_scope_id = ?",
            (f"prn_{_B}", f"quota_{_A}"),
        )
    elif corruption == "credential_chain":
        connection.execute(
            """
            UPDATE credentials
               SET principal_id = ?, quota_scope_id = ?
             WHERE credential_id = ?
            """,
            (f"prn_{_B}", f"quota_{_B}", f"cred_{_A}"),
        )
    else:
        assert corruption == "pool_chain"
        connection.execute(
            """
            UPDATE external_resources
               SET pool_id = ?
             WHERE service_id = ? AND provider_resource_id = ?
            """,
            (f"pool_{_B}", fact.service_id, fact.provider_resource_id),
        )
        row = connection.execute("SELECT metadata_json FROM jobs").fetchone()
        assert row is not None
        metadata = json.loads(str(row[0]))
        metadata["pool_id"] = f"pool_{_B}"
        connection.execute(
            "UPDATE jobs SET metadata_json = ?",
            (json.dumps(metadata, sort_keys=True, separators=(",", ":")),),
        )

    assert connection.execute("PRAGMA quick_check").fetchone()[0] == "ok"
    assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
    with pytest.raises(JobCorruptionError, match="invalid durable authority"):
        store.validate_startup_integrity(
            supported_operation_resource_types={"firecrawl.crawl.start": "crawl"}
        )
    connection.close()


@pytest.mark.asyncio
async def test_startup_integrity_accepts_complete_live_job(tmp_path: Path) -> None:
    connection = open_migrated_database(tmp_path / "complete.db")
    seed_authority(connection)
    store, fact = await create_job(connection)
    await store.create_from_affinity(fact, maximum_runtime_at_ms=10_000)

    assert (
        store.validate_startup_integrity(
            supported_operation_resource_types={"firecrawl.crawl.start": "crawl"}
        )
        == 1
    )
    connection.close()


@pytest.mark.asyncio
async def test_create_is_idempotent_and_owner_fenced(tmp_path: Path) -> None:
    connection = open_migrated_database(tmp_path / "gatehouse.db")
    seed_authority(connection)
    store, fact = await create_job(connection)

    created = await store.create_from_affinity(
        fact,
        maximum_runtime_at_ms=10_000,
        next_poll_at_ms=200,
        provider_status="accepted",
    )
    repeated = await store.create_from_affinity(
        replace(fact, bound_at_ms=200),
        maximum_runtime_at_ms=10_000,
        next_poll_at_ms=200,
        provider_status="accepted",
    )

    assert created == repeated
    assert JobId(str(created.job_id)) == created.job_id
    assert await store.load(created.job_id, owner=owner()) == created
    assert await store.load(created.job_id, owner=owner(_B)) is None
    assert await store.list(owner=owner(_B)) == ()
    assert (
        await store.request_cancellation(
            created.job_id,
            owner=owner(_B),
            now_ms=150,
        )
        is None
    )
    assert connection.execute("SELECT COUNT(*) FROM jobs").fetchone()[0] == 1
    connection.close()


@pytest.mark.asyncio
async def test_same_provider_resource_cannot_resolve_to_another_request(
    tmp_path: Path,
) -> None:
    connection = open_migrated_database(tmp_path / "gatehouse.db")
    seed_authority(connection)
    store, fact = await create_job(connection)
    await store.create_from_affinity(fact, maximum_runtime_at_ms=10_000)

    with pytest.raises(JobConflictError, match="provider resource"):
        await store.create_from_affinity(
            affinity(suffix=_B),
            maximum_runtime_at_ms=10_000,
        )
    assert connection.execute("SELECT COUNT(*) FROM jobs").fetchone()[0] == 1
    connection.close()


@pytest.mark.asyncio
async def test_job_identifier_and_recovering_state_survive_reopen(tmp_path: Path) -> None:
    path = tmp_path / "gatehouse.db"
    first_connection = open_migrated_database(path)
    seed_authority(first_connection)
    first_store, fact = await create_job(first_connection)
    created = await first_store.create_from_affinity(
        fact,
        maximum_runtime_at_ms=10_000,
        next_poll_at_ms=200,
    )
    first_connection.close()

    restarted_connection = open_migrated_database(path)
    report = recover_startup(restarted_connection, now_ms=500)
    restarted_store = SqliteJobStore(restarted_connection)
    restored = await restarted_store.load(created.job_id, owner=owner())

    assert report.jobs_recovering == 1
    assert restored is not None
    assert restored.job_id == created.job_id
    assert restored.state is JobState.RECOVERING
    assert restored.revision == created.revision
    restarted_connection.close()


@pytest.mark.asyncio
async def test_cancellation_is_idempotent_and_durable(tmp_path: Path) -> None:
    path = tmp_path / "gatehouse.db"
    connection = open_migrated_database(path)
    seed_authority(connection)
    store, fact = await create_job(connection)
    created = await store.create_from_affinity(fact, maximum_runtime_at_ms=10_000)

    cancelling = await store.request_cancellation(
        created.job_id,
        owner=owner(),
        now_ms=150,
    )
    repeated = await store.request_cancellation(
        created.job_id,
        owner=owner(),
        now_ms=151,
    )
    assert cancelling is not None
    assert cancelling.state is JobState.CANCELLING
    assert cancelling.cancel_requested_at_ms == 150
    assert repeated == cancelling
    connection.close()

    reopened = open_migrated_database(path)
    assert await SqliteJobStore(reopened).load(created.job_id, owner=owner()) == cancelling
    reopened.close()


@pytest.mark.asyncio
async def test_provider_update_is_cas_and_bounded_await_rereads_sqlite(
    tmp_path: Path,
) -> None:
    path = tmp_path / "gatehouse.db"
    first_connection = open_migrated_database(path)
    seed_authority(first_connection)
    first, fact = await create_job(first_connection)
    created = await first.create_from_affinity(fact, maximum_runtime_at_ms=10_000)
    second_connection = open_migrated_database(path)
    second = SqliteJobStore(second_connection)
    stale = await second.load(created.job_id, owner=owner())
    assert stale == created

    waiting = asyncio.create_task(
        first.await_update(
            created.job_id,
            owner=owner(),
            after_revision=created.revision,
            maximum_wait_ms=1_000,
        )
    )
    await asyncio.sleep(0)
    updated = await first.compare_and_set(
        expected=created,
        owner=owner(),
        target_state=JobState.RUNNING,
        provider_status="running",
        observed_at_ms=200,
        next_poll_at_ms=300,
    )
    assert updated is not None
    assert updated.revision == created.revision + 1
    assert updated.provider_status == "running"
    assert (
        await second.compare_and_set(
            expected=stale,
            owner=owner(),
            target_state=JobState.FAILED,
            provider_status="failed",
            observed_at_ms=201,
        )
        is None
    )

    awakened = await waiting
    assert awakened.record == updated
    assert awakened.changed and not awakened.timed_out
    timed_out = await first.await_update(
        created.job_id,
        owner=owner(),
        after_revision=updated.revision,
        maximum_wait_ms=10,
    )
    assert timed_out.record == updated
    assert timed_out.timed_out and not timed_out.changed
    first_connection.close()
    second_connection.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("target_state", "resource_state"),
    (
        (JobState.SUCCEEDED, "COMPLETED"),
        (JobState.FAILED, "FAILED"),
        (JobState.CANCELLED, "CANCELLED"),
        (JobState.UNKNOWN, "ACTIVE"),
    ),
)
async def test_terminal_cas_closes_only_resources_with_known_terminal_outcomes(
    tmp_path: Path,
    target_state: JobState,
    resource_state: str,
) -> None:
    connection = open_migrated_database(tmp_path / "terminal-cas.db")
    seed_authority(connection)
    store, fact = await create_job(connection)
    created = await store.create_from_affinity(fact, maximum_runtime_at_ms=10_000)

    terminal = await store.compare_and_set(
        expected=created,
        owner=created.owner,
        target_state=target_state,
        observed_at_ms=500,
        provider_status="terminal",
    )

    assert terminal is not None and terminal.state is target_state
    resource = connection.execute(
        """
        SELECT state, service_id, resource_type, provider_resource_id,
               principal_id, quota_scope_id, credential_id,
               credential_generation, pool_id, creating_request_id,
               owner_session_id, owner_workspace_id, owner_root_run_id
          FROM external_resources
        """
    ).fetchone()
    assert resource is not None
    assert tuple(resource) == (
        resource_state,
        fact.service_id,
        fact.resource_type,
        fact.provider_resource_id,
        str(fact.principal_id),
        str(fact.quota_scope_id),
        str(fact.credential_id),
        fact.credential_generation,
        str(fact.pool_id),
        str(fact.creating_request_id),
        str(fact.owner_session_id),
        str(fact.owner_workspace_id),
        str(fact.owner_root_run_id),
    )
    assert await store.load(created.job_id, owner=created.owner) == terminal
    assert await store.list(owner=created.owner) == (terminal,)
    connection.close()


@pytest.mark.asyncio
async def test_due_job_requires_one_cross_connection_cas_winner(tmp_path: Path) -> None:
    path = tmp_path / "gatehouse.db"
    first_connection = open_migrated_database(path)
    seed_authority(first_connection)
    first, fact = await create_job(first_connection)
    created = await first.create_from_affinity(
        fact,
        maximum_runtime_at_ms=10_000,
        next_poll_at_ms=200,
    )
    second_connection = open_migrated_database(path)
    second = SqliteJobStore(second_connection)

    assert await first.list_due(now_ms=199) == ()
    first_due = await first.list_due(now_ms=200)
    second_due = await second.list_due(now_ms=200)
    assert first_due == second_due == (created,)

    claimed = await first.compare_and_set(
        expected=first_due[0],
        owner=owner(),
        target_state=JobState.POLLING,
        observed_at_ms=200,
        next_poll_at_ms=1_000,
    )
    lost = await second.compare_and_set(
        expected=second_due[0],
        owner=owner(),
        target_state=JobState.POLLING,
        observed_at_ms=200,
        next_poll_at_ms=1_000,
    )

    assert claimed is not None
    assert lost is None
    assert await second.list_due(now_ms=999) == ()
    first_connection.close()
    second_connection.close()


@pytest.mark.asyncio
async def test_terminal_usage_settles_original_quota_and_budget_idempotently(
    tmp_path: Path,
) -> None:
    connection = open_migrated_database(tmp_path / "gatehouse.db")
    seed_authority(connection)
    store, fact = await create_job(connection)
    created = await store.create_from_affinity(fact, maximum_runtime_at_ms=10_000)
    connection.execute(
        "UPDATE root_runs SET budget_json = ?, consumed_json = ? WHERE root_run_id = ?",
        ('{"credits":100,"requests":30}', '{"requests":1}', str(created.owner.root_run_id)),
    )
    connection.execute(
        """
        INSERT INTO quota_reservations(
            reservation_id, request_id, quota_scope_id, amount_units, unit,
            state, created_at_ms, expires_at_ms
        ) VALUES ('reservation-one', ?, ?, 25, 'credits',
                  'PENDING_RECONCILIATION', 100, 1000)
        """,
        (str(created.request_id), str(created.quota_scope_id)),
    )
    connection.execute(
        """
        INSERT INTO quota_scopes(
            quota_scope_id, principal_id, alias, state, unit,
            configured_floor_units
        ) VALUES ('quota-replaced', ?, 'replaced', 'HEALTHY', 'credits', 0)
        """,
        (str(created.principal_id),),
    )
    connection.execute(
        """
        INSERT INTO quota_reservations(
            reservation_id, request_id, quota_scope_id, amount_units,
            actual_units, unit, state, created_at_ms, expires_at_ms,
            reconciled_at_ms
        ) VALUES ('reservation-replaced', ?, 'quota-replaced', 25, 0,
                  'credits', 'RECONCILED', 90, 99, 100)
        """,
        (str(created.request_id),),
    )
    connection.execute(
        """
        INSERT INTO budget_reservations(
            budget_reservation_id, request_id, root_run_id, amount_units,
            unit, state, created_at_ms
        ) VALUES ('budget-one', ?, ?, 25, 'credits',
                  'PENDING_RECONCILIATION', 100)
        """,
        (str(created.request_id), str(created.owner.root_run_id)),
    )
    settlement = SqliteJobSettlementGateway(
        connection,
        quota=GatehouseRepository(connection),
        budgets=SqliteBudgetGateway(connection, now_ms=lambda: 500),
        clock=FixedUtcClock(500),
    )

    await settlement.reconcile(created, actual_units=7)
    await settlement.reconcile(created, actual_units=7)

    quota = connection.execute(
        "SELECT state, actual_units FROM quota_reservations WHERE reservation_id = ?",
        ("reservation-one",),
    ).fetchone()
    budget = connection.execute(
        "SELECT state, actual_units FROM budget_reservations WHERE budget_reservation_id = ?",
        ("budget-one",),
    ).fetchone()
    consumed = connection.execute(
        "SELECT consumed_json FROM root_runs WHERE root_run_id = ?",
        (str(created.owner.root_run_id),),
    ).fetchone()
    assert quota is not None and tuple(quota) == ("RECONCILED", 7)
    replaced = connection.execute(
        "SELECT state, actual_units FROM quota_reservations WHERE reservation_id = ?",
        ("reservation-replaced",),
    ).fetchone()
    assert replaced is not None and tuple(replaced) == ("RECONCILED", 0)
    assert budget is not None and tuple(budget) == ("RECONCILED", 7)
    assert consumed is not None
    assert json.loads(str(consumed[0])) == {"credits": 7, "requests": 1}
    with pytest.raises(JobSettlementError, match="differently"):
        await settlement.reconcile(created, actual_units=8)
    connection.close()


@pytest.mark.asyncio
async def test_restart_recovers_bound_crawl_before_job_materialization(
    tmp_path: Path,
) -> None:
    connection = open_migrated_database(tmp_path / "gatehouse.db")
    seed_authority(connection)
    connection.execute(
        """
        UPDATE invocations
           SET state = 'RUNNING', completed_at_ms = NULL
         WHERE request_id = ?
        """,
        (f"req_{_A}",),
    )
    connection.execute(
        """
        INSERT INTO attempts(
            attempt_id, request_id, ordinal, credential_id, principal_id,
            quota_scope_id, state, estimated_cost_units, cost_unit,
            started_at_ms, completed_at_ms, error_class, resource_type,
            provider_resource_id, credential_generation, pool_id,
            dispatch_credential_generation, dispatch_pool_id
        ) VALUES ('attempt-orphan', ?, 1, ?, ?, ?, 'SUCCEEDED', 25,
                  'credits', 90, 100, 'none', 'crawl', 'provider-orphan',
                  3, ?, 3, ?)
        """,
        (
            f"req_{_A}",
            f"cred_{_A}",
            f"prn_{_A}",
            f"quota_{_A}",
            f"pool_{_A}",
            f"pool_{_A}",
        ),
    )
    fact = affinity(provider_resource_id="provider-orphan")
    await SqliteResourceAffinityStore(connection).bind(fact)

    report = recover_startup(connection, now_ms=200)

    assert report.async_invocations_recovered == 1
    assert report.invocations_unknown == 0
    invocation = connection.execute(
        "SELECT state, completed_at_ms FROM invocations WHERE request_id = ?",
        (f"req_{_A}",),
    ).fetchone()
    assert invocation is not None and tuple(invocation) == ("SUCCEEDED", 200)

    store = SqliteJobStore(connection, entropy=DeterministicEntropy())
    assert (
        await store.recover_orphaned_resources(
            maximum_runtime_ms_by_client_id={f"client_{_A}": 1_000},
            now_ms=200,
        )
        == 1
    )
    recovered = await store.list(owner=owner())
    assert len(recovered) == 1
    job = recovered[0]
    assert job.request_id == fact.creating_request_id
    assert job.provider_resource_id == "provider-orphan"
    assert job.state is JobState.CREATED
    assert job.next_poll_at_ms == 200
    assert job.maximum_runtime_at_ms == 1_100
    assert (
        await store.recover_orphaned_resources(
            maximum_runtime_ms_by_client_id={f"client_{_A}": 1_000},
            now_ms=201,
        )
        == 0
    )
    connection.close()


@pytest.mark.asyncio
async def test_checkpointed_terminal_usage_survives_restart_and_cancellation_race(
    tmp_path: Path,
) -> None:
    path = tmp_path / "gatehouse.db"
    connection = open_migrated_database(path)
    seed_authority(connection)
    store, fact = await create_job(connection)
    created = await store.create_from_affinity(fact, maximum_runtime_at_ms=10_000)
    connection.execute(
        "UPDATE root_runs SET budget_json = ? WHERE root_run_id = ?",
        ('{"credits":100,"requests":30}', str(created.owner.root_run_id)),
    )
    connection.execute(
        """
        INSERT INTO quota_reservations(
            reservation_id, request_id, quota_scope_id, amount_units, unit,
            state, created_at_ms, expires_at_ms
        ) VALUES ('reservation-checkpoint', ?, ?, 25, 'credits',
                  'PENDING_RECONCILIATION', 100, 1000)
        """,
        (str(created.request_id), str(created.quota_scope_id)),
    )
    connection.execute(
        """
        INSERT INTO budget_reservations(
            budget_reservation_id, request_id, root_run_id, amount_units,
            unit, state, created_at_ms
        ) VALUES ('budget-checkpoint', ?, ?, 25, 'credits',
                  'PENDING_RECONCILIATION', 100)
        """,
        (str(created.request_id), str(created.owner.root_run_id)),
    )
    prepared = await store.prepare_settlement(
        expected=created,
        owner=created.owner,
        target_state=JobState.SUCCEEDED,
        actual_cost_units=7,
        observed_at_ms=500,
        provider_status="completed",
    )
    assert prepared is not None and prepared.state is JobState.SETTLING
    assert (
        await store.request_cancellation(
            created.job_id,
            owner=created.owner,
            now_ms=501,
        )
        == prepared
    )
    connection.close()

    reopened = open_migrated_database(path)
    report = recover_startup(reopened, now_ms=600)
    assert report.jobs_recovering == 0
    recovered_store = SqliteJobStore(reopened)
    recovered = await recovered_store.load(created.job_id, owner=created.owner)
    assert recovered is not None and recovered.state is JobState.SETTLING
    settlement = SqliteJobSettlementGateway(
        reopened,
        quota=GatehouseRepository(reopened),
        budgets=SqliteBudgetGateway(reopened, now_ms=lambda: 600),
        clock=FixedUtcClock(600),
    )
    supervisor = JobSupervisor(
        store=recovered_store,
        gateway=UnexpectedObservationGateway(),
        settlements=settlement,
        clock=FixedUtcClock(600),
    )

    assert await supervisor.run_once() == 1
    completed = await recovered_store.load(created.job_id, owner=created.owner)
    assert completed is not None and completed.state is JobState.SUCCEEDED
    assert completed.completed_at_ms == 500
    quota = reopened.execute(
        "SELECT state, actual_units FROM quota_reservations WHERE reservation_id = ?",
        ("reservation-checkpoint",),
    ).fetchone()
    budget = reopened.execute(
        "SELECT state, actual_units FROM budget_reservations WHERE budget_reservation_id = ?",
        ("budget-checkpoint",),
    ).fetchone()
    assert quota is not None and tuple(quota) == ("RECONCILED", 7)
    assert budget is not None and tuple(budget) == ("RECONCILED", 7)
    reopened.close()


@pytest.mark.asyncio
async def test_terminal_resource_transition_is_atomic_and_resumable_after_crash(
    tmp_path: Path,
) -> None:
    path = tmp_path / "terminal-resource-crash.db"
    connection = open_migrated_database(path)
    seed_authority(connection)
    store, fact = await create_job(connection)
    created = await store.create_from_affinity(fact, maximum_runtime_at_ms=10_000)
    prepared = await store.prepare_settlement(
        expected=created,
        owner=created.owner,
        target_state=JobState.SUCCEEDED,
        actual_cost_units=7,
        observed_at_ms=500,
        provider_status="completed",
    )
    assert prepared is not None and prepared.state is JobState.SETTLING
    authority_before = connection.execute(
        """
        SELECT resource_id, service_id, resource_type, provider_resource_id,
               principal_id, quota_scope_id, credential_id,
               credential_generation, pool_id, creating_request_id,
               owner_session_id, owner_workspace_id, owner_root_run_id,
               created_at_ms, metadata_json
          FROM external_resources
        """
    ).fetchone()
    assert authority_before is not None
    connection.execute(
        """
        CREATE TRIGGER reject_terminal_resource_transition
        BEFORE UPDATE OF state ON external_resources
        WHEN OLD.state = 'ACTIVE' AND NEW.state = 'COMPLETED'
        BEGIN
            SELECT RAISE(ABORT, 'synthetic terminal resource crash');
        END
        """
    )

    with pytest.raises(sqlite3.IntegrityError, match="terminal resource crash"):
        await store.complete_settlement(expected=prepared, owner=prepared.owner)

    rolled_back = await store.load(created.job_id, owner=created.owner)
    assert rolled_back == prepared
    assert connection.execute("SELECT state FROM external_resources").fetchone()[0] == "ACTIVE"
    connection.execute("DROP TRIGGER reject_terminal_resource_transition")
    connection.close()

    reopened = open_migrated_database(path)
    restarted = SqliteJobStore(reopened)
    recovered = await restarted.load(created.job_id, owner=created.owner)
    assert recovered == prepared
    terminal = await restarted.complete_settlement(
        expected=recovered,
        owner=recovered.owner,
    )

    assert terminal is not None and terminal.state is JobState.SUCCEEDED
    resource = reopened.execute(
        """
        SELECT resource_id, service_id, resource_type, provider_resource_id,
               principal_id, quota_scope_id, credential_id,
               credential_generation, pool_id, creating_request_id,
               owner_session_id, owner_workspace_id, owner_root_run_id,
               created_at_ms, metadata_json, state, updated_at_ms
          FROM external_resources
        """
    ).fetchone()
    assert resource is not None
    assert tuple(resource[:-2]) == tuple(authority_before)
    assert tuple(resource[-2:]) == ("COMPLETED", 500)
    assert await restarted.load(created.job_id, owner=created.owner) == terminal
    assert await restarted.list(owner=created.owner) == (terminal,)
    reopened.close()
