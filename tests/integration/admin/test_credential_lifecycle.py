from __future__ import annotations

import asyncio
import json
import os
import sqlite3
import threading
from collections.abc import Callable
from pathlib import Path
from unittest import mock

import pytest

from gatehouse.admin.lifecycle import (
    CredentialLifecycleConflict,
    CredentialLifecycleFailure,
    SqliteCredentialLifecycleService,
)
from gatehouse.admin.models import (
    CredentialMutationResult,
    CredentialProvisionRequest,
    CredentialRotationRequest,
    CredentialStateChangeRequest,
)
from gatehouse.core.ids import (
    CredentialId,
    LeaseId,
    PoolId,
    PrincipalId,
    QuotaScopeId,
    RequestId,
    RootRunId,
    SessionId,
    WorkspaceId,
)
from gatehouse.credentials import DpapiCurrentUserKeyStore, InMemoryKeyStore
from gatehouse.credentials.base import CredentialMetadata
from gatehouse.database import GatehouseRepository, open_migrated_database
from gatehouse.jobs import JobState, SqliteJobStore
from gatehouse.routing import CredentialLeaseManager, ResourceAffinity, SqliteRoutingCatalog

CANARY = b"FAKE-LIFECYCLE-CANARY-NOT-A-REAL-KEY-1234567890"
REASON_CANARY = "ghp_FAKE_REASON_CANARY_MUST_NOT_REACH_SQLITE_987654"
NOW_MS = 1_800_000_000_000
PRINCIPAL_ID = "prn_01K00000000000000000000000"
SCOPE_ID = "quota_01K00000000000000000000000"
POOL_ID = "pool_01K00000000000000000000000"
JOB_SUFFIX = "01K00000000000000000000001"


def _seed_route(connection: sqlite3.Connection) -> None:
    connection.execute(
        """
        INSERT INTO principals(
            principal_id, service_id, alias, enabled, created_at_ms, updated_at_ms
        ) VALUES (?, 'firecrawl', 'primary-principal', 1, ?, ?)
        """,
        (PRINCIPAL_ID, NOW_MS, NOW_MS),
    )
    connection.execute(
        """
        INSERT INTO quota_scopes(
            quota_scope_id, principal_id, alias, state, unit,
            last_known_remaining_units, configured_floor_units
        ) VALUES (?, ?, 'primary-scope', 'HEALTHY', 'credits', NULL, 0)
        """,
        (SCOPE_ID, PRINCIPAL_ID),
    )
    connection.execute(
        """
        INSERT INTO credentials(
            credential_id, principal_id, quota_scope_id, alias,
            secret_backend, secret_reference, state, generation, created_at_ms,
            credential_role
        ) VALUES ('credential-lifecycle-observer', ?, ?, 'balance-observer',
                  'test', 'observer-reference', 'HEALTHY', 1, ?, 'OBSERVER')
        """,
        (PRINCIPAL_ID, SCOPE_ID, NOW_MS),
    )
    connection.execute(
        """
        INSERT INTO quota_snapshots(
            snapshot_id, quota_scope_id, remaining_units, unit,
            captured_at_ms, source, observed_remaining_units_decimal,
            quota_dimension_id, credential_id, credential_generation,
            stale_at_ms, observation_kind
        ) VALUES ('snapshot-lifecycle-route', ?, 1000, 'credits', ?,
                  'integration-test', '1000', ?, 'credential-lifecycle-observer',
                  1, 9223372036854775807, 'AUTHENTICATED')
        """,
        (SCOPE_ID, NOW_MS, f"dimension_legacy_primary:{SCOPE_ID}"),
    )
    connection.execute(
        """
        UPDATE quota_scopes
           SET last_known_remaining_units = 1000,
               balance_as_of_ms = ?,
               balance_snapshot_id = 'snapshot-lifecycle-route'
         WHERE quota_scope_id = ?
        """,
        (NOW_MS, SCOPE_ID),
    )
    connection.execute(
        """
        INSERT INTO pools(
            pool_id, service_id, alias, state, selection_strategy,
            automatic_use, config_json
        ) VALUES (?, 'firecrawl', 'interactive-default', 'ACTIVE',
                  'fill_first', 1, '{}')
        """,
        (POOL_ID,),
    )
    connection.execute(
        """
        INSERT INTO pool_members(pool_id, quota_scope_id, priority, cost_rank, enabled)
        VALUES (?, ?, 100, 100, 1)
        """,
        (POOL_ID, SCOPE_ID),
    )


def _service(
    path: Path,
    *,
    event_id_factory: Callable[[], str] | None = None,
) -> tuple[sqlite3.Connection, InMemoryKeyStore, SqliteCredentialLifecycleService]:
    connection = open_migrated_database(path)
    _seed_route(connection)
    store = InMemoryKeyStore()
    if event_id_factory is None:
        service = SqliteCredentialLifecycleService(
            connection,
            persistent_key_store=store,
            now_ms=lambda: NOW_MS,
        )
    else:
        service = SqliteCredentialLifecycleService(
            connection,
            persistent_key_store=store,
            now_ms=lambda: NOW_MS,
            event_id_factory=event_id_factory,
        )
    return connection, store, service


def _provision_request(mutation_id: str = "mutation-provision-0001") -> CredentialProvisionRequest:
    return CredentialProvisionRequest(
        mutation_id=mutation_id,
        principal_id=PRINCIPAL_ID,
        quota_scope_id=SCOPE_ID,
        pool_id=POOL_ID,
        alias="primary",
        expires_at_ms=None,
        exclusive_usage=True,
    )


def _database_text(connection: sqlite3.Connection) -> str:
    values: list[str] = []
    tables = tuple(
        str(row[0])
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
        )
    )
    for table in tables:
        for row in connection.execute(f'SELECT * FROM "{table}"'):  # noqa: S608
            values.extend(str(value) for value in row if value is not None)
    return "\n".join(values)


def _managed_credential_count(connection: sqlite3.Connection) -> int:
    return int(
        connection.execute(
            "SELECT COUNT(*) FROM credentials WHERE credential_role != 'OBSERVER'"
        ).fetchone()[0]
    )


def _assert_database_files_exclude(path: Path, *canaries: bytes) -> None:
    for candidate in (path, Path(f"{path}-wal"), Path(f"{path}-shm")):
        if not candidate.exists():
            continue
        content = candidate.read_bytes()
        for canary in canaries:
            assert canary not in content


async def _wait_for_thread_event(event: threading.Event) -> None:
    for _ in range(500):
        if event.is_set():
            return
        await asyncio.sleep(0.01)
    raise AssertionError("synthetic worker did not reach its publication checkpoint")


def _exception_graph_text(exception: BaseException) -> str:
    pending = [exception]
    seen: set[int] = set()
    rendered: list[str] = []
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        rendered.append(f"{type(current).__name__}: {current!s}")
        if current.__cause__ is not None:
            pending.append(current.__cause__)
        if current.__context__ is not None:
            pending.append(current.__context__)
    return "\n".join(rendered)


class _LeaseAfterReplacementStageStore(InMemoryKeyStore):
    def __init__(self, connection: sqlite3.Connection) -> None:
        super().__init__()
        self.connection = connection
        self.original_credential_id: str | None = None

    async def put(self, metadata: CredentialMetadata, secret: bytes) -> str:
        reference = await super().put(metadata, secret)
        if metadata.generation > 1 and self.original_credential_id is not None:
            self.connection.execute(
                """
                INSERT INTO leases(
                    lease_id, lease_type, lease_key, owner_id, state, generation,
                    acquired_at_ms, heartbeat_at_ms, expires_at_ms
                ) VALUES ('lease-arrived-during-rotation', 'provider-credential', ?,
                          'request-owner', 'ACTIVE', 1, ?, ?, ?)
                """,
                (
                    self.original_credential_id,
                    NOW_MS,
                    NOW_MS,
                    NOW_MS + 60_000,
                ),
            )
        return reference


class _ConcurrentRotationStore(InMemoryKeyStore):
    def __init__(self) -> None:
        super().__init__()
        self._staged_successors = 0
        self._both_staged = asyncio.Event()

    async def put(self, metadata: CredentialMetadata, secret: bytes) -> str:
        reference = await super().put(metadata, secret)
        if metadata.generation > 1:
            self._staged_successors += 1
            if self._staged_successors == 2:
                self._both_staged.set()
            await asyncio.wait_for(self._both_staged.wait(), timeout=1)
        return reference


class _SyntheticCrash(BaseException):
    pass


class _CrashAfterDrainStore(InMemoryKeyStore):
    crash_after_drain = False

    async def update_metadata(
        self,
        metadata: CredentialMetadata,
        *,
        expected_generation: int,
    ) -> CredentialMetadata:
        updated = await super().update_metadata(
            metadata,
            expected_generation=expected_generation,
        )
        if self.crash_after_drain and metadata.state == "DRAINING":
            raise _SyntheticCrash
        return updated


class _PartialDeleteStore(InMemoryKeyStore):
    fail_next_delete = False

    def __init__(self) -> None:
        super().__init__()
        self.partial_ids: set[str] = set()

    async def delete(self, credential_id: str) -> None:
        await super().delete(credential_id)
        if self.fail_next_delete:
            self.fail_next_delete = False
            self.partial_ids.add(credential_id)
            raise RuntimeError("synthetic partial delete")

    async def discard_partial(self, credential_id: str) -> bool:
        if credential_id not in self.partial_ids:
            return False
        self.partial_ids.remove(credential_id)
        return True


class _CrashBeforeStateCustodyStore(InMemoryKeyStore):
    crash_before_disable = False

    async def update_metadata(
        self,
        metadata: CredentialMetadata,
        *,
        expected_generation: int,
    ) -> CredentialMetadata:
        if self.crash_before_disable and metadata.state == "DISABLED":
            raise _SyntheticCrash
        return await super().update_metadata(
            metadata,
            expected_generation=expected_generation,
        )


class _CrashBeforeCustodyMarkerService(SqliteCredentialLifecycleService):
    crash_before_marker = True

    def _advance_mutation_phase(
        self,
        mutation_id: str,
        operation: str,
        *,
        expected_state: str,
        next_state: str,
        active_secret: bytearray | None = None,
    ) -> None:
        if self.crash_before_marker:
            raise _SyntheticCrash
        super()._advance_mutation_phase(
            mutation_id,
            operation,
            expected_state=expected_state,
            next_state=next_state,
            active_secret=active_secret,
        )


class _CrashAfterCustodyMarkerService(SqliteCredentialLifecycleService):
    def _advance_mutation_phase(
        self,
        mutation_id: str,
        operation: str,
        *,
        expected_state: str,
        next_state: str,
        active_secret: bytearray | None = None,
    ) -> None:
        super()._advance_mutation_phase(
            mutation_id,
            operation,
            expected_state=expected_state,
            next_state=next_state,
            active_secret=active_secret,
        )
        if next_state == "CUSTODY_CREATED":
            raise _SyntheticCrash


class _FailureAfterCustodyPublishStore(InMemoryKeyStore):
    async def put(self, metadata: CredentialMetadata, secret: bytes) -> str:
        await super().put(metadata, secret)
        raise RuntimeError(CANARY.decode())


class _ActiveSecretReferenceStore(InMemoryKeyStore):
    return_active_secret = False

    async def put(self, metadata: CredentialMetadata, secret: bytes) -> str:
        reference = await super().put(metadata, secret)
        if self.return_active_secret:
            return bytes(secret).decode("utf-8")
        return reference


class _OwnedStagedPartialFailureStore(InMemoryKeyStore):
    def __init__(self) -> None:
        super().__init__()
        self.staged: dict[str, str] = {}
        self.cleanup_calls: list[tuple[str, str]] = []

    async def put(self, metadata: CredentialMetadata, secret: bytes) -> str:
        del secret
        self.staged[metadata.credential_id] = metadata.alias
        raise RuntimeError("synthetic owned partial publication")

    async def discard_staged(self, credential_id: str, *, staged_alias: str) -> bool:
        self.cleanup_calls.append((credential_id, staged_alias))
        if self.staged.get(credential_id) != staged_alias:
            return False
        self.staged.pop(credential_id)
        return True


class _SwitchingClock:
    def __init__(self, value: int) -> None:
        self.value = value

    def __call__(self) -> int:
        return self.value


class _ClockSwitchFailureStore(InMemoryKeyStore):
    def __init__(self, clock: _SwitchingClock, failure_time: int) -> None:
        super().__init__()
        self.clock = clock
        self.failure_time = failure_time
        self.fail_next_put = False

    async def put(self, metadata: CredentialMetadata, secret: bytes) -> str:
        if self.fail_next_put:
            self.fail_next_put = False
            self.clock.value = self.failure_time
            raise RuntimeError("synthetic custody failure after clock switch")
        return await super().put(metadata, secret)


@pytest.mark.asyncio
@pytest.mark.parametrize("secret_value", (b"RUNNING", b"none", b"application/json", b"201"))
async def test_non_namespaced_secret_is_rejected_before_custody_or_mutation(
    tmp_path: Path,
    secret_value: bytes,
) -> None:
    connection, store, service = _service(tmp_path / f"invalid-secret-{secret_value.hex()}.db")
    secret = bytearray(secret_value)

    with pytest.raises(CredentialLifecycleFailure, match="accepted provider namespace"):
        await service.provision_credential(
            _provision_request(f"mutation-invalid-secret-{secret_value.hex()}"),
            secret,
            "admin-session-1",
        )

    assert secret == bytearray(len(secret_value))
    assert await store.list_metadata() == ()
    assert connection.execute("SELECT COUNT(*) FROM credential_mutations").fetchone()[0] == 0
    assert _managed_credential_count(connection) == 0
    connection.close()


@pytest.mark.asyncio
async def test_provision_is_idempotent_and_persists_only_redacted_metadata(tmp_path: Path) -> None:
    database = tmp_path / "provision.db"
    replay_audit_id = "fc-" + "replay-audit-token-000000000001"
    connection, store, service = _service(
        database,
        event_id_factory=lambda: replay_audit_id,
    )
    request = _provision_request()
    first_secret = bytearray(CANARY)
    replay_secret = bytearray(CANARY)

    first = await service.provision_credential(request, first_secret, "admin-session-1")
    second = await service.provision_credential(request, replay_secret, "admin-session-1")

    assert first_secret == bytearray(len(CANARY))
    assert replay_secret == bytearray(len(CANARY))
    assert second == first
    assert first.state == "HEALTHY"
    assert first.generation == 1
    assert first.mutation_id == request.mutation_id
    assert first.principal_id == PRINCIPAL_ID
    assert first.principal_alias == "primary-principal"
    assert first.quota_scope_id == SCOPE_ID
    assert first.quota_scope_alias == "primary-scope"
    assert first.pool_id == POOL_ID
    assert first.pool_alias == "interactive-default"
    assert CANARY.decode() not in repr(first)
    assert CANARY.decode() not in _database_text(connection)
    metadata = await store.list_metadata()
    assert len(metadata) == 1
    assert metadata[0].credential_id == first.credential_id
    assert metadata[0].alias == "primary"
    lease = await store.open_lease(
        first.credential_id,
        "provider-transport:test",
        expected_generation=1,
    )
    async with lease as view:
        assert bytes(view) == CANARY
    audit = connection.execute(
        "SELECT event_type, preserve, payload_json FROM audit_events"
    ).fetchone()
    assert tuple(audit)[:2] == ("credential.provisioned", 1)
    assert CANARY.decode() not in str(audit["payload_json"])
    _assert_database_files_exclude(database, CANARY)
    reflected_replay = bytearray(first.audit_event_id.encode("utf-8"))
    with pytest.raises(CredentialLifecycleFailure, match="result overlaps"):
        await service.provision_credential(request, reflected_replay, "admin-session-1")
    assert reflected_replay == bytearray(len(first.audit_event_id.encode("utf-8")))
    connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    connection.close()
    _assert_database_files_exclude(database, CANARY)


@pytest.mark.asyncio
async def test_duplicate_alias_and_invalid_route_fail_without_orphaned_custody(
    tmp_path: Path,
) -> None:
    connection, store, service = _service(tmp_path / "duplicates.db")
    await service.provision_credential(
        _provision_request("mutation-provision-first"),
        bytearray(CANARY),
        "admin-session-1",
    )

    with pytest.raises(CredentialLifecycleConflict):
        await service.provision_credential(
            _provision_request("mutation-provision-second"),
            bytearray(b"FAKE-SECOND-CANARY-NOT-A-REAL-KEY-123456"),
            "admin-session-1",
        )
    invalid = _provision_request("mutation-invalid-route").model_copy(
        update={"pool_id": "pool_01K00000000000000000000001"}
    )
    with pytest.raises(CredentialLifecycleFailure):
        await service.provision_credential(invalid, bytearray(CANARY), "admin-session-1")

    assert len(await store.list_metadata()) == 1
    assert _managed_credential_count(connection) == 1
    assert CANARY.decode() not in _database_text(connection)
    connection.close()


class _FailingStore(InMemoryKeyStore):
    async def put(self, *args: object, **kwargs: object) -> str:
        del args, kwargs
        raise RuntimeError(CANARY.decode())


@pytest.mark.asyncio
async def test_custody_failure_rolls_back_without_secret_or_route(tmp_path: Path) -> None:
    connection = open_migrated_database(tmp_path / "failure.db")
    _seed_route(connection)
    service = SqliteCredentialLifecycleService(
        connection,
        persistent_key_store=_FailingStore(),
        now_ms=lambda: NOW_MS,
    )

    secret = bytearray(CANARY)
    with pytest.raises(CredentialLifecycleFailure) as captured:
        await service.provision_credential(
            _provision_request("mutation-custody-failure"),
            secret,
            "admin-session-1",
        )

    assert secret == bytearray(len(CANARY))
    assert CANARY.decode() not in str(captured.value)
    assert CANARY.decode() not in _exception_graph_text(captured.value)
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None
    assert _managed_credential_count(connection) == 0
    mutation = connection.execute(
        "SELECT state FROM credential_mutations WHERE mutation_id = ?",
        ("mutation-custody-failure",),
    ).fetchone()
    assert mutation[0] == "CLEANUP_REQUIRED"
    assert CANARY.decode() not in _database_text(connection)

    assert await service.recover_incomplete_mutations() >= 1
    recovered = connection.execute(
        "SELECT state FROM credential_mutations WHERE mutation_id = ?",
        ("mutation-custody-failure",),
    ).fetchone()
    assert recovered[0] == "ROLLED_BACK"
    connection.close()


@pytest.mark.asyncio
async def test_provision_rejects_secret_duplicated_into_metadata_before_persistence(
    tmp_path: Path,
) -> None:
    connection, store, service = _service(tmp_path / "provision-secret-overlap.db")
    request = _provision_request("mutation-provision-secret-overlap").model_copy(
        update={"alias": CANARY.decode()}
    )
    secret = bytearray(CANARY)

    with pytest.raises(CredentialLifecycleFailure, match="metadata overlaps"):
        await service.provision_credential(request, secret, "admin-session-1")

    assert secret == bytearray(len(CANARY))
    assert await store.list_metadata() == ()
    assert _managed_credential_count(connection) == 0
    assert connection.execute("SELECT COUNT(*) FROM credential_mutations").fetchone()[0] == 0
    assert CANARY.decode() not in _database_text(connection)
    connection.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("case", "generated_credential_id", "generated_event_id"),
    (
        ("credential-id", CANARY.decode(), "evt_safe_provision_overlap"),
        ("event-id", "cred_safe_provision_overlap", CANARY.decode()),
    ),
)
async def test_provision_rejects_generated_value_equal_to_active_secret(
    tmp_path: Path,
    case: str,
    generated_credential_id: str,
    generated_event_id: str,
) -> None:
    database = tmp_path / f"provision-generated-{case}.db"
    connection = open_migrated_database(database)
    _seed_route(connection)
    store = InMemoryKeyStore()
    service = SqliteCredentialLifecycleService(
        connection,
        persistent_key_store=store,
        now_ms=lambda: NOW_MS,
        credential_id_factory=lambda: generated_credential_id,
        event_id_factory=lambda: generated_event_id,
    )
    caller_secret = bytearray(CANARY)

    with pytest.raises(CredentialLifecycleFailure, match="metadata overlaps") as captured:
        await service.provision_credential(
            _provision_request(f"mutation-provision-generated-{case}"),
            caller_secret,
            "admin-session-1",
        )

    assert caller_secret == bytearray(len(CANARY))
    assert await store.list_metadata() == ()
    assert _managed_credential_count(connection) == 0
    assert connection.execute("SELECT COUNT(*) FROM credential_mutations").fetchone()[0] == 0
    assert CANARY.decode() not in repr(captured.value)
    assert CANARY.decode() not in _database_text(connection)
    _assert_database_files_exclude(database, CANARY)
    connection.close()


@pytest.mark.asyncio
async def test_provision_cleans_custody_when_returned_reference_equals_active_secret(
    tmp_path: Path,
) -> None:
    database = tmp_path / "provision-reference-secret-overlap.db"
    connection = open_migrated_database(database)
    _seed_route(connection)
    store = _ActiveSecretReferenceStore()
    store.return_active_secret = True
    service = SqliteCredentialLifecycleService(
        connection,
        persistent_key_store=store,
        now_ms=lambda: NOW_MS,
        credential_id_factory=lambda: "cred_provision_reference_overlap",
        event_id_factory=lambda: "evt_provision_reference_overlap",
    )
    caller_secret = bytearray(CANARY)

    with pytest.raises(CredentialLifecycleFailure, match="custody metadata is invalid") as captured:
        await service.provision_credential(
            _provision_request("mutation-provision-reference-overlap"),
            caller_secret,
            "admin-session-1",
        )

    assert caller_secret == bytearray(len(CANARY))
    assert await store.list_metadata() == ()
    assert _managed_credential_count(connection) == 0
    mutation = connection.execute(
        "SELECT state, result_json FROM credential_mutations WHERE mutation_id = ?",
        ("mutation-provision-reference-overlap",),
    ).fetchone()
    assert tuple(mutation) == ("ROLLED_BACK", "{}")
    assert CANARY.decode() not in repr(captured.value)
    assert CANARY.decode() not in _database_text(connection)
    _assert_database_files_exclude(database, CANARY)
    connection.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "secret_value",
    (
        b"true",
        b"null",
        b"custody_created",
        b'{"logical_alias":"primary"}',
        b'"alias":"primary"',
    ),
)
async def test_provision_rejects_exact_serialized_internal_secret_surfaces(
    tmp_path: Path,
    secret_value: bytes,
) -> None:
    database = tmp_path / f"serialized-overlap-{secret_value.hex()}.db"
    connection, store, service = _service(database)
    secret = bytearray(secret_value)

    with pytest.raises(
        CredentialLifecycleFailure,
        match="metadata overlaps|metadata is invalid|accepted provider namespace",
    ):
        await service.provision_credential(
            _provision_request(f"mutation-serialized-overlap-{secret_value.hex()}"),
            secret,
            "admin-session-1",
        )

    assert secret == bytearray(len(secret_value))
    assert await store.list_metadata() == ()
    assert _managed_credential_count(connection) == 0
    assert secret_value.decode("ascii") not in _database_text(connection)
    _assert_database_files_exclude(database, secret_value)
    connection.close()


@pytest.mark.asyncio
async def test_cleanup_timestamp_equal_to_secret_is_never_persisted(tmp_path: Path) -> None:
    cleanup_time = NOW_MS + 987_654
    clock = _SwitchingClock(NOW_MS)
    connection = open_migrated_database(tmp_path / "cleanup-time-overlap.db")
    _seed_route(connection)
    store = _ClockSwitchFailureStore(clock, cleanup_time)
    store.fail_next_put = True
    service = SqliteCredentialLifecycleService(
        connection,
        persistent_key_store=store,
        now_ms=clock,
    )
    secret_value = str(cleanup_time).encode("ascii")
    secret = bytearray(secret_value)

    with pytest.raises(CredentialLifecycleFailure, match="accepted provider namespace"):
        await service.provision_credential(
            _provision_request("mutation-cleanup-time-overlap"),
            secret,
            "admin-session-1",
        )

    assert secret == bytearray(len(secret_value))
    assert await store.list_metadata() == ()
    assert secret_value.decode("ascii") not in _database_text(connection)
    connection.close()


@pytest.mark.asyncio
async def test_metadata_commit_failure_deletes_complete_new_custody(tmp_path: Path) -> None:
    connection, store, service = _service(tmp_path / "commit-rollback.db")
    connection.execute(
        """
        CREATE TRIGGER reject_test_credential_insert
        BEFORE INSERT ON credentials
        BEGIN
            SELECT RAISE(ABORT, 'synthetic metadata failure');
        END
        """
    )

    with pytest.raises(CredentialLifecycleConflict):
        await service.provision_credential(
            _provision_request("mutation-commit-rollback"),
            bytearray(CANARY),
            "admin-session-1",
        )

    assert await store.list_metadata() == ()
    assert _managed_credential_count(connection) == 0
    assert (
        connection.execute(
            "SELECT state FROM credential_mutations WHERE mutation_id = ?",
            ("mutation-commit-rollback",),
        ).fetchone()[0]
        == "ROLLED_BACK"
    )
    connection.close()


@pytest.mark.asyncio
async def test_custody_id_collision_never_deletes_unowned_material(tmp_path: Path) -> None:
    connection = open_migrated_database(tmp_path / "custody-collision.db")
    _seed_route(connection)
    store = InMemoryKeyStore()
    collision_id = "cred_collision_0001"
    collision_secret = b"FAKE-UNOWNED-COLLISION-CANARY-NOT-A-REAL-KEY"
    await store.put(
        CredentialMetadata(
            credential_id=collision_id,
            principal_id=PRINCIPAL_ID,
            quota_scope_id=SCOPE_ID,
            alias="preexisting-custody",
        ),
        collision_secret,
    )
    service = SqliteCredentialLifecycleService(
        connection,
        persistent_key_store=store,
        now_ms=lambda: NOW_MS,
        credential_id_factory=lambda: collision_id,
    )

    with pytest.raises(CredentialLifecycleConflict):
        await service.provision_credential(
            _provision_request("mutation-custody-collision"),
            bytearray(CANARY),
            "admin-session-1",
        )

    await service.recover_incomplete_mutations()
    lease = await store.open_lease(collision_id, "collision-preservation")
    async with lease as view:
        assert bytes(view) == collision_secret
    assert (
        connection.execute(
            "SELECT state FROM credential_mutations WHERE mutation_id = ?",
            ("mutation-custody-collision",),
        ).fetchone()[0]
        == "CLEANUP_REQUIRED"
    )
    connection.close()


@pytest.mark.asyncio
async def test_recovery_removes_intent_marked_custody_created_before_phase_marker(
    tmp_path: Path,
) -> None:
    connection = open_migrated_database(tmp_path / "ambiguous-custody.db")
    _seed_route(connection)
    store = InMemoryKeyStore()
    service = _CrashBeforeCustodyMarkerService(
        connection,
        persistent_key_store=store,
        now_ms=lambda: NOW_MS,
        credential_id_factory=lambda: "cred_ambiguous_custody",
    )

    with pytest.raises(_SyntheticCrash):
        await service.provision_credential(
            _provision_request("mutation-ambiguous-custody"),
            bytearray(CANARY),
            "admin-session-1",
        )

    staged = (await store.list_metadata())[0]
    assert staged.credential_id == "cred_ambiguous_custody"
    assert staged.alias.startswith("pending-")
    await service.recover_incomplete_mutations()
    assert await store.list_metadata() == ()
    assert (
        connection.execute(
            "SELECT state FROM credential_mutations WHERE mutation_id = ?",
            ("mutation-ambiguous-custody",),
        ).fetchone()[0]
        == "ROLLED_BACK"
    )
    connection.close()


@pytest.mark.asyncio
async def test_recovery_cleans_owned_custody_when_put_fails_after_publication(
    tmp_path: Path,
) -> None:
    connection = open_migrated_database(tmp_path / "published-put-failure.db")
    _seed_route(connection)
    store = _FailureAfterCustodyPublishStore()
    service = SqliteCredentialLifecycleService(
        connection,
        persistent_key_store=store,
        now_ms=lambda: NOW_MS,
        credential_id_factory=lambda: "cred_failed_after_publish",
    )

    with pytest.raises(CredentialLifecycleFailure) as captured:
        await service.provision_credential(
            _provision_request("mutation-failed-after-publish"),
            bytearray(CANARY),
            "admin-session-1",
        )

    assert CANARY.decode() not in _exception_graph_text(captured.value)
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None
    assert [item.credential_id for item in await store.list_metadata()] == [
        "cred_failed_after_publish"
    ]
    assert (
        connection.execute(
            "SELECT state FROM credential_mutations WHERE mutation_id = ?",
            ("mutation-failed-after-publish",),
        ).fetchone()[0]
        == "CLEANUP_REQUIRED"
    )

    assert await service.recover_incomplete_mutations() >= 1
    assert await store.list_metadata() == ()
    assert (
        connection.execute(
            "SELECT state FROM credential_mutations WHERE mutation_id = ?",
            ("mutation-failed-after-publish",),
        ).fetchone()[0]
        == "ROLLED_BACK"
    )
    connection.close()


@pytest.mark.asyncio
async def test_recovery_uses_exact_journal_intent_for_owned_partial_custody(
    tmp_path: Path,
) -> None:
    connection = open_migrated_database(tmp_path / "owned-partial-recovery.db")
    _seed_route(connection)
    store = _OwnedStagedPartialFailureStore()
    credential_id = "cred_owned_partial_recovery"
    service = SqliteCredentialLifecycleService(
        connection,
        persistent_key_store=store,
        now_ms=lambda: NOW_MS,
        credential_id_factory=lambda: credential_id,
    )

    with pytest.raises(CredentialLifecycleFailure):
        await service.provision_credential(
            _provision_request("mutation-owned-partial-recovery"),
            bytearray(CANARY),
            "admin-session-1",
        )

    journal = connection.execute(
        "SELECT state, metadata_json FROM credential_mutations WHERE mutation_id = ?",
        ("mutation-owned-partial-recovery",),
    ).fetchone()
    assert journal[0] == "CLEANUP_REQUIRED"
    intent_alias = json.loads(journal[1])["custody_intent_alias"]
    assert store.staged == {credential_id: intent_alias}

    assert await service.recover_incomplete_mutations() >= 1
    assert store.cleanup_calls == [(credential_id, intent_alias)]
    assert store.staged == {}
    assert (
        connection.execute(
            "SELECT state FROM credential_mutations WHERE mutation_id = ?",
            ("mutation-owned-partial-recovery",),
        ).fetchone()[0]
        == "ROLLED_BACK"
    )
    connection.close()


@pytest.mark.skipif(os.name != "nt", reason="current-user DPAPI lifecycle test requires Windows")
@pytest.mark.asyncio
async def test_real_dpapi_lifecycle_provision_survives_fresh_reopen(tmp_path: Path) -> None:
    database = tmp_path / "dpapi-lifecycle-reopen.db"
    custody_root = tmp_path / "credentials"
    first_connection = open_migrated_database(database)
    _seed_route(first_connection)
    first_store = DpapiCurrentUserKeyStore(custody_root)
    first_service = SqliteCredentialLifecycleService(
        first_connection,
        persistent_key_store=first_store,
        now_ms=lambda: NOW_MS,
    )
    caller_secret = bytearray(CANARY)
    provisioned = await first_service.provision_credential(
        _provision_request("mutation-dpapi-reopen"),
        caller_secret,
        "admin-session-1",
    )
    assert caller_secret == bytearray(len(CANARY))
    first_connection.close()

    reopened_connection = open_migrated_database(database)
    reopened_store = DpapiCurrentUserKeyStore(custody_root)
    reopened_service = SqliteCredentialLifecycleService(
        reopened_connection,
        persistent_key_store=reopened_store,
        now_ms=lambda: NOW_MS,
    )
    assert await reopened_service.recover_incomplete_mutations() == 0
    reopened_metadata = await reopened_store.list_metadata()
    assert [(item.credential_id, item.state, item.generation) for item in reopened_metadata] == [
        (provisioned.credential_id, "HEALTHY", 1)
    ]
    assert (
        reopened_metadata[0].secret_reference
        == reopened_connection.execute(
            "SELECT secret_reference FROM credentials WHERE credential_id = ?",
            (provisioned.credential_id,),
        ).fetchone()[0]
    )

    reopened_lease = await reopened_store.open_lease(
        provisioned.credential_id,
        "provider-transport:reopen-proof",
        expected_generation=1,
    )
    async with reopened_lease as view:
        assert bytes(view) == CANARY
        retained_view = view
    assert bytes(retained_view) == b"\x00" * len(CANARY)
    _assert_database_files_exclude(database, CANARY)
    assert all(CANARY not in path.read_bytes() for path in custody_root.iterdir() if path.is_file())
    reopened_connection.close()


@pytest.mark.skipif(os.name != "nt", reason="current-user DPAPI lifecycle test requires Windows")
@pytest.mark.asyncio
async def test_custody_created_recovery_uses_fresh_dpapi_store_and_connection(
    tmp_path: Path,
) -> None:
    database = tmp_path / "dpapi-custody-created-crash.db"
    custody_root = tmp_path / "credentials"
    credential_id = "cred_dpapi_custody_created_recovery"
    first_connection = open_migrated_database(database)
    _seed_route(first_connection)
    first_store = DpapiCurrentUserKeyStore(custody_root)
    crashing_service = _CrashAfterCustodyMarkerService(
        first_connection,
        persistent_key_store=first_store,
        now_ms=lambda: NOW_MS,
        credential_id_factory=lambda: credential_id,
    )
    caller_secret = bytearray(CANARY)

    with pytest.raises(_SyntheticCrash):
        await crashing_service.provision_credential(
            _provision_request("mutation-dpapi-custody-created-crash"),
            caller_secret,
            "admin-session-1",
        )

    assert caller_secret == bytearray(len(CANARY))
    assert (
        first_connection.execute(
            "SELECT state FROM credential_mutations WHERE mutation_id = ?",
            ("mutation-dpapi-custody-created-crash",),
        ).fetchone()[0]
        == "CUSTODY_CREATED"
    )
    assert _managed_credential_count(first_connection) == 0
    assert [item.credential_id for item in await first_store.list_metadata()] == [credential_id]
    first_connection.close()

    reopened_connection = open_migrated_database(database)
    reopened_store = DpapiCurrentUserKeyStore(custody_root)
    reopened_service = SqliteCredentialLifecycleService(
        reopened_connection,
        persistent_key_store=reopened_store,
        now_ms=lambda: NOW_MS,
    )
    assert await reopened_service.recover_incomplete_mutations() >= 1
    assert await reopened_store.list_metadata() == ()
    assert list(custody_root.iterdir()) == []
    assert (
        reopened_connection.execute(
            "SELECT state FROM credential_mutations WHERE mutation_id = ?",
            ("mutation-dpapi-custody-created-crash",),
        ).fetchone()[0]
        == "ROLLED_BACK"
    )
    assert _managed_credential_count(reopened_connection) == 0
    _assert_database_files_exclude(database, CANARY)
    reopened_connection.close()


@pytest.mark.skipif(os.name != "nt", reason="current-user DPAPI lifecycle test requires Windows")
@pytest.mark.asyncio
async def test_cancelled_dpapi_publication_retains_restart_cleanup_evidence(
    tmp_path: Path,
) -> None:
    database = tmp_path / "dpapi-cancelled-publication.db"
    custody_root = tmp_path / "credentials"
    credential_id = "cred_dpapi_cancelled_publication"
    mutation_id = "mutation-dpapi-cancelled-publication"
    first_connection = open_migrated_database(database)
    _seed_route(first_connection)
    first_store = DpapiCurrentUserKeyStore(custody_root, maximum_io_workers=1)
    first_service = SqliteCredentialLifecycleService(
        first_connection,
        persistent_key_store=first_store,
        now_ms=lambda: NOW_MS,
        credential_id_factory=lambda: credential_id,
    )
    publication_blocked = threading.Event()
    release_publication = threading.Event()
    original_stage = first_store._stage_owned_file
    intent_path = first_store._intent_path(credential_id)
    blob_path, metadata_path = first_store._paths(credential_id)

    def block_metadata_stage(path: Path, data: bytes) -> Path:
        if ".json." in path.name:
            publication_blocked.set()
            if not release_publication.wait(timeout=5):
                raise TimeoutError("synthetic publication worker timed out")
        return original_stage(path, data)

    def fail_late_cleanup(_credential_id: str, *, staged_alias: str) -> bool:
        del staged_alias
        raise OSError("synthetic late cleanup failure")

    caller_secret = bytearray(CANARY)
    staged: tuple[CredentialMetadata, ...] = ()
    task: asyncio.Task[CredentialMutationResult] | None = None
    safety_release = threading.Timer(2, release_publication.set)
    safety_release.start()
    try:
        with (
            mock.patch.object(
                first_store,
                "_stage_owned_file",
                side_effect=block_metadata_stage,
            ),
            mock.patch.object(
                first_store,
                "_discard_staged_sync",
                side_effect=fail_late_cleanup,
            ),
        ):
            task = asyncio.create_task(
                first_service.provision_credential(
                    _provision_request(mutation_id),
                    caller_secret,
                    "admin-session-1",
                )
            )
            await _wait_for_thread_event(publication_blocked)
            assert intent_path.is_file()
            assert blob_path.is_file()
            assert not metadata_path.exists()

            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            release_publication.set()

            # With one worker slot, this cannot start until the abandoned
            # publication and its injected late-cleanup failure are acknowledged.
            staged = await asyncio.wait_for(first_store.list_metadata(), timeout=2)
    finally:
        release_publication.set()
        safety_release.cancel()
        if task is not None and not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    assert caller_secret == bytearray(len(CANARY))
    assert [(item.credential_id, item.alias.startswith("pending-")) for item in staged] == [
        (credential_id, True)
    ]
    assert intent_path.is_file()
    assert blob_path.is_file()
    assert metadata_path.is_file()
    assert (
        first_connection.execute(
            "SELECT state FROM credential_mutations WHERE mutation_id = ?",
            (mutation_id,),
        ).fetchone()[0]
        == "PREPARED"
    )
    assert _managed_credential_count(first_connection) == 0
    first_connection.close()

    reopened_connection = open_migrated_database(database)
    reopened_store = DpapiCurrentUserKeyStore(custody_root)
    reopened_service = SqliteCredentialLifecycleService(
        reopened_connection,
        persistent_key_store=reopened_store,
        now_ms=lambda: NOW_MS,
    )
    assert await reopened_service.recover_incomplete_mutations() >= 1
    assert await reopened_store.list_metadata() == ()
    assert list(custody_root.iterdir()) == []
    assert (
        reopened_connection.execute(
            "SELECT state FROM credential_mutations WHERE mutation_id = ?",
            (mutation_id,),
        ).fetchone()[0]
        == "ROLLED_BACK"
    )
    assert _managed_credential_count(reopened_connection) == 0
    _assert_database_files_exclude(database, CANARY)
    reopened_connection.close()


@pytest.mark.asyncio
async def test_provision_mutation_id_is_bound_to_all_nonsecret_inputs(tmp_path: Path) -> None:
    connection, _store, service = _service(tmp_path / "provision-binding.db")
    request = _provision_request("mutation-provision-binding")
    await service.provision_credential(request, bytearray(CANARY), "admin-session-1")
    variants = (
        {"principal_id": "prn_different"},
        {"quota_scope_id": "quota_different"},
        {"pool_id": "pool_different"},
        {"alias": "different"},
        {"expires_at_ms": NOW_MS + 60_000},
        {"exclusive_usage": False},
    )

    for update in variants:
        with pytest.raises(CredentialLifecycleConflict):
            await service.provision_credential(
                request.model_copy(update=update),
                bytearray(CANARY),
                "admin-session-1",
            )

    connection.close()


@pytest.mark.asyncio
async def test_rotation_rejects_secret_duplicated_into_command_metadata(tmp_path: Path) -> None:
    connection, store, service = _service(tmp_path / "rotation-secret-overlap.db")
    provisioned = await service.provision_credential(
        _provision_request("mutation-rotation-secret-overlap-source"),
        bytearray(CANARY),
        "admin-session-1",
    )
    secret = bytearray(CANARY)

    with pytest.raises(CredentialLifecycleFailure, match="metadata overlaps"):
        await service.rotate_credential(
            provisioned.credential_id,
            CredentialRotationRequest(
                mutation_id=CANARY.decode(),
                expires_at_ms=None,
            ),
            secret,
            "admin-session-1",
        )

    assert secret == bytearray(len(CANARY))
    assert len(await store.list_metadata()) == 1
    assert _managed_credential_count(connection) == 1
    assert connection.execute("SELECT COUNT(*) FROM credential_mutations").fetchone()[0] == 1
    assert CANARY.decode() not in _database_text(connection)
    connection.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("case", "generated_replacement_id", "generated_event_id"),
    (
        ("replacement-id", CANARY.decode(), "evt_safe_rotation_overlap"),
        ("event-id", "cred_safe_rotation_overlap", CANARY.decode()),
    ),
)
async def test_rotation_rejects_generated_value_equal_to_active_secret(
    tmp_path: Path,
    case: str,
    generated_replacement_id: str,
    generated_event_id: str,
) -> None:
    database = tmp_path / f"rotation-generated-{case}.db"
    connection, store, provision_service = _service(database)
    original_secret = b"FAKE-ORIGINAL-ROTATION-KEY-NOT-A-REAL-SECRET"
    original = await provision_service.provision_credential(
        _provision_request(f"mutation-rotation-generated-{case}-source"),
        bytearray(original_secret),
        "admin-session-1",
    )
    service = SqliteCredentialLifecycleService(
        connection,
        persistent_key_store=store,
        now_ms=lambda: NOW_MS,
        credential_id_factory=lambda: generated_replacement_id,
        event_id_factory=lambda: generated_event_id,
    )
    caller_secret = bytearray(CANARY)

    with pytest.raises(CredentialLifecycleFailure, match="metadata overlaps") as captured:
        await service.rotate_credential(
            original.credential_id,
            CredentialRotationRequest(
                mutation_id=f"mutation-rotation-generated-{case}",
                expires_at_ms=None,
            ),
            caller_secret,
            "admin-session-1",
        )

    assert caller_secret == bytearray(len(CANARY))
    stored = await store.list_metadata()
    assert [item.credential_id for item in stored] == [original.credential_id]
    assert CANARY.decode() not in repr(stored)
    assert _managed_credential_count(connection) == 1
    assert connection.execute("SELECT COUNT(*) FROM credential_mutations").fetchone()[0] == 1
    assert CANARY.decode() not in repr(captured.value)
    assert CANARY.decode() not in _database_text(connection)
    _assert_database_files_exclude(database, CANARY)
    connection.close()


@pytest.mark.asyncio
async def test_rotation_cleans_replacement_when_returned_reference_equals_active_secret(
    tmp_path: Path,
) -> None:
    database = tmp_path / "rotation-reference-secret-overlap.db"
    connection = open_migrated_database(database)
    _seed_route(connection)
    store = _ActiveSecretReferenceStore()
    service = SqliteCredentialLifecycleService(
        connection,
        persistent_key_store=store,
        now_ms=lambda: NOW_MS,
        credential_id_factory=lambda: "cred_rotation_reference_source",
        event_id_factory=lambda: "evt_rotation_reference_source",
    )
    original = await service.provision_credential(
        _provision_request("mutation-rotation-reference-source"),
        bytearray(b"FAKE-ORIGINAL-ROTATION-REFERENCE-KEY"),
        "admin-session-1",
    )
    store.return_active_secret = True
    replacement_id = "cred_rotation_reference_replacement"
    rotation_service = SqliteCredentialLifecycleService(
        connection,
        persistent_key_store=store,
        now_ms=lambda: NOW_MS,
        credential_id_factory=lambda: replacement_id,
        event_id_factory=lambda: "evt_rotation_reference_overlap",
    )
    caller_secret = bytearray(CANARY)

    with pytest.raises(CredentialLifecycleFailure, match="custody metadata is invalid") as captured:
        await rotation_service.rotate_credential(
            original.credential_id,
            CredentialRotationRequest(
                mutation_id="mutation-rotation-reference-overlap",
                expires_at_ms=None,
            ),
            caller_secret,
            "admin-session-1",
        )

    assert caller_secret == bytearray(len(CANARY))
    stored = await store.list_metadata()
    assert [item.credential_id for item in stored] == [original.credential_id]
    assert replacement_id not in repr(stored)
    assert CANARY.decode() not in repr(stored)
    durable = connection.execute(
        "SELECT credential_id, state, generation FROM credentials "
        "WHERE credential_role != 'OBSERVER'"
    ).fetchall()
    assert [tuple(row) for row in durable] == [(original.credential_id, "HEALTHY", 1)]
    mutation = connection.execute(
        "SELECT state, result_json FROM credential_mutations WHERE mutation_id = ?",
        ("mutation-rotation-reference-overlap",),
    ).fetchone()
    assert tuple(mutation) == ("ROLLED_BACK", "{}")
    assert CANARY.decode() not in repr(captured.value)
    assert CANARY.decode() not in _database_text(connection)
    _assert_database_files_exclude(database, CANARY)
    connection.close()


@pytest.mark.asyncio
async def test_rotation_rejects_exact_serialized_custody_metadata(tmp_path: Path) -> None:
    database = tmp_path / "rotation-serialized-overlap.db"
    connection, store, service = _service(database)
    original = await service.provision_credential(
        _provision_request("mutation-rotation-serialized-source"),
        bytearray(CANARY),
        "admin-session-1",
    )
    secret_value = b'"alias":"primary"'
    secret = bytearray(secret_value)

    with pytest.raises(
        CredentialLifecycleFailure,
        match="metadata is invalid|accepted provider namespace",
    ):
        await service.rotate_credential(
            original.credential_id,
            CredentialRotationRequest(
                mutation_id="mutation-rotation-serialized-overlap",
                expires_at_ms=None,
            ),
            secret,
            "admin-session-1",
        )

    assert secret == bytearray(len(secret_value))
    metadata = await store.list_metadata()
    assert [item.credential_id for item in metadata] == [original.credential_id]
    durable = connection.execute(
        "SELECT credential_id, state, generation, metadata_json FROM credentials "
        "WHERE credential_role != 'OBSERVER'"
    ).fetchall()
    assert [tuple(row) for row in durable] == [
        (original.credential_id, "HEALTHY", 1, '{"logical_alias":"primary"}')
    ]
    assert (
        connection.execute(
            "SELECT 1 FROM credential_mutations WHERE mutation_id = ?",
            ("mutation-rotation-serialized-overlap",),
        ).fetchone()
        is None
    )
    connection.close()


@pytest.mark.asyncio
async def test_rotation_replay_rejects_secret_equal_to_committed_result(tmp_path: Path) -> None:
    event_ids = iter(
        (
            "evt_rotation_replay_source",
            "fc-" + "rotation-replay-audit-000000000001",
        )
    )
    connection, _store, service = _service(
        tmp_path / "rotation-replay-reflection.db",
        event_id_factory=lambda: next(event_ids),
    )
    original = await service.provision_credential(
        _provision_request("mutation-rotation-replay-source"),
        bytearray(CANARY),
        "admin-session-1",
    )
    request = CredentialRotationRequest(
        mutation_id="mutation-rotation-replay-result",
        expires_at_ms=None,
    )
    rotated = await service.rotate_credential(
        original.credential_id,
        request,
        bytearray(b"FAKE-ROTATION-REPLAY-SECRET-NOT-REAL-123456"),
        "admin-session-1",
    )
    reflected_replay = bytearray(rotated.audit_event_id.encode("utf-8"))

    with pytest.raises(CredentialLifecycleFailure, match="result overlaps"):
        await service.rotate_credential(
            original.credential_id,
            request,
            reflected_replay,
            "admin-session-1",
        )

    assert reflected_replay == bytearray(len(rotated.audit_event_id.encode("utf-8")))
    connection.close()


@pytest.mark.asyncio
async def test_rotation_cleanup_timestamp_equal_to_secret_is_never_persisted(
    tmp_path: Path,
) -> None:
    cleanup_time = NOW_MS + 456_789
    clock = _SwitchingClock(NOW_MS)
    connection = open_migrated_database(tmp_path / "rotation-cleanup-time-overlap.db")
    _seed_route(connection)
    store = _ClockSwitchFailureStore(clock, cleanup_time)
    service = SqliteCredentialLifecycleService(
        connection,
        persistent_key_store=store,
        now_ms=clock,
    )
    original = await service.provision_credential(
        _provision_request("mutation-rotation-cleanup-time-source"),
        bytearray(CANARY),
        "admin-session-1",
    )
    store.fail_next_put = True
    secret_value = str(cleanup_time).encode("ascii")
    secret = bytearray(secret_value)

    with pytest.raises(CredentialLifecycleFailure, match="accepted provider namespace"):
        await service.rotate_credential(
            original.credential_id,
            CredentialRotationRequest(
                mutation_id="mutation-rotation-cleanup-time-overlap",
                expires_at_ms=None,
            ),
            secret,
            "admin-session-1",
        )

    assert secret == bytearray(len(secret_value))
    assert [item.credential_id for item in await store.list_metadata()] == [original.credential_id]
    assert secret_value.decode("ascii") not in _database_text(connection)
    connection.close()


@pytest.mark.asyncio
async def test_rotation_preserves_old_generation_for_exact_affinity(tmp_path: Path) -> None:
    database = tmp_path / "rotation.db"
    connection, store, service = _service(database)
    original_secret = bytearray(CANARY)
    original = await service.provision_credential(
        _provision_request("mutation-original"),
        original_secret,
        "admin-session-1",
    )
    replacement_secret = b"FAKE-ROTATED-CANARY-NOT-A-REAL-KEY-1234567890"
    replacement_buffer = bytearray(replacement_secret)

    rotated = await service.rotate_credential(
        original.credential_id,
        CredentialRotationRequest(
            mutation_id="mutation-rotation-0001",
            expires_at_ms=None,
        ),
        replacement_buffer,
        "admin-session-1",
    )

    assert original_secret == bytearray(len(CANARY))
    assert replacement_buffer == bytearray(len(replacement_secret))
    assert rotated.credential_id != original.credential_id
    assert rotated.generation == 2
    old = connection.execute(
        "SELECT state, generation, metadata_json FROM credentials WHERE credential_id = ?",
        (original.credential_id,),
    ).fetchone()
    assert tuple(old)[:2] == ("DRAINING", 1)
    assert json.loads(str(old["metadata_json"]))["logical_alias"] == "primary"
    new_work = SqliteRoutingCatalog(connection).plan(
        service_id="firecrawl",
        operation="firecrawl.search",
        pool_name="interactive-default",
        estimated_cost_units=1,
        unit="credits",
        now_ms=NOW_MS,
    )
    assert new_work.pool_id == PoolId(POOL_ID)
    assert [
        (candidate.credential.credential_id, candidate.credential.generation)
        for candidate in new_work.candidates
    ] == [(CredentialId(rotated.credential_id), 2)]
    old_lease = await store.open_lease(
        original.credential_id,
        "provider-transport:firecrawl.crawl.status",
        expected_generation=1,
    )
    async with old_lease as view:
        assert bytes(view) == CANARY
    new_lease = await store.open_lease(
        rotated.credential_id,
        "provider-transport:firecrawl.search",
        expected_generation=2,
    )
    async with new_lease as view:
        assert bytes(view) == replacement_secret
    replacement_metadata = {item.credential_id: item for item in await store.list_metadata()}[
        rotated.credential_id
    ]
    assert replacement_metadata.alias == "primary"
    assert CANARY.decode() not in _database_text(connection)
    assert replacement_secret.decode() not in _database_text(connection)
    _assert_database_files_exclude(database, CANARY, replacement_secret)
    connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    connection.close()
    _assert_database_files_exclude(database, CANARY, replacement_secret)


@pytest.mark.asyncio
async def test_rotation_rejects_an_active_logical_lease_and_has_one_winner(tmp_path: Path) -> None:
    connection, _store, service = _service(tmp_path / "rotation-lease.db")
    original = await service.provision_credential(
        _provision_request("mutation-original-active"),
        bytearray(CANARY),
        "admin-session-1",
    )
    connection.execute(
        """
        INSERT INTO leases(
            lease_id, lease_type, lease_key, owner_id, state, generation,
            acquired_at_ms, heartbeat_at_ms, expires_at_ms
        ) VALUES ('lease-active', 'provider-credential', ?, 'req-owner',
                  'ACTIVE', 1, ?, ?, ?)
        """,
        (original.credential_id, NOW_MS, NOW_MS, NOW_MS + 60_000),
    )
    blocked_secret = bytearray(CANARY)
    with pytest.raises(CredentialLifecycleConflict):
        await service.rotate_credential(
            original.credential_id,
            CredentialRotationRequest(
                mutation_id="mutation-rotation-blocked",
                expires_at_ms=None,
            ),
            blocked_secret,
            "admin-session-1",
        )
    assert blocked_secret == bytearray(len(CANARY))
    connection.execute("UPDATE leases SET state = 'RELEASED', released_at_ms = ?", (NOW_MS,))

    winner = await service.rotate_credential(
        original.credential_id,
        CredentialRotationRequest(
            mutation_id="mutation-rotation-winner",
            expires_at_ms=None,
        ),
        bytearray(CANARY),
        "admin-session-1",
    )
    with pytest.raises(CredentialLifecycleConflict):
        await service.rotate_credential(
            original.credential_id,
            CredentialRotationRequest(
                mutation_id="mutation-rotation-loser",
                expires_at_ms=None,
            ),
            bytearray(CANARY),
            "admin-session-2",
        )
    assert winner.generation == 2
    connection.close()


@pytest.mark.asyncio
async def test_two_staged_rotations_have_one_durable_winner_and_clean_the_loser(
    tmp_path: Path,
) -> None:
    connection = open_migrated_database(tmp_path / "rotation-concurrent-winner.db")
    _seed_route(connection)
    store = _ConcurrentRotationStore()
    service = SqliteCredentialLifecycleService(
        connection,
        persistent_key_store=store,
        now_ms=lambda: NOW_MS,
    )
    original = await service.provision_credential(
        _provision_request("mutation-concurrent-rotation-source"),
        bytearray(CANARY),
        "admin-session-1",
    )
    first_value = b"FAKE-CONCURRENT-ROTATION-ONE-NOT-A-REAL-KEY-123456"
    second_value = b"FAKE-CONCURRENT-ROTATION-TWO-NOT-A-REAL-KEY-123456"
    first = bytearray(first_value)
    second = bytearray(second_value)

    outcomes = await asyncio.gather(
        service.rotate_credential(
            original.credential_id,
            CredentialRotationRequest(
                mutation_id="mutation-concurrent-rotation-one",
                expires_at_ms=None,
            ),
            first,
            "admin-session-1",
        ),
        service.rotate_credential(
            original.credential_id,
            CredentialRotationRequest(
                mutation_id="mutation-concurrent-rotation-two",
                expires_at_ms=None,
            ),
            second,
            "admin-session-1",
        ),
        return_exceptions=True,
    )

    winners = [item for item in outcomes if not isinstance(item, BaseException)]
    losers = [item for item in outcomes if isinstance(item, BaseException)]
    assert len(winners) == len(losers) == 1
    assert isinstance(losers[0], CredentialLifecycleConflict)
    assert first == bytearray(len(first_value))
    assert second == bytearray(len(second_value))
    durable = connection.execute(
        "SELECT credential_id, state, generation FROM credentials "
        "WHERE credential_role != 'OBSERVER' ORDER BY generation"
    ).fetchall()
    assert [(row["state"], row["generation"]) for row in durable] == [
        ("DRAINING", 1),
        ("HEALTHY", 2),
    ]
    assert {item.credential_id for item in await store.list_metadata()} == {
        str(row["credential_id"]) for row in durable
    }
    assert first_value.decode() not in _database_text(connection)
    assert second_value.decode() not in _database_text(connection)
    connection.close()


@pytest.mark.asyncio
async def test_rotation_rechecks_lease_after_staging_replacement(tmp_path: Path) -> None:
    connection = open_migrated_database(tmp_path / "rotation-race.db")
    _seed_route(connection)
    store = _LeaseAfterReplacementStageStore(connection)
    identifiers = iter(("cred_original_race", "cred_replacement_race"))
    service = SqliteCredentialLifecycleService(
        connection,
        persistent_key_store=store,
        now_ms=lambda: NOW_MS,
        credential_id_factory=lambda: next(identifiers),
    )
    original = await service.provision_credential(
        _provision_request("mutation-race-original"),
        bytearray(CANARY),
        "admin-session-1",
    )
    store.original_credential_id = original.credential_id

    with pytest.raises(CredentialLifecycleConflict):
        await service.rotate_credential(
            original.credential_id,
            CredentialRotationRequest(
                mutation_id="mutation-race-rotation",
                expires_at_ms=None,
            ),
            bytearray(b"FAKE-RACE-ROTATION-CANARY-NOT-A-REAL-KEY"),
            "admin-session-1",
        )

    durable = connection.execute(
        "SELECT state, generation, alias FROM credentials WHERE credential_id = ?",
        (original.credential_id,),
    ).fetchone()
    assert tuple(durable) == ("HEALTHY", 1, "primary")
    assert [item.credential_id for item in await store.list_metadata()] == [original.credential_id]
    assert (
        connection.execute(
            "SELECT state FROM credential_mutations WHERE mutation_id = ?",
            ("mutation-race-rotation",),
        ).fetchone()[0]
        == "ROLLED_BACK"
    )
    connection.close()


@pytest.mark.asyncio
async def test_rotation_recovery_restores_durable_and_custody_state_after_crash(
    tmp_path: Path,
) -> None:
    connection = open_migrated_database(tmp_path / "rotation-crash.db")
    _seed_route(connection)
    store = _CrashAfterDrainStore()
    identifiers = iter(("cred_original_crash", "cred_replacement_crash"))
    service = SqliteCredentialLifecycleService(
        connection,
        persistent_key_store=store,
        now_ms=lambda: NOW_MS,
        credential_id_factory=lambda: next(identifiers),
    )
    original = await service.provision_credential(
        _provision_request("mutation-crash-original"),
        bytearray(CANARY),
        "admin-session-1",
    )
    store.crash_after_drain = True

    with pytest.raises(_SyntheticCrash):
        await service.rotate_credential(
            original.credential_id,
            CredentialRotationRequest(
                mutation_id="mutation-crash-rotation",
                expires_at_ms=None,
            ),
            bytearray(b"FAKE-CRASH-ROTATION-CANARY-NOT-A-REAL-KEY"),
            "admin-session-1",
        )

    assert (
        connection.execute(
            "SELECT state FROM credentials WHERE credential_id = ?",
            (original.credential_id,),
        ).fetchone()[0]
        == "DRAINING"
    )
    assert (
        connection.execute(
            "SELECT state FROM credential_mutations WHERE mutation_id = ?",
            ("mutation-crash-rotation",),
        ).fetchone()[0]
        == "DURABLE_DRAINED"
    )

    assert await service.recover_incomplete_mutations() >= 1
    durable = connection.execute(
        "SELECT state, generation, alias FROM credentials WHERE credential_id = ?",
        (original.credential_id,),
    ).fetchone()
    assert tuple(durable) == ("HEALTHY", 1, "primary")
    stored = await store.list_metadata()
    assert [(item.credential_id, item.state, item.generation) for item in stored] == [
        (original.credential_id, "HEALTHY", 1)
    ]
    assert (
        connection.execute(
            "SELECT state FROM credential_mutations WHERE mutation_id = ?",
            ("mutation-crash-rotation",),
        ).fetchone()[0]
        == "ROLLED_BACK"
    )
    connection.close()


@pytest.mark.asyncio
async def test_rotate_and_state_mutation_ids_are_bound_to_the_path_target(
    tmp_path: Path,
) -> None:
    connection, _store, service = _service(tmp_path / "target-binding.db")
    first = await service.provision_credential(
        _provision_request("mutation-binding-first"),
        bytearray(CANARY),
        "admin-session-1",
    )
    second = await service.provision_credential(
        _provision_request("mutation-binding-second").model_copy(update={"alias": "secondary"}),
        bytearray(CANARY),
        "admin-session-1",
    )
    rotation = CredentialRotationRequest(
        mutation_id="mutation-binding-rotation",
        expires_at_ms=None,
    )
    await service.rotate_credential(
        first.credential_id,
        rotation,
        bytearray(CANARY),
        "admin-session-1",
    )
    with pytest.raises(CredentialLifecycleConflict):
        await service.rotate_credential(
            second.credential_id,
            rotation,
            bytearray(CANARY),
            "admin-session-1",
        )
    with pytest.raises(CredentialLifecycleConflict):
        await service.rotate_credential(
            first.credential_id,
            rotation.model_copy(update={"expires_at_ms": NOW_MS + 60_000}),
            bytearray(CANARY),
            "admin-session-1",
        )

    state_change = CredentialStateChangeRequest(
        mutation_id="mutation-binding-state",
        action="disable",
        reason="synthetic",
    )
    await service.change_credential_state(
        second.credential_id,
        state_change,
        "admin-session-1",
    )
    with pytest.raises(CredentialLifecycleConflict):
        await service.change_credential_state(
            first.credential_id,
            state_change,
            "admin-session-1",
        )
    with pytest.raises(CredentialLifecycleConflict):
        await service.change_credential_state(
            second.credential_id,
            state_change.model_copy(update={"reason": "different synthetic reason"}),
            "admin-session-1",
        )
    connection.close()


@pytest.mark.asyncio
async def test_state_change_uses_inactive_route_metadata_without_reopening_routing(
    tmp_path: Path,
) -> None:
    connection, store, service = _service(tmp_path / "inactive-route-state.db")
    provisioned = await service.provision_credential(
        _provision_request("mutation-inactive-route-source"),
        bytearray(CANARY),
        "admin-session-1",
    )
    connection.execute("UPDATE principals SET enabled = 0 WHERE principal_id = ?", (PRINCIPAL_ID,))
    connection.execute(
        "UPDATE quota_scopes SET state = 'DISABLED' WHERE quota_scope_id = ?",
        (SCOPE_ID,),
    )
    connection.execute("UPDATE pools SET state = 'DISABLED' WHERE pool_id = ?", (POOL_ID,))
    connection.execute(
        "UPDATE pool_members SET enabled = 0 WHERE pool_id = ? AND quota_scope_id = ?",
        (POOL_ID, SCOPE_ID),
    )

    result = await service.change_credential_state(
        provisioned.credential_id,
        CredentialStateChangeRequest(
            mutation_id="mutation-inactive-route-disable",
            action="disable",
            reason="synthetic inactive route",
        ),
        "admin-session-1",
    )

    assert result.state == "DISABLED"
    assert result.principal_alias == "primary-principal"
    assert result.quota_scope_alias == "primary-scope"
    assert result.pool_id == POOL_ID
    assert result.pool_alias == "interactive-default"
    metadata = (await store.list_metadata())[0]
    assert (metadata.state, metadata.generation) == ("DISABLED", 2)
    connection.close()


@pytest.mark.asyncio
async def test_disable_quarantine_and_retire_are_fail_closed_and_audited(
    tmp_path: Path,
) -> None:
    connection, store, service = _service(tmp_path / "states.db")
    first = await service.provision_credential(
        _provision_request("mutation-state-original"),
        bytearray(CANARY),
        "admin-session-1",
    )
    open_lease = await store.open_lease(
        first.credential_id,
        "provider-transport:test",
        expected_generation=1,
    )
    retained = await open_lease.__aenter__()

    disabled = await service.change_credential_state(
        first.credential_id,
        CredentialStateChangeRequest(
            mutation_id="mutation-disable-0001",
            action="disable",
            reason=REASON_CANARY,
        ),
        "admin-session-1",
    )
    assert disabled.state == "DISABLED"
    assert disabled.generation == 2
    assert bytes(retained) == b"\x00" * len(CANARY)

    second = await service.provision_credential(
        _provision_request("mutation-quarantine-source").model_copy(update={"alias": "secondary"}),
        bytearray(CANARY),
        "admin-session-1",
    )
    quarantine_lease = await store.open_lease(
        second.credential_id,
        "provider-transport:test-quarantine",
        expected_generation=1,
    )
    quarantine_view = await quarantine_lease.__aenter__()
    quarantined = await service.change_credential_state(
        second.credential_id,
        CredentialStateChangeRequest(
            mutation_id="mutation-quarantine-0001",
            action="quarantine",
            reason="synthetic incident",
        ),
        "admin-session-1",
    )
    assert quarantined.state == "QUARANTINED"
    assert quarantined.generation == 2
    assert bytes(quarantine_view) == b"\x00" * len(CANARY)
    retired = await service.change_credential_state(
        second.credential_id,
        CredentialStateChangeRequest(
            mutation_id="mutation-retire-0001",
            action="retire",
            reason="locally retired after review",
        ),
        "admin-session-1",
    )
    assert retired.state == "RETIRED"
    assert retired.generation == 3
    third = await service.provision_credential(
        _provision_request("mutation-retire-open-secret-source").model_copy(
            update={"alias": "tertiary"}
        ),
        bytearray(CANARY),
        "admin-session-1",
    )
    retirement_lease = await store.open_lease(
        third.credential_id,
        "provider-transport:test-retire",
        expected_generation=1,
    )
    retirement_view = await retirement_lease.__aenter__()
    directly_retired = await service.change_credential_state(
        third.credential_id,
        CredentialStateChangeRequest(
            mutation_id="mutation-retire-open-secret",
            action="retire",
            reason="synthetic direct local retirement",
        ),
        "admin-session-1",
    )
    assert directly_retired.state == "RETIRED"
    assert bytes(retirement_view) == b"\x00" * len(CANARY)
    assert {row[0] for row in connection.execute("SELECT event_type FROM audit_events")} >= {
        "credential.disabled",
        "credential.quarantined",
        "credential.retired",
    }
    assert CANARY.decode() not in _database_text(connection)
    assert REASON_CANARY not in _database_text(connection)
    connection.close()


@pytest.mark.asyncio
async def test_retire_blocks_a_production_shaped_active_credential_lease(
    tmp_path: Path,
) -> None:
    connection, store, service = _service(tmp_path / "retire-active-lease.db")
    provisioned = await service.provision_credential(
        _provision_request("mutation-retire-lease-source"),
        bytearray(CANARY),
        "admin-session-1",
    )
    plan = SqliteRoutingCatalog(connection).plan(
        service_id="firecrawl",
        operation="firecrawl.search",
        pool_name="interactive-default",
        estimated_cost_units=1,
        unit="credits",
        now_ms=NOW_MS,
    )
    manager = CredentialLeaseManager(
        GatehouseRepository(connection),
        id_factory=lambda: LeaseId(f"lease_{JOB_SUFFIX}"),
    )
    dispatch_lease = manager.acquire(
        candidate=plan.candidates[0],
        request_id=RequestId(f"req_{JOB_SUFFIX}"),
        now_ms=NOW_MS,
        expires_at_ms=NOW_MS + 60_000,
    )
    durable_lease = connection.execute(
        "SELECT lease_key, metadata_json FROM leases WHERE lease_id = ?",
        (str(dispatch_lease.lease_id),),
    ).fetchone()
    lease_metadata = json.loads(str(durable_lease["metadata_json"]))
    assert durable_lease["lease_key"] == (
        f"{provisioned.credential_id}:1:dispatch:req_{JOB_SUFFIX}"
    )
    assert lease_metadata["credential_id"] == provisioned.credential_id
    assert lease_metadata["credential_generation"] == 1
    assert lease_metadata["pool_id"] == POOL_ID

    request = CredentialStateChangeRequest(
        mutation_id="mutation-retire-active-production-lease",
        action="retire",
        reason="synthetic active exact lease",
    )
    with pytest.raises(CredentialLifecycleConflict, match="active work"):
        await service.change_credential_state(
            provisioned.credential_id,
            request,
            "admin-session-1",
        )

    assert (
        connection.execute(
            "SELECT state FROM credentials WHERE credential_id = ?",
            (provisioned.credential_id,),
        ).fetchone()[0]
        == "HEALTHY"
    )
    assert manager.release(dispatch_lease, now_ms=NOW_MS + 1)
    retired = await service.change_credential_state(
        provisioned.credential_id,
        request,
        "admin-session-1",
    )
    assert retired.state == "RETIRED"
    assert await store.list_metadata() == ()
    connection.close()


def _seed_active_resource(connection: sqlite3.Connection, credential_id: str) -> None:
    connection.execute(
        """
        INSERT INTO clients(
            client_id, display_name, kind, unattended, policy_profile,
            enabled, created_at_ms, updated_at_ms
        ) VALUES ('client-resource', 'Resource client', 'cli', 0, 'default', 1, ?, ?)
        """,
        (NOW_MS, NOW_MS),
    )
    connection.execute(
        """
        INSERT INTO workspaces(
            workspace_id, display_name, canonical_root, enabled,
            created_at_ms, updated_at_ms
        ) VALUES ('workspace-resource', 'Resource workspace', 'C:\\resource', 1, ?, ?)
        """,
        (NOW_MS, NOW_MS),
    )
    connection.execute(
        """
        INSERT INTO sessions(
            session_id, client_id, workspace_id, bootstrap_verifier,
            bootstrap_version, token_epoch, revocation_epoch, state,
            identity_assurance, policy_version, created_at_ms,
            reconnect_until_ms, absolute_expires_at_ms
        ) VALUES ('session-resource', 'client-resource', 'workspace-resource',
                  X'00', 1, 0, 0, 'ACTIVE', 'LOCAL_INTERACTIVE', 'v1', ?, ?, ?)
        """,
        (NOW_MS, NOW_MS + 60_000, NOW_MS + 120_000),
    )
    connection.execute(
        """
        INSERT INTO root_runs(
            root_run_id, session_id, state, started_at_ms, budget_json,
            consumed_json
        ) VALUES ('root-resource', 'session-resource', 'ACTIVE', ?,
                  '{"requests": 10, "credits": 10}',
                  '{"requests": 0, "credits": 0}')
        """,
        (NOW_MS,),
    )
    connection.execute(
        """
        INSERT INTO invocations(
            request_id, session_id, root_run_id, service_id, operation,
            request_fingerprint, fingerprint_version, canonicalization_version,
            state, priority_class, request_size_bytes, received_at_ms
        ) VALUES ('request-resource', 'session-resource', 'root-resource',
                  'firecrawl', 'firecrawl.crawl.start', X'00', 1, 1,
                  'SUCCEEDED', 'interactive', 0, ?)
        """,
        (NOW_MS,),
    )
    connection.execute(
        """
        INSERT INTO external_resources(
            resource_id, service_id, resource_type, provider_resource_id,
            principal_id, quota_scope_id, credential_id, credential_generation,
            pool_id, creating_request_id, owner_session_id, owner_workspace_id,
            owner_root_run_id, state, created_at_ms, updated_at_ms
        ) VALUES ('resource-active', 'firecrawl', 'crawl', 'provider-resource',
                  ?, ?, ?, 1, ?, 'request-resource', 'session-resource',
                  'workspace-resource', 'root-resource', 'ACTIVE', ?, ?)
        """,
        (PRINCIPAL_ID, SCOPE_ID, credential_id, POOL_ID, NOW_MS, NOW_MS),
    )


def _seed_job_compatible_active_resource(
    connection: sqlite3.Connection,
    credential_id: str,
) -> ResourceAffinity:
    client_id = f"client_{JOB_SUFFIX}"
    workspace_id = f"ws_{JOB_SUFFIX}"
    session_id = f"ses_{JOB_SUFFIX}"
    root_run_id = f"run_{JOB_SUFFIX}"
    request_id = f"req_{JOB_SUFFIX}"
    connection.execute(
        """
        INSERT INTO clients(
            client_id, display_name, kind, unattended, policy_profile,
            enabled, created_at_ms, updated_at_ms
        ) VALUES (?, 'Resource client', 'cli', 0, 'default', 1, ?, ?)
        """,
        (client_id, NOW_MS, NOW_MS),
    )
    connection.execute(
        """
        INSERT INTO workspaces(
            workspace_id, display_name, canonical_root, enabled,
            created_at_ms, updated_at_ms
        ) VALUES (?, 'Resource workspace', 'C:\\resource-job', 1, ?, ?)
        """,
        (workspace_id, NOW_MS, NOW_MS),
    )
    connection.execute(
        """
        INSERT INTO sessions(
            session_id, client_id, workspace_id, bootstrap_verifier,
            bootstrap_version, token_epoch, revocation_epoch, state,
            identity_assurance, policy_version, created_at_ms,
            reconnect_until_ms, absolute_expires_at_ms
        ) VALUES (?, ?, ?, X'00', 1, 0, 0, 'ACTIVE', 'LOCAL_INTERACTIVE',
                  'v1', ?, ?, ?)
        """,
        (
            session_id,
            client_id,
            workspace_id,
            NOW_MS,
            NOW_MS + 60_000,
            NOW_MS + 120_000,
        ),
    )
    connection.execute(
        """
        INSERT INTO root_runs(
            root_run_id, session_id, state, started_at_ms, budget_json,
            consumed_json
        ) VALUES (?, ?, 'ACTIVE', ?, '{"requests": 10, "credits": 10}',
                  '{"requests": 0, "credits": 0}')
        """,
        (root_run_id, session_id, NOW_MS),
    )
    connection.execute(
        """
        INSERT INTO invocations(
            request_id, session_id, root_run_id, service_id, operation,
            request_fingerprint, fingerprint_version, canonicalization_version,
            state, priority_class, request_size_bytes, received_at_ms,
            completed_at_ms
        ) VALUES (?, ?, ?, 'firecrawl', 'firecrawl.crawl.start', X'00', 1, 1,
                  'SUCCEEDED', 'interactive', 0, ?, ?)
        """,
        (request_id, session_id, root_run_id, NOW_MS, NOW_MS),
    )
    connection.execute(
        """
        INSERT INTO external_resources(
            resource_id, service_id, resource_type, provider_resource_id,
            principal_id, quota_scope_id, credential_id, credential_generation,
            pool_id, creating_request_id, owner_session_id, owner_workspace_id,
            owner_root_run_id, state, created_at_ms, updated_at_ms
        ) VALUES ('resource-job-terminal', 'firecrawl', 'crawl',
                  'provider-terminal-resource', ?, ?, ?, 1, ?, ?, ?, ?, ?,
                  'ACTIVE', ?, ?)
        """,
        (
            PRINCIPAL_ID,
            SCOPE_ID,
            credential_id,
            POOL_ID,
            request_id,
            session_id,
            workspace_id,
            root_run_id,
            NOW_MS,
            NOW_MS,
        ),
    )
    return ResourceAffinity(
        service_id="firecrawl",
        resource_type="crawl",
        provider_resource_id="provider-terminal-resource",
        principal_id=PrincipalId(PRINCIPAL_ID),
        quota_scope_id=QuotaScopeId(SCOPE_ID),
        credential_id=CredentialId(credential_id),
        credential_generation=1,
        pool_id=PoolId(POOL_ID),
        creating_request_id=RequestId(request_id),
        owner_session_id=SessionId(session_id),
        owner_workspace_id=WorkspaceId(workspace_id),
        owner_root_run_id=RootRunId(root_run_id),
        bound_at_ms=NOW_MS,
    )


@pytest.mark.asyncio
async def test_retire_blocks_a_nonterminal_job_after_its_resource_is_terminal(
    tmp_path: Path,
) -> None:
    connection, _store, service = _service(tmp_path / "retire-nonterminal-job.db")
    provisioned = await service.provision_credential(
        _provision_request("mutation-retire-job-source"),
        bytearray(CANARY),
        "admin-session-1",
    )
    affinity = _seed_job_compatible_active_resource(connection, provisioned.credential_id)
    jobs = SqliteJobStore(connection, entropy=lambda length: b"\x02" * length)
    created = await jobs.create_from_affinity(
        affinity,
        maximum_runtime_at_ms=NOW_MS + 60_000,
    )
    assert created.state is JobState.CREATED
    connection.execute(
        "UPDATE external_resources SET state = 'COMPLETED' WHERE credential_id = ?",
        (provisioned.credential_id,),
    )
    assert (
        connection.execute(
            "SELECT state FROM external_resources WHERE credential_id = ?",
            (provisioned.credential_id,),
        ).fetchone()[0]
        == "COMPLETED"
    )

    with pytest.raises(CredentialLifecycleConflict, match="active work"):
        await service.change_credential_state(
            provisioned.credential_id,
            CredentialStateChangeRequest(
                mutation_id="mutation-retire-nonterminal-job",
                action="retire",
                reason="synthetic active job",
            ),
            "admin-session-1",
        )

    assert (
        connection.execute(
            "SELECT state FROM credentials WHERE credential_id = ?",
            (provisioned.credential_id,),
        ).fetchone()[0]
        == "HEALTHY"
    )
    connection.close()


def _seed_unmaterialized_async_checkpoint(
    connection: sqlite3.Connection,
    credential_id: str,
    *,
    invocation_state: str = "UNKNOWN",
) -> None:
    _seed_active_resource(connection, credential_id)
    connection.execute("DELETE FROM external_resources")
    connection.execute(
        "UPDATE invocations SET state = ? WHERE request_id = 'request-resource'",
        (invocation_state,),
    )
    connection.execute(
        """
        INSERT INTO attempts(
            attempt_id, request_id, ordinal, credential_id, principal_id,
            quota_scope_id, state, error_class, started_at_ms,
            completed_at_ms, resource_type, provider_resource_id,
            credential_generation, pool_id, dispatch_credential_generation,
            dispatch_pool_id
        ) VALUES ('attempt-resource-checkpoint', 'request-resource', 1, ?, ?, ?,
                  'SUCCEEDED', 'none', ?, ?, 'crawl', 'provider-resource',
                  1, ?, 1, ?)
        """,
        (credential_id, PRINCIPAL_ID, SCOPE_ID, NOW_MS, NOW_MS, POOL_ID, POOL_ID),
    )


def _seed_async_handoff_attempt(
    connection: sqlite3.Connection,
    credential_id: str,
    *,
    invocation_state: str,
    attempt_state: str,
    error_class: str | None,
    provider_status_code: int | None,
) -> None:
    _seed_active_resource(connection, credential_id)
    connection.execute("DELETE FROM external_resources")
    connection.execute(
        "UPDATE invocations SET state = ? WHERE request_id = 'request-resource'",
        (invocation_state,),
    )
    connection.execute(
        """
        INSERT INTO attempts(
            attempt_id, request_id, ordinal, credential_id, principal_id,
            quota_scope_id, state, provider_status_code, error_class,
            estimated_cost_units, cost_unit, started_at_ms, completed_at_ms,
            dispatch_credential_generation, dispatch_pool_id
        ) VALUES ('attempt-ambiguous-handoff', 'request-resource', 1, ?, ?, ?,
                  ?, ?, ?, 10, 'credits', ?, ?, 1, ?)
        """,
        (
            credential_id,
            PRINCIPAL_ID,
            SCOPE_ID,
            attempt_state,
            provider_status_code,
            error_class,
            NOW_MS,
            None if attempt_state in {"DISPATCHING", "RUNNING"} else NOW_MS,
            POOL_ID,
        ),
    )


@pytest.mark.parametrize("resource_state", ["ACTIVE", "OWNER_REBIND_REQUIRED"])
@pytest.mark.asyncio
async def test_retire_blocks_unresolved_external_resource_affinity(
    tmp_path: Path,
    resource_state: str,
) -> None:
    connection, _store, service = _service(tmp_path / "retire-resource.db")
    provisioned = await service.provision_credential(
        _provision_request("mutation-resource-source"),
        bytearray(CANARY),
        "admin-session-1",
    )
    _seed_active_resource(connection, provisioned.credential_id)
    connection.execute(
        "UPDATE external_resources SET state = ? WHERE credential_id = ?",
        (resource_state, provisioned.credential_id),
    )

    with pytest.raises(CredentialLifecycleConflict):
        await service.change_credential_state(
            provisioned.credential_id,
            CredentialStateChangeRequest(
                mutation_id="mutation-retire-active-resource",
                action="retire",
                reason="synthetic",
            ),
            "admin-session-1",
        )

    assert (
        connection.execute(
            "SELECT state FROM credentials WHERE credential_id = ?",
            (provisioned.credential_id,),
        ).fetchone()[0]
        == "HEALTHY"
    )
    connection.close()


@pytest.mark.asyncio
async def test_terminal_settled_resource_releases_credential_retirement_fence(
    tmp_path: Path,
) -> None:
    connection, _store, service = _service(tmp_path / "retire-settled-resource.db")
    provisioned = await service.provision_credential(
        _provision_request("mutation-settled-resource-source"),
        bytearray(CANARY),
        "admin-session-1",
    )
    affinity = _seed_job_compatible_active_resource(
        connection,
        provisioned.credential_id,
    )
    jobs = SqliteJobStore(connection, entropy=lambda length: b"\x01" * length)
    created = await jobs.create_from_affinity(
        affinity,
        maximum_runtime_at_ms=NOW_MS + 60_000,
    )
    prepared = await jobs.prepare_settlement(
        expected=created,
        owner=created.owner,
        target_state=JobState.SUCCEEDED,
        actual_cost_units=1,
        observed_at_ms=NOW_MS,
        provider_status="completed",
    )
    assert prepared is not None
    terminal = await jobs.complete_settlement(
        expected=prepared,
        owner=prepared.owner,
    )
    assert terminal is not None and terminal.state is JobState.SUCCEEDED
    assert (
        connection.execute(
            "SELECT state FROM external_resources WHERE resource_id = 'resource-job-terminal'"
        ).fetchone()[0]
        == "COMPLETED"
    )

    retired = await service.change_credential_state(
        provisioned.credential_id,
        CredentialStateChangeRequest(
            mutation_id="mutation-retire-settled-resource",
            action="retire",
            reason="synthetic completed crawl",
        ),
        "admin-session-1",
    )

    assert retired.state == "RETIRED"
    connection.close()


@pytest.mark.asyncio
async def test_retire_blocks_unknown_invocation_with_unmaterialized_async_checkpoint(
    tmp_path: Path,
) -> None:
    connection, _store, service = _service(tmp_path / "retire-checkpoint.db")
    provisioned = await service.provision_credential(
        _provision_request("mutation-checkpoint-source"),
        bytearray(CANARY),
        "admin-session-1",
    )
    _seed_unmaterialized_async_checkpoint(connection, provisioned.credential_id)

    with pytest.raises(CredentialLifecycleConflict):
        await service.change_credential_state(
            provisioned.credential_id,
            CredentialStateChangeRequest(
                mutation_id="mutation-retire-unmaterialized-checkpoint",
                action="retire",
                reason="synthetic checkpoint recovery",
            ),
            "admin-session-1",
        )

    connection.execute(
        """
        INSERT INTO external_resources(
            resource_id, service_id, resource_type, provider_resource_id,
            principal_id, quota_scope_id, credential_id, credential_generation,
            pool_id, creating_request_id, owner_session_id, owner_workspace_id,
            owner_root_run_id, state, created_at_ms, updated_at_ms
        ) VALUES ('resource-terminal', 'firecrawl', 'crawl', 'provider-resource',
                  ?, ?, ?, 1, ?, 'request-resource', 'session-resource',
                  'workspace-resource', 'root-resource', 'COMPLETED', ?, ?)
        """,
        (PRINCIPAL_ID, SCOPE_ID, provisioned.credential_id, POOL_ID, NOW_MS, NOW_MS),
    )

    retired = await service.change_credential_state(
        provisioned.credential_id,
        CredentialStateChangeRequest(
            mutation_id="mutation-retire-materialized-checkpoint",
            action="retire",
            reason="synthetic terminal affinity",
        ),
        "admin-session-1",
    )

    assert retired.state == "RETIRED"
    connection.close()


@pytest.mark.asyncio
async def test_retire_ignores_historical_success_checkpoint_without_live_owner(
    tmp_path: Path,
) -> None:
    connection, _store, service = _service(tmp_path / "retire-historical-checkpoint.db")
    provisioned = await service.provision_credential(
        _provision_request("mutation-historical-checkpoint-source"),
        bytearray(CANARY),
        "admin-session-1",
    )
    _seed_unmaterialized_async_checkpoint(
        connection,
        provisioned.credential_id,
        invocation_state="SUCCEEDED",
    )

    retired = await service.change_credential_state(
        provisioned.credential_id,
        CredentialStateChangeRequest(
            mutation_id="mutation-retire-historical-checkpoint",
            action="retire",
            reason="synthetic historical checkpoint",
        ),
        "admin-session-1",
    )

    assert retired.state == "RETIRED"
    connection.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("case", "invocation_state", "attempt_state", "error_class", "provider_status_code"),
    (
        ("malformed", "UNKNOWN", "UNKNOWN", "malformed_response", 200),
        ("recovered", "UNKNOWN", "UNKNOWN", "daemon_restart", None),
        ("legacy-success", "UNKNOWN", "SUCCEEDED", "none", 200),
        ("live", "RUNNING", "RUNNING", None, None),
    ),
)
async def test_retire_blocks_ambiguous_async_create_handoff_without_checkpoint(
    tmp_path: Path,
    case: str,
    invocation_state: str,
    attempt_state: str,
    error_class: str | None,
    provider_status_code: int | None,
) -> None:
    connection, _store, service = _service(tmp_path / f"retire-{case}-handoff.db")
    provisioned = await service.provision_credential(
        _provision_request(f"mutation-{case}-handoff-source"),
        bytearray(CANARY),
        "admin-session-1",
    )
    _seed_async_handoff_attempt(
        connection,
        provisioned.credential_id,
        invocation_state=invocation_state,
        attempt_state=attempt_state,
        error_class=error_class,
        provider_status_code=provider_status_code,
    )

    with pytest.raises(CredentialLifecycleConflict):
        await service.change_credential_state(
            provisioned.credential_id,
            CredentialStateChangeRequest(
                mutation_id=f"mutation-retire-{case}-handoff",
                action="retire",
                reason="synthetic ambiguous provider handoff",
            ),
            "admin-session-1",
        )

    assert (
        connection.execute(
            "SELECT state FROM credentials WHERE credential_id = ?",
            (provisioned.credential_id,),
        ).fetchone()[0]
        == "HEALTHY"
    )
    connection.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("case", "invocation_state", "attempt_state", "error_class"),
    (
        ("never-dispatched", "RUNNING", "DISPATCHING", None),
        ("pre-handoff-failed", "FAILED", "FAILED", "transient"),
    ),
)
async def test_retire_does_not_fence_pre_handoff_async_create_attempts(
    tmp_path: Path,
    case: str,
    invocation_state: str,
    attempt_state: str,
    error_class: str | None,
) -> None:
    connection, _store, service = _service(tmp_path / f"retire-{case}.db")
    provisioned = await service.provision_credential(
        _provision_request(f"mutation-{case}-source"),
        bytearray(CANARY),
        "admin-session-1",
    )
    _seed_async_handoff_attempt(
        connection,
        provisioned.credential_id,
        invocation_state=invocation_state,
        attempt_state=attempt_state,
        error_class=error_class,
        provider_status_code=None,
    )

    retired = await service.change_credential_state(
        provisioned.credential_id,
        CredentialStateChangeRequest(
            mutation_id=f"mutation-retire-{case}",
            action="retire",
            reason="synthetic pre-handoff attempt",
        ),
        "admin-session-1",
    )

    assert retired.state == "RETIRED"
    connection.close()


@pytest.mark.asyncio
async def test_retire_recovery_discards_blob_only_partial_custody(tmp_path: Path) -> None:
    connection = open_migrated_database(tmp_path / "retire-partial.db")
    _seed_route(connection)
    store = _PartialDeleteStore()
    service = SqliteCredentialLifecycleService(
        connection,
        persistent_key_store=store,
        now_ms=lambda: NOW_MS,
    )
    provisioned = await service.provision_credential(
        _provision_request("mutation-partial-source"),
        bytearray(CANARY),
        "admin-session-1",
    )
    store.fail_next_delete = True

    with pytest.raises(CredentialLifecycleFailure):
        await service.change_credential_state(
            provisioned.credential_id,
            CredentialStateChangeRequest(
                mutation_id="mutation-retire-partial",
                action="retire",
                reason="synthetic partial cleanup",
            ),
            "admin-session-1",
        )

    assert store.partial_ids == {provisioned.credential_id}
    assert (
        connection.execute(
            "SELECT state FROM credentials WHERE credential_id = ?",
            (provisioned.credential_id,),
        ).fetchone()[0]
        == "RETIRED"
    )
    assert await service.recover_incomplete_mutations() >= 1
    assert store.partial_ids == set()
    connection.close()


@pytest.mark.asyncio
async def test_state_durable_commit_failure_leaves_custody_generation_unchanged(
    tmp_path: Path,
) -> None:
    connection, store, service = _service(tmp_path / "state-rollback.db")
    provisioned = await service.provision_credential(
        _provision_request("mutation-state-rollback-source"),
        bytearray(CANARY),
        "admin-session-1",
    )
    connection.execute(
        """
        CREATE TRIGGER reject_test_disable
        BEFORE UPDATE OF state ON credentials
        WHEN NEW.state = 'DISABLED'
        BEGIN
            SELECT RAISE(ABORT, 'synthetic state failure');
        END
        """
    )

    with pytest.raises(sqlite3.IntegrityError):
        await service.change_credential_state(
            provisioned.credential_id,
            CredentialStateChangeRequest(
                mutation_id="mutation-state-rollback",
                action="disable",
                reason="synthetic rollback",
            ),
            "admin-session-1",
        )

    metadata = (await store.list_metadata())[0]
    assert metadata.state == "HEALTHY"
    assert metadata.generation == 1
    row = connection.execute(
        "SELECT state, generation FROM credentials WHERE credential_id = ?",
        (provisioned.credential_id,),
    ).fetchone()
    assert tuple(row) == ("HEALTHY", 1)
    connection.close()


@pytest.mark.asyncio
async def test_state_recovery_completes_custody_after_durable_crash(tmp_path: Path) -> None:
    connection = open_migrated_database(tmp_path / "state-crash.db")
    _seed_route(connection)
    store = _CrashBeforeStateCustodyStore()
    service = SqliteCredentialLifecycleService(
        connection,
        persistent_key_store=store,
        now_ms=lambda: NOW_MS,
    )
    provisioned = await service.provision_credential(
        _provision_request("mutation-state-crash-source"),
        bytearray(CANARY),
        "admin-session-1",
    )
    store.crash_before_disable = True

    request = CredentialStateChangeRequest(
        mutation_id="mutation-state-crash",
        action="disable",
        reason=REASON_CANARY,
    )
    with pytest.raises(_SyntheticCrash):
        await service.change_credential_state(
            provisioned.credential_id,
            request,
            "admin-session-1",
        )

    durable = connection.execute(
        "SELECT state, generation FROM credentials WHERE credential_id = ?",
        (provisioned.credential_id,),
    ).fetchone()
    assert tuple(durable) == ("DISABLED", 2)
    stored = (await store.list_metadata())[0]
    assert (stored.state, stored.generation) == ("HEALTHY", 1)
    assert (
        connection.execute(
            "SELECT state FROM credential_mutations WHERE mutation_id = ?",
            (request.mutation_id,),
        ).fetchone()[0]
        == "DURABLE_STATE_CHANGED"
    )

    store.crash_before_disable = False
    assert await service.recover_incomplete_mutations() >= 1
    stored = (await store.list_metadata())[0]
    assert (stored.state, stored.generation) == ("DISABLED", 2)
    replayed = await service.change_credential_state(
        provisioned.credential_id,
        request,
        "admin-session-1",
    )
    assert replayed.state == "DISABLED"
    assert REASON_CANARY not in _database_text(connection)
    connection.close()
