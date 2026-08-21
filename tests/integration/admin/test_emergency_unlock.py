from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from gatehouse.admin.lifecycle import (
    CredentialLifecycleConflict,
    CredentialLifecycleFailure,
    SqliteCredentialLifecycleService,
)
from gatehouse.admin.models import EmergencyUnlockCancelRequest, EmergencyUnlockRequest
from gatehouse.core.ids import CredentialId, PrincipalId, QuotaScopeId
from gatehouse.credentials import CredentialMetadata, InMemoryKeyStore
from gatehouse.credentials.emergency import (
    EmergencyUnlockError,
    EmergencyUnlockManager,
    EmergencyUnlockState,
)
from gatehouse.database import open_migrated_database

NOW_MS = 1_800_000_000_000
CANARY = b"FAKE-EMERGENCY-CANARY-NOT-A-REAL-KEY-123456"
REASON_CANARY = "ghp_FAKE_REASON_CANARY_MUST_NOT_REACH_SQLITE_123456"
SESSION_ID = "ses_01K00000000000000000000000"
ROOT_ID = "run_01K00000000000000000000000"
CLIENT_ID = "client_01K00000000000000000000000"
WORKSPACE_ID = "ws_01K00000000000000000000000"
POOL_ID = "pool_01K00000000000000000000000"
CREDENTIAL_ID = "cred_01K00000000000000000000000"
PRINCIPAL_ID = "prn_01K00000000000000000000000"
SCOPE_ID = "quota_01K00000000000000000000000"
UNLOCK_ID = "synthetic-emergency-unlock-000000000001"


def _seed_authority(connection: sqlite3.Connection) -> None:
    connection.execute(
        """
        INSERT INTO clients(
            client_id, display_name, kind, unattended, policy_profile,
            enabled, created_at_ms, updated_at_ms
        ) VALUES (?, 'interactive', 'cli', 0, 'test', 1, ?, ?)
        """,
        (CLIENT_ID, NOW_MS, NOW_MS),
    )
    connection.execute(
        """
        INSERT INTO workspaces(
            workspace_id, display_name, canonical_root, enabled,
            created_at_ms, updated_at_ms
        ) VALUES (?, 'workspace', 'C:\\workspace', 1, ?, ?)
        """,
        (WORKSPACE_ID, NOW_MS, NOW_MS),
    )
    connection.execute(
        """
        INSERT INTO sessions(
            session_id, client_id, workspace_id, bootstrap_verifier,
            bootstrap_version, token_epoch, state, identity_assurance,
            policy_version, created_at_ms, reconnect_until_ms,
            absolute_expires_at_ms, budget_json
        ) VALUES (?, ?, ?, ?, 1, 1, 'ACTIVE', 'interactive', '1', ?, ?, ?, ?)
        """,
        (
            SESSION_ID,
            CLIENT_ID,
            WORKSPACE_ID,
            b"v" * 32,
            NOW_MS,
            NOW_MS + 60_000,
            NOW_MS + 600_000,
            '{"credits":50,"requests":10}',
        ),
    )
    connection.execute(
        """
        INSERT INTO root_runs(
            root_run_id, session_id, state, started_at_ms,
            budget_json, consumed_json
        ) VALUES (?, ?, 'ACTIVE', ?, ?, ?)
        """,
        (
            ROOT_ID,
            SESSION_ID,
            NOW_MS,
            '{"credits":50,"requests":10}',
            '{"credits":0,"requests":0}',
        ),
    )
    connection.execute(
        """
        INSERT INTO pools(
            pool_id, service_id, alias, state, selection_strategy,
            automatic_use, config_json
        ) VALUES (?, 'firecrawl', 'emergency-locked', 'ACTIVE',
                  'pinned', 0, '{}')
        """,
        (POOL_ID,),
    )


def _manager(store: InMemoryKeyStore) -> EmergencyUnlockManager:
    return EmergencyUnlockManager(
        key_store=store,
        now_ms=lambda: NOW_MS,
        unlock_id_factory=lambda: UNLOCK_ID,
        credential_id_factory=lambda: str(CredentialId(CREDENTIAL_ID)),
        principal_id_factory=lambda: str(PrincipalId(PRINCIPAL_ID)),
        quota_scope_id_factory=lambda: str(QuotaScopeId(SCOPE_ID)),
        permit_id_factory=lambda: "permit-000000000000000000000001",
    )


def _request(mutation_id: str = "mutation-emergency-unlock-0001") -> EmergencyUnlockRequest:
    return EmergencyUnlockRequest(
        mutation_id=mutation_id,
        service="firecrawl",
        pool_id=POOL_ID,
        session_id=SESSION_ID,
        root_run_id=ROOT_ID,
        alias="emergency-primary",
        reason=REASON_CANARY,
        duration_ms=60_000,
        maximum_requests=5,
        maximum_credits=20,
        maximum_concurrency=1,
    )


def _database_text(connection: sqlite3.Connection) -> str:
    values: list[str] = []
    for table_row in connection.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
    ):
        table = str(table_row[0])
        for row in connection.execute(f'SELECT * FROM "{table}"'):  # noqa: S608
            values.extend(str(value) for value in row if value is not None)
    return "\n".join(values)


def _catalog_counts(connection: sqlite3.Connection) -> tuple[int, int, int, int]:
    row = connection.execute(
        """
        SELECT (SELECT COUNT(*) FROM principals),
               (SELECT COUNT(*) FROM quota_scopes),
               (SELECT COUNT(*) FROM credentials),
               (SELECT COUNT(*) FROM pool_members)
        """
    ).fetchone()
    assert row is not None
    return (
        int(row[0]),
        int(row[1]),
        int(row[2]),
        int(row[3]),
    )


def _assert_database_files_exclude(path: Path, *canaries: bytes) -> None:
    for candidate in (path, Path(f"{path}-wal"), Path(f"{path}-shm")):
        if not candidate.exists():
            continue
        content = candidate.read_bytes()
        for canary in canaries:
            assert canary not in content


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


class _FailingEmergencyCleanupStore(InMemoryKeyStore):
    async def delete(self, credential_id: str) -> None:
        del credential_id
        raise RuntimeError(CANARY.decode())


class _SwitchingClock:
    def __init__(self, value: int) -> None:
        self.value = value

    def __call__(self) -> int:
        return self.value


class _ClockSwitchEmergencyFailureStore(InMemoryKeyStore):
    def __init__(self, clock: _SwitchingClock, failure_time: int) -> None:
        super().__init__()
        self.clock = clock
        self.failure_time = failure_time

    async def put(self, metadata: CredentialMetadata, secret: bytes) -> str:
        del metadata, secret
        self.clock.value = self.failure_time
        raise RuntimeError("synthetic emergency custody failure after clock switch")


@pytest.mark.asyncio
async def test_unlock_rejects_secret_duplicated_into_metadata_before_persistence(
    tmp_path: Path,
) -> None:
    connection = open_migrated_database(tmp_path / "emergency-secret-overlap.db")
    _seed_authority(connection)
    manager = _manager(InMemoryKeyStore())
    service = SqliteCredentialLifecycleService(
        connection,
        persistent_key_store=InMemoryKeyStore(),
        emergency_manager=manager,
        now_ms=lambda: NOW_MS,
    )
    request = _request("mutation-emergency-secret-overlap").model_copy(
        update={"alias": CANARY.decode()}
    )
    secret = bytearray(CANARY)

    with pytest.raises(
        CredentialLifecycleFailure,
        match="metadata overlaps|accepted provider namespace",
    ):
        await service.unlock_emergency(request, secret, "admin-session-1")

    assert secret == bytearray(len(CANARY))
    assert (await manager.status()).state is EmergencyUnlockState.LOCKED
    assert connection.execute("SELECT COUNT(*) FROM credential_mutations").fetchone()[0] == 0
    assert connection.execute("SELECT COUNT(*) FROM emergency_unlock_records").fetchone()[0] == 0
    assert CANARY.decode() not in _database_text(connection)
    await manager.close()
    connection.close()


@pytest.mark.asyncio
async def test_unlock_rejects_lifecycle_event_id_equal_to_active_secret(
    tmp_path: Path,
) -> None:
    database = tmp_path / "emergency-event-secret-overlap.db"
    connection = open_migrated_database(database)
    _seed_authority(connection)
    catalog_counts = _catalog_counts(connection)
    emergency_store = InMemoryKeyStore()
    manager = _manager(emergency_store)
    service = SqliteCredentialLifecycleService(
        connection,
        persistent_key_store=InMemoryKeyStore(),
        emergency_manager=manager,
        now_ms=lambda: NOW_MS,
        event_id_factory=lambda: CANARY.decode(),
    )
    caller_secret = bytearray(CANARY)

    with pytest.raises(CredentialLifecycleFailure, match="metadata overlaps") as captured:
        await service.unlock_emergency(
            _request("mutation-emergency-event-overlap"),
            caller_secret,
            "admin-session-1",
        )

    assert caller_secret == bytearray(len(CANARY))
    assert (await manager.status()).state is EmergencyUnlockState.LOCKED
    assert await emergency_store.list_metadata() == ()
    assert connection.execute("SELECT COUNT(*) FROM credential_mutations").fetchone()[0] == 0
    assert connection.execute("SELECT COUNT(*) FROM emergency_unlock_records").fetchone()[0] == 0
    assert _catalog_counts(connection) == catalog_counts
    assert CANARY.decode() not in repr(captured.value)
    assert CANARY.decode() not in _database_text(connection)
    _assert_database_files_exclude(database, CANARY)
    await manager.close()
    connection.close()


@pytest.mark.asyncio
async def test_unlock_rejects_exact_serialized_phase_secret_before_persistence(
    tmp_path: Path,
) -> None:
    database = tmp_path / "emergency-serialized-overlap.db"
    connection = open_migrated_database(database)
    _seed_authority(connection)
    manager = _manager(InMemoryKeyStore())
    service = SqliteCredentialLifecycleService(
        connection,
        persistent_key_store=InMemoryKeyStore(),
        emergency_manager=manager,
        now_ms=lambda: NOW_MS,
    )
    secret_value = f'"credential_id":"{CREDENTIAL_ID}"'.encode()
    secret = bytearray(secret_value)

    with pytest.raises(
        CredentialLifecycleFailure,
        match="metadata overlaps|accepted provider namespace",
    ):
        await service.unlock_emergency(
            _request("mutation-emergency-serialized-overlap"),
            secret,
            "admin-session-1",
        )

    assert secret == bytearray(len(secret_value))
    assert (await manager.status()).state is EmergencyUnlockState.LOCKED
    assert connection.execute("SELECT COUNT(*) FROM emergency_unlock_records").fetchone()[0] == 0
    assert secret_value.decode("ascii") not in _database_text(connection)
    _assert_database_files_exclude(database, secret_value)
    await manager.close()
    connection.close()


@pytest.mark.asyncio
async def test_emergency_cleanup_timestamp_equal_to_secret_is_never_persisted(
    tmp_path: Path,
) -> None:
    cleanup_time = NOW_MS + 765_432
    clock = _SwitchingClock(NOW_MS)
    connection = open_migrated_database(tmp_path / "emergency-cleanup-time-overlap.db")
    _seed_authority(connection)
    store = _ClockSwitchEmergencyFailureStore(clock, cleanup_time)
    manager = EmergencyUnlockManager(
        key_store=store,
        now_ms=clock,
        unlock_id_factory=lambda: UNLOCK_ID,
        credential_id_factory=lambda: str(CredentialId(CREDENTIAL_ID)),
        principal_id_factory=lambda: str(PrincipalId(PRINCIPAL_ID)),
        quota_scope_id_factory=lambda: str(QuotaScopeId(SCOPE_ID)),
        permit_id_factory=lambda: "permit-000000000000000000000001",
    )
    service = SqliteCredentialLifecycleService(
        connection,
        persistent_key_store=InMemoryKeyStore(),
        emergency_manager=manager,
        now_ms=clock,
    )
    secret_value = str(cleanup_time).encode("ascii")
    secret = bytearray(secret_value)

    with pytest.raises(CredentialLifecycleFailure, match="accepted provider namespace"):
        await service.unlock_emergency(
            _request("mutation-emergency-cleanup-time-overlap"),
            secret,
            "admin-session-1",
        )

    assert secret == bytearray(len(secret_value))
    assert (await manager.status()).state is EmergencyUnlockState.LOCKED
    assert secret_value.decode("ascii") not in _database_text(connection)
    await manager.close()
    connection.close()


@pytest.mark.asyncio
async def test_unlock_is_memory_only_exact_and_never_automatically_routed(
    tmp_path: Path,
) -> None:
    database = tmp_path / "emergency.db"
    connection = open_migrated_database(database)
    _seed_authority(connection)
    catalog_counts = _catalog_counts(connection)
    store = InMemoryKeyStore()
    manager = _manager(store)
    service = SqliteCredentialLifecycleService(
        connection,
        persistent_key_store=InMemoryKeyStore(),
        emergency_manager=manager,
        now_ms=lambda: NOW_MS,
    )
    caller_secret = bytearray(CANARY)

    result = await service.unlock_emergency(
        _request(),
        caller_secret,
        "admin-session-1",
    )
    reflected_replay = bytearray(result.unlock_id.encode("utf-8"))
    with pytest.raises(CredentialLifecycleFailure, match="result overlaps"):
        await service.unlock_emergency(
            _request(),
            reflected_replay,
            "admin-session-1",
        )

    assert caller_secret == bytearray(len(CANARY))
    assert reflected_replay == bytearray(len(result.unlock_id.encode("utf-8")))
    assert result.state == "ACTIVE"
    assert result.remaining_requests == 5
    assert result.remaining_credits == 20
    assert CANARY.decode() not in _database_text(connection)
    assert REASON_CANARY not in _database_text(connection)
    assert _catalog_counts(connection) == catalog_counts
    durable = connection.execute(
        """
        SELECT credential_id, credential_alias, credential_generation,
               principal_id, quota_scope_id, state
          FROM emergency_unlock_records WHERE unlock_id = ?
        """,
        (result.unlock_id,),
    ).fetchone()
    assert tuple(durable) == (
        result.credential_id,
        "emergency-primary",
        1,
        PRINCIPAL_ID,
        SCOPE_ID,
        "ACTIVE",
    )
    status = await manager.status()
    assert status.state is EmergencyUnlockState.ACTIVE
    assert status.session_id == SESSION_ID
    assert status.root_run_id == ROOT_ID
    lease = await store.open_lease(
        result.credential_id,
        "provider-transport:firecrawl.search",
        expected_generation=1,
    )
    async with lease as secret:
        assert bytes(secret) == CANARY

    with pytest.raises(EmergencyUnlockError):
        await manager.project(
            service_id="firecrawl",
            pool_name="emergency-locked",
            session_id=SESSION_ID,
            root_run_id=ROOT_ID,
            automatic=True,
        )
    manual = await manager.project(
        service_id="firecrawl",
        pool_name="emergency-locked",
        session_id=SESSION_ID,
        root_run_id=ROOT_ID,
        automatic=False,
    )
    assert manual.credential_id == result.credential_id
    assert CANARY.decode() not in repr(result)
    assert CANARY.decode() not in repr(status)
    _assert_database_files_exclude(
        database,
        CANARY,
        REASON_CANARY.encode(),
    )
    await manager.close()
    connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    connection.close()
    _assert_database_files_exclude(
        database,
        CANARY,
        REASON_CANARY.encode(),
    )


@pytest.mark.asyncio
async def test_unlock_caps_and_cancel_zero_secret_without_catalog_mutation(tmp_path: Path) -> None:
    connection = open_migrated_database(tmp_path / "cancel.db")
    _seed_authority(connection)
    catalog_counts = _catalog_counts(connection)
    store = InMemoryKeyStore()
    manager = _manager(store)
    service = SqliteCredentialLifecycleService(
        connection,
        persistent_key_store=InMemoryKeyStore(),
        emergency_manager=manager,
        now_ms=lambda: NOW_MS,
    )
    excessive = _request("mutation-emergency-excessive").model_copy(update={"maximum_requests": 11})
    excessive_secret = bytearray(CANARY)
    with pytest.raises(CredentialLifecycleFailure):
        await service.unlock_emergency(excessive, excessive_secret, "admin-session-1")
    assert excessive_secret == bytearray(len(CANARY))

    caller_secret = bytearray(CANARY)
    unlocked = await service.unlock_emergency(_request(), caller_secret, "admin-session-1")
    assert caller_secret == bytearray(len(CANARY))
    lease = await store.open_lease(
        unlocked.credential_id,
        "provider-transport:test",
        expected_generation=1,
    )
    retained = await lease.__aenter__()
    cancelled = await service.cancel_emergency_unlock(
        unlocked.unlock_id,
        EmergencyUnlockCancelRequest(
            mutation_id="mutation-emergency-cancel-0001",
            reason="synthetic cancellation",
        ),
        "admin-session-1",
    )

    assert cancelled.state == "CANCELLED"
    assert cancelled.remaining_requests == 0
    assert bytes(retained) == b"\x00" * len(CANARY)
    assert (await manager.status()).state is EmergencyUnlockState.LOCKED
    record = connection.execute(
        "SELECT state, credential_generation FROM emergency_unlock_records WHERE unlock_id = ?",
        (unlocked.unlock_id,),
    ).fetchone()
    assert tuple(record) == ("CANCELLED", 1)
    assert _catalog_counts(connection) == catalog_counts
    assert REASON_CANARY not in _database_text(connection)
    await manager.close()
    connection.close()


@pytest.mark.asyncio
async def test_unlock_durable_failure_redacts_recursive_cleanup_exception(
    tmp_path: Path,
) -> None:
    connection = open_migrated_database(tmp_path / "emergency-cleanup-failure.db")
    _seed_authority(connection)
    manager = _manager(_FailingEmergencyCleanupStore())
    service = SqliteCredentialLifecycleService(
        connection,
        persistent_key_store=InMemoryKeyStore(),
        emergency_manager=manager,
        now_ms=lambda: NOW_MS,
    )
    connection.execute(
        """
        CREATE TRIGGER reject_emergency_record
        BEFORE INSERT ON emergency_unlock_records
        BEGIN
            SELECT RAISE(ABORT, 'synthetic emergency metadata failure');
        END
        """
    )
    secret = bytearray(CANARY)

    with pytest.raises(CredentialLifecycleFailure) as captured:
        await service.unlock_emergency(_request(), secret, "admin-session-1")

    assert secret == bytearray(len(CANARY))
    assert CANARY.decode() not in _exception_graph_text(captured.value)
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None
    mutation = connection.execute(
        "SELECT state FROM credential_mutations WHERE mutation_id = ?",
        (_request().mutation_id,),
    ).fetchone()
    assert mutation[0] == "CLEANUP_REQUIRED"
    connection.close()


@pytest.mark.asyncio
async def test_emergency_mutation_ids_bind_authority_and_bounded_ceilings(
    tmp_path: Path,
) -> None:
    connection = open_migrated_database(tmp_path / "emergency-binding.db")
    _seed_authority(connection)
    manager = _manager(InMemoryKeyStore())
    service = SqliteCredentialLifecycleService(
        connection,
        persistent_key_store=InMemoryKeyStore(),
        emergency_manager=manager,
        now_ms=lambda: NOW_MS,
    )
    request = _request("mutation-emergency-binding")
    first = await service.unlock_emergency(
        request,
        bytearray(CANARY),
        "admin-session-1",
    )
    assert (
        await service.unlock_emergency(
            request,
            bytearray(CANARY),
            "admin-session-1",
        )
        == first
    )

    variants = (
        {"pool_id": "pool_01K00000000000000000000001"},
        {"session_id": "ses_01K00000000000000000000001"},
        {"root_run_id": "run_01K00000000000000000000001"},
        {"alias": "different-emergency"},
        {"duration_ms": 30_000},
        {"maximum_requests": 4},
        {"maximum_credits": 19},
        {"reason": "different synthetic unlock reason"},
    )
    for update in variants:
        with pytest.raises(CredentialLifecycleConflict):
            await service.unlock_emergency(
                request.model_copy(update=update),
                bytearray(CANARY),
                "admin-session-1",
            )

    cancel = EmergencyUnlockCancelRequest(
        mutation_id="mutation-emergency-cancel-binding",
        reason=REASON_CANARY,
    )
    cancelled = await service.cancel_emergency_unlock(
        first.unlock_id,
        cancel,
        "admin-session-1",
    )
    assert (
        await service.cancel_emergency_unlock(
            first.unlock_id,
            cancel,
            "admin-session-1",
        )
        == cancelled
    )
    with pytest.raises(CredentialLifecycleConflict):
        await service.cancel_emergency_unlock(
            "unlock-000000000000000000000099",
            cancel,
            "admin-session-1",
        )
    with pytest.raises(CredentialLifecycleConflict):
        await service.cancel_emergency_unlock(
            first.unlock_id,
            cancel.model_copy(update={"reason": "different synthetic cancel reason"}),
            "admin-session-1",
        )

    assert REASON_CANARY not in _database_text(connection)
    await manager.close()
    connection.close()


@pytest.mark.asyncio
async def test_fresh_manager_relocks_durable_emergency_authority(tmp_path: Path) -> None:
    database = tmp_path / "restart.db"
    connection = open_migrated_database(database)
    _seed_authority(connection)
    catalog_counts = _catalog_counts(connection)
    first_store = InMemoryKeyStore()
    first_manager = _manager(first_store)
    first = SqliteCredentialLifecycleService(
        connection,
        persistent_key_store=InMemoryKeyStore(),
        emergency_manager=first_manager,
        now_ms=lambda: NOW_MS,
    )
    unlocked = await first.unlock_emergency(_request(), bytearray(CANARY), "admin-session-1")
    await first_manager.close()

    fresh_manager = EmergencyUnlockManager(
        key_store=InMemoryKeyStore(),
        now_ms=lambda: NOW_MS,
    )
    restarted = SqliteCredentialLifecycleService(
        connection,
        persistent_key_store=InMemoryKeyStore(),
        emergency_manager=fresh_manager,
        now_ms=lambda: NOW_MS,
    )
    recovered = await restarted.recover_incomplete_mutations()

    assert recovered >= 1
    assert (await fresh_manager.status()).state is EmergencyUnlockState.LOCKED
    record = connection.execute(
        "SELECT state FROM emergency_unlock_records WHERE unlock_id = ?",
        (unlocked.unlock_id,),
    ).fetchone()
    assert record[0] == "RELOCKED"
    assert _catalog_counts(connection) == catalog_counts
    assert CANARY.decode() not in _database_text(connection)
    assert REASON_CANARY not in _database_text(connection)
    await fresh_manager.close()
    connection.close()
