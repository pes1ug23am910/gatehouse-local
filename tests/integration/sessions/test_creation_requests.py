from __future__ import annotations

import hashlib
import sqlite3
from collections.abc import Iterator
from typing import Any

import pytest

from gatehouse.core.states import SessionState
from gatehouse.database import open_migrated_database
from gatehouse.sessions import (
    SessionCreationOutcomeUnresolved,
    SessionCreationRequest,
    SessionCreationRequestConflict,
    SessionManager,
    SqliteSessionPersistence,
)
from gatehouse.sessions.manager import LaunchedSession


class _Random:
    def __init__(self) -> None:
        self.count = 0

    def __call__(self, size: int) -> bytes:
        self.count += 1
        return hashlib.shake_256(str(self.count).encode()).digest(size)


@pytest.fixture
def connection() -> Iterator[sqlite3.Connection]:
    connection = open_migrated_database(":memory:")
    connection.execute(
        """INSERT INTO clients(client_id, display_name, kind, policy_profile,
                               created_at_ms, updated_at_ms)
           VALUES ('client-test', 'Test', 'interactive', 'test', 0, 0)"""
    )
    connection.execute(
        """INSERT INTO workspaces(workspace_id, display_name, canonical_root,
                                  created_at_ms, updated_at_ms)
           VALUES ('workspace-test', 'Test', 'E:\\SessionTest', 0, 0)"""
    )
    yield connection
    connection.close()


async def _manager(persistence: SqliteSessionPersistence) -> SessionManager:
    return await SessionManager.start(
        persistence=persistence,
        verifier_key=b"s" * 32,
        now_ms=lambda: 1_000,
        random_bytes=_Random(),
        access_token_ttl_ms=600,
        reconnect_grace_ms=2_000,
    )


async def _create(
    manager: SessionManager,
    request_id: str = "1" * 32,
    digest: str = "a" * 64,
) -> LaunchedSession:
    return await manager.create_session(
        client_id="client-test",
        workspace_id="workspace-test",
        identity_assurance="CONTROLLED_INTERACTIVE_LAUNCH",
        policy_version="policy-v1",
        absolute_ttl_ms=10_000,
        budget={"credits": 100, "requests": 20},
        creation_request=SessionCreationRequest(request_id, digest),
    )


@pytest.mark.asyncio
async def test_request_maps_exactly_one_session_without_persisting_bootstrap(
    connection: sqlite3.Connection,
) -> None:
    manager = await _manager(SqliteSessionPersistence(connection))
    launched = await _create(manager)
    row = connection.execute("SELECT * FROM controlled_session_requests").fetchone()
    assert row["state"] == "BOUND"
    assert row["session_id"] == launched.session.session_id
    assert row["authority_digest"] == "a" * 64
    assert row["request_digest"] == SessionCreationRequest("1" * 32, "a" * 64).request_digest
    assert launched.bootstrap_capability not in repr(tuple(row))
    assert "1" * 32 not in repr(tuple(row))
    with pytest.raises(SessionCreationRequestConflict, match="already bound"):
        await _create(manager)
    assert connection.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("digest", ["a" * 64, "b" * 64])
async def test_cancel_before_mint_permanently_blocks_request(
    connection: sqlite3.Connection,
    digest: str,
) -> None:
    manager = await _manager(SqliteSessionPersistence(connection))
    assert await manager.cancel_creation_request("1" * 32) is None
    with pytest.raises(SessionCreationRequestConflict):
        await _create(manager, digest=digest)
    assert await manager.cancel_creation_request("1" * 32) is None
    assert connection.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 0
    row = connection.execute("SELECT * FROM controlled_session_requests").fetchone()
    assert row["state"] == "CANCELLED" and row["session_id"] is None


@pytest.mark.asyncio
async def test_lost_create_acknowledgement_cancels_exact_persisted_session(
    connection: sqlite3.Connection,
) -> None:
    class LostAcknowledgement(SqliteSessionPersistence):
        async def insert_session(self, *args: Any, **kwargs: Any) -> None:
            await super().insert_session(*args, **kwargs)
            raise RuntimeError("synthetic acknowledgement failure")

    manager = await _manager(LostAcknowledgement(connection))
    with pytest.raises(SessionCreationOutcomeUnresolved, match="outcome is unresolved"):
        await _create(manager)
    mapped = connection.execute("SELECT session_id FROM controlled_session_requests").fetchone()[0]
    with pytest.raises(SessionCreationRequestConflict):
        await _create(manager)
    cancelled = await manager.cancel_creation_request("1" * 32)
    assert cancelled is not None and cancelled.session_id == mapped
    assert cancelled.state is SessionState.REVOKED
    assert await manager.cancel_creation_request("1" * 32) == cancelled


@pytest.mark.asyncio
@pytest.mark.parametrize("interruption", [RuntimeError, KeyboardInterrupt, SystemExit])
async def test_cancel_commit_interruption_keeps_tombstone_and_allows_exact_retry(
    connection: sqlite3.Connection,
    interruption: type[BaseException],
) -> None:
    class InterruptedCancellation(SqliteSessionPersistence):
        interrupt = True

        async def cancel_session_request(self, *args: Any, **kwargs: Any) -> str | None:
            result = await super().cancel_session_request(*args, **kwargs)
            if self.interrupt:
                self.interrupt = False
                raise interruption("synthetic cancellation interruption")
            return result

    persistence = InterruptedCancellation(connection)
    manager = await _manager(persistence)
    launched = await _create(manager)
    with pytest.raises(interruption):
        await manager.cancel_creation_request("1" * 32)
    row = connection.execute("SELECT state FROM controlled_session_requests").fetchone()
    assert row["state"] == "CANCELLED"
    with pytest.raises(SessionCreationRequestConflict):
        await _create(manager)
    result = await manager.cancel_creation_request("1" * 32)
    assert result is not None
    assert result.session_id == launched.session.session_id
    assert result.state is SessionState.REVOKED


@pytest.mark.asyncio
async def test_request_insert_failure_rolls_back_session_in_same_transaction(
    connection: sqlite3.Connection,
) -> None:
    manager = await _manager(SqliteSessionPersistence(connection))
    connection.execute(
        """CREATE TRIGGER deny_request BEFORE INSERT ON controlled_session_requests
           BEGIN SELECT RAISE(ABORT, 'synthetic refusal'); END"""
    )
    with pytest.raises(SessionCreationRequestConflict):
        await _create(manager)
    assert connection.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 0
    assert not connection.in_transaction


@pytest.mark.asyncio
async def test_request_capacity_is_finite_without_eviction(connection: sqlite3.Connection) -> None:
    manager = await _manager(SqliteSessionPersistence(connection))
    await manager.cancel_creation_request("1" * 32)
    connection.execute(
        "UPDATE sqlite_sequence SET seq = 100000 WHERE name = 'controlled_session_requests'"
    )
    with pytest.raises(SessionCreationRequestConflict):
        await _create(manager, request_id="2" * 32)
    with pytest.raises(SessionCreationRequestConflict):
        await manager.cancel_creation_request("2" * 32)
    assert await manager.cancel_creation_request("1" * 32) is None
    assert connection.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "sql",
    [
        "DELETE FROM controlled_session_requests",
        "UPDATE controlled_session_requests SET request_digest = '" + "b" * 64 + "'",
        "UPDATE controlled_session_requests SET authority_digest = '" + "b" * 64 + "'",
        "UPDATE controlled_session_requests SET session_id = NULL",
        "UPDATE controlled_session_requests SET state = 'BOUND' WHERE state = 'CANCELLED'",
    ],
)
async def test_durable_request_identity_and_cancellation_cannot_be_rewritten(
    connection: sqlite3.Connection,
    sql: str,
) -> None:
    manager = await _manager(SqliteSessionPersistence(connection))
    await _create(manager)
    await manager.cancel_creation_request("1" * 32)
    with pytest.raises(sqlite3.IntegrityError):
        connection.execute(sql)


@pytest.mark.parametrize("request_id", ["", "1" * 31, "1" * 33, "A" * 32, "1" * 31 + "\n"])
def test_request_identifier_has_exact_bounded_ascii_shape(request_id: str) -> None:
    with pytest.raises(ValueError, match="invalid"):
        SessionCreationRequest(request_id, "a" * 64)


@pytest.mark.asyncio
async def test_restart_reconstructs_request_cleanup_without_bootstrap_or_response(
    connection: sqlite3.Connection,
) -> None:
    first = await _manager(SqliteSessionPersistence(connection))
    launched = await _create(first)
    restarted = await _manager(SqliteSessionPersistence(connection))
    with pytest.raises(SessionCreationRequestConflict):
        await _create(restarted)
    cancelled = await restarted.cancel_creation_request("1" * 32)
    assert cancelled is not None
    assert cancelled.session_id == launched.session.session_id
    assert cancelled.state is SessionState.REVOKED


@pytest.mark.asyncio
@pytest.mark.parametrize("field", ["request_digest", "authority_digest"])
@pytest.mark.parametrize(
    "suffix", ["\x00", "\x00" + "x" * 100_000], ids=["nul", "hidden-large-tail"]
)
async def test_request_sql_authority_rejects_hidden_bytes(
    connection: sqlite3.Connection,
    field: str,
    suffix: str,
) -> None:
    manager = await _manager(SqliteSessionPersistence(connection))
    launched = await _create(manager)
    row = connection.execute("SELECT * FROM controlled_session_requests").fetchone()
    request_digest = "2" * 64 + (suffix if field == "request_digest" else "")
    authority_digest = "3" * 64 + (suffix if field == "authority_digest" else "")
    # A second, otherwise valid session avoids the independent uniqueness guard.
    other = await manager.create_session(
        client_id=launched.session.client_id,
        workspace_id=launched.session.workspace_id,
        identity_assurance=launched.session.identity_assurance,
        policy_version=launched.session.policy_version,
        absolute_ttl_ms=60_000,
    )
    with pytest.raises(sqlite3.IntegrityError):
        connection.execute(
            "INSERT INTO controlled_session_requests(request_digest, authority_digest, "
            "session_id, state, created_at_ms, updated_at_ms) VALUES (?, ?, ?, 'BOUND', ?, ?)",
            (
                request_digest,
                authority_digest,
                other.session.session_id,
                row["created_at_ms"],
                row["updated_at_ms"],
            ),
        )
    assert connection.execute("SELECT COUNT(*) FROM controlled_session_requests").fetchone()[0] == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["create", "cancel"])
async def test_request_operation_refuses_without_committing_caller_transaction(
    connection: sqlite3.Connection,
    operation: str,
) -> None:
    manager = await _manager(SqliteSessionPersistence(connection))
    connection.execute("BEGIN IMMEDIATE")
    try:
        with pytest.raises(SessionCreationRequestConflict):
            if operation == "create":
                await _create(manager)
            else:
                await manager.cancel_creation_request("1" * 32)
        assert connection.in_transaction
        row = connection.execute("SELECT COUNT(*) FROM controlled_session_requests").fetchone()
        assert row[0] == 0
    finally:
        connection.rollback()
