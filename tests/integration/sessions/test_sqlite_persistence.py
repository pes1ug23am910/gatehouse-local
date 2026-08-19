from __future__ import annotations

import hashlib
import sqlite3
from dataclasses import replace
from pathlib import Path

import pytest

from gatehouse.core.ids import RootRunId, SessionId
from gatehouse.core.states import SessionState
from gatehouse.database import open_migrated_database, recover_startup
from gatehouse.sessions import (
    InvalidAccessToken,
    SessionManager,
    SqliteSessionPersistence,
)


class FakeClock:
    def __init__(self, now_ms: int = 1_000) -> None:
        self.value = now_ms

    def __call__(self) -> int:
        return self.value

    def advance(self, milliseconds: int) -> None:
        self.value += milliseconds


class DeterministicRandom:
    def __init__(self) -> None:
        self.counter = 0

    def __call__(self, length: int) -> bytes:
        self.counter += 1
        seed = hashlib.sha512(f"sqlite-session-{self.counter}".encode()).digest()
        repeats = (length + len(seed) - 1) // len(seed)
        return (seed * repeats)[:length]


def seed_authority(connection: sqlite3.Connection) -> None:
    connection.execute(
        """
        INSERT INTO clients(
            client_id, display_name, kind, policy_profile, created_at_ms, updated_at_ms
        ) VALUES ('client-test', 'Test client', 'interactive', 'test', 0, 0)
        """
    )
    connection.execute(
        """
        INSERT INTO workspaces(
            workspace_id, display_name, canonical_root, created_at_ms, updated_at_ms
        ) VALUES ('workspace-test', 'Test workspace', 'E:\\SessionTest', 0, 0)
        """
    )


async def manager(
    persistence: SqliteSessionPersistence,
    clock: FakeClock,
    random: DeterministicRandom,
) -> SessionManager:
    return await SessionManager.start(
        persistence=persistence,
        verifier_key=b"s" * 32,
        now_ms=clock,
        random_bytes=random,
        access_token_ttl_ms=600,
        reconnect_grace_ms=2_000,
        maximum_access_tokens=16,
    )


async def launch(manager: SessionManager) -> tuple[str, str, str]:
    launched = await manager.create_session(
        client_id="client-test",
        workspace_id="workspace-test",
        identity_assurance="LAUNCHER_SESSION",
        policy_version="policy-v1",
        absolute_ttl_ms=10_000,
        budget={"credits": 100, "requests": 20},
    )
    issued = await manager.exchange_bootstrap(
        session_id=launched.session.session_id,
        bootstrap_capability=launched.bootstrap_capability,
    )
    return (
        launched.session.session_id,
        launched.bootstrap_capability,
        issued.access_token,
    )


@pytest.mark.asyncio
async def test_file_backed_session_and_root_run_survive_reopen_and_readoption(
    tmp_path: Path,
) -> None:
    path = tmp_path / "gatehouse.db"
    clock = FakeClock()
    random = DeterministicRandom()
    first_connection = open_migrated_database(path)
    seed_authority(first_connection)
    first = await manager(SqliteSessionPersistence(first_connection), clock, random)
    session_id, bootstrap, old_access_token = await launch(first)
    root_run = await first.create_root_run(
        access_token=old_access_token,
        budget={"credits": 25, "requests": 5},
    )

    assert SessionId(session_id) == session_id
    assert RootRunId(root_run.root_run_id) == root_run.root_run_id
    first_connection.close()

    clock.advance(100)
    second_connection = open_migrated_database(path)
    second = await manager(SqliteSessionPersistence(second_connection), clock, random)
    with pytest.raises(InvalidAccessToken):
        await second.authenticate(old_access_token)
    replacement = await second.exchange_bootstrap(
        session_id=session_id,
        bootstrap_capability=bootstrap,
    )
    assert replacement.principal.token_epoch == second.token_epoch
    assert (
        await second.resolve_root_run(
            access_token=replacement.access_token,
            root_run_id=root_run.root_run_id,
        )
        == root_run
    )
    second_connection.close()


@pytest.mark.asyncio
async def test_replace_session_is_semantic_compare_and_swap_across_reopen(
    tmp_path: Path,
) -> None:
    path = tmp_path / "gatehouse.db"
    connection = open_migrated_database(path)
    seed_authority(connection)
    persistence = SqliteSessionPersistence(connection)
    current_manager = await manager(persistence, FakeClock(), DeterministicRandom())
    launched = await current_manager.create_session(
        client_id="client-test",
        workspace_id="workspace-test",
        identity_assurance="LAUNCHER_SESSION",
        policy_version="policy-v1",
        absolute_ttl_ms=10_000,
        budget={"credits": 100},
    )
    stale = await persistence.load_session(launched.session.session_id)
    assert stale is not None
    contender_connection = open_migrated_database(path)
    contender = SqliteSessionPersistence(contender_connection)
    contender_stale = await contender.load_session(launched.session.session_id)
    assert contender_stale == stale
    winner = stale.transition(SessionState.ACTIVE, now_ms=1_100)
    loser = contender_stale.transition(SessionState.ACTIVE, now_ms=1_101)

    assert await persistence.replace_session(expected=stale, replacement=winner)
    assert not await contender.replace_session(expected=contender_stale, replacement=loser)
    contender_connection.close()
    connection.close()

    reopened = open_migrated_database(path)
    assert await SqliteSessionPersistence(reopened).load_session(stale.session_id) == winner
    reopened.close()


@pytest.mark.asyncio
async def test_recovered_epoch_is_adopted_once_without_double_increment(
    tmp_path: Path,
) -> None:
    connection = open_migrated_database(tmp_path / "gatehouse.db")
    seed_authority(connection)
    clock = FakeClock()
    random = DeterministicRandom()
    first = await manager(SqliteSessionPersistence(connection), clock, random)
    session_id, bootstrap, _ = await launch(first)

    clock.advance(100)
    report = recover_startup(connection, now_ms=clock())
    persistence = SqliteSessionPersistence(
        connection,
        recovered_token_epoch=report.token_epoch,
    )
    second = await manager(persistence, clock, random)

    assert second.token_epoch == report.token_epoch
    assert (
        connection.execute(
            "SELECT token_epoch FROM system_state WHERE singleton_id = 1"
        ).fetchone()[0]
        == report.token_epoch
    )
    disconnected = await persistence.load_session(session_id)
    assert disconnected is not None
    assert disconnected.state is SessionState.DISCONNECTED
    assert disconnected.reconnect_until_ms == clock() + 2_000
    replacement = await second.exchange_bootstrap(
        session_id=session_id,
        bootstrap_capability=bootstrap,
    )
    assert replacement.principal.token_epoch == report.token_epoch

    assert (
        await persistence.begin_daemon_epoch(
            now_ms=clock(),
            reconnect_grace_ms=2_000,
        )
        == report.token_epoch + 1
    )
    connection.close()


@pytest.mark.asyncio
async def test_malformed_accounting_json_fails_closed(tmp_path: Path) -> None:
    connection = open_migrated_database(tmp_path / "gatehouse.db")
    seed_authority(connection)
    persistence = SqliteSessionPersistence(connection)
    current_manager = await manager(persistence, FakeClock(), DeterministicRandom())
    launched = await current_manager.create_session(
        client_id="client-test",
        workspace_id="workspace-test",
        identity_assurance="LAUNCHER_SESSION",
        policy_version="policy-v1",
        absolute_ttl_ms=10_000,
        budget={"credits": 100},
    )
    connection.execute(
        "UPDATE sessions SET budget_json = ? WHERE session_id = ?",
        ('{"credits":true}', launched.session.session_id),
    )

    with pytest.raises(ValueError, match="budget_json"):
        await persistence.load_session(launched.session.session_id)
    connection.close()


@pytest.mark.asyncio
async def test_cas_rejects_authority_rebinding(tmp_path: Path) -> None:
    connection = open_migrated_database(tmp_path / "gatehouse.db")
    seed_authority(connection)
    persistence = SqliteSessionPersistence(connection)
    current_manager = await manager(persistence, FakeClock(), DeterministicRandom())
    launched = await current_manager.create_session(
        client_id="client-test",
        workspace_id="workspace-test",
        identity_assurance="LAUNCHER_SESSION",
        policy_version="policy-v1",
        absolute_ttl_ms=10_000,
    )
    current = await persistence.load_session(launched.session.session_id)
    assert current is not None

    with pytest.raises(ValueError, match="authority"):
        await persistence.replace_session(
            expected=current,
            replacement=replace(current, client_id="other-client"),
        )
    connection.close()
