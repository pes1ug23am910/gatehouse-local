from __future__ import annotations

import asyncio
import hashlib
import sqlite3
import threading
from dataclasses import replace
from pathlib import Path

import pytest

from gatehouse.core.ids import RootRunId, SessionId
from gatehouse.core.states import SessionState
from gatehouse.database import open_migrated_database, recover_startup
from gatehouse.sessions import (
    InvalidAccessToken,
    LaunchedSession,
    RootRunRecord,
    RootRunState,
    SessionManager,
    SessionRunawayQuarantined,
    SessionRunCapacityExceeded,
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
    *,
    maximum_concurrent_runs: int | None = None,
) -> SessionManager:
    return await SessionManager.start(
        persistence=persistence,
        verifier_key=b"s" * 32,
        now_ms=clock,
        random_bytes=random,
        access_token_ttl_ms=600,
        reconnect_grace_ms=2_000,
        maximum_access_tokens=16,
        maximum_concurrent_runs_by_client_id=(
            None if maximum_concurrent_runs is None else {"client-test": maximum_concurrent_runs}
        ),
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


@pytest.mark.asyncio
async def test_same_session_cannot_mint_more_than_profile_root_run_limit(
    tmp_path: Path,
) -> None:
    connection = open_migrated_database(tmp_path / "gatehouse.db")
    seed_authority(connection)
    clock = FakeClock()
    current = await manager(
        SqliteSessionPersistence(connection),
        clock,
        DeterministicRandom(),
        maximum_concurrent_runs=1,
    )
    _, _, access_token = await launch(current)

    first = await current.create_root_run(access_token=access_token)
    with pytest.raises(SessionRunCapacityExceeded, match="capacity"):
        await current.create_root_run(access_token=access_token)

    assert first.state.value == "ACTIVE"
    assert connection.execute("SELECT COUNT(*) FROM root_runs").fetchone()[0] == 1
    connection.close()


@pytest.mark.asyncio
async def test_concurrent_profile_session_admission_has_one_winner_and_revoke_releases_slot(
    tmp_path: Path,
) -> None:
    connection = open_migrated_database(tmp_path / "gatehouse.db")
    seed_authority(connection)
    current = await manager(
        SqliteSessionPersistence(connection),
        FakeClock(),
        DeterministicRandom(),
        maximum_concurrent_runs=1,
    )

    async def create() -> LaunchedSession:
        return await current.create_session(
            client_id="client-test",
            workspace_id="workspace-test",
            identity_assurance="LAUNCHER_SESSION",
            policy_version="policy-v1",
            absolute_ttl_ms=10_000,
            maximum_concurrent_runs=1,
            block_on_runaway_quarantine=True,
        )

    outcomes = await asyncio.gather(create(), create(), return_exceptions=True)
    launched = [item for item in outcomes if not isinstance(item, BaseException)]
    failures = [item for item in outcomes if isinstance(item, BaseException)]
    assert len(launched) == len(failures) == 1
    assert isinstance(failures[0], SessionRunCapacityExceeded)

    winner = launched[0]
    assert isinstance(winner, LaunchedSession)
    await current.revoke(winner.session.session_id)
    replacement = await create()
    assert replacement.session.state is SessionState.CREATED
    connection.close()


@pytest.mark.asyncio
async def test_cross_session_root_run_race_has_one_durable_winner(tmp_path: Path) -> None:
    path = tmp_path / "gatehouse.db"
    connection = open_migrated_database(path)
    seed_authority(connection)
    current = await manager(
        SqliteSessionPersistence(connection),
        FakeClock(),
        DeterministicRandom(),
        maximum_concurrent_runs=1,
    )
    first_session, _, _ = await launch(current)
    second_session, _, _ = await launch(current)
    barrier = threading.Barrier(2)

    def contend(root_run: RootRunRecord) -> RootRunRecord | BaseException:
        contender_connection = open_migrated_database(path)
        try:
            contender = SqliteSessionPersistence(contender_connection)
            barrier.wait(timeout=10)
            try:
                asyncio.run(
                    contender.insert_root_run(
                        root_run,
                        client_id="client-test",
                        maximum_concurrent_runs=1,
                        now_ms=1_000,
                        stale_after_ms=1_200,
                        reconnect_grace_ms=2_000,
                        block_on_runaway_quarantine=True,
                    )
                )
            except BaseException as error:
                return error
            return root_run
        finally:
            contender_connection.close()

    outcomes = await asyncio.gather(
        asyncio.to_thread(
            contend,
            RootRunRecord(
                root_run_id="root-thread-one",
                session_id=first_session,
                state=RootRunState.ACTIVE,
                started_at_ms=1_000,
            ),
        ),
        asyncio.to_thread(
            contend,
            RootRunRecord(
                root_run_id="root-thread-two",
                session_id=second_session,
                state=RootRunState.ACTIVE,
                started_at_ms=1_000,
            ),
        ),
    )

    assert sum(not isinstance(item, BaseException) for item in outcomes) == 1
    failures = [item for item in outcomes if isinstance(item, BaseException)]
    assert len(failures) == 1
    assert isinstance(failures[0], SessionRunCapacityExceeded)
    assert connection.execute("SELECT COUNT(*) FROM root_runs").fetchone()[0] == 1
    connection.close()


@pytest.mark.asyncio
async def test_disconnected_restart_owner_holds_root_slot_until_reconnect_deadline(
    tmp_path: Path,
) -> None:
    connection = open_migrated_database(tmp_path / "gatehouse.db")
    seed_authority(connection)
    clock = FakeClock()
    random = DeterministicRandom()
    first = await manager(
        SqliteSessionPersistence(connection),
        clock,
        random,
        maximum_concurrent_runs=1,
    )
    _, _, first_token = await launch(first)
    await first.create_root_run(access_token=first_token)

    clock.advance(100)
    recovery = recover_startup(connection, now_ms=clock())
    second = await manager(
        SqliteSessionPersistence(connection, recovered_token_epoch=recovery.token_epoch),
        clock,
        random,
        maximum_concurrent_runs=1,
    )
    second_session, second_bootstrap, second_token = await launch(second)
    with pytest.raises(SessionRunCapacityExceeded, match="capacity"):
        await second.create_root_run(access_token=second_token)

    clock.advance(2_001)
    refreshed = await second.exchange_bootstrap(
        session_id=second_session,
        bootstrap_capability=second_bootstrap,
    )
    admitted = await second.create_root_run(access_token=refreshed.access_token)

    assert admitted.state.value == "ACTIVE"
    assert (
        connection.execute("SELECT COUNT(*) FROM sessions WHERE state = 'EXPIRED'").fetchone()[0]
        == 1
    )
    connection.close()


@pytest.mark.parametrize("quarantine_state", ["OPEN", "AUTHORIZED"])
@pytest.mark.asyncio
async def test_blocking_quarantine_fences_fresh_root_after_owner_revocation(
    tmp_path: Path,
    quarantine_state: str,
) -> None:
    connection = open_migrated_database(tmp_path / "gatehouse.db")
    seed_authority(connection)
    current = await manager(
        SqliteSessionPersistence(connection),
        FakeClock(),
        DeterministicRandom(),
        maximum_concurrent_runs=2,
    )
    first_session, _, first_token = await launch(current)
    first_root = await current.create_root_run(access_token=first_token)
    if quarantine_state == "OPEN":
        connection.execute(
            """
            INSERT INTO runaway_quarantines(
                quarantine_id, session_id, root_run_id, service_id, state,
                trigger_reason, trigger_operation, generation, opened_at_ms, updated_at_ms
            ) VALUES (
                'rqu_profile_fence', ?, ?, 'firecrawl', 'OPEN',
                'AGGREGATE_BURST', 'firecrawl.search', 1, 1000, 1000
            )
            """,
            (first_session, first_root.root_run_id),
        )
    else:
        connection.execute(
            """
            INSERT INTO runaway_quarantines(
                quarantine_id, session_id, root_run_id, service_id, state,
                trigger_reason, trigger_operation, generation, opened_at_ms, updated_at_ms,
                decided_at_ms, expires_at_ms, decision_actor_id,
                decision_reason_fingerprint, decision_reason_supplied,
                maximum_requests, remaining_requests, maximum_credits,
                remaining_credits, maximum_concurrency, operations_json
            ) VALUES (
                'rqu_profile_fence', ?, ?, 'firecrawl', 'AUTHORIZED',
                'AGGREGATE_BURST', 'firecrawl.search', 2, 1000, 1001,
                1001, 2000, 'operator-test', ?, 1, 1, 1, 1, 1, 1,
                '["firecrawl.search"]'
            )
            """,
            (first_session, first_root.root_run_id, "a" * 64),
        )
    await current.revoke(first_session)
    with pytest.raises(SessionRunawayQuarantined, match="quarantine"):
        await current.create_session(
            client_id="client-test",
            workspace_id="workspace-test",
            identity_assurance="LAUNCHER_SESSION",
            policy_version="policy-v1",
            absolute_ttl_ms=10_000,
            maximum_concurrent_runs=2,
            block_on_runaway_quarantine=True,
        )
    _, _, replacement_token = await launch(current)

    with pytest.raises(SessionRunawayQuarantined, match="quarantine"):
        await current.create_root_run(access_token=replacement_token)

    assert connection.execute("SELECT COUNT(*) FROM root_runs").fetchone()[0] == 1
    connection.close()


@pytest.mark.asyncio
async def test_exact_current_quarantine_recovery_survives_restart_and_allows_fresh_root(
    tmp_path: Path,
) -> None:
    path = tmp_path / "gatehouse.db"
    connection = open_migrated_database(path)
    seed_authority(connection)
    clock = FakeClock()
    random = DeterministicRandom()
    current = await manager(
        SqliteSessionPersistence(connection),
        clock,
        random,
        maximum_concurrent_runs=2,
    )
    old_session, _, old_token = await launch(current)
    old_root = await current.create_root_run(access_token=old_token)
    connection.execute(
        """
        INSERT INTO runaway_quarantines(
            quarantine_id, session_id, root_run_id, service_id, state,
            trigger_reason, trigger_operation, generation, opened_at_ms, updated_at_ms
        ) VALUES (
            'rqu_recovered_restart', ?, ?, 'firecrawl', 'OPEN',
            'AGGREGATE_BURST', 'firecrawl.search', 2, 1000, 1000
        )
        """,
        (old_session, old_root.root_run_id),
    )
    await current.revoke(old_session)
    connection.execute(
        "UPDATE root_runs SET state = 'CANCELLED', ended_at_ms = 1001 WHERE root_run_id = ?",
        (old_root.root_run_id,),
    )
    connection.execute(
        """
        INSERT INTO runaway_quarantine_recoveries(
            recovery_id, quarantine_id, quarantine_generation,
            client_id, session_id, root_run_id, previous_state,
            recovered_at_ms, decision_actor_id,
            decision_reason_fingerprint, confirmation
        ) VALUES (
            'recovery-restart', 'rqu_recovered_restart', 2,
            'client-test', ?, ?, 'OPEN', 1000, 'admin-session', ?,
            'RECOVER_FRESH_RUN'
        )
        """,
        (old_session, old_root.root_run_id, "a" * 64),
    )
    connection.close()

    reopened = open_migrated_database(path)
    restarted = await manager(
        SqliteSessionPersistence(reopened),
        clock,
        random,
        maximum_concurrent_runs=2,
    )
    fresh = await restarted.create_session(
        client_id="client-test",
        workspace_id="workspace-test",
        identity_assurance="LAUNCHER_SESSION",
        policy_version="policy-v1",
        absolute_ttl_ms=10_000,
        maximum_concurrent_runs=2,
        block_on_runaway_quarantine=True,
    )
    fresh_token = await restarted.exchange_bootstrap(
        session_id=fresh.session.session_id,
        bootstrap_capability=fresh.bootstrap_capability,
    )
    fresh_root = await restarted.create_root_run(access_token=fresh_token.access_token)

    assert fresh_root.state is RootRunState.ACTIVE
    assert fresh_root.root_run_id != old_root.root_run_id
    assert (
        reopened.execute(
            "SELECT COUNT(*) FROM runaway_burst_permits WHERE state = 'ACTIVE'"
        ).fetchone()[0]
        == 0
    )
    reopened.close()


@pytest.mark.asyncio
async def test_stale_or_partial_quarantine_recovery_evidence_remains_blocking(
    tmp_path: Path,
) -> None:
    connection = open_migrated_database(tmp_path / "gatehouse.db")
    seed_authority(connection)
    current = await manager(
        SqliteSessionPersistence(connection),
        FakeClock(),
        DeterministicRandom(),
        maximum_concurrent_runs=2,
    )
    old_session, _, old_token = await launch(current)
    old_root = await current.create_root_run(access_token=old_token)
    connection.execute(
        """
        INSERT INTO runaway_quarantines(
            quarantine_id, session_id, root_run_id, service_id, state,
            trigger_reason, trigger_operation, generation, opened_at_ms, updated_at_ms
        ) VALUES (
            'rqu_stale_recovery', ?, ?, 'firecrawl', 'OPEN',
            'AGGREGATE_BURST', 'firecrawl.search', 1, 1000, 1000
        )
        """,
        (old_session, old_root.root_run_id),
    )
    await current.revoke(old_session)
    connection.execute(
        "UPDATE root_runs SET state = 'CANCELLED', ended_at_ms = 1001 WHERE root_run_id = ?",
        (old_root.root_run_id,),
    )
    connection.execute(
        """
        INSERT INTO runaway_quarantine_recoveries(
            recovery_id, quarantine_id, quarantine_generation,
            client_id, session_id, root_run_id, previous_state,
            recovered_at_ms, decision_actor_id,
            decision_reason_fingerprint, confirmation
        ) VALUES (
            'recovery-stale', 'rqu_stale_recovery', 1,
            'client-test', ?, ?, 'OPEN', 1000, 'admin-session', ?,
            'RECOVER_FRESH_RUN'
        )
        """,
        (old_session, old_root.root_run_id, "b" * 64),
    )
    connection.execute(
        """
        UPDATE runaway_quarantines SET generation = 2, updated_at_ms = 1002
         WHERE quarantine_id = 'rqu_stale_recovery'
        """
    )

    with pytest.raises(SessionRunawayQuarantined, match="quarantine"):
        await current.create_session(
            client_id="client-test",
            workspace_id="workspace-test",
            identity_assurance="LAUNCHER_SESSION",
            policy_version="policy-v1",
            absolute_ttl_ms=10_000,
            maximum_concurrent_runs=2,
            block_on_runaway_quarantine=True,
        )
    connection.close()


@pytest.mark.asyncio
async def test_recovering_only_one_of_multiple_client_quarantines_remains_blocking(
    tmp_path: Path,
) -> None:
    connection = open_migrated_database(tmp_path / "gatehouse.db")
    seed_authority(connection)
    current = await manager(
        SqliteSessionPersistence(connection),
        FakeClock(),
        DeterministicRandom(),
        maximum_concurrent_runs=2,
    )
    old_session, _, old_token = await launch(current)
    old_root = await current.create_root_run(access_token=old_token)
    connection.executemany(
        """
        INSERT INTO runaway_quarantines(
            quarantine_id, session_id, root_run_id, service_id, state,
            trigger_reason, trigger_operation, generation, opened_at_ms, updated_at_ms
        ) VALUES (?, ?, ?, ?, 'OPEN', 'AGGREGATE_BURST', ?, 1, 1000, 1000)
        """,
        (
            (
                "rqu_recovered_one",
                old_session,
                old_root.root_run_id,
                "firecrawl",
                "firecrawl.search",
            ),
            (
                "rqu_still_blocking",
                old_session,
                old_root.root_run_id,
                "openrouter",
                "openrouter.chat",
            ),
        ),
    )
    await current.revoke(old_session)
    connection.execute(
        "UPDATE root_runs SET state = 'CANCELLED', ended_at_ms = 1000 WHERE root_run_id = ?",
        (old_root.root_run_id,),
    )
    connection.execute(
        """
        INSERT INTO runaway_quarantine_recoveries(
            recovery_id, quarantine_id, quarantine_generation,
            client_id, session_id, root_run_id, previous_state,
            recovered_at_ms, decision_actor_id,
            decision_reason_fingerprint, confirmation
        ) VALUES (
            'recovery-only-one', 'rqu_recovered_one', 1,
            'client-test', ?, ?, 'OPEN', 1000, 'admin-session', ?,
            'RECOVER_FRESH_RUN'
        )
        """,
        (old_session, old_root.root_run_id, "c" * 64),
    )

    with pytest.raises(SessionRunawayQuarantined, match="quarantine"):
        await current.create_session(
            client_id="client-test",
            workspace_id="workspace-test",
            identity_assurance="LAUNCHER_SESSION",
            policy_version="policy-v1",
            absolute_ttl_ms=10_000,
            maximum_concurrent_runs=2,
            block_on_runaway_quarantine=True,
        )
    connection.close()
