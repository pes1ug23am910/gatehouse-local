from __future__ import annotations

import asyncio
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

import pytest

from gatehouse.database import (
    MIGRATIONS,
    Migration,
    RunawayAdmissionState,
    RunawayQuarantineConflict,
    RunawayQuarantineState,
    SqliteRunawayQuarantineService,
    apply_migrations,
    connect_database,
    open_migrated_database,
    recover_startup,
    transaction,
)
from gatehouse.database.migrations import RUNAWAY_QUARANTINE_BURST_AUTHORITY
from gatehouse.fingerprint import RequestFingerprint, RunawayDetector, RunawayTrigger


@dataclass
class ManualClock:
    value: int = 1_000

    def __call__(self) -> int:
        return self.value


def _fingerprint(seed: int) -> RequestFingerprint:
    return RequestFingerprint(bytes([seed]) * 32, 1, 1)


def _seed_owner(
    connection: sqlite3.Connection,
    suffix: str,
    *,
    request_count: int = 12,
) -> tuple[str, str, tuple[str, ...]]:
    client_id = f"client-{suffix}"
    workspace_id = f"workspace-{suffix}"
    session_id = f"session-{suffix}"
    root_run_id = f"root-{suffix}"
    connection.execute(
        """
        INSERT INTO clients(
            client_id, display_name, kind, policy_profile, created_at_ms, updated_at_ms
        ) VALUES (?, ?, 'interactive', 'default', 0, 0)
        """,
        (client_id, client_id),
    )
    connection.execute(
        """
        INSERT INTO workspaces(
            workspace_id, display_name, canonical_root, created_at_ms, updated_at_ms
        ) VALUES (?, ?, ?, 0, 0)
        """,
        (workspace_id, workspace_id, f"C:\\work\\{suffix}"),
    )
    connection.execute(
        """
        INSERT INTO sessions(
            session_id, client_id, workspace_id, bootstrap_verifier,
            bootstrap_version, token_epoch, state, identity_assurance,
            policy_version, created_at_ms, reconnect_until_ms,
            absolute_expires_at_ms
        ) VALUES (?, ?, ?, X'01', 1, 0, 'ACTIVE', 'CONTROLLED', 'v1', 0, 50000, 50000)
        """,
        (session_id, client_id, workspace_id),
    )
    connection.execute(
        "INSERT INTO root_runs(root_run_id, session_id, state, started_at_ms) "
        "VALUES (?, ?, 'ACTIVE', 0)",
        (root_run_id, session_id),
    )
    request_ids = tuple(f"request-{suffix}-{index}" for index in range(request_count))
    for request_id in request_ids:
        connection.execute(
            """
            INSERT INTO invocations(
                request_id, session_id, root_run_id, service_id, operation,
                request_fingerprint, fingerprint_version, canonicalization_version,
                state, priority_class, request_size_bytes, received_at_ms
            ) VALUES (?, ?, ?, 'firecrawl', 'firecrawl.search', X'01', 1, 1,
                      'DEDUPLICATION', 'NORMAL_AGENT', 0, 0)
            """,
            (request_id, session_id, root_run_id),
        )
    return session_id, root_run_id, request_ids


def _service(
    connection: sqlite3.Connection,
    clock: ManualClock,
    *,
    repeated: int = 2,
    aggregate: int = 4,
) -> SqliteRunawayQuarantineService:
    ids = iter(f"rqu-{index}" for index in range(100))
    permits = iter(f"permit-{index}" for index in range(100))
    audits = iter(f"event-{index}" for index in range(1_000))
    return SqliteRunawayQuarantineService(
        connection,
        action_token_key=b"a" * 32,
        now_ms=clock,
        detector=RunawayDetector(
            threshold=repeated,
            aggregate_threshold=aggregate,
            window_ms=30_000,
        ),
        quarantine_id_factory=lambda: next(ids),
        permit_id_factory=lambda: next(permits),
        audit_event_id_factory=lambda: next(audits),
    )


async def _open_quarantine(
    service: SqliteRunawayQuarantineService,
    session_id: str,
    root_run_id: str,
    request_ids: tuple[str, ...],
    clock: ManualClock,
) -> str:
    first = await service.admit(
        session_id=session_id,
        root_run_id=root_run_id,
        request_id=request_ids[0],
        service_id="firecrawl",
        operation="firecrawl.search",
        fingerprint=_fingerprint(1),
        estimated_cost_units=1,
        now_ms=clock.value,
    )
    assert first.state is RunawayAdmissionState.ALLOW
    opened = await service.admit(
        session_id=session_id,
        root_run_id=root_run_id,
        request_id=request_ids[1],
        service_id="firecrawl",
        operation="firecrawl.search",
        fingerprint=_fingerprint(1),
        estimated_cost_units=1,
        now_ms=clock.value + 1,
    )
    assert opened.state is RunawayAdmissionState.QUARANTINED
    assert opened.trigger is RunawayTrigger.REPEATED_EQUIVALENT
    assert opened.quarantine_id is not None
    return opened.quarantine_id


@pytest.mark.asyncio
async def test_quarantine_is_offender_scoped_durable_and_never_timer_healed(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "runaway-restart.db"
    clock = ManualClock()
    connection = open_migrated_database(database_path)
    session_id, root_run_id, request_ids = _seed_owner(connection, "one")
    other_session, other_root, other_requests = _seed_owner(connection, "two")
    service = _service(connection, clock)
    quarantine_id = await _open_quarantine(
        service,
        session_id,
        root_run_id,
        request_ids,
        clock,
    )

    unrelated = await service.admit(
        session_id=other_session,
        root_run_id=other_root,
        request_id=other_requests[0],
        service_id="firecrawl",
        operation="firecrawl.search",
        fingerprint=_fingerprint(1),
        estimated_cost_units=1,
        now_ms=clock.value + 2,
    )
    assert unrelated.state is RunawayAdmissionState.ALLOW
    connection.close()

    clock.value += 24 * 60 * 60_000
    reopened = open_migrated_database(database_path)
    restarted = _service(reopened, clock, repeated=10, aggregate=20)
    blocked = await restarted.admit(
        session_id=session_id,
        root_run_id=root_run_id,
        request_id=request_ids[2],
        service_id="firecrawl",
        operation="firecrawl.search",
        fingerprint=_fingerprint(9),
        estimated_cost_units=1,
        now_ms=clock.value,
    )
    assert blocked.state is RunawayAdmissionState.QUARANTINED
    assert blocked.quarantine_id == quarantine_id
    assert blocked.quarantine_state is RunawayQuarantineState.OPEN
    assert blocked.reason_code == "operator_authorization_required"
    reopened.close()


@pytest.mark.asyncio
async def test_bounded_authorization_consumes_requests_credits_and_concurrency_atomically() -> None:
    clock = ManualClock()
    connection = open_migrated_database(":memory:")
    session_id, root_run_id, request_ids = _seed_owner(connection, "bounded")
    service = _service(connection, clock)
    quarantine_id = await _open_quarantine(
        service,
        session_id,
        root_run_id,
        request_ids,
        clock,
    )
    view = await service.get_quarantine(quarantine_id)
    assert view is not None

    authorized = await service.authorize(
        quarantine_id=quarantine_id,
        expected_generation=view.generation,
        action_token=view.action_token,
        actor_id="admin-session",
        reason="Explicit personal-use burst authorization",
        duration_ms=10_000,
        maximum_requests=2,
        maximum_credits=3,
        maximum_concurrency=1,
        operations=("firecrawl.search",),
        now_ms=clock.value + 2,
    )
    assert authorized.state is RunawayQuarantineState.AUTHORIZED

    first = await service.admit(
        session_id=session_id,
        root_run_id=root_run_id,
        request_id=request_ids[2],
        service_id="firecrawl",
        operation="firecrawl.search",
        fingerprint=_fingerprint(2),
        estimated_cost_units=1,
        now_ms=clock.value + 3,
    )
    concurrent = await service.admit(
        session_id=session_id,
        root_run_id=root_run_id,
        request_id=request_ids[3],
        service_id="firecrawl",
        operation="firecrawl.search",
        fingerprint=_fingerprint(3),
        estimated_cost_units=1,
        now_ms=clock.value + 3,
    )
    assert first.state is RunawayAdmissionState.AUTHORIZED
    assert first.permit is not None
    assert concurrent.state is RunawayAdmissionState.CAPACITY
    assert concurrent.reason_code == "burst_concurrency_limit"
    assert await service.settle_permit(first.permit.permit_id, now_ms=clock.value + 4)
    assert not await service.settle_permit(first.permit.permit_id, now_ms=clock.value + 4)

    second = await service.admit(
        session_id=session_id,
        root_run_id=root_run_id,
        request_id=request_ids[3],
        service_id="firecrawl",
        operation="firecrawl.search",
        fingerprint=_fingerprint(3),
        estimated_cost_units=2,
        now_ms=clock.value + 5,
    )
    assert second.state is RunawayAdmissionState.AUTHORIZED
    assert second.permit is not None
    exhausted = await service.get_quarantine(quarantine_id)
    assert exhausted is not None
    assert exhausted.state is RunawayQuarantineState.EXHAUSTED
    assert exhausted.remaining_requests == 0
    assert exhausted.remaining_credits == 0
    assert exhausted.active_concurrency == 1
    assert await service.settle_permit(second.permit.permit_id, now_ms=clock.value + 6)

    blocked = await service.admit(
        session_id=session_id,
        root_run_id=root_run_id,
        request_id=request_ids[4],
        service_id="firecrawl",
        operation="firecrawl.search",
        fingerprint=_fingerprint(4),
        estimated_cost_units=1,
        now_ms=clock.value + 7,
    )
    assert blocked.state is RunawayAdmissionState.QUARANTINED
    assert blocked.reason_code == "authorization_exhausted"
    connection.close()


@pytest.mark.asyncio
async def test_separate_connections_compete_for_one_burst_concurrency_slot(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "runaway-concurrency.db"
    clock = ManualClock()
    connection = open_migrated_database(database_path)
    session_id, root_run_id, request_ids = _seed_owner(connection, "concurrent")
    service = _service(connection, clock)
    quarantine_id = await _open_quarantine(
        service,
        session_id,
        root_run_id,
        request_ids,
        clock,
    )
    opened = await service.get_quarantine(quarantine_id)
    assert opened is not None
    await service.authorize(
        quarantine_id=quarantine_id,
        expected_generation=opened.generation,
        action_token=opened.action_token,
        actor_id="admin-session",
        reason="One-slot concurrency test",
        duration_ms=10_000,
        maximum_requests=2,
        maximum_credits=2,
        maximum_concurrency=1,
        operations=("firecrawl.search",),
        now_ms=clock.value + 2,
    )
    connection.close()

    barrier = threading.Barrier(2)

    def compete(index: int) -> RunawayAdmissionState:
        local = open_migrated_database(database_path)

        def permit_id() -> str:
            barrier.wait(timeout=5)
            return f"permit-competing-{index}"

        contender = SqliteRunawayQuarantineService(
            local,
            action_token_key=b"a" * 32,
            now_ms=clock,
            permit_id_factory=permit_id,
        )
        try:
            admission = asyncio.run(
                contender.admit(
                    session_id=session_id,
                    root_run_id=root_run_id,
                    request_id=request_ids[index + 2],
                    service_id="firecrawl",
                    operation="firecrawl.search",
                    fingerprint=_fingerprint(index + 2),
                    estimated_cost_units=1,
                    now_ms=clock.value + 3,
                )
            )
            return admission.state
        finally:
            local.close()

    with ThreadPoolExecutor(max_workers=2) as executor:
        states = tuple(executor.map(compete, (0, 1)))
    assert sorted(states) == sorted(
        (RunawayAdmissionState.AUTHORIZED, RunawayAdmissionState.CAPACITY)
    )

    verified = open_migrated_database(database_path)
    try:
        row = verified.execute(
            "SELECT remaining_requests, remaining_credits, active_concurrency "
            "FROM runaway_quarantines WHERE quarantine_id = ?",
            (quarantine_id,),
        ).fetchone()
        assert row is not None
        assert tuple(row) == (1, 1, 1)
        assert (
            verified.execute(
                "SELECT COUNT(*) FROM runaway_burst_permits WHERE state = 'ACTIVE'"
            ).fetchone()[0]
            == 1
        )
    finally:
        verified.close()


@pytest.mark.asyncio
async def test_expiry_and_denial_block_until_a_fresh_explicit_fenced_decision() -> None:
    clock = ManualClock()
    connection = open_migrated_database(":memory:")
    session_id, root_run_id, request_ids = _seed_owner(connection, "expiry")
    service = _service(connection, clock)
    quarantine_id = await _open_quarantine(
        service,
        session_id,
        root_run_id,
        request_ids,
        clock,
    )
    opened = await service.get_quarantine(quarantine_id)
    assert opened is not None
    await service.authorize(
        quarantine_id=quarantine_id,
        expected_generation=opened.generation,
        action_token=opened.action_token,
        actor_id="admin-session",
        reason="Short bounded authorization",
        duration_ms=100,
        maximum_requests=2,
        maximum_credits=2,
        maximum_concurrency=1,
        operations=("firecrawl.search",),
        now_ms=clock.value + 2,
    )
    stale_token = opened.action_token
    clock.value += 200
    expired = await service.get_quarantine(quarantine_id)
    assert expired is not None
    assert expired.state is RunawayQuarantineState.EXPIRED
    with pytest.raises(RunawayQuarantineConflict):
        await service.authorize(
            quarantine_id=quarantine_id,
            expected_generation=opened.generation,
            action_token=stale_token,
            actor_id="admin-session",
            reason="Stale replay",
            duration_ms=100,
            maximum_requests=1,
            maximum_credits=1,
            maximum_concurrency=1,
            operations=("firecrawl.search",),
            now_ms=clock.value,
        )
    denied = await service.deny(
        quarantine_id=quarantine_id,
        expected_generation=expired.generation,
        action_token=expired.action_token,
        actor_id="admin-session",
        reason="Operator denied continued access",
        now_ms=clock.value + 1,
    )
    assert denied.state is RunawayQuarantineState.DENIED
    blocked = await service.admit(
        session_id=session_id,
        root_run_id=root_run_id,
        request_id=request_ids[2],
        service_id="firecrawl",
        operation="firecrawl.search",
        fingerprint=_fingerprint(8),
        estimated_cost_units=1,
        now_ms=clock.value + 50_000,
    )
    assert blocked.state is RunawayAdmissionState.QUARANTINED
    assert blocked.reason_code == "authorization_denied"
    connection.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "operations",
    (("firecrawl.unregistered",), ("openrouter.chat",)),
)
async def test_authorization_rejects_nonregistered_typed_operations(
    operations: tuple[str, ...],
) -> None:
    clock = ManualClock()
    connection = open_migrated_database(":memory:")
    session_id, root_run_id, request_ids = _seed_owner(connection, "typed")
    service = _service(connection, clock)
    quarantine_id = await _open_quarantine(
        service,
        session_id,
        root_run_id,
        request_ids,
        clock,
    )
    opened = await service.get_quarantine(quarantine_id)
    assert opened is not None
    with pytest.raises(ValueError, match="code-owned operations"):
        await service.authorize(
            quarantine_id=quarantine_id,
            expected_generation=opened.generation,
            action_token=opened.action_token,
            actor_id="admin-session",
            reason="Invalid typed operation test",
            duration_ms=1_000,
            maximum_requests=1,
            maximum_credits=1,
            maximum_concurrency=1,
            operations=operations,
            now_ms=clock.value + 2,
        )
    unchanged = await service.get_quarantine(quarantine_id)
    assert unchanged is not None
    assert unchanged.state is RunawayQuarantineState.OPEN
    assert unchanged.generation == opened.generation
    connection.close()


@pytest.mark.asyncio
async def test_decision_reason_is_fingerprinted_and_never_reaches_sqlite(tmp_path: Path) -> None:
    database_path = tmp_path / "runaway-reason-canary.db"
    reason_canary = "FC-SECRET-CANARY-do-not-persist-123456789"
    clock = ManualClock()
    connection = open_migrated_database(database_path)
    session_id, root_run_id, request_ids = _seed_owner(connection, "reason")
    service = _service(connection, clock)
    quarantine_id = await _open_quarantine(
        service,
        session_id,
        root_run_id,
        request_ids,
        clock,
    )
    opened = await service.get_quarantine(quarantine_id)
    assert opened is not None
    result = await service.authorize(
        quarantine_id=quarantine_id,
        expected_generation=opened.generation,
        action_token=opened.action_token,
        actor_id="admin-session",
        reason=reason_canary,
        duration_ms=1_000,
        maximum_requests=1,
        maximum_credits=1,
        maximum_concurrency=1,
        operations=("firecrawl.search",),
        now_ms=clock.value + 2,
    )
    assert reason_canary not in repr(result)
    row = connection.execute(
        "SELECT decision_reason_fingerprint, decision_reason_supplied "
        "FROM runaway_quarantines WHERE quarantine_id = ?",
        (quarantine_id,),
    ).fetchone()
    assert row is not None
    assert len(str(row["decision_reason_fingerprint"])) == 64
    assert int(row["decision_reason_supplied"]) == 1
    audit_payloads = tuple(
        str(item[0])
        for item in connection.execute(
            "SELECT payload_json FROM audit_events WHERE event_type LIKE 'runaway.%'"
        ).fetchall()
    )
    assert all(reason_canary not in payload for payload in audit_payloads)
    assert any('"operations":["firecrawl.search"]' in payload for payload in audit_payloads)
    connection.close()

    canary_bytes = reason_canary.encode("utf-8")
    sqlite_files = await asyncio.to_thread(lambda: tuple(tmp_path.glob(f"{database_path.name}*")))
    assert sqlite_files
    sqlite_contents = await asyncio.gather(
        *(asyncio.to_thread(path.read_bytes) for path in sqlite_files)
    )
    assert all(canary_bytes not in content for content in sqlite_contents)


@pytest.mark.asyncio
async def test_restart_orphans_live_permit_without_refund_or_automatic_reenable(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "runaway-orphan.db"
    clock = ManualClock()
    connection = open_migrated_database(database_path)
    session_id, root_run_id, request_ids = _seed_owner(connection, "orphan")
    service = _service(connection, clock)
    quarantine_id = await _open_quarantine(
        service,
        session_id,
        root_run_id,
        request_ids,
        clock,
    )
    opened = await service.get_quarantine(quarantine_id)
    assert opened is not None
    await service.authorize(
        quarantine_id=quarantine_id,
        expected_generation=opened.generation,
        action_token=opened.action_token,
        actor_id="admin-session",
        reason="Crash recovery authority",
        duration_ms=10_000,
        maximum_requests=2,
        maximum_credits=2,
        maximum_concurrency=1,
        operations=("firecrawl.search",),
        now_ms=clock.value + 2,
    )
    admitted = await service.admit(
        session_id=session_id,
        root_run_id=root_run_id,
        request_id=request_ids[2],
        service_id="firecrawl",
        operation="firecrawl.search",
        fingerprint=_fingerprint(2),
        estimated_cost_units=1,
        now_ms=clock.value + 3,
    )
    assert admitted.state is RunawayAdmissionState.AUTHORIZED
    connection.close()

    restarted_connection = open_migrated_database(database_path)
    recover_startup(restarted_connection, now_ms=clock.value + 4)
    restarted = SqliteRunawayQuarantineService(
        restarted_connection,
        action_token_key=b"a" * 32,
        now_ms=clock,
    )
    assert await restarted.recover_orphaned_permits(now_ms=clock.value + 4) == 1
    recovered = await restarted.get_quarantine(quarantine_id)
    assert recovered is not None
    assert recovered.state is RunawayQuarantineState.EXPIRED
    assert recovered.remaining_requests == 1
    assert recovered.remaining_credits == 1
    assert recovered.active_concurrency == 0
    permit = restarted_connection.execute(
        "SELECT state, actual_cost_state FROM runaway_burst_permits"
    ).fetchone()
    assert permit is not None
    assert tuple(permit) == ("ORPHANED", "UNKNOWN")
    blocked = await restarted.admit(
        session_id=session_id,
        root_run_id=root_run_id,
        request_id=request_ids[3],
        service_id="firecrawl",
        operation="firecrawl.search",
        fingerprint=_fingerprint(3),
        estimated_cost_units=1,
        now_ms=clock.value + 5,
    )
    assert blocked.state is RunawayAdmissionState.QUARANTINED
    assert blocked.reason_code == "authorization_expired"
    restarted_connection.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("invocation_state", "actual_cost_units", "expected_state", "expected_remaining"),
    (
        ("SUCCEEDED", 4, RunawayQuarantineState.AUTHORIZED, 1),
        ("UNKNOWN", None, RunawayQuarantineState.EXHAUSTED, 0),
    ),
)
async def test_settlement_conservatively_reconciles_overrun_and_unknown_cost(
    invocation_state: str,
    actual_cost_units: int | None,
    expected_state: RunawayQuarantineState,
    expected_remaining: int,
) -> None:
    clock = ManualClock()
    connection = open_migrated_database(":memory:")
    session_id, root_run_id, request_ids = _seed_owner(connection, f"cost-{invocation_state}")
    service = _service(connection, clock)
    quarantine_id = await _open_quarantine(
        service,
        session_id,
        root_run_id,
        request_ids,
        clock,
    )
    opened = await service.get_quarantine(quarantine_id)
    assert opened is not None
    await service.authorize(
        quarantine_id=quarantine_id,
        expected_generation=opened.generation,
        action_token=opened.action_token,
        actor_id="admin-session",
        reason="Cost reconciliation test",
        duration_ms=10_000,
        maximum_requests=2,
        maximum_credits=5,
        maximum_concurrency=1,
        operations=("firecrawl.search",),
        now_ms=clock.value + 2,
    )
    admission = await service.admit(
        session_id=session_id,
        root_run_id=root_run_id,
        request_id=request_ids[2],
        service_id="firecrawl",
        operation="firecrawl.search",
        fingerprint=_fingerprint(2),
        estimated_cost_units=1,
        now_ms=clock.value + 3,
    )
    assert admission.permit is not None
    connection.execute(
        "UPDATE invocations SET state = ?, actual_cost_units = ? WHERE request_id = ?",
        (invocation_state, actual_cost_units, request_ids[2]),
    )
    assert await service.settle_permit(admission.permit.permit_id, now_ms=clock.value + 4)
    reconciled = await service.get_quarantine(quarantine_id)
    assert reconciled is not None
    assert reconciled.state is expected_state
    assert reconciled.remaining_credits == expected_remaining
    connection.close()


@pytest.mark.asyncio
async def test_stale_expiry_row_cannot_revoke_a_new_authorization(tmp_path: Path) -> None:
    database_path = tmp_path / "runaway-generation-race.db"
    clock = ManualClock()
    first_connection = open_migrated_database(database_path)
    session_id, root_run_id, request_ids = _seed_owner(first_connection, "generation")
    first = _service(first_connection, clock)
    quarantine_id = await _open_quarantine(
        first,
        session_id,
        root_run_id,
        request_ids,
        clock,
    )
    opened = await first.get_quarantine(quarantine_id)
    assert opened is not None
    await first.authorize(
        quarantine_id=quarantine_id,
        expected_generation=opened.generation,
        action_token=opened.action_token,
        actor_id="admin-session",
        reason="Short grant",
        duration_ms=10,
        maximum_requests=2,
        maximum_credits=2,
        maximum_concurrency=1,
        operations=("firecrawl.search",),
        now_ms=clock.value + 2,
    )
    stale = first._load_quarantine_row(quarantine_id)
    assert stale is not None

    second_connection = open_migrated_database(database_path)
    second = SqliteRunawayQuarantineService(
        second_connection,
        action_token_key=b"a" * 32,
        now_ms=clock,
    )
    short = await second.get_quarantine(quarantine_id)
    assert short is not None
    await second.authorize(
        quarantine_id=quarantine_id,
        expected_generation=short.generation,
        action_token=short.action_token,
        actor_id="admin-session",
        reason="Fresh grant",
        duration_ms=10_000,
        maximum_requests=2,
        maximum_credits=2,
        maximum_concurrency=1,
        operations=("firecrawl.search",),
        now_ms=clock.value + 13,
    )
    with transaction(first_connection, "IMMEDIATE"):
        assert not first._expire_locked(stale, clock.value + 13)
    current = await first.get_quarantine(quarantine_id)
    assert current is not None
    assert current.state is RunawayQuarantineState.AUTHORIZED
    assert current.generation == short.generation + 1
    second_connection.close()
    first_connection.close()


@pytest.mark.asyncio
async def test_varied_requests_open_aggregate_quarantine() -> None:
    clock = ManualClock()
    connection = open_migrated_database(":memory:")
    session_id, root_run_id, request_ids = _seed_owner(connection, "aggregate")
    service = _service(connection, clock, repeated=3, aggregate=3)
    decisions = []
    for index in range(3):
        decisions.append(
            await service.admit(
                session_id=session_id,
                root_run_id=root_run_id,
                request_id=request_ids[index],
                service_id="firecrawl",
                operation="firecrawl.search",
                fingerprint=_fingerprint(index + 1),
                estimated_cost_units=1,
                now_ms=clock.value + index,
            )
        )
    assert [item.state for item in decisions] == [
        RunawayAdmissionState.ALLOW,
        RunawayAdmissionState.ALLOW,
        RunawayAdmissionState.QUARANTINED,
    ]
    assert decisions[-1].trigger is RunawayTrigger.AGGREGATE_BURST
    connection.close()


def test_migration_11_is_append_only_and_crash_rolls_back(tmp_path: Path) -> None:
    database_path = tmp_path / "migration-11.db"
    connection = connect_database(database_path)
    try:
        assert apply_migrations(connection, migrations=MIGRATIONS[:10]) == 10
        broken = Migration(
            version=11,
            name=MIGRATIONS[10].name,
            sql=(
                RUNAWAY_QUARANTINE_BURST_AUTHORITY
                + "\nINSERT INTO gatehouse_missing_table(value) VALUES (1);"
            ),
        )
        with pytest.raises(sqlite3.OperationalError):
            apply_migrations(connection, migrations=(*MIGRATIONS[:10], broken))
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 10
        assert connection.execute("SELECT COUNT(*) FROM schema_migrations").fetchone()[0] == 10
        assert (
            connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'runaway_quarantines'"
            ).fetchone()
            is None
        )
        assert apply_migrations(connection) == 12
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
    finally:
        connection.close()
