from __future__ import annotations

import asyncio
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from threading import Barrier

import pytest

from gatehouse.admin import (
    ApprovalDecision,
    ApprovalDecisionConflict,
    SqliteApprovalAdminService,
)
from gatehouse.core.ids import ClientId, RequestId, RootRunId, SessionId, WorkspaceId
from gatehouse.core.states import ApprovalState
from gatehouse.credentials import SecretScanner
from gatehouse.database import connect_database, open_migrated_database
from gatehouse.fingerprint import RequestFingerprint
from gatehouse.invocations import ApprovalResolution, InvocationRequest, InvocationSession
from gatehouse.policy import ClientClass, Decision, PolicyResult

_A = "0" * 26
_B = "1" * 26
_C = "2" * 26
_ACTION_KEY = b"approval-action-key-for-tests-32b"


def _seed(connection: sqlite3.Connection, *, canary: str | None = None) -> None:
    execute = connection.execute
    execute(
        """
        INSERT INTO clients(
            client_id, display_name, kind, policy_profile, created_at_ms, updated_at_ms
        ) VALUES (?, 'Interactive client', 'interactive', 'default', 0, 0)
        """,
        (f"client_{_A}",),
    )
    execute(
        """
        INSERT INTO workspaces(
            workspace_id, display_name, canonical_root, created_at_ms, updated_at_ms
        ) VALUES (?, 'Workspace', 'E:\\Workspace', 0, 0)
        """,
        (f"ws_{_A}",),
    )
    for suffix in (_A, _B):
        execute(
            """
            INSERT INTO sessions(
                session_id, client_id, workspace_id, bootstrap_verifier,
                bootstrap_version, token_epoch, state, identity_assurance,
                policy_version, created_at_ms, reconnect_until_ms,
                absolute_expires_at_ms
            ) VALUES (?, ?, ?, X'01', 1, 0, 'ACTIVE', 'TEST', 'policy-v1',
                      0, 100000, 100000)
            """,
            (f"ses_{suffix}", f"client_{_A}", f"ws_{_A}"),
        )
        execute(
            """
            INSERT INTO root_runs(root_run_id, session_id, state, started_at_ms)
            VALUES (?, ?, 'ACTIVE', 0)
            """,
            (f"run_{suffix}", f"ses_{suffix}"),
        )
    execute(
        """
        INSERT INTO principals(
            principal_id, service_id, alias, created_at_ms, updated_at_ms
        ) VALUES ('principal', 'firecrawl', 'primary', 0, 0)
        """
    )
    execute(
        """
        INSERT INTO quota_scopes(
            quota_scope_id, principal_id, alias, state, unit,
            last_known_remaining_units, configured_floor_units
        ) VALUES ('quota', 'principal', 'team', 'HEALTHY', 'credits', 100, 0)
        """
    )
    for pool_id, alias in (("pool-default", "default"), ("pool-other", "other")):
        execute(
            """
            INSERT INTO pools(pool_id, service_id, alias, state, selection_strategy)
            VALUES (?, 'firecrawl', ?, 'ACTIVE', 'pinned')
            """,
            (pool_id, alias),
        )
        execute(
            """
            INSERT INTO pool_members(pool_id, quota_scope_id)
            VALUES (?, 'quota')
            """,
            (pool_id,),
        )
    execute(
        """
        INSERT INTO credentials(
            credential_id, principal_id, quota_scope_id, alias,
            secret_backend, secret_reference, state, created_at_ms
        ) VALUES ('credential', 'principal', 'quota', 'primary', 'test', ?, 'HEALTHY', 0)
        """,
        (canary or "secret-reference",),
    )
    execute(
        """
        INSERT INTO invocations(
            request_id, session_id, root_run_id, service_id, operation,
            request_fingerprint, fingerprint_version, canonicalization_version,
            state, priority_class, request_size_bytes, estimated_cost_units,
            cost_unit, received_at_ms
        ) VALUES (?, ?, ?, 'firecrawl', 'firecrawl.crawl.start', ?, 1, 1,
                  'WAITING_APPROVAL', 'NORMAL_AGENT', 10, 25, 'credits', 0)
        """,
        (f"req_{_A}", f"ses_{_A}", f"run_{_A}", b"a" * 32),
    )


def _request(
    *,
    request_id: str = f"req_{_A}",
    session_suffix: str = _A,
    approval_id: str | None = None,
) -> InvocationRequest:
    return InvocationRequest(
        request_id=RequestId(request_id),
        access_token="access-token",
        root_run_id=RootRunId(f"run_{session_suffix}"),
        service_id="firecrawl",
        operation="firecrawl.crawl.start",
        input_payload={"url": "https://careers.example.com/jobs"},
        purpose="career_discovery",
        data_classifications=frozenset({"public_web_query"}),
        queue_deadline_ms=10_000,
        approval_id=approval_id,
    )


def _session(suffix: str = _A, *, pool: str = "default") -> InvocationSession:
    return InvocationSession(
        session_id=SessionId(f"ses_{suffix}"),
        client_id=ClientId(f"client_{_A}"),
        root_run_id=RootRunId(f"run_{suffix}"),
        workspace_id=WorkspaceId(f"ws_{_A}"),
        client_class=ClientClass.INTERACTIVE,
        allowed_capabilities=frozenset({"firecrawl.crawl.start"}),
        pool_bindings={"firecrawl": pool},
        request_count_remaining=10,
        credit_budget_remaining_units=100,
    )


def _policy() -> PolicyResult:
    return PolicyResult(
        decision=Decision.ASK,
        rule_id="purpose:career_discovery:crawl",
        reason_code="approval_required",
        policy_id="policy",
        policy_version="policy-v1",
    )


async def _resolve(
    service: SqliteApprovalAdminService,
    *,
    request: InvocationRequest | None = None,
    session: InvocationSession | None = None,
    fingerprint: RequestFingerprint | None = None,
    pool_name: str = "default",
    estimated_cost_units: int = 25,
) -> ApprovalResolution:
    return await service.resolve(
        request=request or _request(),
        session=session or _session(),
        fingerprint=fingerprint or RequestFingerprint(b"a" * 32, 1, 1),
        policy=_policy(),
        pool_name=pool_name,
        estimated_cost_units=estimated_cost_units,
    )


@pytest.mark.asyncio
async def test_create_or_return_pending_and_derive_token_across_reopen(tmp_path: Path) -> None:
    database = tmp_path / "gatehouse.db"
    connection = open_migrated_database(database)
    _seed(connection)
    service = SqliteApprovalAdminService(
        connection,
        action_token_key=_ACTION_KEY,
        now_ms=lambda: 100,
        approval_ttl_ms=500,
    )

    first = await _resolve(service)
    second = await _resolve(service)
    assert first.state is ApprovalState.PENDING
    assert first.approval_id == second.approval_id
    assert first.approval_id is not None
    view = await service.get_approval(first.approval_id)
    assert view is not None
    assert view.request_fingerprint == str(RequestFingerprint(b"a" * 32, 1, 1))
    assert view.pool == "default"
    assert view.maximum_estimated_cost == 25
    assert view.maximum_uses == 1
    assert view.expires_at_ms == 600
    token = view.action_token
    connection.close()

    reopened = open_migrated_database(database)
    same = await SqliteApprovalAdminService(
        reopened,
        action_token_key=_ACTION_KEY,
        now_ms=lambda: 100,
    ).get_approval(first.approval_id)
    assert same is not None
    assert same.action_token == token
    reopened.close()
    assert all(
        token.encode("ascii") not in artifact.read_bytes()
        for artifact in database.parent.glob(f"{database.name}*")
        if artifact.is_file()
    )


@pytest.mark.asyncio
async def test_approved_binding_is_consumed_once_and_mismatch_does_not_consume(
    tmp_path: Path,
) -> None:
    connection = open_migrated_database(tmp_path / "gatehouse.db")
    _seed(connection)
    service = SqliteApprovalAdminService(
        connection,
        action_token_key=_ACTION_KEY,
        now_ms=lambda: 100,
    )
    pending = await _resolve(service)
    assert pending.approval_id is not None
    view = await service.get_approval(pending.approval_id)
    assert view is not None
    await service.decide_approval(
        approval=view,
        decision=ApprovalDecision.APPROVE,
        now_ms=110,
    )

    mismatched = await _resolve(
        service,
        request=_request(approval_id=pending.approval_id),
        session=_session(pool="other"),
        pool_name="other",
    )
    assert mismatched.state is ApprovalState.DENIED
    wrong_session = await _resolve(
        service,
        request=_request(session_suffix=_B, approval_id=pending.approval_id),
        session=_session(_B),
    )
    wrong_operation = await _resolve(
        service,
        request=replace(
            _request(approval_id=pending.approval_id),
            operation="firecrawl.crawl.cancel",
        ),
    )
    wrong_digest = await _resolve(
        service,
        request=_request(approval_id=pending.approval_id),
        fingerprint=RequestFingerprint(b"b" * 32, 1, 1),
    )
    wrong_version = await _resolve(
        service,
        request=_request(approval_id=pending.approval_id),
        fingerprint=RequestFingerprint(b"a" * 32, 2, 1),
    )
    excessive_cost = await _resolve(
        service,
        request=_request(approval_id=pending.approval_id),
        estimated_cost_units=26,
    )
    assert {
        wrong_session.state,
        wrong_operation.state,
        wrong_digest.state,
        wrong_version.state,
        excessive_cost.state,
    } == {ApprovalState.DENIED}
    row = connection.execute(
        "SELECT state, uses_consumed FROM approvals WHERE approval_id = ?",
        (pending.approval_id,),
    ).fetchone()
    assert tuple(row) == ("APPROVED", 0)

    consumed = await _resolve(
        service,
        request=_request(approval_id=pending.approval_id),
    )
    replay = await _resolve(
        service,
        request=_request(approval_id=pending.approval_id),
    )
    assert consumed.state is ApprovalState.APPROVED
    assert consumed.approval_id == pending.approval_id
    assert replay.state is ApprovalState.DENIED
    connection.close()


@pytest.mark.asyncio
async def test_expired_pending_approval_cannot_be_decided_or_consumed(tmp_path: Path) -> None:
    clock = [100]
    connection = open_migrated_database(tmp_path / "gatehouse.db")
    _seed(connection)
    service = SqliteApprovalAdminService(
        connection,
        action_token_key=_ACTION_KEY,
        now_ms=lambda: clock[0],
        approval_ttl_ms=50,
    )
    pending = await _resolve(service)
    assert pending.approval_id is not None
    view = await service.get_approval(pending.approval_id)
    assert view is not None

    clock[0] = 150
    with pytest.raises(ApprovalDecisionConflict, match="EXPIRED"):
        await service.decide_approval(
            approval=view,
            decision=ApprovalDecision.APPROVE,
            now_ms=150,
        )
    expired = await _resolve(
        service,
        request=_request(approval_id=pending.approval_id),
    )
    assert expired.state is ApprovalState.EXPIRED
    connection.close()


def test_n_way_file_backed_approve_deny_has_exactly_one_winner(tmp_path: Path) -> None:
    database = tmp_path / "gatehouse.db"
    connection = open_migrated_database(database)
    _seed(connection)
    service = SqliteApprovalAdminService(
        connection,
        action_token_key=_ACTION_KEY,
        now_ms=lambda: 100,
    )
    pending = asyncio.run(_resolve(service))
    assert pending.approval_id is not None
    view = asyncio.run(service.get_approval(pending.approval_id))
    assert view is not None
    connection.close()

    contenders = 16
    barrier = Barrier(contenders)

    def decide(index: int) -> str:
        contender_connection = connect_database(database)
        contender = SqliteApprovalAdminService(
            contender_connection,
            action_token_key=_ACTION_KEY,
            now_ms=lambda: 120,
        )
        barrier.wait(timeout=10)
        try:
            result = asyncio.run(
                contender.decide_approval(
                    approval=view,
                    decision=(
                        ApprovalDecision.APPROVE if index % 2 == 0 else ApprovalDecision.DENY
                    ),
                    now_ms=120,
                )
            )
            return f"won:{result.state}"
        except ApprovalDecisionConflict as exc:
            return f"lost:{exc.current_state}"
        finally:
            contender_connection.close()

    with ThreadPoolExecutor(max_workers=contenders) as executor:
        outcomes = list(executor.map(decide, range(contenders)))
    winners = [outcome for outcome in outcomes if outcome.startswith("won:")]
    assert len(winners) == 1
    winner_state = winners[0].partition(":")[2]
    assert winner_state in {"APPROVED", "DENIED"}
    assert all(outcome == f"lost:{winner_state}" for outcome in outcomes if outcome != winners[0])

    reopened = open_migrated_database(database)
    row = reopened.execute(
        "SELECT state, decided_at_ms, decision_source FROM approvals WHERE approval_id = ?",
        (pending.approval_id,),
    ).fetchone()
    assert tuple(row) == (winner_state, 120, "ADMIN")
    reopened.close()


def test_n_way_file_backed_approval_consumption_is_exactly_once(tmp_path: Path) -> None:
    database = tmp_path / "gatehouse.db"
    connection = open_migrated_database(database)
    _seed(connection)
    service = SqliteApprovalAdminService(
        connection,
        action_token_key=_ACTION_KEY,
        now_ms=lambda: 100,
    )
    pending = asyncio.run(_resolve(service))
    assert pending.approval_id is not None
    view = asyncio.run(service.get_approval(pending.approval_id))
    assert view is not None
    asyncio.run(
        service.decide_approval(
            approval=view,
            decision=ApprovalDecision.APPROVE,
            now_ms=110,
        )
    )
    connection.close()

    contenders = 12
    barrier = Barrier(contenders)

    def consume(_: int) -> ApprovalState:
        contender_connection = connect_database(database)
        contender = SqliteApprovalAdminService(
            contender_connection,
            action_token_key=_ACTION_KEY,
            now_ms=lambda: 120,
        )
        barrier.wait(timeout=10)
        try:
            resolution = asyncio.run(
                _resolve(
                    contender,
                    request=_request(approval_id=pending.approval_id),
                )
            )
            return resolution.state
        finally:
            contender_connection.close()

    with ThreadPoolExecutor(max_workers=contenders) as executor:
        states = list(executor.map(consume, range(contenders)))
    assert states.count(ApprovalState.APPROVED) == 1
    assert states.count(ApprovalState.DENIED) == contenders - 1

    reopened = open_migrated_database(database)
    row = reopened.execute(
        "SELECT state, uses_consumed FROM approvals WHERE approval_id = ?",
        (pending.approval_id,),
    ).fetchone()
    assert tuple(row) == ("CONSUMED", 1)
    reopened.close()


@pytest.mark.asyncio
async def test_admin_read_models_are_bounded_and_secret_free(tmp_path: Path) -> None:
    canary = "fc-admin-read-model-secret-canary-123456"
    connection = open_migrated_database(tmp_path / "gatehouse.db")
    _seed(connection, canary=canary)
    connection.execute("UPDATE system_state SET daemon_state = 'READY', last_started_at_ms = 100")
    connection.execute(
        """
        INSERT INTO quota_reservations(
            reservation_id, request_id, quota_scope_id, amount_units, unit,
            state, created_at_ms, expires_at_ms
        ) VALUES ('reservation', ?, 'quota', 5, 'credits', 'ACTIVE', 100, 1000)
        """,
        (f"req_{_A}",),
    )
    connection.execute(
        """
        INSERT INTO alerts(
            alert_id, severity, category, state, title, summary, created_at_ms
        ) VALUES ('alert', 'HIGH', 'test', 'OPEN', 'Incident', ?, 150)
        """,
        (f"unsafe {canary}",),
    )
    connection.execute(
        """
        INSERT INTO reconciliation_runs(
            reconciliation_id, service_id, mode, state, started_at_ms,
            completed_at_ms
        ) VALUES ('reconciliation', 'firecrawl', 'quick', 'COMPLETED', 100, 150)
        """
    )
    connection.execute(
        """
        INSERT INTO reconciliation_items(
            item_id, reconciliation_id, quota_scope_id, unit, state
        ) VALUES ('item', 'reconciliation', 'quota', 'credits', 'MISMATCH')
        """
    )
    service = SqliteApprovalAdminService(
        connection,
        action_token_key=_ACTION_KEY,
        now_ms=lambda: 200,
        scanner=SecretScanner(canaries=(canary,)),
    )

    status = await service.status()
    assert status.service_state == "READY"
    assert status.uptime_seconds == 0
    assert status.active_sessions == 2
    assert status.high_severity_incidents == 1
    pools = await service.list_pools(limit=10)
    assert {item.pool_id for item in pools} == {"pool-default", "pool-other"}
    assert all(item.eligible_credentials == 1 for item in pools)
    assert all(item.in_flight == 1 for item in pools)
    credentials = await service.list_credentials(limit=10)
    assert len(credentials) == 1
    assert canary not in repr(credentials)
    incidents = await service.list_incidents(limit=10)
    assert len(incidents) == 1
    assert canary not in incidents[0].summary
    summaries = await service.reconciliation()
    assert summaries[0].service == "firecrawl"
    assert summaries[0].unresolved_reservations == 1
    assert summaries[0].ledger_mismatch_count == 1
    connection.close()
