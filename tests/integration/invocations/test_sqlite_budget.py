from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from gatehouse.core.ids import (
    ClientId,
    RequestId,
    RootRunId,
    SessionId,
    WorkspaceId,
)
from gatehouse.database import open_migrated_database
from gatehouse.invocations import (
    BudgetUnavailableError,
    InvocationRequest,
    InvocationSession,
    SqliteBudgetGateway,
)
from gatehouse.policy import ClientClass

_A = "01K32J0B80E4G7P6H9Q2R5T8VW"
_B = "01K32J0B80F5H8Q7J0R3S6V9WX"
_C = "01K32J0B80G6J9R8K1S4T7W0XY"
_D = "01K32J0B80H7K0S9M2T5V8X1YZ"


def _seed(connection: sqlite3.Connection) -> tuple[InvocationSession, InvocationRequest]:
    client_id = ClientId(f"client_{_A}")
    workspace_id = WorkspaceId(f"ws_{_A}")
    session_id = SessionId(f"ses_{_A}")
    root_run_id = RootRunId(f"run_{_A}")
    request_id = RequestId(f"req_{_A}")
    connection.execute(
        """
        INSERT INTO clients(
            client_id, display_name, kind, policy_profile, created_at_ms, updated_at_ms
        ) VALUES (?, 'Client', 'interactive', 'default', 1, 1)
        """,
        (str(client_id),),
    )
    connection.execute(
        """
        INSERT INTO workspaces(
            workspace_id, display_name, canonical_root, created_at_ms, updated_at_ms
        ) VALUES (?, 'Workspace', 'E:\\Workspace', 1, 1)
        """,
        (str(workspace_id),),
    )
    connection.execute(
        """
        INSERT INTO sessions(
            session_id, client_id, workspace_id, bootstrap_verifier,
            bootstrap_version, token_epoch, state, identity_assurance,
            policy_version, created_at_ms, reconnect_until_ms,
            absolute_expires_at_ms, budget_json
        ) VALUES (?, ?, ?, ?, 1, 1, 'ACTIVE', 'LAUNCHER_SESSION',
                  'policy-v1', 1, 100000, 100000, '{"credits":100}')
        """,
        (str(session_id), str(client_id), str(workspace_id), b"x" * 32),
    )
    connection.execute(
        """
        INSERT INTO root_runs(
            root_run_id, session_id, state, started_at_ms, budget_json, consumed_json
        ) VALUES (?, ?, 'ACTIVE', 1, '{"credits":100}', '{}')
        """,
        (str(root_run_id), str(session_id)),
    )
    connection.execute(
        """
        INSERT INTO invocations(
            request_id, session_id, root_run_id, service_id, operation,
            request_fingerprint, fingerprint_version, canonicalization_version,
            state, priority_class, request_size_bytes, queue_deadline_ms,
            received_at_ms
        ) VALUES (?, ?, ?, 'firecrawl', 'firecrawl.search', ?, 1, 1,
                  'DEDUPLICATION', 'NORMAL_AGENT', 2, 100000, 1)
        """,
        (str(request_id), str(session_id), str(root_run_id), b"f" * 32),
    )
    session = InvocationSession(
        session_id=session_id,
        client_id=client_id,
        root_run_id=root_run_id,
        workspace_id=workspace_id,
        client_class=ClientClass.INTERACTIVE,
        allowed_capabilities=frozenset({"firecrawl.search"}),
        pool_bindings={"firecrawl": "interactive-default"},
        request_count_remaining=10,
        credit_budget_remaining_units=100,
    )
    request = InvocationRequest(
        request_id=request_id,
        access_token="memory-only-token",
        root_run_id=root_run_id,
        service_id="firecrawl",
        operation="firecrawl.search",
        input_payload={"query": "jobs"},
        purpose="career_discovery",
        data_classifications=frozenset({"public_web_query"}),
        queue_deadline_ms=100000,
    )
    return session, request


def _add_request(
    connection: sqlite3.Connection,
    *,
    request_id: RequestId,
    session: InvocationSession,
) -> InvocationRequest:
    connection.execute(
        """
        INSERT INTO invocations(
            request_id, session_id, root_run_id, service_id, operation,
            request_fingerprint, fingerprint_version, canonicalization_version,
            state, priority_class, request_size_bytes, queue_deadline_ms,
            received_at_ms
        ) VALUES (?, ?, ?, 'firecrawl', 'firecrawl.search', ?, 1, 1,
                  'DEDUPLICATION', 'NORMAL_AGENT', 2, 100000, 1)
        """,
        (str(request_id), str(session.session_id), str(session.root_run_id), b"g" * 32),
    )
    return InvocationRequest(
        request_id=request_id,
        access_token="memory-only-token",
        root_run_id=session.root_run_id,
        service_id="firecrawl",
        operation="firecrawl.search",
        input_payload={"query": "jobs"},
        purpose="career_discovery",
        data_classifications=frozenset({"public_web_query"}),
        queue_deadline_ms=100000,
    )


@pytest.mark.asyncio
async def test_known_settlement_replaces_estimate_and_survives_reopen(
    tmp_path: Path,
) -> None:
    path = tmp_path / "budget.db"
    connection = open_migrated_database(path)
    session, first_request = _seed(connection)
    gateway = SqliteBudgetGateway(connection, now_ms=lambda: 10)

    first = await gateway.reserve(
        request=first_request,
        session=session,
        amount_units=60,
        unit="credits",
    )
    second_request = _add_request(
        connection,
        request_id=RequestId(f"req_{_B}"),
        session=session,
    )
    with pytest.raises(BudgetUnavailableError):
        await gateway.reserve(
            request=second_request,
            session=session,
            amount_units=50,
            unit="credits",
        )

    await gateway.reconcile(first, actual_units=40, outcome_known=True)
    second = await gateway.reserve(
        request=second_request,
        session=session,
        amount_units=50,
        unit="credits",
    )
    assert await gateway.remaining(session.root_run_id, "credits") == 10
    connection.close()

    reopened = open_migrated_database(path)
    try:
        restarted = SqliteBudgetGateway(reopened, now_ms=lambda: 20)
        assert await restarted.remaining(session.root_run_id, "credits") == 10
        await restarted.reconcile(second, actual_units=30, outcome_known=True)
        assert await restarted.remaining(session.root_run_id, "credits") == 30
        consumed = reopened.execute(
            "SELECT consumed_json FROM root_runs WHERE root_run_id = ?",
            (str(session.root_run_id),),
        ).fetchone()[0]
        assert consumed == '{"credits":70}'
    finally:
        reopened.close()


@pytest.mark.asyncio
async def test_ambiguous_hold_is_durable_and_can_later_settle(
    tmp_path: Path,
) -> None:
    path = tmp_path / "ambiguous.db"
    connection = open_migrated_database(path)
    session, request = _seed(connection)
    gateway = SqliteBudgetGateway(connection, now_ms=lambda: 10)
    hold = await gateway.reserve(
        request=request,
        session=session,
        amount_units=80,
        unit="credits",
    )
    await gateway.reconcile(hold, actual_units=None, outcome_known=False)
    connection.close()

    reopened = open_migrated_database(path)
    try:
        restarted = SqliteBudgetGateway(reopened, now_ms=lambda: 20)
        assert await restarted.remaining(session.root_run_id, "credits") == 20
        await restarted.reconcile(hold, actual_units=25, outcome_known=True)
        await restarted.reconcile(hold, actual_units=25, outcome_known=True)
        assert await restarted.remaining(session.root_run_id, "credits") == 75
        row = reopened.execute("SELECT state, actual_units FROM budget_reservations").fetchone()
        assert tuple(row) == ("RECONCILED", 25)
    finally:
        reopened.close()


@pytest.mark.asyncio
async def test_only_one_competing_reservation_fits(tmp_path: Path) -> None:
    connection = open_migrated_database(tmp_path / "winner.db")
    try:
        session, first_request = _seed(connection)
        second_request = _add_request(
            connection,
            request_id=RequestId(f"req_{_C}"),
            session=session,
        )
        third_request = _add_request(
            connection,
            request_id=RequestId(f"req_{_D}"),
            session=session,
        )
        gateway = SqliteBudgetGateway(connection, now_ms=lambda: 10)
        first = await gateway.reserve(
            request=first_request,
            session=session,
            amount_units=10,
            unit="credits",
        )
        await gateway.reconcile(first, actual_units=10, outcome_known=True)

        winners = 0
        for request in (second_request, third_request):
            try:
                await gateway.reserve(
                    request=request,
                    session=session,
                    amount_units=60,
                    unit="credits",
                )
            except BudgetUnavailableError:
                continue
            winners += 1
        assert winners == 1
        assert await gateway.remaining(session.root_run_id, "credits") == 30
    finally:
        connection.close()
