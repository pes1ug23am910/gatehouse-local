from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from pathlib import Path
from typing import cast

import pytest
from httpx import ASGITransport, AsyncClient

from gatehouse.admin import AdminAuthManager, AdminBackend
from gatehouse.admin.audit_view import AuditViewUnavailable, SqliteAuditView
from gatehouse.api.admin import ADMIN_COOKIE_NAME, create_admin_app
from gatehouse.database.connection import connect_database, transaction
from gatehouse.database.migrations import apply_migrations


@pytest.fixture
def connection(tmp_path: Path) -> Iterator[sqlite3.Connection]:
    value = connect_database(tmp_path / "audit.sqlite3")
    try:
        apply_migrations(value)
        yield value
    finally:
        value.close()


def insert_event(
    connection: sqlite3.Connection,
    *,
    number: int = 1,
    event_type: str = "account.added",
    severity: str = "INFO",
) -> None:
    connection.execute(
        """INSERT INTO audit_events(event_id, occurred_at_ms, event_type, severity,
                                    service_id, operation, preserve, payload_json)
           VALUES (?, ?, ?, ?, ?, ?, 1, ?)""",
        (
            f"synthetic-secret-event-{number}",
            number,
            event_type,
            severity,
            "synthetic-secret-service",
            "synthetic-secret-operation",
            '{"secret":"synthetic-secret-payload"}',
        ),
    )
    connection.commit()


def test_view_exports_only_fixed_event_labels_and_safe_metadata(
    connection: sqlite3.Connection,
) -> None:
    insert_event(connection)
    text = SqliteAuditView(connection).markdown(limit=100)
    assert "account.added" in text
    assert "INFO" in text
    assert "synthetic-secret" not in text
    assert "1970-01-01T00:00:00.001Z" in text
    assert "| Yes |" in text
    assert "1 event(s)" in text


@pytest.mark.parametrize(
    "value",
    (
        "<script>alert(1)</script>",
        "[link](https://invalid)",
        "credential.provider_validated\nSECRET",
        "x" * 100_000,
    ),
    ids=("html", "markdown", "newline", "oversized"),
)
def test_unrecognized_values_are_not_rendered(connection: sqlite3.Connection, value: str) -> None:
    insert_event(connection, event_type=value, severity=value)
    text = SqliteAuditView(connection).markdown(limit=100)
    assert value not in text
    assert "| Other | UNKNOWN |" in text
    assert len(text.encode()) <= 65_536


def test_newest_first_has_stable_tie_order_and_bounded_rows(connection: sqlite3.Connection) -> None:
    for number in range(1, 203):
        insert_event(connection, number=number)
    view = SqliteAuditView(connection)
    text = view.markdown(limit=200)
    assert "200 event(s)" in text
    assert "Older events are available in the database" in text
    assert "00:00:00.202Z" in text and "00:00:00.003Z" in text
    assert "00:00:00.002Z" not in text
    assert text.index("00:00:00.202Z") < text.index("00:00:00.003Z")
    assert len(text.encode()) <= 65_536


def test_equal_timestamps_use_newest_inserted_row_first(connection: sqlite3.Connection) -> None:
    insert_event(connection, number=1, event_type="account.added")
    insert_event(connection, number=2, event_type="account.disabled")
    connection.execute("UPDATE audit_events SET occurred_at_ms = 1000")
    connection.commit()
    text = SqliteAuditView(connection).markdown(limit=2)
    assert text.index("account.disabled") < text.index("account.added")


def test_view_query_uses_time_index_without_sort_or_payload_reads(
    connection: sqlite3.Connection,
) -> None:
    insert_event(connection)
    reads: list[str] = []
    statements: list[str] = []

    def authorize(
        action: int, _table: str | None, column: str | None, _db: str | None, _trigger: str | None
    ) -> int:
        if action == sqlite3.SQLITE_READ:
            assert column is not None
            reads.append(column)
        return sqlite3.SQLITE_OK

    connection.set_authorizer(authorize)
    connection.set_trace_callback(statements.append)
    SqliteAuditView(connection).markdown(limit=1)
    connection.set_authorizer(None)
    connection.set_trace_callback(None)
    assert not {"payload_json", "event_id", "service_id", "operation", "session_id"} & set(reads)
    query = next(value for value in statements if value.lstrip().startswith("SELECT"))
    plan = connection.execute("EXPLAIN QUERY PLAN " + query).fetchall()
    assert any("idx_audit_events_time" in str(row[3]) for row in plan)
    assert not any("TEMP B-TREE" in str(row[3]) for row in plan)


@pytest.mark.parametrize("limit", (0, 201, -1, True, 1.0, "1", None))
def test_invalid_limit_refuses_before_sql(connection: sqlite3.Connection, limit: object) -> None:
    statements: list[str] = []
    connection.set_trace_callback(statements.append)
    with pytest.raises(ValueError, match="audit view limit is invalid"):
        SqliteAuditView(connection).markdown(limit=cast(int, limit))
    assert not statements


def test_empty_view_and_existing_transaction_do_not_mutate(connection: sqlite3.Connection) -> None:
    assert "0 event(s)" in SqliteAuditView(connection).markdown(limit=1)
    with transaction(connection, "IMMEDIATE"):
        with pytest.raises(AuditViewUnavailable, match="audit view is unavailable"):
            SqliteAuditView(connection).markdown(limit=1)
        assert connection.in_transaction


def test_database_failure_has_fixed_message_without_context(connection: sqlite3.Connection) -> None:
    connection.close()
    with pytest.raises(AuditViewUnavailable) as failure:
        SqliteAuditView(connection).markdown(limit=1)
    assert str(failure.value) == "audit view is unavailable"
    assert failure.value.__context__ is None


@pytest.mark.parametrize("authenticated", (True, False))
async def test_markdown_download_requires_admin_cookie(
    connection: sqlite3.Connection, authenticated: bool
) -> None:
    insert_event(connection)
    auth = AdminAuthManager(verifier_key=b"k" * 32, now_ms=lambda: 1_000)
    app = create_admin_app(
        auth=auth,
        backend=cast(AdminBackend, object()),
        now_ms=lambda: 1_000,
        allowed_hosts=("testserver",),
        audit_view=SqliteAuditView(connection),
    )
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        if authenticated:
            login = await auth.exchange_login_code((await auth.mint_login_code()).code)
            client.cookies.set(ADMIN_COOKIE_NAME, login.cookie)
        response = await client.get("/v1/admin/audit.md?limit=1")
    assert response.status_code == (200 if authenticated else 401)
    assert "synthetic-secret" not in response.text
    if authenticated:
        assert response.headers["content-type"].startswith("text/markdown")
        assert (
            response.headers["content-disposition"] == 'attachment; filename="gatehouse-audit.md"'
        )
        assert response.headers["cache-control"] == "no-store"
        assert "account.added" in response.text
