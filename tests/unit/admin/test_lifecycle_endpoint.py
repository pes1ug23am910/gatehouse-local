from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from pathlib import Path
from typing import cast

import pytest
from httpx import ASGITransport, AsyncClient

from gatehouse.admin import AdminAuthManager, AdminBackend
from gatehouse.api.admin import ADMIN_COOKIE_NAME, create_admin_app
from gatehouse.database import open_migrated_database
from gatehouse.database.lifecycle_diagnostics import (
    LifecycleJournal,
    LifecyclePhase,
    LifecycleRecord,
)


@pytest.fixture
def connection(tmp_path: Path) -> Iterator[sqlite3.Connection]:
    database = open_migrated_database(tmp_path / "lifecycle.sqlite3")
    try:
        yield database
    finally:
        database.close()


def _client(journal: LifecycleJournal | None) -> tuple[AsyncClient, AdminAuthManager]:
    auth = AdminAuthManager(verifier_key=b"k" * 32, now_ms=lambda: 1_000)
    app = create_admin_app(
        auth=auth,
        backend=cast(AdminBackend, object()),
        now_ms=lambda: 1_000,
        allowed_hosts=("testserver",),
        lifecycle_journal=journal,
    )
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver"), auth


async def _login(client: AsyncClient, auth: AdminAuthManager) -> str:
    login = await auth.exchange_login_code((await auth.mint_login_code()).code)
    client.cookies.set(ADMIN_COOKIE_NAME, login.cookie)
    return login.cookie


@pytest.mark.parametrize("authenticated", (False, True))
async def test_lifecycle_route_authenticates_before_reading_and_projects_only_fixed_fields(
    connection: sqlite3.Connection,
    monkeypatch: pytest.MonkeyPatch,
    authenticated: bool,
) -> None:
    journal = LifecycleJournal(connection, now_ms=lambda: 1_000, run_id="a" * 32)
    assert journal.record(LifecyclePhase.RECOVERING)
    assert journal.record(LifecyclePhase.READY)
    original_recent = journal.recent
    reads: list[int] = []

    def recent(*, limit: int) -> tuple[LifecycleRecord, ...]:
        reads.append(limit)
        return original_recent(limit=limit)

    monkeypatch.setattr(journal, "recent", recent)
    client, auth = _client(journal)
    async with client:
        cookie = await _login(client, auth) if authenticated else ""
        response = await client.get("/v1/admin/lifecycle?limit=1")
    assert response.status_code == (200 if authenticated else 401)
    assert reads == ([1] if authenticated else [])
    assert response.headers["cache-control"] == "no-store"
    if authenticated:
        assert cookie not in response.text
        assert response.json() == {
            "current_run_id": "a" * 32,
            "dropped_count_saturating_at_256": 0,
            "records": [
                {
                    "sequence": 2,
                    "run_id": "a" * 32,
                    "occurred_at_ms": 1_000,
                    "phase": "READY",
                }
            ],
        }


@pytest.mark.parametrize("limit", ("0", "257", "synthetic-private-query-value"))
async def test_lifecycle_route_rejects_out_of_bound_queries_without_reflection(
    connection: sqlite3.Connection,
    limit: str,
) -> None:
    journal = LifecycleJournal(connection, now_ms=lambda: 1_000)
    client, auth = _client(journal)
    async with client:
        await _login(client, auth)
        response = await client.get("/v1/admin/lifecycle", params={"limit": limit})
    assert response.status_code == 422
    assert "synthetic-private-query-value" not in response.text
    assert response.json()["error"]["code"] == "schema_validation_failed"


@pytest.mark.parametrize("unavailable", ("absent", "closed"))
async def test_lifecycle_route_reports_fixed_unavailability(
    connection: sqlite3.Connection,
    unavailable: str,
) -> None:
    journal = LifecycleJournal(connection, now_ms=lambda: 1_000)
    if unavailable == "closed":
        connection.close()
    client, auth = _client(None if unavailable == "absent" else journal)
    async with client:
        await _login(client, auth)
        response = await client.get("/v1/admin/lifecycle")
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "daemon_degraded"
    assert "sqlite" not in response.text.lower()
    assert response.headers["cache-control"] == "no-store"
