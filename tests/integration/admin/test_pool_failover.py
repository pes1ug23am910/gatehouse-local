from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from pathlib import Path

import pytest

from gatehouse.admin.models import PoolFailoverChangeRequest
from gatehouse.admin.pools import PoolMutationConflict, SqlitePoolAdminService
from gatehouse.database import open_migrated_database


def _seed_pool(connection: sqlite3.Connection, alias: str = "primary") -> None:
    connection.execute(
        """INSERT INTO pools(pool_id, service_id, alias, state, selection_strategy,
                             automatic_use, config_json)
           VALUES (?, 'firecrawl', ?, 'ACTIVE', 'fill_first', 1,
                   '{"minimum_remaining_floor_units":7}')""",
        (f"pool_{alias}", alias),
    )


def _request(
    mutation_id: str = "enable-one", action: str = "enable", reason: str = "operator selection"
) -> PoolFailoverChangeRequest:
    return PoolFailoverChangeRequest.model_validate(
        {"mutation_id": mutation_id, "action": action, "reason": reason}
    )


@pytest.mark.asyncio
async def test_pool_failover_is_explicit_audited_replay_bound_and_reversible(
    tmp_path: Path,
) -> None:
    with closing(open_migrated_database(tmp_path / "pools.db")) as connection:
        _seed_pool(connection)
        service = SqlitePoolAdminService(connection, now_ms=lambda: 10)
        first = await service.change_pool_failover("primary", _request(), "operator")
        assert first.enabled is True
        assert await service.change_pool_failover("primary", _request(), "operator") == first
        assert connection.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0] == 1
        config = json.loads(connection.execute("SELECT config_json FROM pools").fetchone()[0])
        assert config == {
            "automatic_failover_within_pool": True,
            "minimum_remaining_floor_units": 7,
        }
        for request, actor in (
            (_request(reason="another reason"), "operator"),
            (_request(action="disable"), "operator"),
            (_request(), "different operator"),
        ):
            with pytest.raises(PoolMutationConflict):
                await service.change_pool_failover("primary", request, actor)
        _seed_pool(connection, "secondary")
        with pytest.raises(PoolMutationConflict):
            await service.change_pool_failover("secondary", _request(), "operator")
        disabled = await service.change_pool_failover(
            "primary", _request("disable-one", "disable"), "operator"
        )
        assert disabled.enabled is False
        assert connection.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0] == 2
        payloads = " ".join(
            row[0] for row in connection.execute("SELECT payload_json FROM audit_events")
        )
        assert "operator selection" not in payloads
        assert "reason_fingerprint" in payloads
        assert connection.execute("SELECT COUNT(*) FROM credentials").fetchone()[0] == 0


@pytest.mark.asyncio
async def test_pool_failover_audit_failure_rolls_back_every_write(tmp_path: Path) -> None:
    with closing(open_migrated_database(tmp_path / "rollback.db")) as connection:
        _seed_pool(connection)
        connection.execute(
            "CREATE TRIGGER reject_pool_audit BEFORE INSERT ON audit_events "
            "BEGIN SELECT RAISE(ABORT, 'synthetic failure'); END"
        )
        service = SqlitePoolAdminService(connection, now_ms=lambda: 10)
        with pytest.raises(sqlite3.IntegrityError):
            await service.change_pool_failover("primary", _request(), "operator")
        assert (
            connection.execute("SELECT config_json FROM pools").fetchone()[0]
            == '{"minimum_remaining_floor_units":7}'
        )
        assert connection.execute("SELECT COUNT(*) FROM credential_mutations").fetchone()[0] == 0


@pytest.mark.parametrize(
    "column, value",
    [
        ("automatic_use", 0),
        ("state", "DISABLED"),
        ("selection_strategy", "pinned"),
        ("service_id", "other"),
    ],
)
@pytest.mark.asyncio
async def test_pool_failover_cannot_enable_manual_emergency_or_unavailable_pool(
    tmp_path: Path, column: str, value: object
) -> None:
    with closing(open_migrated_database(tmp_path / "excluded.db")) as connection:
        _seed_pool(connection)
        connection.execute(f"UPDATE pools SET {column} = ?", (value,))  # noqa: S608 -- fixed test cases
        with pytest.raises(PoolMutationConflict):
            await SqlitePoolAdminService(connection, now_ms=lambda: 10).change_pool_failover(
                "primary", _request(), "operator"
            )
        assert connection.execute("SELECT COUNT(*) FROM credential_mutations").fetchone()[0] == 0


@pytest.mark.parametrize("reason", ["", " ", "\n\t"])
def test_pool_failover_requires_nonblank_reason(reason: str) -> None:
    with pytest.raises(ValueError):
        _request(reason=reason)
