from __future__ import annotations

from pathlib import Path

import pytest

from gatehouse.daemon import synchronize_scripted_routes
from gatehouse.database import open_migrated_database
from gatehouse.routing import SqliteRoutingCatalog


def test_scripted_routes_are_idempotent_and_credential_free(tmp_path: Path) -> None:
    path = tmp_path / "scripted.db"
    first_connection = open_migrated_database(path)
    first = synchronize_scripted_routes(
        first_connection,
        pool_aliases=("interactive-default", "watcher-reserved"),
    )
    assert SqliteRoutingCatalog(first_connection).validate(now_ms=1) == 2
    row = first_connection.execute(
        """
        SELECT secret_backend, secret_reference, metadata_json
          FROM credentials WHERE credential_id = ?
        """,
        (str(first.credential_id),),
    ).fetchone()
    assert tuple(row) == ("scripted", "builtin:no-network:v1", '{"network":false}')
    first_connection.close()

    second_connection = open_migrated_database(path)
    second = synchronize_scripted_routes(
        second_connection,
        pool_aliases=("watcher-reserved", "interactive-default"),
    )
    assert second == first
    assert second_connection.execute("SELECT COUNT(*) FROM credentials").fetchone()[0] == 1
    assert second_connection.execute("SELECT COUNT(*) FROM pools").fetchone()[0] == 2
    second_connection.close()


def test_scripted_routes_fail_closed_on_live_pool_collision(tmp_path: Path) -> None:
    connection = open_migrated_database(tmp_path / "collision.db")
    first = synchronize_scripted_routes(connection, pool_aliases=("interactive-default",))
    connection.execute(
        "UPDATE pools SET selection_strategy = 'cheapest_first' WHERE pool_id = ?",
        (str(first.pool_ids_by_alias["interactive-default"]),),
    )

    with pytest.raises(RuntimeError, match="pool conflicts"):
        synchronize_scripted_routes(connection, pool_aliases=("interactive-default",))
    connection.close()
