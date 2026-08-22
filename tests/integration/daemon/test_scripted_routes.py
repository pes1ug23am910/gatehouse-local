from __future__ import annotations

from pathlib import Path

import pytest

from gatehouse.core.clock import FixedUtcClock
from gatehouse.daemon import synchronize_scripted_routes
from gatehouse.database import apply_migrations, connect_database, open_migrated_database
from gatehouse.database.migrations import MIGRATIONS
from gatehouse.routing import SqliteRoutingCatalog

_SCRIPTED_SNAPSHOT_ID = "snapshot_gatehouse_scripted_no_network_v1"
_A = "01K32J0B80E4G7P6H9Q2R5T8VW"


def test_scripted_routes_are_idempotent_and_credential_free(tmp_path: Path) -> None:
    path = tmp_path / "scripted.db"
    first_connection = open_migrated_database(path)
    first = synchronize_scripted_routes(
        first_connection,
        pool_aliases=("interactive-default", "watcher-reserved"),
        clock=FixedUtcClock(100),
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
    snapshot = first_connection.execute(
        """
        SELECT snapshot_id, quota_scope_id, remaining_units, plan_total_units,
               observed_remaining_units_decimal,
               observed_plan_total_units_decimal, unit, captured_at_ms,
               source, metadata_json
          FROM quota_snapshots WHERE snapshot_id = ?
        """,
        (_SCRIPTED_SNAPSHOT_ID,),
    ).fetchone()
    assert tuple(snapshot) == (
        _SCRIPTED_SNAPSHOT_ID,
        str(first.quota_scope_id),
        1_000_000,
        None,
        "1000000",
        None,
        "credits",
        100,
        "scripted-no-network-synthetic",
        '{"network":false,"synthetic":true,"transport":"scripted"}',
    )
    first_connection.close()

    second_connection = open_migrated_database(path)
    second = synchronize_scripted_routes(
        second_connection,
        pool_aliases=("watcher-reserved", "interactive-default"),
        clock=FixedUtcClock(999),
    )
    assert second == first
    assert second_connection.execute("SELECT COUNT(*) FROM credentials").fetchone()[0] == 1
    assert second_connection.execute("SELECT COUNT(*) FROM pools").fetchone()[0] == 2
    scope = second_connection.execute(
        """
        SELECT last_known_remaining_units, balance_as_of_ms,
               balance_snapshot_id, last_refreshed_at_ms
          FROM quota_scopes WHERE quota_scope_id = ?
        """,
        (str(second.quota_scope_id),),
    ).fetchone()
    assert tuple(scope) == (1_000_000, 100, _SCRIPTED_SNAPSHOT_ID, 100)
    assert (
        second_connection.execute(
            "SELECT captured_at_ms FROM quota_snapshots WHERE snapshot_id = ?",
            (_SCRIPTED_SNAPSHOT_ID,),
        ).fetchone()[0]
        == 100
    )
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


@pytest.mark.parametrize(
    ("legacy_refreshed_at_ms", "expected_snapshot_ms"),
    ((1, 1), (None, 0)),
)
def test_migrated_scripted_cache_receives_one_snapshot_without_losing_reservations(
    tmp_path: Path,
    legacy_refreshed_at_ms: int | None,
    expected_snapshot_ms: int,
) -> None:
    connection = connect_database(tmp_path / "migrated-scripted.db")
    assert apply_migrations(connection, migrations=MIGRATIONS[:8]) == 8
    principal_id = f"prn_{_A}"
    scope_id = f"quota_{_A}"
    connection.execute(
        """
        INSERT INTO principals(
            principal_id, service_id, alias, enabled, metadata_json,
            created_at_ms, updated_at_ms
        ) VALUES (?, 'firecrawl', 'gatehouse-scripted-no-network', 1,
                  '{"transport":"scripted","network":false}', 1, 1)
        """,
        (principal_id,),
    )
    connection.execute(
        """
        INSERT INTO quota_scopes(
            quota_scope_id, principal_id, alias, state, unit,
            last_known_remaining_units, configured_floor_units,
            last_refreshed_at_ms, metadata_json, balance_as_of_ms
        ) VALUES (?, ?, 'gatehouse-scripted-no-network', 'HEALTHY', 'credits',
                  1000000, 0, ?, '{"transport":"scripted","network":false}', 1)
        """,
        (scope_id, principal_id, legacy_refreshed_at_ms),
    )
    connection.execute("PRAGMA foreign_keys = OFF")
    connection.execute(
        """
        INSERT INTO quota_reservations(
            reservation_id, request_id, quota_scope_id, amount_units,
            actual_units, unit, state, created_at_ms, expires_at_ms,
            reconciled_at_ms
        ) VALUES ('legacy-active', 'missing-request-a', ?, 7, NULL,
                  'credits', 'ACTIVE', 1, 1000, NULL),
                 ('legacy-settled', 'missing-request-b', ?, 5, 3,
                  'credits', 'RECONCILED', 1, 1000, 2)
        """,
        (scope_id, scope_id),
    )
    connection.execute("PRAGMA foreign_keys = ON")
    assert apply_migrations(connection) == 9
    assert tuple(
        connection.execute(
            """
            SELECT last_known_remaining_units, balance_as_of_ms, balance_snapshot_id
              FROM quota_scopes WHERE quota_scope_id = ?
            """,
            (scope_id,),
        ).fetchone()
    ) == (None, None, None)

    authority = synchronize_scripted_routes(
        connection,
        pool_aliases=("interactive-default",),
        clock=FixedUtcClock(500),
    )

    assert str(authority.quota_scope_id) == scope_id
    assert connection.execute("SELECT COUNT(*) FROM quota_snapshots").fetchone()[0] == 1
    assert tuple(
        connection.execute(
            """
            SELECT q.last_known_remaining_units, q.balance_as_of_ms,
                   q.balance_snapshot_id, q.last_refreshed_at_ms,
                   s.captured_at_ms
              FROM quota_scopes AS q
              JOIN quota_snapshots AS s
                ON s.snapshot_id = q.balance_snapshot_id
             WHERE q.quota_scope_id = ?
            """,
            (scope_id,),
        ).fetchone()
    ) == (
        1_000_000,
        expected_snapshot_ms,
        _SCRIPTED_SNAPSHOT_ID,
        expected_snapshot_ms,
        expected_snapshot_ms,
    )
    assert [
        tuple(row)
        for row in connection.execute(
            """
            SELECT reservation_id, amount_units, actual_units, state,
                   reconciled_at_ms
              FROM quota_reservations ORDER BY reservation_id
            """
        )
    ] == [
        ("legacy-active", 7, None, "ACTIVE", None),
        ("legacy-settled", 5, 3, "RECONCILED", 2),
    ]
    plan = SqliteRoutingCatalog(connection).plan(
        service_id="firecrawl",
        operation="firecrawl.search",
        pool_name="interactive-default",
        estimated_cost_units=1,
        unit="credits",
        now_ms=500,
    )
    assert plan.candidates[0].scope.active_reserved_units == 10
    connection.close()


def test_scripted_snapshot_id_collision_rolls_back_all_new_authority(tmp_path: Path) -> None:
    connection = open_migrated_database(tmp_path / "snapshot-collision.db")
    connection.execute(
        """
        INSERT INTO principals(
            principal_id, service_id, alias, created_at_ms, updated_at_ms
        ) VALUES ('unrelated-principal', 'other', 'unrelated', 0, 0)
        """
    )
    connection.execute(
        """
        INSERT INTO quota_scopes(
            quota_scope_id, principal_id, alias, state, unit
        ) VALUES ('unrelated-scope', 'unrelated-principal', 'unrelated',
                  'HEALTHY', 'credits')
        """
    )
    connection.execute(
        """
        INSERT INTO quota_snapshots(
            snapshot_id, quota_scope_id, remaining_units, unit,
            captured_at_ms, source, observed_remaining_units_decimal
        ) VALUES (?, 'unrelated-scope', 1, 'credits', 1, 'collision', '1')
        """,
        (_SCRIPTED_SNAPSHOT_ID,),
    )
    before = tuple(
        connection.execute(
            """
            SELECT
                (SELECT COUNT(*) FROM principals),
                (SELECT COUNT(*) FROM quota_scopes),
                (SELECT COUNT(*) FROM credentials),
                (SELECT COUNT(*) FROM pools),
                (SELECT COUNT(*) FROM quota_snapshots)
            """
        ).fetchone()
    )

    with pytest.raises(RuntimeError, match="snapshot conflicts"):
        synchronize_scripted_routes(
            connection,
            pool_aliases=("interactive-default",),
            clock=FixedUtcClock(100),
        )

    after = tuple(
        connection.execute(
            """
            SELECT
                (SELECT COUNT(*) FROM principals),
                (SELECT COUNT(*) FROM quota_scopes),
                (SELECT COUNT(*) FROM credentials),
                (SELECT COUNT(*) FROM pools),
                (SELECT COUNT(*) FROM quota_snapshots)
            """
        ).fetchone()
    )
    assert after == before
    connection.close()
