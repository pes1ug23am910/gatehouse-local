from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from gatehouse.core.ids import (
    CredentialId,
    PoolId,
    PrincipalId,
    QuotaScopeId,
)
from gatehouse.database import open_migrated_database
from gatehouse.routing import (
    NoEligibleCredentialError,
    SqliteRoutingCatalog,
)

_A = "01K32J0B80E4G7P6H9Q2R5T8VW"


def _seed(connection: sqlite3.Connection) -> tuple[PoolId, QuotaScopeId, CredentialId]:
    pool_id = PoolId(f"pool_{_A}")
    principal_id = PrincipalId(f"prn_{_A}")
    scope_id = QuotaScopeId(f"quota_{_A}")
    credential_id = CredentialId(f"cred_{_A}")
    connection.execute(
        """
        INSERT INTO principals(
            principal_id, service_id, alias, created_at_ms, updated_at_ms
        ) VALUES (?, 'firecrawl', 'primary', 1, 1)
        """,
        (str(principal_id),),
    )
    connection.execute(
        """
        INSERT INTO quota_scopes(
            quota_scope_id, principal_id, alias, state, unit,
            last_known_remaining_units, configured_floor_units
        ) VALUES (?, ?, 'primary', 'HEALTHY', 'credits', 100, 10)
        """,
        (str(scope_id), str(principal_id)),
    )
    connection.execute(
        """
        INSERT INTO credentials(
            credential_id, principal_id, quota_scope_id, alias,
            secret_backend, secret_reference, state, generation, created_at_ms
        ) VALUES (?, ?, ?, 'primary', 'test', 'opaque', 'HEALTHY', 3, 1)
        """,
        (str(credential_id), str(principal_id), str(scope_id)),
    )
    connection.execute(
        """
        INSERT INTO pools(
            pool_id, service_id, alias, state, selection_strategy,
            automatic_use, config_json
        ) VALUES (?, 'firecrawl', 'interactive-default', 'ACTIVE',
                  'cheapest_first', 1,
                  '{"automatic_failover_within_pool":true,"minimum_remaining_floor_units":10}')
        """,
        (str(pool_id),),
    )
    connection.execute(
        """
        INSERT INTO pool_members(pool_id, quota_scope_id, priority, cost_rank, enabled)
        VALUES (?, ?, 20, 5, 1)
        """,
        (str(pool_id), str(scope_id)),
    )
    return pool_id, scope_id, credential_id


def test_catalog_loads_exact_pool_and_reflects_runtime_quarantine(tmp_path: Path) -> None:
    connection = open_migrated_database(tmp_path / "catalog.db")
    try:
        pool_id, scope_id, credential_id = _seed(connection)
        catalog = SqliteRoutingCatalog(connection)
        plan = catalog.plan(
            service_id="firecrawl",
            operation="firecrawl.search",
            pool_name="interactive-default",
            estimated_cost_units=1,
            unit="credits",
            now_ms=10,
        )
        assert plan.pool_id == pool_id
        assert plan.candidates[0].scope.quota_scope_id == scope_id
        assert plan.candidates[0].credential.credential_id == credential_id
        assert plan.candidates[0].credential.generation == 3
        assert catalog.validate(now_ms=10) == 1

        connection.execute(
            "UPDATE credentials SET state = 'QUARANTINED' WHERE credential_id = ?",
            (str(credential_id),),
        )
        with pytest.raises(NoEligibleCredentialError):
            catalog.plan(
                service_id="firecrawl",
                operation="firecrawl.search",
                pool_name="interactive-default",
                estimated_cost_units=1,
                unit="credits",
                now_ms=11,
            )
    finally:
        connection.close()


def test_catalog_accounts_for_durable_holds_and_settled_usage(tmp_path: Path) -> None:
    connection = open_migrated_database(tmp_path / "accounting.db")
    try:
        _, scope_id, _ = _seed(connection)
        # The catalog is read-only; representative rows can use disabled FK checks
        # to prove accounting without constructing an unrelated invocation graph.
        connection.execute("PRAGMA foreign_keys = OFF")
        connection.execute(
            """
            INSERT INTO quota_reservations(
                reservation_id, request_id, quota_scope_id, amount_units,
                actual_units, unit, state, created_at_ms, expires_at_ms,
                reconciled_at_ms
            ) VALUES
                ('active', 'request-a', ?, 20, NULL, 'credits', 'ACTIVE', 1, 1000, NULL),
                ('settled', 'request-b', ?, 40, 15, 'credits', 'RECONCILED', 1, 1000, 5)
            """,
            (str(scope_id), str(scope_id)),
        )
        connection.execute("PRAGMA foreign_keys = ON")
        catalog = SqliteRoutingCatalog(connection)
        plan = catalog.plan(
            service_id="firecrawl",
            operation="firecrawl.search",
            pool_name="interactive-default",
            estimated_cost_units=50,
            unit="credits",
            now_ms=10,
        )
        assert plan.candidates[0].scope.active_reserved_units == 35

        with pytest.raises(NoEligibleCredentialError):
            catalog.plan(
                service_id="firecrawl",
                operation="firecrawl.search",
                pool_name="interactive-default",
                estimated_cost_units=60,
                unit="credits",
                now_ms=10,
            )
    finally:
        connection.close()


def test_catalog_rejects_malformed_authority_identifiers(tmp_path: Path) -> None:
    connection = open_migrated_database(tmp_path / "malformed.db")
    try:
        _seed(connection)
        connection.execute("UPDATE credentials SET credential_id = 'malformed!'")
        catalog = SqliteRoutingCatalog(connection)
        with pytest.raises(ValueError):
            catalog.validate(now_ms=10)
    finally:
        connection.close()
