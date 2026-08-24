from __future__ import annotations

import sqlite3
from collections.abc import Callable
from pathlib import Path

import pytest

from gatehouse.core.ids import (
    CredentialId,
    PoolId,
    PrincipalId,
    QuotaScopeId,
    RequestId,
    RootRunId,
    SessionId,
    WorkspaceId,
)
from gatehouse.core.provider_numbers import SQLITE_INT64_MAX
from gatehouse.database import open_migrated_database
from gatehouse.routing import (
    AffinityUnavailableError,
    NoEligibleCredentialError,
    NoEligiblePoolError,
    ResourceAffinity,
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
        ) VALUES (?, ?, 'primary', 'HEALTHY', 'credits', NULL, 10)
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
        INSERT INTO quota_snapshots(
            snapshot_id, quota_scope_id, remaining_units, unit,
            captured_at_ms, source, observed_remaining_units_decimal,
            quota_dimension_id, credential_id, credential_generation,
            stale_at_ms, observation_kind
        ) VALUES ('snapshot-catalog', ?, 100, 'credits', 1, 'integration-test', '100',
                  ?, ?, 3, 100000, 'AUTHENTICATED')
        """,
        (str(scope_id), f"dimension_legacy_primary:{scope_id}", str(credential_id)),
    )
    connection.execute(
        """
        UPDATE quota_scopes
           SET last_known_remaining_units = 100,
               balance_as_of_ms = 1,
               balance_snapshot_id = 'snapshot-catalog'
         WHERE quota_scope_id = ?
        """,
        (str(scope_id),),
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


def _affinity(
    *,
    pool_id: PoolId,
    scope_id: QuotaScopeId,
    credential_id: CredentialId,
) -> ResourceAffinity:
    return ResourceAffinity(
        service_id="firecrawl",
        resource_type="crawl",
        provider_resource_id="scripted-job",
        principal_id=PrincipalId(f"prn_{_A}"),
        quota_scope_id=scope_id,
        credential_id=credential_id,
        credential_generation=3,
        pool_id=pool_id,
        creating_request_id=RequestId(f"req_{_A}"),
        owner_session_id=SessionId(f"ses_{_A}"),
        owner_workspace_id=WorkspaceId(f"ws_{_A}"),
        owner_root_run_id=RootRunId(f"run_{_A}"),
        bound_at_ms=1,
    )


def _authority_rows(connection: sqlite3.Connection) -> tuple[tuple[object, ...], ...]:
    return tuple(
        tuple(row)
        for row in connection.execute(
            """
            SELECT 'scope', quota_scope_id, unit, last_known_remaining_units,
                   balance_as_of_ms, balance_snapshot_id
              FROM quota_scopes
            UNION ALL
            SELECT 'snapshot', snapshot_id, unit, remaining_units,
                   captured_at_ms, observed_remaining_units_decimal
              FROM quota_snapshots
             ORDER BY 1, 2
            """
        ).fetchall()
    )


def _authority_absent(connection: sqlite3.Connection) -> None:
    connection.execute(
        """
        UPDATE quota_scopes
           SET last_known_remaining_units = NULL,
               balance_as_of_ms = NULL,
               balance_snapshot_id = NULL
        """
    )


def _authority_partial(connection: sqlite3.Connection) -> None:
    connection.execute("DROP TRIGGER quota_scopes_balance_authority_update")
    connection.execute("UPDATE quota_scopes SET balance_snapshot_id = NULL")


def _authority_missing_snapshot(connection: sqlite3.Connection) -> None:
    connection.execute("DROP TRIGGER quota_scopes_balance_authority_update")
    connection.execute("PRAGMA foreign_keys = OFF")
    connection.execute("UPDATE quota_scopes SET balance_snapshot_id = 'missing-snapshot'")
    connection.execute("PRAGMA foreign_keys = ON")


def _snapshot_wrong_scope(connection: sqlite3.Connection) -> None:
    connection.execute("DROP TRIGGER quota_snapshots_observation_immutable")
    connection.execute("DROP TRIGGER quota_snapshots_decimal_shape_update")
    connection.execute("DROP TRIGGER quota_snapshots_v10_shape_update")
    connection.execute("PRAGMA foreign_keys = OFF")
    connection.execute("UPDATE quota_snapshots SET quota_scope_id = 'wrong-scope'")
    connection.execute("PRAGMA foreign_keys = ON")


def _snapshot_wrong_unit(connection: sqlite3.Connection) -> None:
    connection.execute("DROP TRIGGER quota_snapshots_observation_immutable")
    connection.execute("DROP TRIGGER quota_snapshots_decimal_shape_update")
    connection.execute("DROP TRIGGER quota_snapshots_v10_shape_update")
    connection.execute("UPDATE quota_snapshots SET unit = 'requests'")


def _snapshot_wrong_capture_time(connection: sqlite3.Connection) -> None:
    connection.execute("DROP TRIGGER quota_snapshots_observation_immutable")
    connection.execute("UPDATE quota_snapshots SET captured_at_ms = 2")


def _snapshot_mismatched_projection(connection: sqlite3.Connection) -> None:
    connection.execute("DROP TRIGGER quota_snapshots_observation_immutable")
    connection.execute("UPDATE quota_snapshots SET observed_remaining_units_decimal = '99'")


def _snapshot_noncanonical_observation(connection: sqlite3.Connection) -> None:
    connection.execute("DROP TRIGGER quota_snapshots_observation_immutable")
    connection.execute("UPDATE quota_snapshots SET observed_remaining_units_decimal = '100.0'")


def _valid_zero_observation(connection: sqlite3.Connection) -> None:
    connection.execute("DROP TRIGGER quota_snapshots_observation_immutable")
    connection.execute(
        """
        UPDATE quota_snapshots
           SET remaining_units = 0,
               observed_remaining_units_decimal = '0'
        """
    )
    connection.execute("UPDATE quota_scopes SET last_known_remaining_units = 0")


def _valid_negative_observation(connection: sqlite3.Connection) -> None:
    connection.execute("DROP TRIGGER quota_snapshots_observation_immutable")
    connection.execute(
        """
        UPDATE quota_snapshots
           SET remaining_units = 0,
               observed_remaining_units_decimal = '-0.75'
        """
    )
    connection.execute("UPDATE quota_scopes SET last_known_remaining_units = 0")


def _valid_positive_observation(connection: sqlite3.Connection) -> None:
    del connection


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


@pytest.mark.parametrize("credential_role", ("OBSERVER", "MANAGEMENT", "INFERENCE"))
def test_firecrawl_workload_routing_excludes_non_workload_roles(
    tmp_path: Path,
    credential_role: str,
) -> None:
    connection = open_migrated_database(tmp_path / f"role-{credential_role.lower()}.db")
    try:
        _seed(connection)
        connection.execute(
            "UPDATE credentials SET credential_role = ?",
            (credential_role,),
        )
        with pytest.raises((NoEligibleCredentialError, NoEligiblePoolError)):
            SqliteRoutingCatalog(connection).plan(
                service_id="firecrawl",
                operation="firecrawl.search",
                pool_name="interactive-default",
                estimated_cost_units=1,
                unit="credits",
                now_ms=2,
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
        connection.execute("PRAGMA foreign_keys = OFF")
        connection.execute("UPDATE credentials SET credential_id = 'malformed!'")
        connection.execute("PRAGMA foreign_keys = ON")
        catalog = SqliteRoutingCatalog(connection)
        with pytest.raises(ValueError):
            catalog.validate(now_ms=10)
    finally:
        connection.close()


@pytest.mark.parametrize(
    ("mutation", "positive_eligible", "reconciliation_eligible"),
    [
        pytest.param(_authority_absent, False, True, id="absent"),
        pytest.param(_authority_partial, False, False, id="partial"),
        pytest.param(_authority_missing_snapshot, False, False, id="missing-snapshot"),
        pytest.param(_snapshot_wrong_scope, False, False, id="wrong-scope"),
        pytest.param(_snapshot_wrong_unit, False, False, id="wrong-unit"),
        pytest.param(_snapshot_wrong_capture_time, False, False, id="wrong-capture-time"),
        pytest.param(
            _snapshot_mismatched_projection,
            False,
            False,
            id="mismatched-projection",
        ),
        pytest.param(
            _snapshot_noncanonical_observation,
            False,
            False,
            id="noncanonical-observation",
        ),
        pytest.param(_valid_zero_observation, False, True, id="valid-zero"),
        pytest.param(
            _valid_negative_observation,
            False,
            True,
            id="valid-negative-projecting-to-zero",
        ),
        pytest.param(_valid_positive_observation, True, True, id="valid-positive"),
    ],
)
def test_catalog_balance_authority_outcomes_are_distinct_and_read_only(
    tmp_path: Path,
    mutation: Callable[[sqlite3.Connection], None],
    positive_eligible: bool,
    reconciliation_eligible: bool,
) -> None:
    connection = open_migrated_database(tmp_path / "authority-matrix.db")
    try:
        pool_id, scope_id, credential_id = _seed(connection)
        mutation(connection)
        authority_before = _authority_rows(connection)
        changes_before = connection.total_changes
        catalog = SqliteRoutingCatalog(connection)

        if positive_eligible:
            positive = catalog.plan(
                service_id="firecrawl",
                operation="firecrawl.search",
                pool_name="interactive-default",
                estimated_cost_units=1,
                unit="credits",
                now_ms=10,
            )
            assert positive.candidates[0].credential.credential_id == credential_id
        else:
            with pytest.raises(NoEligibleCredentialError):
                catalog.plan(
                    service_id="firecrawl",
                    operation="firecrawl.search",
                    pool_name="interactive-default",
                    estimated_cost_units=1,
                    unit="credits",
                    now_ms=10,
                )

        affinity = _affinity(
            pool_id=pool_id,
            scope_id=scope_id,
            credential_id=credential_id,
        )
        if reconciliation_eligible:
            reconciliation = catalog.plan(
                service_id="firecrawl",
                operation="firecrawl.crawl.status",
                pool_name="interactive-default",
                estimated_cost_units=0,
                unit="credits",
                now_ms=10,
                affinity=affinity,
                reconciliation=True,
            )
            assert reconciliation.candidates[0].credential.credential_id == credential_id
        else:
            with pytest.raises(AffinityUnavailableError):
                catalog.plan(
                    service_id="firecrawl",
                    operation="firecrawl.crawl.status",
                    pool_name="interactive-default",
                    estimated_cost_units=0,
                    unit="credits",
                    now_ms=10,
                    affinity=affinity,
                    reconciliation=True,
                )

        assert _authority_rows(connection) == authority_before
        assert connection.total_changes == changes_before
    finally:
        connection.close()


def test_catalog_excludes_snapshot_at_exact_staleness_deadline(
    tmp_path: Path,
) -> None:
    connection = open_migrated_database(tmp_path / "stale-authority.db")
    try:
        pool_id, scope_id, credential_id = _seed(connection)
        catalog = SqliteRoutingCatalog(connection)

        with pytest.raises(NoEligibleCredentialError):
            catalog.plan(
                service_id="firecrawl",
                operation="firecrawl.search",
                pool_name="interactive-default",
                estimated_cost_units=1,
                unit="credits",
                now_ms=100_000,
            )

        cleanup = catalog.plan(
            service_id="firecrawl",
            operation="firecrawl.crawl.status",
            pool_name="interactive-default",
            estimated_cost_units=0,
            unit="credits",
            now_ms=100_000,
            affinity=_affinity(
                pool_id=pool_id,
                scope_id=scope_id,
                credential_id=credential_id,
            ),
            reconciliation=True,
        )
        assert cleanup.candidates[0].credential.credential_id == credential_id
    finally:
        connection.close()


@pytest.mark.parametrize("invalid", [True, SQLITE_INT64_MAX + 1])
def test_catalog_rejects_invalid_cost_before_sql(tmp_path: Path, invalid: int) -> None:
    connection = open_migrated_database(tmp_path / "invalid-cost.db")
    try:
        _seed(connection)
        statements: list[str] = []
        connection.set_trace_callback(statements.append)
        try:
            with pytest.raises(ValueError):
                SqliteRoutingCatalog(connection).plan(
                    service_id="firecrawl",
                    operation="firecrawl.search",
                    pool_name="interactive-default",
                    estimated_cost_units=invalid,
                    unit="credits",
                    now_ms=10,
                )
        finally:
            connection.set_trace_callback(None)
        assert statements == []
    finally:
        connection.close()


def test_catalog_makes_projection_mismatched_snapshot_ineligible(tmp_path: Path) -> None:
    connection = open_migrated_database(tmp_path / "projection-mismatch.db")
    try:
        _seed(connection)
        connection.execute("DROP TRIGGER quota_snapshots_observation_immutable")
        connection.execute(
            """
            UPDATE quota_snapshots
               SET observed_remaining_units_decimal = '99'
             WHERE snapshot_id = 'snapshot-catalog'
            """
        )
        catalog = SqliteRoutingCatalog(connection)
        with pytest.raises(NoEligibleCredentialError):
            catalog.plan(
                service_id="firecrawl",
                operation="firecrawl.search",
                pool_name="interactive-default",
                estimated_cost_units=0,
                unit="credits",
                now_ms=10,
            )
    finally:
        connection.close()


def test_negative_observation_blocks_positive_cost_but_preserves_zero_cost_affinity(
    tmp_path: Path,
) -> None:
    connection = open_migrated_database(tmp_path / "negative-observation.db")
    try:
        pool_id, scope_id, credential_id = _seed(connection)
        connection.execute("DROP TRIGGER quota_snapshots_observation_immutable")
        connection.execute(
            """
            UPDATE quota_snapshots
               SET remaining_units = 0,
                   observed_remaining_units_decimal = '-0.75'
             WHERE snapshot_id = 'snapshot-catalog'
            """
        )
        connection.execute(
            """
            UPDATE quota_scopes
               SET last_known_remaining_units = 0
             WHERE quota_scope_id = ?
            """,
            (str(scope_id),),
        )
        connection.execute("PRAGMA foreign_keys = OFF")
        connection.execute(
            """
            INSERT INTO quota_reservations(
                reservation_id, request_id, quota_scope_id, amount_units,
                unit, state, created_at_ms, expires_at_ms
            ) VALUES ('preserved-active', 'missing-request', ?, 5,
                      'credits', 'ACTIVE', 1, 1000)
            """,
            (str(scope_id),),
        )
        connection.execute("PRAGMA foreign_keys = ON")
        catalog = SqliteRoutingCatalog(connection)
        with pytest.raises(NoEligibleCredentialError):
            catalog.plan(
                service_id="firecrawl",
                operation="firecrawl.search",
                pool_name="interactive-default",
                estimated_cost_units=1,
                unit="credits",
                now_ms=10,
            )

        affinity = ResourceAffinity(
            service_id="firecrawl",
            resource_type="crawl",
            provider_resource_id="scripted-job",
            principal_id=PrincipalId(f"prn_{_A}"),
            quota_scope_id=scope_id,
            credential_id=credential_id,
            credential_generation=3,
            pool_id=pool_id,
            creating_request_id=RequestId(f"req_{_A}"),
            owner_session_id=SessionId(f"ses_{_A}"),
            owner_workspace_id=WorkspaceId(f"ws_{_A}"),
            owner_root_run_id=RootRunId(f"run_{_A}"),
            bound_at_ms=1,
        )
        plan = catalog.plan(
            service_id="firecrawl",
            operation="firecrawl.crawl.status",
            pool_name="interactive-default",
            estimated_cost_units=0,
            unit="credits",
            now_ms=10,
            affinity=affinity,
            reconciliation=True,
        )
        assert plan.candidates[0].scope.last_known_remaining_units == 0
        assert (
            connection.execute(
                "SELECT state FROM quota_reservations WHERE reservation_id = 'preserved-active'"
            ).fetchone()[0]
            == "ACTIVE"
        )
    finally:
        connection.close()
