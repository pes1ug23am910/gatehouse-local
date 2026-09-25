from __future__ import annotations

import sqlite3
from collections.abc import Callable
from contextlib import closing
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
from gatehouse.providers import ProviderErrorClass
from gatehouse.routing import (
    AffinityUnavailableError,
    NoEligibleCredentialError,
    NoEligiblePoolError,
    ResourceAffinity,
    SqliteRoutingCatalog,
)
from gatehouse.routing.eligibility import (
    LocalRouteAssessment,
    LocalRouteReason,
    LocalRouteStatus,
    WorkloadRouteRequirement,
    assess_local_routes,
)
from gatehouse.routing.retry import BreakerKey, BreakerScopeType, CircuitBreakerRegistry
from gatehouse.routing.sqlite_breakers import SqliteCircuitBreakerPersistence

_A = "01K32J0B80E4G7P6H9Q2R5T8VW"


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("{}", False),
        ('{"automatic_failover_within_pool":false}', False),
        ('{"automatic_failover_within_pool":true}', True),
    ],
)
def test_pool_failover_requires_explicit_boolean(raw: str, expected: bool) -> None:
    assert SqliteRoutingCatalog._config(raw)[0] is expected


@pytest.mark.parametrize(
    "raw",
    [
        '{"automatic_failover_within_pool":1}',
        '{"automatic_failover_within_pool":"true"}',
        '{"automatic_failover_within_pool":null}',
    ],
)
def test_pool_failover_rejects_non_boolean(raw: str) -> None:
    with pytest.raises(ValueError, match="failover"):
        SqliteRoutingCatalog._config(raw)


def test_catalog_bounds_materialized_credentials_and_preserves_exact_affinity(
    tmp_path: Path,
) -> None:
    with closing(open_migrated_database(tmp_path / "bounded-routing.sqlite3")) as connection:
        pool_id, scope_id, credential_id = _seed(connection)
        connection.execute(
            """
            INSERT INTO credentials(credential_id, principal_id, quota_scope_id, alias,
                secret_backend, secret_reference, state, generation, created_at_ms)
            VALUES ('cred_00000000000000000000000002', ?, ?, 'secondary', 'test',
                'opaque-secondary', 'HEALTHY', 4, 1)
            """,
            (f"prn_{_A}", str(scope_id)),
        )
        statements: list[str] = []
        connection.set_trace_callback(statements.append)
        catalog = SqliteRoutingCatalog(connection, maximum_route_candidates=1)
        with pytest.raises(NoEligiblePoolError, match="candidate limit"):
            catalog.plan(
                service_id="firecrawl",
                operation="firecrawl.search",
                pool_name="interactive-default",
                estimated_cost_units=1,
                unit="credits",
                now_ms=10,
            )
        assert any("FROM credentials" in sql and "LIMIT 2" in sql for sql in statements)
        plan = catalog.plan(
            service_id="firecrawl",
            operation="firecrawl.crawl.status",
            pool_name="interactive-default",
            estimated_cost_units=0,
            unit="credits",
            now_ms=10,
            reconciliation=True,
            affinity=_affinity(pool_id=pool_id, scope_id=scope_id, credential_id=credential_id),
        )
        assert len(plan.candidates) == 1
        assert plan.candidates[0].credential.credential_id == credential_id


def test_catalog_bounds_members_before_materializing_and_affinity_ignores_other_members(
    tmp_path: Path,
) -> None:
    with closing(open_migrated_database(tmp_path / "bounded-members.sqlite3")) as connection:
        pool_id, scope_id, credential_id = _seed(connection)
        other_scope = "quota_00000000000000000000000002"
        connection.execute(
            """INSERT INTO quota_scopes(quota_scope_id, principal_id, alias, state, unit,
                   configured_floor_units) VALUES (?, ?, 'other', 'UNKNOWN', 'credits', 10)""",
            (other_scope, f"prn_{_A}"),
        )
        connection.execute(
            "INSERT INTO pool_members(pool_id, quota_scope_id) VALUES (?, ?)",
            (str(pool_id), other_scope),
        )
        statements: list[str] = []
        connection.set_trace_callback(statements.append)
        catalog = SqliteRoutingCatalog(connection, maximum_route_candidates=1)
        with pytest.raises(NoEligiblePoolError, match="candidate limit"):
            catalog.plan(
                service_id="firecrawl",
                operation="firecrawl.search",
                pool_name="interactive-default",
                estimated_cost_units=1,
                unit="credits",
                now_ms=10,
            )
        assert any("FROM pool_members" in sql and "LIMIT 2" in sql for sql in statements)
        assert not any("FROM credentials" in sql for sql in statements)
        plan = catalog.plan(
            service_id="firecrawl",
            operation="firecrawl.crawl.status",
            pool_name="interactive-default",
            estimated_cost_units=0,
            unit="credits",
            now_ms=10,
            reconciliation=True,
            affinity=_affinity(pool_id=pool_id, scope_id=scope_id, credential_id=credential_id),
        )
        assert plan.candidates[0].credential.credential_id == credential_id


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


def _assessment_rows(connection: sqlite3.Connection) -> tuple[tuple[tuple[object, ...], ...], ...]:
    """Read only fixed tables in the newly seeded synthetic database."""

    statements = (
        "SELECT * FROM principals ORDER BY principal_id",
        "SELECT * FROM quota_scopes ORDER BY quota_scope_id",
        "SELECT * FROM credentials ORDER BY credential_id",
        "SELECT * FROM pools ORDER BY pool_id",
        "SELECT * FROM pool_members ORDER BY pool_id, quota_scope_id",
        "SELECT * FROM quota_snapshots ORDER BY snapshot_id",
        "SELECT * FROM quota_reservations ORDER BY reservation_id",
        "SELECT * FROM invocations ORDER BY request_id",
        "SELECT * FROM circuit_breakers ORDER BY breaker_id",
    )
    return tuple(
        tuple(tuple(row) for row in connection.execute(statement).fetchall())
        for statement in statements
    )


def _assessment_without_effects(
    connection: sqlite3.Connection,
    requirements: tuple[WorkloadRouteRequirement, ...],
    *,
    now_ms: int,
    breakers: CircuitBreakerRegistry | None = None,
) -> LocalRouteAssessment:
    registry = breakers if breakers is not None else CircuitBreakerRegistry(now_ms=lambda: now_ms)
    catalog = SqliteRoutingCatalog(connection, circuit_breakers=registry)
    rows_before = _assessment_rows(connection)
    changes_before = connection.total_changes
    transaction_before = connection.in_transaction
    keys_before = tuple(registry._records)
    snapshots_before = tuple(registry.snapshot(key, now_ms=now_ms) for key in keys_before)
    permits_before = dict(registry._active_permits)
    next_permit_before = registry._next_permit_id

    result = assess_local_routes(catalog, requirements, now_ms=now_ms)

    assert _assessment_rows(connection) == rows_before
    assert connection.total_changes == changes_before
    assert connection.in_transaction is transaction_before
    assert tuple(registry._records) == keys_before
    assert tuple(registry.snapshot(key, now_ms=now_ms) for key in keys_before) == snapshots_before
    assert registry._active_permits == permits_before
    assert registry._next_permit_id == next_permit_before
    assert result.observed_at_ms == now_ms
    assert tuple(item.requirement for item in result.results) == requirements
    return result


@pytest.mark.parametrize(
    "operation,cost",
    (
        ("firecrawl.search", 1),
        ("firecrawl.scrape", 1),
        ("firecrawl.map", 1),
        ("firecrawl.crawl.start", 25),
    ),
)
@pytest.mark.parametrize("one_short", (False, True))
def test_local_assessment_uses_operation_cost_at_durable_floor_boundary(
    tmp_path: Path,
    operation: str,
    cost: int,
    one_short: bool,
) -> None:
    with closing(open_migrated_database(tmp_path / "assessment-cost.sqlite3")) as connection:
        _seed(connection)
        # Seeded authority is 100 credits; the durable floor leaves exactly cost
        # credits or one fewer, without modifying the immutable observation.
        connection.execute(
            "UPDATE quota_scopes SET configured_floor_units = ?",
            (100 - cost + int(one_short),),
        )
        requirement = WorkloadRouteRequirement("interactive-default", operation)
        result = _assessment_without_effects(connection, (requirement,), now_ms=10)
        expected_status = LocalRouteStatus.INELIGIBLE if one_short else LocalRouteStatus.ELIGIBLE
        expected_reason = (
            LocalRouteReason.ROUTE_REFUSED if one_short else LocalRouteReason.LOCAL_ROUTE_AVAILABLE
        )
        assert result.status is expected_status
        assert result.results[0].status is expected_status
        assert result.results[0].reason is expected_reason


def test_local_assessment_accounts_for_existing_holds_without_reserving(
    tmp_path: Path,
) -> None:
    with closing(open_migrated_database(tmp_path / "assessment-holds.sqlite3")) as connection:
        _, scope_id, _ = _seed(connection)
        connection.execute(
            """INSERT INTO clients(client_id, display_name, kind, policy_profile,
                   created_at_ms, updated_at_ms)
               VALUES ('assessment-client', 'Synthetic client', 'interactive', 'synthetic', 1, 1)"""
        )
        connection.execute(
            """INSERT INTO sessions(session_id, client_id, bootstrap_verifier, bootstrap_version,
                   token_epoch, state, identity_assurance, policy_version, created_at_ms,
                   reconnect_until_ms, absolute_expires_at_ms)
               VALUES (?, 'assessment-client', ?, 1, 0, 'ACTIVE', 'CONTROLLED', 'synthetic',
                       1, 1000, 1000)""",
            (f"ses_{_A}", b"synthetic-bootstrap-verifier"),
        )
        holds = (
            ("active", "ACTIVE", 20, None, None),
            ("pending", "PENDING_RECONCILIATION", 20, None, None),
            ("disputed", "DISPUTED", 10, None, None),
            ("settled", "RECONCILED", 40, 15, 5),
        )
        for index, (label, state, amount, actual, reconciled) in enumerate(holds, start=1):
            request_id = f"req_{index:026d}"
            connection.execute(
                """INSERT INTO invocations(request_id, session_id, service_id, operation,
                       request_fingerprint, fingerprint_version, canonicalization_version,
                       state, priority_class, request_size_bytes, received_at_ms)
                   VALUES (?, ?, 'firecrawl', 'firecrawl.search', ?, 1, 1, 'RECEIVED',
                           'interactive', 0, 1)""",
                (request_id, f"ses_{_A}", b"synthetic-request-fingerprint"),
            )
            connection.execute(
                """INSERT INTO quota_reservations(reservation_id, request_id, quota_scope_id,
                       amount_units, actual_units, unit, state, created_at_ms, expires_at_ms,
                       reconciled_at_ms)
                   VALUES (?, ?, ?, ?, ?, 'credits', ?, 1, 1000, ?)""",
                (label, request_id, str(scope_id), amount, actual, state, reconciled),
            )
        requirements = tuple(
            WorkloadRouteRequirement("interactive-default", operation)
            for operation in (
                "firecrawl.search",
                "firecrawl.scrape",
                "firecrawl.map",
                "firecrawl.crawl.start",
            )
        )
        # 100 authority - 10 floor - (20 + 20 + 10 + 15 committed) = 25.
        at_boundary = _assessment_without_effects(connection, requirements, now_ms=10)
        assert at_boundary.status is LocalRouteStatus.ELIGIBLE
        assert all(
            item.reason is LocalRouteReason.LOCAL_ROUTE_AVAILABLE for item in at_boundary.results
        )

        connection.execute(
            "UPDATE quota_reservations SET amount_units = 21 WHERE reservation_id = 'active'"
        )
        below_boundary = _assessment_without_effects(connection, requirements, now_ms=10)
        assert below_boundary.status is LocalRouteStatus.INELIGIBLE
        assert tuple(item.status for item in below_boundary.results) == (
            LocalRouteStatus.ELIGIBLE,
            LocalRouteStatus.ELIGIBLE,
            LocalRouteStatus.ELIGIBLE,
            LocalRouteStatus.INELIGIBLE,
        )
        assert below_boundary.results[-1].reason is LocalRouteReason.ROUTE_REFUSED


@pytest.mark.parametrize(
    "defect",
    (
        "credential_disabled",
        "credential_quarantined",
        "credential_expired",
        "scope_disabled",
        "scope_quarantined",
        "authority_missing",
        "authority_expired",
        "pool_manual",
        "pool_disabled",
        "member_disabled",
        "pool_missing",
    ),
)
def test_local_assessment_observes_current_catalog_refusals_without_effects(
    tmp_path: Path,
    defect: str,
) -> None:
    with closing(open_migrated_database(tmp_path / "assessment-refusal.sqlite3")) as connection:
        _seed(connection)
        now_ms = 10
        pool_name = "interactive-default"
        if defect in {"credential_disabled", "credential_quarantined"}:
            state = "DISABLED" if defect == "credential_disabled" else "QUARANTINED"
            connection.execute("UPDATE credentials SET state = ?", (state,))
        elif defect == "credential_expired":
            connection.execute("UPDATE credentials SET expires_at_ms = 10")
        elif defect in {"scope_disabled", "scope_quarantined"}:
            state = "DISABLED" if defect == "scope_disabled" else "QUARANTINED"
            connection.execute("UPDATE quota_scopes SET state = ?", (state,))
        elif defect == "authority_missing":
            _authority_absent(connection)
        elif defect == "authority_expired":
            now_ms = 100_000
        elif defect == "pool_manual":
            connection.execute("UPDATE pools SET automatic_use = 0")
        elif defect == "pool_disabled":
            connection.execute("UPDATE pools SET state = 'DISABLED'")
        elif defect == "member_disabled":
            connection.execute("UPDATE pool_members SET enabled = 0")
        else:
            assert defect == "pool_missing"
            pool_name = "absent-pool"
        result = _assessment_without_effects(
            connection,
            (WorkloadRouteRequirement(pool_name, "firecrawl.search"),),
            now_ms=now_ms,
        )
        assert result.status is LocalRouteStatus.INELIGIBLE
        assert result.results[0].status is LocalRouteStatus.INELIGIBLE
        expected_reason = (
            LocalRouteReason.POOL_REFUSED
            if defect in {"pool_manual", "pool_disabled", "pool_missing"}
            else LocalRouteReason.ROUTE_REFUSED
        )
        assert result.results[0].reason is expected_reason


@pytest.mark.parametrize(
    "scope_type",
    (
        BreakerScopeType.SERVICE,
        BreakerScopeType.PROVIDER_OPERATION,
        BreakerScopeType.QUOTA_SCOPE,
        BreakerScopeType.CREDENTIAL,
    ),
)
def test_local_assessment_observes_breakers_without_taking_half_open_permits(
    tmp_path: Path,
    scope_type: BreakerScopeType,
) -> None:
    with closing(open_migrated_database(tmp_path / "assessment-breaker.sqlite3")) as connection:
        _, quota_scope, credential = _seed(connection)
        scope_id = {
            BreakerScopeType.SERVICE: "firecrawl",
            BreakerScopeType.PROVIDER_OPERATION: "firecrawl.search",
            BreakerScopeType.QUOTA_SCOPE: str(quota_scope),
            BreakerScopeType.CREDENTIAL: str(credential),
        }[scope_type]
        key = BreakerKey(scope_type, scope_id)
        breakers = CircuitBreakerRegistry(
            persistence=SqliteCircuitBreakerPersistence(connection),
            now_ms=lambda: 10,
        )
        breakers.record_failure(
            key,
            now_ms=1,
            error_class=ProviderErrorClass.RATE_LIMITED,
            open_until_ms=100,
            force_open=True,
        )
        requirements = (WorkloadRouteRequirement("interactive-default", "firecrawl.search"),)
        blocked = _assessment_without_effects(
            connection,
            requirements,
            now_ms=10,
            breakers=breakers,
        )
        assert blocked.status is LocalRouteStatus.INELIGIBLE
        assert blocked.results[0].reason is LocalRouteReason.ROUTE_REFUSED

        available = _assessment_without_effects(
            connection,
            requirements,
            now_ms=100,
            breakers=breakers,
        )
        assert available.status is LocalRouteStatus.ELIGIBLE
        assert available.results[0].reason is LocalRouteReason.LOCAL_ROUTE_AVAILABLE
        permit = breakers.try_acquire(key, now_ms=100)
        assert permit is not None
        try:
            occupied = _assessment_without_effects(
                connection,
                requirements,
                now_ms=100,
                breakers=breakers,
            )
            assert occupied.status is LocalRouteStatus.INELIGIBLE
            assert occupied.results[0].reason is LocalRouteReason.ROUTE_REFUSED
        finally:
            assert breakers.release(permit)
