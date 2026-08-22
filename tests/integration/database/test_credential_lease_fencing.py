from __future__ import annotations

import json
import sqlite3
from dataclasses import replace
from pathlib import Path

import pytest

from gatehouse.core.ids import (
    CredentialId,
    LeaseId,
    PoolId,
    PrincipalId,
    QuotaScopeId,
    RequestId,
)
from gatehouse.core.states import CredentialState
from gatehouse.database import GatehouseRepository, LeaseStatus, open_migrated_database
from gatehouse.routing import (
    CredentialLeaseManager,
    CredentialLeaseUnavailableError,
    QuotaScopeSnapshot,
    RouteCandidate,
    RoutingCredential,
)

_A = "00000000000000000000000001"
_B = "00000000000000000000000002"
_CREDENTIAL = CredentialId(f"cred_{_A}")
_PRINCIPAL = PrincipalId(f"prn_{_A}")
_SCOPE = QuotaScopeId(f"quota_{_A}")
_OTHER_SCOPE = QuotaScopeId(f"quota_{_B}")
_POOL = PoolId(f"pool_{_A}")
_OTHER_POOL = PoolId(f"pool_{_B}")
_REQUEST_A = RequestId(f"req_{_A}")
_REQUEST_B = RequestId(f"req_{_B}")
_LEASE_A = LeaseId(f"lease_{_A}")
_LEASE_B = LeaseId(f"lease_{_B}")


def _open_seeded(path: Path) -> sqlite3.Connection:
    connection = open_migrated_database(path)
    connection.execute(
        """
        INSERT INTO principals(
            principal_id, service_id, alias, enabled, created_at_ms, updated_at_ms
        ) VALUES (?, 'firecrawl', 'primary', 1, 0, 0)
        """,
        (str(_PRINCIPAL),),
    )
    connection.executemany(
        """
        INSERT INTO quota_scopes(
            quota_scope_id, principal_id, alias, state, unit,
            last_known_remaining_units, configured_floor_units
        ) VALUES (?, ?, ?, 'HEALTHY', 'credits', NULL, 0)
        """,
        (
            (str(_SCOPE), str(_PRINCIPAL), "primary"),
            (str(_OTHER_SCOPE), str(_PRINCIPAL), "other"),
        ),
    )
    connection.executemany(
        """
        INSERT INTO quota_snapshots(
            snapshot_id, quota_scope_id, remaining_units,
            observed_remaining_units_decimal, unit, captured_at_ms, source
        ) VALUES (?, ?, 100, '100', 'credits', 0, 'lease-fixture')
        """,
        (
            (f"snapshot-{_A}", str(_SCOPE)),
            (f"snapshot-{_B}", str(_OTHER_SCOPE)),
        ),
    )
    connection.executemany(
        """
        UPDATE quota_scopes
           SET last_known_remaining_units = 100,
               balance_as_of_ms = 0,
               balance_snapshot_id = ?
         WHERE quota_scope_id = ?
        """,
        (
            (f"snapshot-{_A}", str(_SCOPE)),
            (f"snapshot-{_B}", str(_OTHER_SCOPE)),
        ),
    )
    connection.execute(
        """
        INSERT INTO credentials(
            credential_id, principal_id, quota_scope_id, alias,
            secret_backend, secret_reference, state, generation,
            exclusive_usage, created_at_ms
        ) VALUES (?, ?, ?, 'primary', 'memory', 'memory://synthetic',
                  'HEALTHY', 1, 1, 0)
        """,
        (str(_CREDENTIAL), str(_PRINCIPAL), str(_SCOPE)),
    )
    connection.executemany(
        """
        INSERT INTO pools(
            pool_id, service_id, alias, state, selection_strategy, automatic_use
        ) VALUES (?, 'firecrawl', ?, 'ACTIVE', 'pinned', 1)
        """,
        ((str(_POOL), "primary"), (str(_OTHER_POOL), "other")),
    )
    connection.execute(
        """
        INSERT INTO pool_members(pool_id, quota_scope_id, priority, cost_rank, enabled)
        VALUES (?, ?, 1, 1, 1)
        """,
        (str(_POOL), str(_SCOPE)),
    )
    return connection


def _candidate(
    *,
    generation: int = 1,
    quota_scope_id: QuotaScopeId = _SCOPE,
    pool_id: PoolId = _POOL,
    state: CredentialState = CredentialState.HEALTHY,
) -> RouteCandidate:
    scope = QuotaScopeSnapshot(
        quota_scope_id=quota_scope_id,
        principal_id=_PRINCIPAL,
        service_id="firecrawl",
        unit="credits",
        last_known_remaining_units=100,
    )
    credential = RoutingCredential(
        credential_id=_CREDENTIAL,
        principal_id=_PRINCIPAL,
        quota_scope_id=quota_scope_id,
        state=state,
        generation=generation,
    )
    return RouteCandidate(
        pool_id=pool_id,
        pool_name="primary",
        service_id="firecrawl",
        scope=scope,
        credential=credential,
        priority=1,
        cost_rank=1,
    )


def _manager(
    connection: sqlite3.Connection,
    lease_id: LeaseId = _LEASE_A,
) -> CredentialLeaseManager:
    return CredentialLeaseManager(
        GatehouseRepository(connection),
        id_factory=lambda: lease_id,
    )


def _lease_count(connection: sqlite3.Connection) -> int:
    return int(connection.execute("SELECT COUNT(*) FROM leases").fetchone()[0])


def _lease_rows(connection: sqlite3.Connection) -> tuple[tuple[object, ...], ...]:
    return tuple(
        tuple(row)
        for row in connection.execute(
            """
            SELECT lease_id, lease_key, owner_id, state, expires_at_ms, released_at_ms
              FROM leases
             ORDER BY lease_id
            """
        ).fetchall()
    )


def test_plan_then_rotation_or_disable_is_fenced_without_a_lease_row(tmp_path: Path) -> None:
    for state, generation in (("DRAINING", 1), ("DISABLED", 2)):
        connection = _open_seeded(tmp_path / f"{state.lower()}.db")
        try:
            planned = _candidate()
            connection.execute(
                "UPDATE credentials SET state = ?, generation = ? WHERE credential_id = ?",
                (state, generation, str(_CREDENTIAL)),
            )

            with pytest.raises(
                CredentialLeaseUnavailableError,
                match="^credential lease is unavailable$",
            ):
                _manager(connection).acquire(
                    candidate=planned,
                    request_id=_REQUEST_A,
                    now_ms=10,
                    expires_at_ms=20,
                )

            assert _lease_count(connection) == 0
        finally:
            connection.close()


@pytest.mark.parametrize("mismatch", ["generation", "scope", "pool"])
def test_wrong_generation_scope_or_pool_is_ineligible_without_insert(
    tmp_path: Path,
    mismatch: str,
) -> None:
    connection = _open_seeded(tmp_path / f"wrong-{mismatch}.db")
    try:
        candidate = _candidate()
        if mismatch == "generation":
            candidate = replace(
                candidate,
                credential=replace(candidate.credential, generation=2),
            )
        elif mismatch == "scope":
            candidate = _candidate(quota_scope_id=_OTHER_SCOPE)
        else:
            candidate = _candidate(pool_id=_OTHER_POOL)

        with pytest.raises(CredentialLeaseUnavailableError):
            _manager(connection).acquire(
                candidate=candidate,
                request_id=_REQUEST_A,
                now_ms=10,
                expires_at_ms=20,
            )

        assert _lease_count(connection) == 0
    finally:
        connection.close()


def test_disabled_membership_or_inactive_pool_is_ineligible(tmp_path: Path) -> None:
    for mutation in ("member", "pool"):
        connection = _open_seeded(tmp_path / f"inactive-{mutation}.db")
        try:
            if mutation == "member":
                connection.execute(
                    "UPDATE pool_members SET enabled = 0 WHERE pool_id = ?",
                    (str(_POOL),),
                )
            else:
                connection.execute(
                    "UPDATE pools SET state = 'DISABLED' WHERE pool_id = ?",
                    (str(_POOL),),
                )

            with pytest.raises(CredentialLeaseUnavailableError):
                _manager(connection).acquire(
                    candidate=_candidate(),
                    request_id=_REQUEST_A,
                    now_ms=10,
                    expires_at_ms=20,
                )
            assert _lease_count(connection) == 0
        finally:
            connection.close()


@pytest.mark.parametrize("corruption", ["principal", "scope", "service"])
def test_final_lease_fence_rejects_ineligible_authority_graph(
    tmp_path: Path,
    corruption: str,
) -> None:
    connection = _open_seeded(tmp_path / f"authority-{corruption}.db")
    try:
        if corruption == "principal":
            connection.execute(
                "UPDATE principals SET enabled = 0 WHERE principal_id = ?",
                (str(_PRINCIPAL),),
            )
        elif corruption == "scope":
            connection.execute(
                "UPDATE quota_scopes SET state = 'QUARANTINED' WHERE quota_scope_id = ?",
                (str(_SCOPE),),
            )
        else:
            connection.execute(
                "UPDATE pools SET service_id = 'wrong-service' WHERE pool_id = ?",
                (str(_POOL),),
            )

        with pytest.raises(CredentialLeaseUnavailableError):
            _manager(connection).acquire(
                candidate=_candidate(),
                request_id=_REQUEST_A,
                now_ms=10,
                expires_at_ms=20,
            )
        assert _lease_count(connection) == 0
    finally:
        connection.close()


def test_draining_requires_explicit_exact_affinity(tmp_path: Path) -> None:
    connection = _open_seeded(tmp_path / "draining.db")
    try:
        connection.execute(
            "UPDATE credentials SET state = 'DRAINING' WHERE credential_id = ?",
            (str(_CREDENTIAL),),
        )
        draining = _candidate(state=CredentialState.DRAINING)

        with pytest.raises(CredentialLeaseUnavailableError):
            _manager(connection).acquire(
                candidate=draining,
                request_id=_REQUEST_A,
                now_ms=10,
                expires_at_ms=20,
            )
        assert _lease_count(connection) == 0

        lease = _manager(connection).acquire(
            candidate=draining,
            request_id=_REQUEST_A,
            now_ms=10,
            expires_at_ms=20,
            exact_affinity=True,
        )
        assert lease.generation == 1
        assert _lease_count(connection) == 1
    finally:
        connection.close()


def test_corrupt_balance_blocks_reconciliation_affinity_without_expiring_prior_lease(
    tmp_path: Path,
) -> None:
    connection = _open_seeded(tmp_path / "corrupt-balance.db")
    try:
        connection.execute("DROP TRIGGER quota_snapshots_observation_immutable")
        connection.execute(
            """
            UPDATE quota_snapshots
               SET observed_remaining_units_decimal = '100.0'
             WHERE quota_scope_id = ?
            """,
            (str(_SCOPE),),
        )
        connection.execute(
            """
            INSERT INTO leases(
                lease_id, lease_type, lease_key, owner_id, state, generation,
                acquired_at_ms, heartbeat_at_ms, expires_at_ms, metadata_json
            ) VALUES (?, 'provider-credential', ?, ?, 'ACTIVE', 1, 0, 0, 5, '{}')
            """,
            (str(_LEASE_A), f"{_CREDENTIAL}:1", str(_REQUEST_A)),
        )
        before = _lease_rows(connection)
        changes_before = connection.total_changes

        result = GatehouseRepository(connection).acquire_credential_lease(
            credential_id=str(_CREDENTIAL),
            credential_generation=1,
            quota_scope_id=str(_SCOPE),
            pool_id=str(_POOL),
            owner_id=str(_REQUEST_B),
            now_ms=10,
            expires_at_ms=20,
            exact_affinity=True,
            reconciliation=True,
            lease_id=str(_LEASE_B),
        )

        assert result.status is LeaseStatus.INELIGIBLE
        assert _lease_rows(connection) == before
        assert connection.total_changes == changes_before
    finally:
        connection.close()


def test_absent_balance_requires_explicit_reconciliation_affinity(tmp_path: Path) -> None:
    connection = _open_seeded(tmp_path / "absent-balance.db")
    try:
        connection.execute(
            """
            UPDATE quota_scopes
               SET last_known_remaining_units = NULL,
                   balance_as_of_ms = NULL,
                   balance_snapshot_id = NULL
             WHERE quota_scope_id = ?
            """,
            (str(_SCOPE),),
        )
        manager = _manager(connection)
        with pytest.raises(CredentialLeaseUnavailableError):
            manager.acquire(
                candidate=_candidate(),
                request_id=_REQUEST_A,
                now_ms=10,
                expires_at_ms=20,
                exact_affinity=True,
            )
        assert _lease_count(connection) == 0

        lease = manager.acquire(
            candidate=_candidate(),
            request_id=_REQUEST_A,
            now_ms=10,
            expires_at_ms=20,
            exact_affinity=True,
            reconciliation=True,
        )
        assert lease.lease_id == _LEASE_A
        assert _lease_count(connection) == 1
    finally:
        connection.close()


def test_generation_fenced_busy_and_expiry_semantics(tmp_path: Path) -> None:
    connection = _open_seeded(tmp_path / "busy.db")
    try:
        candidate = _candidate()
        first = _manager(connection, _LEASE_A).acquire(
            candidate=candidate,
            request_id=_REQUEST_A,
            now_ms=10,
            expires_at_ms=20,
        )
        same_owner = _manager(connection, _LEASE_B).acquire(
            candidate=candidate,
            request_id=_REQUEST_A,
            now_ms=11,
            expires_at_ms=21,
        )
        assert same_owner.lease_id == first.lease_id

        with pytest.raises(CredentialLeaseUnavailableError):
            _manager(connection, _LEASE_B).acquire(
                candidate=candidate,
                request_id=_REQUEST_B,
                now_ms=11,
                expires_at_ms=21,
            )
        assert _lease_count(connection) == 1

        row = connection.execute(
            "SELECT lease_key, metadata_json FROM leases WHERE lease_id = ?",
            (str(_LEASE_A),),
        ).fetchone()
        assert row["lease_key"] == f"{_CREDENTIAL}:1"
        expected_metadata = {
            "credential_id": str(_CREDENTIAL),
            "credential_generation": 1,
            "quota_scope_id": str(_SCOPE),
            "pool_id": str(_POOL),
        }
        assert expected_metadata.items() <= json.loads(str(row["metadata_json"])).items()

        replacement = _manager(connection, _LEASE_B).acquire(
            candidate=candidate,
            request_id=_REQUEST_B,
            now_ms=20,
            expires_at_ms=30,
        )
        assert replacement.lease_id == _LEASE_B
        assert (
            connection.execute(
                "SELECT state FROM leases WHERE lease_id = ?",
                (str(_LEASE_A),),
            ).fetchone()[0]
            == "EXPIRED"
        )
        assert (
            connection.execute("SELECT COUNT(*) FROM leases WHERE state = 'ACTIVE'").fetchone()[0]
            == 1
        )
    finally:
        connection.close()


def test_repository_returns_distinct_ineligible_status(tmp_path: Path) -> None:
    connection = _open_seeded(tmp_path / "status.db")
    try:
        result = GatehouseRepository(connection).acquire_credential_lease(
            credential_id=str(_CREDENTIAL),
            credential_generation=2,
            quota_scope_id=str(_SCOPE),
            pool_id=str(_POOL),
            owner_id=str(_REQUEST_A),
            now_ms=10,
            expires_at_ms=20,
            lease_id=str(_LEASE_A),
        )
        assert result.status is LeaseStatus.INELIGIBLE
        assert not result.acquired
        assert _lease_count(connection) == 0
    finally:
        connection.close()


def test_active_prior_generation_blocks_same_logical_credential(tmp_path: Path) -> None:
    connection = _open_seeded(tmp_path / "prior-generation.db")
    try:
        connection.execute(
            "UPDATE credentials SET generation = 2 WHERE credential_id = ?",
            (str(_CREDENTIAL),),
        )
        connection.execute(
            """
            INSERT INTO leases(
                lease_id, lease_type, lease_key, owner_id, state, generation,
                acquired_at_ms, heartbeat_at_ms, expires_at_ms, metadata_json
            ) VALUES (?, 'provider-credential', ?, ?, 'ACTIVE', 1, 1, 1, 30, '{}')
            """,
            (str(_LEASE_A), f"{_CREDENTIAL}:1", str(_REQUEST_A)),
        )

        result = GatehouseRepository(connection).acquire_credential_lease(
            credential_id=str(_CREDENTIAL),
            credential_generation=2,
            quota_scope_id=str(_SCOPE),
            pool_id=str(_POOL),
            owner_id=str(_REQUEST_B),
            now_ms=10,
            expires_at_ms=20,
            lease_id=str(_LEASE_B),
        )

        assert result.status is LeaseStatus.BUSY
        assert _lease_count(connection) == 1
    finally:
        connection.close()
