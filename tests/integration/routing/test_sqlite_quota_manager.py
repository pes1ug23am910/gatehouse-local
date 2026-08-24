from __future__ import annotations

from pathlib import Path

from gatehouse.core.ids import CredentialId, PoolId, PrincipalId, QuotaScopeId, RequestId
from gatehouse.database import GatehouseRepository, open_migrated_database
from gatehouse.routing import (
    NamedPool,
    NamedPoolRouter,
    PoolMember,
    PoolSelectionStrategy,
    QuotaReservationManager,
    QuotaScopeSnapshot,
    RoutingCredential,
)

_A = "00000000000000000000000001"
_B = "00000000000000000000000002"


def seed(connection: object) -> None:
    import sqlite3

    assert isinstance(connection, sqlite3.Connection)
    connection.execute(
        "INSERT INTO clients(client_id, display_name, kind, policy_profile, "
        "created_at_ms, updated_at_ms) VALUES ('client', 'Client', 'interactive', "
        "'default', 0, 0)"
    )
    connection.execute(
        "INSERT INTO workspaces(workspace_id, display_name, canonical_root, "
        "created_at_ms, updated_at_ms) VALUES ('workspace', 'Workspace', "
        "'E:\\Workspace', 0, 0)"
    )
    connection.execute(
        "INSERT INTO sessions(session_id, client_id, workspace_id, bootstrap_verifier, "
        "bootstrap_version, token_epoch, state, identity_assurance, policy_version, "
        "created_at_ms, reconnect_until_ms, absolute_expires_at_ms) VALUES "
        "('session', 'client', 'workspace', X'01', 1, 0, 'ACTIVE', 'TEST', 'v1', "
        "0, 100000, 100000)"
    )
    for suffix, remaining in ((_A, 12), (_B, 100)):
        connection.execute(
            "INSERT INTO principals(principal_id, service_id, alias, created_at_ms, "
            "updated_at_ms) VALUES (?, 'service', ?, 0, 0)",
            (f"prn_{suffix}", suffix),
        )
        connection.execute(
            "INSERT INTO quota_scopes(quota_scope_id, principal_id, alias, state, "
            "unit, last_known_remaining_units, configured_floor_units) VALUES "
            "(?, ?, ?, 'HEALTHY', 'credits', NULL, 10)",
            (f"quota_{suffix}", f"prn_{suffix}", suffix),
        )
        connection.execute(
            "INSERT INTO credentials(credential_id, principal_id, quota_scope_id, alias, "
            "secret_backend, secret_reference, state, generation, created_at_ms, "
            "credential_role) VALUES (?, ?, ?, ?, 'test', ?, 'HEALTHY', 1, 0, 'OBSERVER')",
            (
                f"observer_{suffix}",
                f"prn_{suffix}",
                f"quota_{suffix}",
                f"observer-{suffix}",
                f"reference-{suffix}",
            ),
        )
        connection.execute(
            "INSERT INTO quota_snapshots(snapshot_id, quota_scope_id, remaining_units, "
            "unit, captured_at_ms, source, observed_remaining_units_decimal, "
            "quota_dimension_id, credential_id, credential_generation, stale_at_ms, "
            "observation_kind) VALUES (?, ?, ?, 'credits', 0, 'integration-test', ?, "
            "?, ?, 1, 9223372036854775807, 'AUTHENTICATED')",
            (
                f"snapshot-{suffix}",
                f"quota_{suffix}",
                remaining,
                str(remaining),
                f"dimension_legacy_primary:quota_{suffix}",
                f"observer_{suffix}",
            ),
        )
        connection.execute(
            "UPDATE quota_scopes SET last_known_remaining_units = ?, "
            "balance_as_of_ms = 0, balance_snapshot_id = ? WHERE quota_scope_id = ?",
            (remaining, f"snapshot-{suffix}", f"quota_{suffix}"),
        )
    connection.execute(
        "INSERT INTO invocations(request_id, session_id, service_id, operation, "
        "request_fingerprint, fingerprint_version, canonicalization_version, state, "
        "priority_class, request_size_bytes, received_at_ms) VALUES "
        "(?, 'session', 'service', 'service.read', X'AA', 1, 1, 'QUEUED', "
        "'INTERACTIVE', 10, 0)",
        (f"req_{_A}",),
    )


def routing_plan() -> object:
    members = []
    for suffix in (_A, _B):
        principal = PrincipalId(f"prn_{suffix}")
        scope = QuotaScopeId(f"quota_{suffix}")
        members.append(
            PoolMember(
                QuotaScopeSnapshot(
                    scope,
                    principal,
                    "service",
                    "credits",
                    last_known_remaining_units=100,
                    configured_floor_units=10,
                ),
                (RoutingCredential(CredentialId(f"cred_{suffix}"), principal, scope),),
                cost_rank=1 if suffix == _A else 2,
            )
        )
    pool = NamedPool(
        PoolId(f"pool_{_A}"),
        "default",
        "service",
        PoolSelectionStrategy.CHEAPEST_FIRST,
        tuple(members),
        minimum_remaining_floor_units=10,
    )
    return NamedPoolRouter([pool]).plan(
        service_id="service",
        operation="service.read",
        pool_name="default",
        estimated_cost_units=5,
        unit="credits",
        now_ms=1,
    )


def test_manager_falls_through_after_atomic_floor_check(tmp_path: Path) -> None:
    from gatehouse.routing import RoutingPlan

    connection = open_migrated_database(tmp_path / "gatehouse.db")
    try:
        seed(connection)
        manager = QuotaReservationManager(GatehouseRepository(connection))
        plan = routing_plan()
        assert isinstance(plan, RoutingPlan)

        grant = manager.reserve(
            plan=plan,
            request_id=RequestId(f"req_{_A}"),
            now_ms=1,
            expires_at_ms=1_000,
        )

        assert grant.reservation is not None
        assert grant.reservation.quota_scope_id == QuotaScopeId(f"quota_{_B}")
        row = connection.execute("SELECT quota_scope_id, state FROM quota_reservations").fetchone()
        assert tuple(row) == (f"quota_{_B}", "ACTIVE")

        held = manager.hold_for_reconciliation(grant.reservation, now_ms=2)
        assert held.state.value == "PENDING_RECONCILIATION"
        state = connection.execute(
            "SELECT state FROM quota_reservations WHERE reservation_id = ?",
            (grant.reservation.reservation_id,),
        ).fetchone()[0]
        assert state == "PENDING_RECONCILIATION"

        reconciled = manager.reconcile_known(held, actual_units=3, now_ms=3)
        assert reconciled.state.value == "RECONCILED"
        assert reconciled.actual_units == 3
        persisted = connection.execute(
            """
            SELECT state, actual_units FROM quota_reservations
             WHERE reservation_id = ?
            """,
            (grant.reservation.reservation_id,),
        ).fetchone()
        assert tuple(persisted) == ("RECONCILED", 3)
    finally:
        connection.close()
