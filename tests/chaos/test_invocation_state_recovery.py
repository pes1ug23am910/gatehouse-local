from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from pathlib import Path

import pytest

from gatehouse.database import open_migrated_database, recover_startup


@pytest.fixture
def recovery_database(tmp_path: Path) -> Iterator[sqlite3.Connection]:
    connection = open_migrated_database(tmp_path / "invocation-state-recovery.db")
    connection.execute(
        """
        INSERT INTO clients(
            client_id, display_name, kind, policy_profile, created_at_ms, updated_at_ms
        ) VALUES ('client', 'Client', 'test', 'default', 0, 0)
        """
    )
    connection.execute(
        """
        INSERT INTO sessions(
            session_id, client_id, bootstrap_verifier, bootstrap_version, token_epoch,
            state, identity_assurance, policy_version, created_at_ms,
            reconnect_until_ms, absolute_expires_at_ms
        ) VALUES ('session', 'client', X'01', 1, 0, 'ACTIVE', 'TEST', 'v1',
                  0, 1000, 1000)
        """
    )
    connection.execute(
        """
        INSERT INTO root_runs(
            root_run_id, session_id, state, started_at_ms, budget_json, consumed_json
        ) VALUES ('root-run', 'session', 'ACTIVE', 0, '{"credits":100}', '{}')
        """
    )
    connection.execute(
        """
        INSERT INTO principals(
            principal_id, service_id, alias, created_at_ms, updated_at_ms
        ) VALUES ('principal', 'service', 'primary', 0, 0)
        """
    )
    connection.execute(
        """
        INSERT INTO quota_scopes(
            quota_scope_id, principal_id, alias, state, unit,
            last_known_remaining_units, configured_floor_units
        ) VALUES ('quota', 'principal', 'primary', 'HEALTHY', 'credits', 100, 0)
        """
    )
    yield connection
    connection.close()


def _insert_invocation(connection: sqlite3.Connection, request_id: str, state: str) -> None:
    connection.execute(
        """
        INSERT INTO invocations(
            request_id, session_id, root_run_id, service_id, operation, request_fingerprint,
            fingerprint_version, canonicalization_version, state, priority_class,
            request_size_bytes, received_at_ms
        ) VALUES (?, 'session', 'root-run', 'service', 'read', X'AA', 1, 1, ?,
                  'NORMAL_AGENT', 1, 0)
        """,
        (request_id, state),
    )


def _insert_expired_claim(
    connection: sqlite3.Connection,
    request_id: str,
) -> None:
    connection.execute(
        """
        INSERT INTO queue_entries(
            queue_id, request_id, state, priority_class, session_id, service_id,
            operation, enqueued_at_ms, deadline_ms, claimed_at_ms, claim_owner,
            claim_expires_at_ms
        ) VALUES (?, ?, 'CLAIMED', 'NORMAL_AGENT', 'session', 'service', 'read',
                  0, 90, 10, 'dead-worker', 80)
        """,
        (f"queue-{request_id}", request_id),
    )


def _insert_expired_reservation(
    connection: sqlite3.Connection,
    request_id: str,
) -> None:
    connection.execute(
        """
        INSERT INTO quota_reservations(
            reservation_id, request_id, quota_scope_id, amount_units, unit,
            state, created_at_ms, expires_at_ms
        ) VALUES (?, ?, 'quota', 10, 'credits', 'ACTIVE', 10, 90)
        """,
        (f"reservation-{request_id}", request_id),
    )


def _insert_budget_reservation(
    connection: sqlite3.Connection,
    request_id: str,
) -> None:
    connection.execute(
        """
        INSERT INTO budget_reservations(
            budget_reservation_id, request_id, root_run_id, amount_units,
            unit, state, created_at_ms
        ) VALUES (?, ?, 'root-run', 10, 'credits', 'ACTIVE', 10)
        """,
        (f"budget-{request_id}", request_id),
    )


def _invocation_outcome(
    connection: sqlite3.Connection,
    request_id: str,
) -> tuple[str, str | None, int | None]:
    row = connection.execute(
        """
        SELECT state, error_code, completed_at_ms
          FROM invocations
         WHERE request_id = ?
        """,
        (request_id,),
    ).fetchone()
    assert row is not None
    return str(row["state"]), row["error_code"], row["completed_at_ms"]


def _reservation_outcome(
    connection: sqlite3.Connection,
    request_id: str,
) -> tuple[str, int | None, int | None]:
    row = connection.execute(
        """
        SELECT state, actual_units, reconciled_at_ms
          FROM quota_reservations
         WHERE request_id = ?
        """,
        (request_id,),
    ).fetchone()
    assert row is not None
    return str(row["state"]), row["actual_units"], row["reconciled_at_ms"]


def test_expired_claim_cannot_overwrite_ambiguous_running_outcome(
    recovery_database: sqlite3.Connection,
) -> None:
    request_id = "request-running"
    _insert_invocation(recovery_database, request_id, "RUNNING")
    _insert_expired_claim(recovery_database, request_id)
    _insert_budget_reservation(recovery_database, request_id)
    recovery_database.execute(
        """
        INSERT INTO attempts(
            attempt_id, request_id, ordinal, state, started_at_ms
        ) VALUES ('attempt-running', ?, 1, 'RUNNING', 20)
        """,
        (request_id,),
    )

    recover_startup(recovery_database, now_ms=100)

    outcome = _invocation_outcome(recovery_database, request_id)
    assert outcome == ("UNKNOWN", "uncertain_outcome", 100)
    attempt = recovery_database.execute(
        """
        SELECT state, error_class, completed_at_ms
          FROM attempts
         WHERE attempt_id = 'attempt-running'
        """
    ).fetchone()
    assert attempt is not None
    assert tuple(attempt) == ("UNKNOWN", "daemon_restart", 100)
    assert (
        recovery_database.execute(
            "SELECT state FROM queue_entries WHERE request_id = ?",
            (request_id,),
        ).fetchone()[0]
        == "EXPIRED"
    )
    assert (
        recovery_database.execute(
            "SELECT state FROM budget_reservations WHERE request_id = ?",
            (request_id,),
        ).fetchone()[0]
        == "PENDING_RECONCILIATION"
    )


def test_expired_queued_request_releases_known_unused_quota(
    recovery_database: sqlite3.Connection,
) -> None:
    request_id = "request-queued"
    _insert_invocation(recovery_database, request_id, "QUEUED")
    _insert_expired_claim(recovery_database, request_id)
    _insert_expired_reservation(recovery_database, request_id)
    _insert_budget_reservation(recovery_database, request_id)

    recover_startup(recovery_database, now_ms=100)

    assert _invocation_outcome(recovery_database, request_id) == (
        "CAPACITY_EXCEEDED",
        "capacity_exceeded",
        100,
    )
    reservation = _reservation_outcome(recovery_database, request_id)
    assert reservation == ("RECONCILED", 0, 100)
    assert tuple(
        recovery_database.execute(
            """
            SELECT state, actual_units, reconciled_at_ms
              FROM budget_reservations WHERE request_id = ?
            """,
            (request_id,),
        ).fetchone()
    ) == ("RECONCILED", 0, 100)


@pytest.mark.parametrize(
    "checkpoint",
    ["DEDUPLICATION", "QUOTA_RESERVED", "DISPATCHING", "RETRY_WAIT"],
)
def test_expired_predispatch_reservation_fails_closed_and_releases_quota(
    recovery_database: sqlite3.Connection,
    checkpoint: str,
) -> None:
    request_id = f"request-{checkpoint.lower()}"
    _insert_invocation(recovery_database, request_id, checkpoint)
    _insert_expired_reservation(recovery_database, request_id)
    _insert_budget_reservation(recovery_database, request_id)

    recover_startup(recovery_database, now_ms=100)

    assert _invocation_outcome(recovery_database, request_id) == (
        "FAILED",
        "daemon_restart_before_dispatch",
        100,
    )
    assert _reservation_outcome(recovery_database, request_id) == (
        "RECONCILED",
        0,
        100,
    )
    assert tuple(
        recovery_database.execute(
            """
            SELECT state, actual_units, reconciled_at_ms
              FROM budget_reservations WHERE request_id = ?
            """,
            (request_id,),
        ).fetchone()
    ) == ("RECONCILED", 0, 100)

    # Startup recovery is idempotent for already terminal requests and settled quota.
    recover_startup(recovery_database, now_ms=101)
    assert _invocation_outcome(recovery_database, request_id) == (
        "FAILED",
        "daemon_restart_before_dispatch",
        100,
    )
    assert _reservation_outcome(recovery_database, request_id) == (
        "RECONCILED",
        0,
        100,
    )
