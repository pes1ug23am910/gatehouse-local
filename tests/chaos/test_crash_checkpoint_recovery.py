from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from pathlib import Path

import pytest

from gatehouse.database import (
    AsyncCheckpointRecoveryError,
    open_migrated_database,
    recover_startup,
)


@pytest.fixture
def crash_database(tmp_path: Path) -> Iterator[sqlite3.Connection]:
    connection = open_migrated_database(tmp_path / "crash.db")
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
        ) VALUES ('session', 'client', X'01', 1, 0, 'ACTIVE', 'TEST', 'v1', 0, 1000, 1000)
        """
    )
    connection.execute(
        """
        INSERT INTO principals(principal_id, service_id, alias, created_at_ms, updated_at_ms)
        VALUES ('principal', 'firecrawl', 'primary', 0, 0)
        """
    )
    connection.execute(
        """
        INSERT INTO quota_scopes(
            quota_scope_id, principal_id, alias, state, unit,
            last_known_remaining_units, configured_floor_units
        ) VALUES ('quota', 'principal', 'main', 'HEALTHY', 'credits', 100, 0)
        """
    )
    connection.execute(
        """
        INSERT INTO credentials(
            credential_id, principal_id, quota_scope_id, alias, secret_backend,
            secret_reference, state, created_at_ms
        ) VALUES ('credential', 'principal', 'quota', 'primary', 'memory',
                  'opaque-reference', 'ACTIVE', 0)
        """
    )
    states = {
        "queued": "QUEUED",
        "reserved-expired": "QUEUED",
        "reserved-live": "QUEUED",
        "submitted": "RUNNING",
        "async-job": "SUCCEEDED",
    }
    for name, state in states.items():
        connection.execute(
            """
            INSERT INTO invocations(
                request_id, session_id, service_id, operation, request_fingerprint,
                fingerprint_version, canonicalization_version, state, priority_class,
                request_size_bytes, received_at_ms
            ) VALUES (?, 'session', 'firecrawl', 'scrape', X'AA', 1, 1, ?,
                      'NORMAL_AGENT', 1, 0)
            """,
            (f"request-{name}", state),
        )
    connection.execute(
        """
        INSERT INTO queue_entries(
            queue_id, request_id, state, priority_class, session_id, service_id,
            operation, enqueued_at_ms, deadline_ms, claimed_at_ms, claim_owner,
            claim_expires_at_ms
        ) VALUES ('queue-queued', 'request-queued', 'CLAIMED', 'NORMAL_AGENT',
                  'session', 'firecrawl', 'scrape', 0, 1000, 10, 'dead-worker', 50)
        """
    )
    connection.execute(
        """
        INSERT INTO queue_entries(
            queue_id, request_id, state, priority_class, session_id, service_id,
            operation, enqueued_at_ms, deadline_ms, claimed_at_ms, claim_owner,
            claim_expires_at_ms
        ) VALUES ('queue-submitted', 'request-submitted', 'CLAIMED', 'NORMAL_AGENT',
                  'session', 'firecrawl', 'scrape', 0, 1000, 10, 'dead-worker', 50)
        """
    )
    for suffix, expires_at_ms in (("expired", 50), ("live", 500)):
        connection.execute(
            """
            INSERT INTO quota_reservations(
                reservation_id, request_id, quota_scope_id, amount_units, unit,
                state, created_at_ms, expires_at_ms
            ) VALUES (?, ?, 'quota', 10, 'credits', 'ACTIVE', 10, ?)
            """,
            (
                f"reservation-{suffix}",
                f"request-reserved-{suffix}",
                expires_at_ms,
            ),
        )
    connection.execute(
        """
        INSERT INTO attempts(
            attempt_id, request_id, ordinal, credential_id, principal_id,
            quota_scope_id, state, estimated_cost_units, cost_unit, started_at_ms
        ) VALUES ('attempt-submitted', 'request-submitted', 1, 'credential',
                  'principal', 'quota', 'RUNNING', 1, 'credits', 20)
        """
    )
    connection.execute(
        """
        INSERT INTO jobs(
            job_id, request_id, service_id, operation, state, provider_job_id,
            principal_id, quota_scope_id, credential_id, created_at_ms
        ) VALUES ('job', 'request-async-job', 'firecrawl', 'crawl.start', 'RUNNING',
                  'provider-job-1', 'principal', 'quota', 'credential', 20)
        """
    )
    yield connection
    connection.close()


def test_crash_checkpoints_recover_without_replay_or_quota_release(
    crash_database: sqlite3.Connection,
) -> None:
    report = recover_startup(crash_database, now_ms=100)
    assert report.queue_entries_requeued == 1
    assert report.queue_entries_flagged == 1
    assert report.invocations_unknown == 1
    assert report.attempts_unknown == 1
    assert report.invocations_failed_before_dispatch == 1
    assert report.reservations_released_without_usage == 1
    assert report.reservations_pending_reconciliation == 0
    assert report.jobs_recovering == 1

    queue_rows = {
        str(row["queue_id"]): str(row["state"])
        for row in crash_database.execute("SELECT queue_id, state FROM queue_entries")
    }
    assert queue_rows == {
        "queue-queued": "QUEUED",
        "queue-submitted": "RECOVERY_REQUIRED",
    }
    assert (
        crash_database.execute(
            "SELECT state FROM invocations WHERE request_id = 'request-submitted'"
        ).fetchone()[0]
        == "UNKNOWN"
    )
    attempt = crash_database.execute(
        "SELECT state, error_class FROM attempts WHERE attempt_id = 'attempt-submitted'"
    ).fetchone()
    assert tuple(attempt) == ("UNKNOWN", "daemon_restart")
    reservations = {
        str(row["reservation_id"]): (str(row["state"]), row["actual_units"])
        for row in crash_database.execute(
            "SELECT reservation_id, state, actual_units FROM quota_reservations"
        )
    }
    assert reservations == {
        "reservation-expired": ("RECONCILED", 0),
        "reservation-live": ("ACTIVE", None),
    }
    assert (
        crash_database.execute("SELECT state FROM jobs WHERE job_id = 'job'").fetchone()[0]
        == "RECOVERING"
    )

    # Recovery is conservative and idempotent for all ambiguous external outcomes.
    again = recover_startup(crash_database, now_ms=101)
    assert again.invocations_unknown == 0
    assert again.attempts_unknown == 0
    assert again.invocations_failed_before_dispatch == 0
    assert again.reservations_released_without_usage == 0
    assert again.reservations_pending_reconciliation == 0
    assert again.jobs_recovering == 0


def _seed_async_success_checkpoint(connection: sqlite3.Connection) -> None:
    connection.executescript(
        """
        INSERT INTO clients(
            client_id, display_name, kind, policy_profile,
            created_at_ms, updated_at_ms
        ) VALUES ('client-checkpoint', 'Checkpoint client', 'test', 'default', 0, 0);
        INSERT INTO workspaces(
            workspace_id, display_name, canonical_root,
            created_at_ms, updated_at_ms
        ) VALUES ('workspace-checkpoint', 'Checkpoint workspace',
                  'E:\\Checkpoint', 0, 0);
        INSERT INTO sessions(
            session_id, client_id, workspace_id, bootstrap_verifier,
            bootstrap_version, token_epoch, state, identity_assurance,
            policy_version, created_at_ms, reconnect_until_ms,
            absolute_expires_at_ms
        ) VALUES ('session-checkpoint', 'client-checkpoint',
                  'workspace-checkpoint', X'01', 1, 0, 'ACTIVE', 'TEST',
                  'v1', 0, 1000, 1000);
        INSERT INTO root_runs(root_run_id, session_id, state, started_at_ms)
        VALUES ('root-checkpoint', 'session-checkpoint', 'ACTIVE', 0);
        INSERT INTO principals(
            principal_id, service_id, alias, created_at_ms, updated_at_ms
        ) VALUES ('principal-checkpoint', 'firecrawl', 'primary', 0, 0);
        INSERT INTO quota_scopes(
            quota_scope_id, principal_id, alias, state, unit,
            configured_floor_units
        ) VALUES ('quota-checkpoint', 'principal-checkpoint', 'main',
                  'HEALTHY', 'credits', 0);
        INSERT INTO credentials(
            credential_id, principal_id, quota_scope_id, alias,
            secret_backend, secret_reference, state, generation, created_at_ms
        ) VALUES ('credential-checkpoint', 'principal-checkpoint',
                  'quota-checkpoint', 'primary', 'memory',
                  'opaque-checkpoint-reference', 'ACTIVE', 3, 0);
        INSERT INTO pools(
            pool_id, service_id, alias, state, selection_strategy
        ) VALUES ('pool-checkpoint', 'firecrawl', 'interactive-default',
                  'ACTIVE', 'cheapest_first');
        INSERT INTO pool_members(pool_id, quota_scope_id, enabled)
        VALUES ('pool-checkpoint', 'quota-checkpoint', 1);
        INSERT INTO invocations(
            request_id, session_id, root_run_id, service_id, operation,
            request_fingerprint, fingerprint_version,
            canonicalization_version, state, priority_class,
            request_size_bytes, queue_deadline_ms, received_at_ms,
            started_at_ms
        ) VALUES ('request-checkpoint', 'session-checkpoint',
                  'root-checkpoint', 'firecrawl', 'firecrawl.crawl.start',
                  X'AA', 1, 1, 'RUNNING', 'NORMAL_AGENT', 1, 1000, 10, 20);
        INSERT INTO queue_entries(
            queue_id, request_id, state, priority_class, session_id,
            root_run_id, service_id, operation, enqueued_at_ms, deadline_ms,
            claimed_at_ms, claim_owner, claim_expires_at_ms
        ) VALUES ('queue-checkpoint', 'request-checkpoint', 'CLAIMED',
                  'NORMAL_AGENT', 'session-checkpoint', 'root-checkpoint',
                  'firecrawl', 'firecrawl.crawl.start', 15, 1000, 20,
                  'dead-worker', 1000);
        INSERT INTO attempts(
            attempt_id, request_id, ordinal, credential_id, principal_id,
            quota_scope_id, state, error_class, started_at_ms,
            completed_at_ms, resource_type, provider_resource_id,
            credential_generation, pool_id
        ) VALUES ('attempt-checkpoint', 'request-checkpoint', 1,
                  'credential-checkpoint', 'principal-checkpoint',
                  'quota-checkpoint', 'SUCCEEDED', 'none', 20, 50,
                  'crawl', 'provider-job-checkpoint', 3, 'pool-checkpoint');
        """
    )


def test_restart_reconstructs_resource_from_terminal_attempt_checkpoint(
    tmp_path: Path,
) -> None:
    connection = open_migrated_database(tmp_path / "async-attempt-crash.db")
    try:
        _seed_async_success_checkpoint(connection)

        report = recover_startup(connection, now_ms=100)

        assert report.async_invocations_recovered == 1
        invocation = connection.execute(
            """
            SELECT state, completed_at_ms
              FROM invocations WHERE request_id = 'request-checkpoint'
            """
        ).fetchone()
        assert tuple(invocation) == ("SUCCEEDED", 100)
        resource = connection.execute(
            """
            SELECT service_id, resource_type, provider_resource_id,
                   principal_id, quota_scope_id, credential_id,
                   credential_generation, pool_id, creating_request_id,
                   owner_session_id, owner_workspace_id, owner_root_run_id,
                   state, created_at_ms
              FROM external_resources
            """
        ).fetchone()
        assert tuple(resource) == (
            "firecrawl",
            "crawl",
            "provider-job-checkpoint",
            "principal-checkpoint",
            "quota-checkpoint",
            "credential-checkpoint",
            3,
            "pool-checkpoint",
            "request-checkpoint",
            "session-checkpoint",
            "workspace-checkpoint",
            "root-checkpoint",
            "ACTIVE",
            50,
        )
        queue = connection.execute(
            """
            SELECT state, claim_owner, claim_expires_at_ms
              FROM queue_entries WHERE request_id = 'request-checkpoint'
            """
        ).fetchone()
        assert tuple(queue) == ("SUCCEEDED", None, None)
        assert recover_startup(connection, now_ms=101).async_invocations_recovered == 0
        assert connection.execute("SELECT COUNT(*) FROM external_resources").fetchone()[0] == 1
    finally:
        connection.close()


def test_restart_recovers_unknown_after_online_affinity_bind_failure(
    tmp_path: Path,
) -> None:
    connection = open_migrated_database(tmp_path / "async-attempt-online-failure.db")
    try:
        _seed_async_success_checkpoint(connection)
        connection.execute(
            """
            UPDATE invocations
               SET state = 'UNKNOWN', error_code = 'uncertain_outcome',
                   completed_at_ms = 60
             WHERE request_id = 'request-checkpoint'
            """
        )

        report = recover_startup(connection, now_ms=100)

        assert report.async_invocations_recovered == 1
        invocation = connection.execute(
            """
            SELECT state, error_code FROM invocations
             WHERE request_id = 'request-checkpoint'
            """
        ).fetchone()
        assert tuple(invocation) == ("SUCCEEDED", None)
        resource = connection.execute(
            """
            SELECT provider_resource_id, creating_request_id
              FROM external_resources
            """
        ).fetchone()
        assert tuple(resource) == ("provider-job-checkpoint", "request-checkpoint")
        assert (
            connection.execute(
                "SELECT state FROM queue_entries WHERE request_id = 'request-checkpoint'"
            ).fetchone()[0]
            == "SUCCEEDED"
        )
    finally:
        connection.close()


def test_restart_fails_closed_on_checkpoint_authority_corruption(
    tmp_path: Path,
) -> None:
    connection = open_migrated_database(tmp_path / "async-attempt-corrupt.db")
    try:
        _seed_async_success_checkpoint(connection)
        connection.execute(
            """
            UPDATE credentials SET generation = 4
             WHERE credential_id = 'credential-checkpoint'
            """
        )
        original_epoch = connection.execute(
            "SELECT token_epoch FROM system_state WHERE singleton_id = 1"
        ).fetchone()[0]

        with pytest.raises(
            AsyncCheckpointRecoveryError,
            match="routing authority",
        ):
            recover_startup(connection, now_ms=100)

        assert (
            connection.execute(
                "SELECT token_epoch FROM system_state WHERE singleton_id = 1"
            ).fetchone()[0]
            == original_epoch
        )
        assert (
            connection.execute(
                "SELECT state FROM invocations WHERE request_id = 'request-checkpoint'"
            ).fetchone()[0]
            == "RUNNING"
        )
        assert connection.execute("SELECT COUNT(*) FROM external_resources").fetchone()[0] == 0
    finally:
        connection.close()


def test_restart_fails_closed_on_conflicting_resource_binding(tmp_path: Path) -> None:
    connection = open_migrated_database(tmp_path / "async-attempt-conflict.db")
    try:
        _seed_async_success_checkpoint(connection)
        connection.execute(
            """
            INSERT INTO external_resources(
                resource_id, service_id, resource_type, provider_resource_id,
                principal_id, quota_scope_id, credential_id,
                credential_generation, pool_id, creating_request_id,
                owner_session_id, owner_workspace_id, owner_root_run_id,
                state, created_at_ms, updated_at_ms
            ) VALUES ('conflicting-resource', 'firecrawl', 'crawl',
                      'provider-job-checkpoint', 'principal-checkpoint',
                      'quota-checkpoint', 'credential-checkpoint', 4,
                      'pool-checkpoint', 'request-checkpoint',
                      'session-checkpoint', 'workspace-checkpoint',
                      'root-checkpoint', 'ACTIVE', 50, 50)
            """
        )

        with pytest.raises(
            AsyncCheckpointRecoveryError,
            match="conflicts with an existing provider resource",
        ):
            recover_startup(connection, now_ms=100)

        assert (
            connection.execute(
                "SELECT state FROM invocations WHERE request_id = 'request-checkpoint'"
            ).fetchone()[0]
            == "RUNNING"
        )
    finally:
        connection.close()
