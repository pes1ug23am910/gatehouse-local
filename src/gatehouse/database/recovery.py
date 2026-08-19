"""Conservative startup recovery transitions for durable Gatehouse state."""

from __future__ import annotations

import hashlib
import sqlite3
from dataclasses import dataclass

from .connection import transaction

_ASYNC_RESOURCE_TYPES = {"firecrawl.crawl.start": "crawl"}


class AsyncCheckpointRecoveryError(RuntimeError):
    """A durable provider-success checkpoint cannot be safely reconstructed."""


def _bounded_text(value: object, *, field: str, maximum: int) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise AsyncCheckpointRecoveryError(f"async checkpoint {field} is invalid")
    return value


def _positive_integer(value: object, *, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise AsyncCheckpointRecoveryError(f"async checkpoint {field} is invalid")
    return value


def _recover_async_attempt_checkpoints(connection: sqlite3.Connection) -> None:
    """Materialize exact resource affinity after a crash before ``bind``.

    Only complete terminal checkpoints are candidates. Legacy successful attempts
    with no checkpoint remain governed by the pre-existing external-resource
    recovery path; a partial or contradictory checkpoint is startup-fatal.
    """

    rows = connection.execute(
        """
        SELECT a.attempt_id, a.request_id, a.state AS attempt_state,
               a.error_class, a.credential_id, a.principal_id,
               a.quota_scope_id, a.resource_type, a.provider_resource_id,
               a.credential_generation, a.pool_id, a.completed_at_ms,
               i.service_id, i.operation, i.session_id, i.root_run_id,
               s.workspace_id, rr.session_id AS root_session_id,
               c.principal_id AS credential_principal_id,
               c.quota_scope_id AS credential_quota_scope_id,
               c.generation AS current_credential_generation,
               q.principal_id AS quota_principal_id,
               p.service_id AS principal_service_id,
               pl.service_id AS pool_service_id,
               pm.quota_scope_id AS member_quota_scope_id
          FROM attempts AS a
          JOIN invocations AS i ON i.request_id = a.request_id
          LEFT JOIN sessions AS s ON s.session_id = i.session_id
          LEFT JOIN root_runs AS rr ON rr.root_run_id = i.root_run_id
          LEFT JOIN credentials AS c ON c.credential_id = a.credential_id
          LEFT JOIN quota_scopes AS q ON q.quota_scope_id = a.quota_scope_id
          LEFT JOIN principals AS p ON p.principal_id = a.principal_id
          LEFT JOIN pools AS pl ON pl.pool_id = a.pool_id
          LEFT JOIN pool_members AS pm
            ON pm.pool_id = a.pool_id
           AND pm.quota_scope_id = a.quota_scope_id
         WHERE i.state IN ('RUNNING', 'UNKNOWN')
           AND (
               a.resource_type IS NOT NULL
               OR a.provider_resource_id IS NOT NULL
               OR a.credential_generation IS NOT NULL
               OR a.pool_id IS NOT NULL
           )
         ORDER BY a.request_id, a.ordinal
        """
    ).fetchall()
    seen_requests: set[str] = set()
    for row in rows:
        request_id = _bounded_text(row["request_id"], field="request_id", maximum=128)
        if request_id in seen_requests:
            raise AsyncCheckpointRecoveryError("async invocation has multiple resource checkpoints")
        seen_requests.add(request_id)

        if str(row["attempt_state"]) != "SUCCEEDED" or str(row["error_class"]) != "none":
            raise AsyncCheckpointRecoveryError(
                "async resource checkpoint is not a successful terminal attempt"
            )
        operation = _bounded_text(row["operation"], field="operation", maximum=128)
        expected_resource_type = _ASYNC_RESOURCE_TYPES.get(operation)
        if expected_resource_type is None:
            raise AsyncCheckpointRecoveryError(
                "async resource checkpoint belongs to an unsupported operation"
            )
        service_id = _bounded_text(row["service_id"], field="service_id", maximum=64)
        resource_type = _bounded_text(row["resource_type"], field="resource_type", maximum=64)
        if resource_type != expected_resource_type:
            raise AsyncCheckpointRecoveryError(
                "async resource checkpoint type contradicts its operation"
            )
        provider_resource_id = _bounded_text(
            row["provider_resource_id"],
            field="provider_resource_id",
            maximum=128,
        )
        credential_id = _bounded_text(row["credential_id"], field="credential_id", maximum=128)
        principal_id = _bounded_text(row["principal_id"], field="principal_id", maximum=128)
        quota_scope_id = _bounded_text(row["quota_scope_id"], field="quota_scope_id", maximum=128)
        pool_id = _bounded_text(row["pool_id"], field="pool_id", maximum=128)
        session_id = _bounded_text(row["session_id"], field="session_id", maximum=128)
        root_run_id = _bounded_text(row["root_run_id"], field="root_run_id", maximum=128)
        workspace_id = _bounded_text(row["workspace_id"], field="workspace_id", maximum=128)
        credential_generation = _positive_integer(
            row["credential_generation"], field="credential_generation"
        )
        completed_at_ms = row["completed_at_ms"]
        if (
            isinstance(completed_at_ms, bool)
            or not isinstance(completed_at_ms, int)
            or completed_at_ms < 0
        ):
            raise AsyncCheckpointRecoveryError("async checkpoint completion time is invalid")

        expected_authority = (
            session_id,
            principal_id,
            quota_scope_id,
            credential_generation,
            principal_id,
            service_id,
            service_id,
            quota_scope_id,
        )
        durable_authority = (
            row["root_session_id"],
            row["credential_principal_id"],
            row["credential_quota_scope_id"],
            row["current_credential_generation"],
            row["quota_principal_id"],
            row["principal_service_id"],
            row["pool_service_id"],
            row["member_quota_scope_id"],
        )
        if durable_authority != expected_authority:
            raise AsyncCheckpointRecoveryError(
                "async checkpoint authority no longer matches durable routing authority"
            )

        existing = connection.execute(
            """
            SELECT service_id, resource_type, provider_resource_id,
                   principal_id, quota_scope_id, credential_id,
                   credential_generation, pool_id, creating_request_id,
                   owner_session_id, owner_workspace_id, owner_root_run_id,
                   state
              FROM external_resources
             WHERE service_id = ? AND provider_resource_id = ?
            """,
            (service_id, provider_resource_id),
        ).fetchone()
        exact_resource = (
            service_id,
            resource_type,
            provider_resource_id,
            principal_id,
            quota_scope_id,
            credential_id,
            credential_generation,
            pool_id,
            request_id,
            session_id,
            workspace_id,
            root_run_id,
            "ACTIVE",
        )
        if existing is not None:
            if tuple(existing) != exact_resource:
                raise AsyncCheckpointRecoveryError(
                    "async checkpoint conflicts with an existing provider resource"
                )
            continue

        digest = hashlib.sha256(f"{service_id}\0{provider_resource_id}".encode()).hexdigest()[:32]
        try:
            connection.execute(
                """
                INSERT INTO external_resources(
                    resource_id, service_id, resource_type,
                    provider_resource_id, principal_id, quota_scope_id,
                    credential_id, credential_generation, pool_id,
                    creating_request_id, owner_session_id,
                    owner_workspace_id, owner_root_run_id, state,
                    created_at_ms, updated_at_ms, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                          'ACTIVE', ?, ?, '{}')
                """,
                (
                    f"resource_recovered_{digest}",
                    service_id,
                    resource_type,
                    provider_resource_id,
                    principal_id,
                    quota_scope_id,
                    credential_id,
                    credential_generation,
                    pool_id,
                    request_id,
                    session_id,
                    workspace_id,
                    root_run_id,
                    completed_at_ms,
                    completed_at_ms,
                ),
            )
        except sqlite3.IntegrityError as error:
            raise AsyncCheckpointRecoveryError(
                "async checkpoint resource reconstruction violated durable authority"
            ) from error


@dataclass(frozen=True, slots=True)
class RecoveryReport:
    token_epoch: int
    sessions_expired: int
    sessions_disconnected: int
    approvals_expired: int
    admin_sessions_revoked: int
    leases_expired: int
    coalesced_results_lost: int
    invocations_failed_before_dispatch: int
    attempts_failed_before_dispatch: int
    queue_entries_expired: int
    queue_entries_requeued: int
    queue_entries_flagged: int
    async_invocations_recovered: int
    invocations_unknown: int
    attempts_unknown: int
    reservations_released_without_usage: int
    reservations_pending_reconciliation: int
    budget_reservations_released_without_usage: int
    budget_reservations_pending_reconciliation: int
    jobs_recovering: int
    watcher_runs_recovering: int


def recover_startup(connection: sqlite3.Connection, *, now_ms: int) -> RecoveryReport:
    """Advance restart-sensitive epochs and classify interrupted work.

    The function intentionally performs no network I/O and never releases an
    ambiguous quota reservation.  Provider-job re-adoption happens after this
    local transaction commits.
    """

    with transaction(connection, "IMMEDIATE"):
        state = connection.execute(
            "SELECT token_epoch FROM system_state WHERE singleton_id = 1"
        ).fetchone()
        if state is None:
            raise RuntimeError("database is missing the system_state singleton")
        token_epoch = int(state["token_epoch"]) + 1
        connection.execute(
            """
            UPDATE system_state
               SET token_epoch = ?, daemon_state = 'RECOVERING', last_started_at_ms = ?
             WHERE singleton_id = 1
            """,
            (token_epoch, now_ms),
        )

        sessions_expired = connection.execute(
            """
            UPDATE sessions
               SET state = 'EXPIRED', disconnected_at_ms = COALESCE(disconnected_at_ms, ?)
             WHERE state IN ('CREATED', 'ACTIVE', 'DISCONNECTED', 'SUSPENDED')
               AND absolute_expires_at_ms <= ?
            """,
            (now_ms, now_ms),
        ).rowcount
        sessions_disconnected = connection.execute(
            """
            UPDATE sessions
               SET state = 'DISCONNECTED', disconnected_at_ms = ?, token_epoch = ?
             WHERE state = 'ACTIVE' AND absolute_expires_at_ms > ?
            """,
            (now_ms, token_epoch, now_ms),
        ).rowcount
        approvals_expired = connection.execute(
            """
            UPDATE approvals SET state = 'EXPIRED'
             WHERE state IN ('PENDING', 'APPROVED') AND expires_at_ms <= ?
            """,
            (now_ms,),
        ).rowcount
        admin_sessions_revoked = connection.execute(
            """
            UPDATE admin_sessions SET state = 'REVOKED', revoked_at_ms = ?
             WHERE state = 'ACTIVE'
            """,
            (now_ms,),
        ).rowcount
        leases_expired = connection.execute(
            """
            UPDATE leases SET state = 'EXPIRED', released_at_ms = ?
             WHERE state = 'ACTIVE' AND expires_at_ms <= ?
            """,
            (now_ms, now_ms),
        ).rowcount

        coalesced_results_lost = connection.execute(
            """
            UPDATE invocations
               SET state = 'FAILED', completed_at_ms = ?,
                   error_code = 'result_unavailable_after_restart'
             WHERE state = 'DUPLICATE_IN_FLIGHT'
            """,
            (now_ms,),
        ).rowcount

        attempts_failed_before_dispatch = connection.execute(
            """
            UPDATE attempts
               SET state = 'FAILED', completed_at_ms = ?,
                   error_class = 'daemon_restart_before_dispatch'
             WHERE state = 'DISPATCHING'
            """,
            (now_ms,),
        ).rowcount
        invocations_failed_before_dispatch = connection.execute(
            """
            UPDATE invocations
               SET state = 'FAILED', completed_at_ms = ?,
                   error_code = 'daemon_restart_before_dispatch'
             WHERE state IN (
                 'DEDUPLICATION', 'QUOTA_RESERVED', 'DISPATCHING', 'RETRY_WAIT'
             )
            """,
            (now_ms,),
        ).rowcount

        connection.execute(
            """
            UPDATE invocations
               SET state = 'CAPACITY_EXCEEDED', completed_at_ms = ?,
                   error_code = 'capacity_exceeded'
             WHERE request_id IN (
                 SELECT request_id FROM queue_entries
                  WHERE state IN ('QUEUED', 'CLAIMED') AND deadline_ms <= ?
             ) AND state = 'QUEUED'
            """,
            (now_ms, now_ms),
        )
        queue_entries_expired = connection.execute(
            """
            UPDATE queue_entries
               SET state = 'EXPIRED', claim_owner = NULL, claim_expires_at_ms = NULL
             WHERE state IN ('QUEUED', 'CLAIMED') AND deadline_ms <= ?
            """,
            (now_ms,),
        ).rowcount

        stranded_queued = connection.execute(
            """
            UPDATE invocations
               SET state = 'FAILED', completed_at_ms = ?,
                   error_code = 'daemon_restart_before_dispatch'
             WHERE state = 'QUEUED'
               AND EXISTS (
                   SELECT 1 FROM quota_reservations AS qr
                    WHERE qr.request_id = invocations.request_id
                      AND qr.state = 'ACTIVE' AND qr.expires_at_ms <= ?
               )
            """,
            (now_ms, now_ms),
        ).rowcount
        invocations_failed_before_dispatch += stranded_queued

        reservations_released_without_usage = connection.execute(
            """
            UPDATE quota_reservations
               SET state = 'RECONCILED', actual_units = 0, reconciled_at_ms = ?
             WHERE state = 'ACTIVE'
               AND request_id IN (
                   SELECT request_id FROM invocations
                    WHERE state = 'CAPACITY_EXCEEDED'
                       OR error_code = 'daemon_restart_before_dispatch'
               )
            """,
            (now_ms,),
        ).rowcount

        queue_entries_requeued = connection.execute(
            """
            UPDATE queue_entries
               SET state = 'QUEUED', claimed_at_ms = NULL, claim_owner = NULL,
                   claim_expires_at_ms = NULL
             WHERE state = 'CLAIMED' AND deadline_ms > ?
               AND request_id IN (
                   SELECT request_id FROM invocations WHERE state = 'QUEUED'
               )
            """,
            (now_ms,),
        ).rowcount
        queue_entries_flagged = connection.execute(
            """
            UPDATE queue_entries
               SET state = 'RECOVERY_REQUIRED', claim_expires_at_ms = NULL
             WHERE state = 'CLAIMED' AND deadline_ms > ?
            """,
            (now_ms,),
        ).rowcount

        _recover_async_attempt_checkpoints(connection)
        async_invocations_recovered = connection.execute(
            """
            UPDATE invocations
               SET state = 'SUCCEEDED', completed_at_ms = ?, error_code = NULL
             WHERE state IN ('RUNNING', 'UNKNOWN')
               AND EXISTS (
                   SELECT 1 FROM attempts AS a
                    WHERE a.request_id = invocations.request_id
                      AND a.state = 'SUCCEEDED'
               )
               AND EXISTS (
                   SELECT 1 FROM external_resources AS er
                    WHERE er.creating_request_id = invocations.request_id
                      AND er.state = 'ACTIVE'
               )
            """,
            (now_ms,),
        ).rowcount
        connection.execute(
            """
            UPDATE queue_entries
               SET state = 'SUCCEEDED', claim_owner = NULL,
                   claim_expires_at_ms = NULL
             WHERE state NOT IN ('SUCCEEDED', 'FAILED', 'CANCELLED', 'EXPIRED')
               AND request_id IN (
                   SELECT i.request_id
                     FROM invocations AS i
                    WHERE i.state = 'SUCCEEDED'
                      AND EXISTS (
                          SELECT 1 FROM attempts AS a
                           WHERE a.request_id = i.request_id
                             AND a.state = 'SUCCEEDED'
                      )
                      AND EXISTS (
                          SELECT 1 FROM external_resources AS er
                           WHERE er.creating_request_id = i.request_id
                             AND er.state = 'ACTIVE'
                      )
               )
            """
        )
        attempts_unknown = connection.execute(
            """
            UPDATE attempts
               SET state = 'UNKNOWN', completed_at_ms = ?, error_class = 'daemon_restart'
             WHERE state = 'RUNNING'
            """,
            (now_ms,),
        ).rowcount
        invocations_unknown = connection.execute(
            """
            UPDATE invocations
               SET state = 'UNKNOWN', completed_at_ms = ?, error_code = 'uncertain_outcome'
             WHERE state = 'RUNNING'
            """,
            (now_ms,),
        ).rowcount
        connection.execute(
            """
            UPDATE queue_entries SET state = 'RECOVERY_REQUIRED'
             WHERE request_id IN (SELECT request_id FROM invocations WHERE state = 'UNKNOWN')
               AND state NOT IN ('EXPIRED', 'CANCELLED')
            """
        )

        reservations_pending = connection.execute(
            """
            UPDATE quota_reservations
               SET state = 'PENDING_RECONCILIATION'
             WHERE state = 'ACTIVE' AND expires_at_ms <= ?
            """,
            (now_ms,),
        ).rowcount
        budget_reservations_released_without_usage = connection.execute(
            """
            UPDATE budget_reservations
               SET state = 'RECONCILED', actual_units = 0, reconciled_at_ms = ?
             WHERE state = 'ACTIVE'
               AND request_id IN (
                   SELECT request_id FROM invocations
                    WHERE state = 'CAPACITY_EXCEEDED'
                       OR error_code = 'daemon_restart_before_dispatch'
               )
            """,
            (now_ms,),
        ).rowcount
        budget_reservations_pending_reconciliation = connection.execute(
            """
            UPDATE budget_reservations
               SET state = 'PENDING_RECONCILIATION'
             WHERE state = 'ACTIVE'
               AND request_id IN (
                   SELECT request_id FROM invocations WHERE state = 'UNKNOWN'
               )
            """
        ).rowcount
        jobs_recovering = connection.execute(
            """
            UPDATE jobs SET state = 'RECOVERING'
             WHERE state IN ('CREATED', 'RUNNING', 'POLLING', 'CANCELLING')
               AND provider_job_id IS NOT NULL
            """
        ).rowcount
        watcher_runs_recovering = connection.execute(
            """
            UPDATE watcher_runs SET state = 'RECOVERING'
             WHERE state = 'RUNNING' AND maximum_runtime_at_ms > ?
            """,
            (now_ms,),
        ).rowcount
        connection.execute(
            """
            UPDATE watcher_runs SET state = 'EXPIRED', completed_at_ms = ?
             WHERE state IN ('RUNNING', 'RECOVERING') AND maximum_runtime_at_ms <= ?
            """,
            (now_ms, now_ms),
        )

    return RecoveryReport(
        token_epoch=token_epoch,
        sessions_expired=sessions_expired,
        sessions_disconnected=sessions_disconnected,
        approvals_expired=approvals_expired,
        admin_sessions_revoked=admin_sessions_revoked,
        leases_expired=leases_expired,
        coalesced_results_lost=coalesced_results_lost,
        invocations_failed_before_dispatch=invocations_failed_before_dispatch,
        attempts_failed_before_dispatch=attempts_failed_before_dispatch,
        queue_entries_expired=queue_entries_expired,
        queue_entries_requeued=queue_entries_requeued,
        queue_entries_flagged=queue_entries_flagged,
        async_invocations_recovered=async_invocations_recovered,
        invocations_unknown=invocations_unknown,
        attempts_unknown=attempts_unknown,
        reservations_released_without_usage=reservations_released_without_usage,
        reservations_pending_reconciliation=reservations_pending,
        budget_reservations_released_without_usage=(budget_reservations_released_without_usage),
        budget_reservations_pending_reconciliation=(budget_reservations_pending_reconciliation),
        jobs_recovering=jobs_recovering,
        watcher_runs_recovering=watcher_runs_recovering,
    )
