"""Small, append-only stdlib migration runner and the Gatehouse v1 schema."""

from __future__ import annotations

import hashlib
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path

from .connection import DEFAULT_BUSY_TIMEOUT_MS, connect_database


class MigrationError(RuntimeError):
    """Base class for migration failures."""


class MigrationDriftError(MigrationError):
    """Raised when an applied migration no longer matches its source."""


class MigrationOrderError(MigrationError):
    """Raised when the configured migration sequence is not contiguous."""


@dataclass(frozen=True, slots=True)
class Migration:
    version: int
    name: str
    sql: str

    @property
    def checksum(self) -> str:
        return hashlib.sha256(self.sql.encode("utf-8")).hexdigest()


INITIAL_SCHEMA = r"""
CREATE TABLE system_state (
    singleton_id INTEGER PRIMARY KEY CHECK (singleton_id = 1),
    token_epoch INTEGER NOT NULL DEFAULT 0 CHECK (token_epoch >= 0),
    daemon_state TEXT NOT NULL DEFAULT 'STOPPED',
    last_started_at_ms INTEGER,
    last_clean_shutdown_at_ms INTEGER,
    metadata_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json))
);

INSERT INTO system_state(singleton_id) VALUES (1);

CREATE TABLE clients (
    client_id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    kind TEXT NOT NULL,
    unattended INTEGER NOT NULL DEFAULT 0 CHECK (unattended IN (0, 1)),
    policy_profile TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    config_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(config_json)),
    created_at_ms INTEGER NOT NULL,
    updated_at_ms INTEGER NOT NULL
);

CREATE TABLE workspaces (
    workspace_id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    canonical_root TEXT NOT NULL,
    repository_fingerprint TEXT,
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    config_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(config_json)),
    created_at_ms INTEGER NOT NULL,
    updated_at_ms INTEGER NOT NULL
);

CREATE UNIQUE INDEX uq_workspaces_canonical_root
ON workspaces(canonical_root COLLATE NOCASE);

CREATE TABLE sessions (
    session_id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL REFERENCES clients(client_id),
    workspace_id TEXT REFERENCES workspaces(workspace_id),
    bootstrap_verifier BLOB NOT NULL,
    bootstrap_version INTEGER NOT NULL,
    token_epoch INTEGER NOT NULL CHECK (token_epoch >= 0),
    revocation_epoch INTEGER NOT NULL DEFAULT 0 CHECK (revocation_epoch >= 0),
    state TEXT NOT NULL,
    identity_assurance TEXT NOT NULL,
    policy_version TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL,
    last_seen_at_ms INTEGER,
    disconnected_at_ms INTEGER,
    reconnect_until_ms INTEGER NOT NULL,
    absolute_expires_at_ms INTEGER NOT NULL,
    revoked_at_ms INTEGER,
    debug_until_ms INTEGER,
    budget_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(budget_json))
);

CREATE INDEX idx_sessions_state_expiry
ON sessions(state, absolute_expires_at_ms);

CREATE TABLE agents (
    agent_row_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES sessions(session_id),
    reported_agent_id TEXT,
    reported_parent_agent_id TEXT,
    reported_agent_type TEXT,
    reported_model TEXT,
    first_seen_at_ms INTEGER NOT NULL,
    last_seen_at_ms INTEGER NOT NULL,
    state TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json))
);

CREATE INDEX idx_agents_session ON agents(session_id);

CREATE TABLE root_runs (
    root_run_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES sessions(session_id),
    state TEXT NOT NULL,
    started_at_ms INTEGER NOT NULL,
    ended_at_ms INTEGER,
    budget_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(budget_json)),
    consumed_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(consumed_json))
);

CREATE INDEX idx_root_runs_session_state ON root_runs(session_id, state);

CREATE TABLE principals (
    principal_id TEXT PRIMARY KEY,
    service_id TEXT NOT NULL,
    alias TEXT NOT NULL,
    provider_subject_hash TEXT,
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    metadata_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json)),
    created_at_ms INTEGER NOT NULL,
    updated_at_ms INTEGER NOT NULL,
    UNIQUE(service_id, alias)
);

CREATE TABLE quota_scopes (
    quota_scope_id TEXT PRIMARY KEY,
    principal_id TEXT NOT NULL REFERENCES principals(principal_id),
    alias TEXT NOT NULL,
    state TEXT NOT NULL,
    unit TEXT NOT NULL,
    last_known_remaining_units INTEGER,
    configured_floor_units INTEGER NOT NULL DEFAULT 0 CHECK (configured_floor_units >= 0),
    billing_period_start_ms INTEGER,
    billing_period_end_ms INTEGER,
    last_refreshed_at_ms INTEGER,
    metadata_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json)),
    UNIQUE(principal_id, alias)
);

CREATE TABLE credentials (
    credential_id TEXT PRIMARY KEY,
    principal_id TEXT NOT NULL REFERENCES principals(principal_id),
    quota_scope_id TEXT NOT NULL REFERENCES quota_scopes(quota_scope_id),
    alias TEXT NOT NULL,
    secret_backend TEXT NOT NULL,
    secret_reference TEXT NOT NULL,
    state TEXT NOT NULL,
    generation INTEGER NOT NULL DEFAULT 1 CHECK (generation > 0),
    exclusive_usage INTEGER NOT NULL DEFAULT 1 CHECK (exclusive_usage IN (0, 1)),
    expires_at_ms INTEGER,
    created_at_ms INTEGER NOT NULL,
    last_used_at_ms INTEGER,
    metadata_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json)),
    UNIQUE(principal_id, alias),
    UNIQUE(secret_backend, secret_reference)
);

CREATE INDEX idx_credentials_quota_state
ON credentials(quota_scope_id, state);

CREATE TABLE pools (
    pool_id TEXT PRIMARY KEY,
    service_id TEXT NOT NULL,
    alias TEXT NOT NULL,
    state TEXT NOT NULL,
    selection_strategy TEXT NOT NULL,
    automatic_use INTEGER NOT NULL DEFAULT 1 CHECK (automatic_use IN (0, 1)),
    config_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(config_json)),
    UNIQUE(service_id, alias)
);

CREATE TABLE pool_members (
    pool_id TEXT NOT NULL REFERENCES pools(pool_id),
    quota_scope_id TEXT NOT NULL REFERENCES quota_scopes(quota_scope_id),
    priority INTEGER NOT NULL DEFAULT 100,
    cost_rank INTEGER NOT NULL DEFAULT 100,
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    PRIMARY KEY (pool_id, quota_scope_id)
);

CREATE TABLE invocations (
    request_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES sessions(session_id),
    root_run_id TEXT REFERENCES root_runs(root_run_id),
    agent_row_id TEXT REFERENCES agents(agent_row_id),
    service_id TEXT NOT NULL,
    operation TEXT NOT NULL,
    request_fingerprint BLOB NOT NULL,
    fingerprint_version INTEGER NOT NULL,
    canonicalization_version INTEGER NOT NULL,
    state TEXT NOT NULL,
    priority_class TEXT NOT NULL,
    policy_decision TEXT,
    policy_rule_id TEXT,
    request_size_bytes INTEGER NOT NULL CHECK (request_size_bytes >= 0),
    response_size_bytes INTEGER CHECK (response_size_bytes >= 0),
    estimated_cost_units INTEGER CHECK (estimated_cost_units >= 0),
    actual_cost_units INTEGER CHECK (actual_cost_units >= 0),
    cost_unit TEXT,
    queue_deadline_ms INTEGER,
    received_at_ms INTEGER NOT NULL,
    started_at_ms INTEGER,
    completed_at_ms INTEGER,
    error_code TEXT,
    retry_after_ms INTEGER,
    metadata_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json))
);

CREATE INDEX idx_invocations_fingerprint_state
ON invocations(session_id, request_fingerprint, state);

CREATE INDEX idx_invocations_session_time
ON invocations(session_id, received_at_ms);

CREATE TABLE queue_entries (
    queue_sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    queue_id TEXT NOT NULL UNIQUE,
    request_id TEXT NOT NULL UNIQUE REFERENCES invocations(request_id),
    state TEXT NOT NULL,
    priority_class TEXT NOT NULL,
    session_id TEXT NOT NULL REFERENCES sessions(session_id),
    root_run_id TEXT REFERENCES root_runs(root_run_id),
    service_id TEXT NOT NULL,
    operation TEXT NOT NULL,
    estimated_cost_units INTEGER CHECK (estimated_cost_units >= 0),
    cost_unit TEXT,
    enqueued_at_ms INTEGER NOT NULL,
    deadline_ms INTEGER NOT NULL,
    claimed_at_ms INTEGER,
    claim_owner TEXT,
    claim_expires_at_ms INTEGER,
    dispatch_attempts INTEGER NOT NULL DEFAULT 0 CHECK (dispatch_attempts >= 0),
    metadata_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json))
);

CREATE INDEX idx_queue_dispatch
ON queue_entries(state, priority_class, queue_sequence);

CREATE INDEX idx_queue_deadline ON queue_entries(state, deadline_ms);

CREATE TABLE attempts (
    attempt_id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL REFERENCES invocations(request_id),
    ordinal INTEGER NOT NULL CHECK (ordinal > 0),
    credential_id TEXT REFERENCES credentials(credential_id),
    principal_id TEXT REFERENCES principals(principal_id),
    quota_scope_id TEXT REFERENCES quota_scopes(quota_scope_id),
    state TEXT NOT NULL,
    provider_status_code INTEGER,
    provider_request_id TEXT,
    error_class TEXT,
    estimated_cost_units INTEGER CHECK (estimated_cost_units >= 0),
    actual_cost_units INTEGER CHECK (actual_cost_units >= 0),
    cost_unit TEXT,
    started_at_ms INTEGER NOT NULL,
    completed_at_ms INTEGER,
    latency_ms INTEGER CHECK (latency_ms >= 0),
    metadata_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json)),
    UNIQUE(request_id, ordinal)
);

CREATE TABLE quota_reservations (
    reservation_id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL REFERENCES invocations(request_id),
    quota_scope_id TEXT NOT NULL REFERENCES quota_scopes(quota_scope_id),
    amount_units INTEGER NOT NULL CHECK (amount_units > 0),
    actual_units INTEGER CHECK (actual_units >= 0),
    unit TEXT NOT NULL,
    state TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL,
    expires_at_ms INTEGER NOT NULL,
    reconciled_at_ms INTEGER,
    metadata_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json))
);

CREATE INDEX idx_quota_reservations_active
ON quota_reservations(quota_scope_id, state, expires_at_ms);

CREATE TABLE approvals (
    approval_id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL REFERENCES invocations(request_id),
    request_fingerprint BLOB NOT NULL,
    session_id TEXT NOT NULL REFERENCES sessions(session_id),
    service_id TEXT NOT NULL,
    operation TEXT NOT NULL,
    state TEXT NOT NULL,
    maximum_uses INTEGER NOT NULL DEFAULT 1 CHECK (maximum_uses > 0),
    uses_consumed INTEGER NOT NULL DEFAULT 0 CHECK (uses_consumed >= 0),
    maximum_cost_units INTEGER CHECK (maximum_cost_units >= 0),
    cost_unit TEXT,
    pool_id TEXT REFERENCES pools(pool_id),
    created_at_ms INTEGER NOT NULL,
    expires_at_ms INTEGER NOT NULL,
    decided_at_ms INTEGER,
    consumed_at_ms INTEGER,
    decision_source TEXT,
    reason TEXT,
    metadata_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json)),
    CHECK (uses_consumed <= maximum_uses)
);

CREATE INDEX idx_approvals_state_expiry ON approvals(state, expires_at_ms);

CREATE TABLE jobs (
    job_id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL REFERENCES invocations(request_id),
    service_id TEXT NOT NULL,
    operation TEXT NOT NULL,
    state TEXT NOT NULL,
    provider_job_id TEXT,
    principal_id TEXT REFERENCES principals(principal_id),
    quota_scope_id TEXT REFERENCES quota_scopes(quota_scope_id),
    credential_id TEXT REFERENCES credentials(credential_id),
    next_poll_at_ms INTEGER,
    maximum_runtime_at_ms INTEGER,
    created_at_ms INTEGER NOT NULL,
    completed_at_ms INTEGER,
    metadata_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json)),
    UNIQUE(service_id, provider_job_id)
);

CREATE TABLE external_resources (
    resource_id TEXT PRIMARY KEY,
    service_id TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    provider_resource_id TEXT NOT NULL,
    principal_id TEXT NOT NULL REFERENCES principals(principal_id),
    quota_scope_id TEXT NOT NULL REFERENCES quota_scopes(quota_scope_id),
    credential_id TEXT REFERENCES credentials(credential_id),
    creating_request_id TEXT NOT NULL REFERENCES invocations(request_id),
    state TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL,
    updated_at_ms INTEGER NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json)),
    UNIQUE(service_id, provider_resource_id)
);

CREATE TABLE leases (
    lease_id TEXT PRIMARY KEY,
    lease_type TEXT NOT NULL,
    lease_key TEXT NOT NULL,
    owner_id TEXT NOT NULL,
    state TEXT NOT NULL,
    generation INTEGER NOT NULL DEFAULT 1 CHECK (generation > 0),
    acquired_at_ms INTEGER NOT NULL,
    heartbeat_at_ms INTEGER NOT NULL,
    expires_at_ms INTEGER NOT NULL,
    released_at_ms INTEGER,
    metadata_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json))
);

CREATE UNIQUE INDEX uq_leases_one_active_holder
ON leases(lease_type, lease_key) WHERE state = 'ACTIVE';

CREATE INDEX idx_leases_expiry ON leases(state, expires_at_ms);

CREATE TABLE circuit_breakers (
    breaker_id TEXT PRIMARY KEY,
    scope_type TEXT NOT NULL,
    scope_id TEXT NOT NULL,
    state TEXT NOT NULL,
    failure_count INTEGER NOT NULL DEFAULT 0 CHECK (failure_count >= 0),
    opened_at_ms INTEGER,
    retry_after_ms INTEGER,
    last_failure_class TEXT,
    metadata_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json)),
    UNIQUE(scope_type, scope_id)
);

CREATE TABLE quota_snapshots (
    snapshot_id TEXT PRIMARY KEY,
    quota_scope_id TEXT NOT NULL REFERENCES quota_scopes(quota_scope_id),
    remaining_units INTEGER,
    plan_total_units INTEGER,
    unit TEXT NOT NULL,
    period_start_ms INTEGER,
    period_end_ms INTEGER,
    captured_at_ms INTEGER NOT NULL,
    source TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json))
);

CREATE INDEX idx_quota_snapshots_scope_time
ON quota_snapshots(quota_scope_id, captured_at_ms);

CREATE TABLE reconciliation_runs (
    reconciliation_id TEXT PRIMARY KEY,
    service_id TEXT NOT NULL,
    mode TEXT NOT NULL,
    state TEXT NOT NULL,
    started_at_ms INTEGER NOT NULL,
    completed_at_ms INTEGER,
    summary_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(summary_json))
);

CREATE TABLE reconciliation_items (
    item_id TEXT PRIMARY KEY,
    reconciliation_id TEXT NOT NULL REFERENCES reconciliation_runs(reconciliation_id),
    quota_scope_id TEXT NOT NULL REFERENCES quota_scopes(quota_scope_id),
    provider_delta_units INTEGER,
    ledger_delta_units INTEGER,
    manual_adjustment_units INTEGER NOT NULL DEFAULT 0,
    unexplained_delta_units INTEGER,
    unit TEXT NOT NULL,
    state TEXT NOT NULL,
    details_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(details_json))
);

CREATE TABLE alerts (
    alert_id TEXT PRIMARY KEY,
    severity TEXT NOT NULL,
    category TEXT NOT NULL,
    state TEXT NOT NULL,
    title TEXT NOT NULL,
    summary TEXT NOT NULL,
    related_request_id TEXT REFERENCES invocations(request_id),
    created_at_ms INTEGER NOT NULL,
    acknowledged_at_ms INTEGER,
    preserve INTEGER NOT NULL DEFAULT 1 CHECK (preserve IN (0, 1)),
    metadata_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json))
);

CREATE TABLE feedback (
    feedback_id TEXT PRIMARY KEY,
    session_id TEXT REFERENCES sessions(session_id),
    category TEXT NOT NULL,
    severity TEXT NOT NULL,
    component TEXT NOT NULL,
    summary TEXT NOT NULL,
    state TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL,
    content_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(content_json))
);

CREATE TABLE audit_events (
    event_id TEXT PRIMARY KEY,
    occurred_at_ms INTEGER NOT NULL,
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    session_id TEXT REFERENCES sessions(session_id),
    root_run_id TEXT REFERENCES root_runs(root_run_id),
    request_id TEXT REFERENCES invocations(request_id),
    attempt_id TEXT REFERENCES attempts(attempt_id),
    service_id TEXT,
    operation TEXT,
    preserve INTEGER NOT NULL DEFAULT 0 CHECK (preserve IN (0, 1)),
    payload_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(payload_json))
);

CREATE INDEX idx_audit_events_time ON audit_events(occurred_at_ms);
CREATE INDEX idx_audit_events_request ON audit_events(request_id, occurred_at_ms);

CREATE TABLE debug_excerpts (
    excerpt_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES sessions(session_id),
    reason TEXT NOT NULL,
    redacted_excerpt TEXT NOT NULL,
    size_bytes INTEGER NOT NULL CHECK (size_bytes >= 0),
    created_at_ms INTEGER NOT NULL,
    expires_at_ms INTEGER NOT NULL
);

CREATE INDEX idx_debug_excerpts_expiry ON debug_excerpts(expires_at_ms);

CREATE TABLE daily_usage_aggregates (
    aggregate_id TEXT PRIMARY KEY,
    day_utc TEXT NOT NULL,
    service_id TEXT NOT NULL,
    client_id TEXT,
    operation TEXT,
    request_count INTEGER NOT NULL DEFAULT 0 CHECK (request_count >= 0),
    success_count INTEGER NOT NULL DEFAULT 0 CHECK (success_count >= 0),
    actual_cost_units INTEGER NOT NULL DEFAULT 0 CHECK (actual_cost_units >= 0),
    cost_unit TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL,
    UNIQUE(day_utc, service_id, client_id, operation, cost_unit)
);

CREATE TABLE admin_sessions (
    admin_session_id TEXT PRIMARY KEY,
    cookie_verifier BLOB NOT NULL,
    csrf_verifier BLOB NOT NULL,
    token_epoch INTEGER NOT NULL CHECK (token_epoch >= 0),
    state TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL,
    last_seen_at_ms INTEGER NOT NULL,
    idle_expires_at_ms INTEGER NOT NULL,
    absolute_expires_at_ms INTEGER NOT NULL,
    revoked_at_ms INTEGER,
    metadata_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json))
);

CREATE INDEX idx_admin_sessions_expiry
ON admin_sessions(state, idle_expires_at_ms, absolute_expires_at_ms);

CREATE TABLE documentation_sources (
    source_id TEXT PRIMARY KEY,
    service_id TEXT NOT NULL,
    canonical_url TEXT NOT NULL,
    trust_level TEXT NOT NULL,
    update_interval_seconds INTEGER NOT NULL CHECK (update_interval_seconds > 0),
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    last_checked_at_ms INTEGER,
    metadata_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json)),
    UNIQUE(service_id, canonical_url)
);

CREATE TABLE documentation_versions (
    version_id TEXT PRIMARY KEY,
    source_id TEXT NOT NULL REFERENCES documentation_sources(source_id),
    digest_sha256 TEXT NOT NULL,
    state TEXT NOT NULL,
    retrieved_at_ms INTEGER NOT NULL,
    promoted_at_ms INTEGER,
    metadata_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json)),
    UNIQUE(source_id, digest_sha256)
);

CREATE TABLE documentation_chunks (
    chunk_id TEXT PRIMARY KEY,
    version_id TEXT NOT NULL REFERENCES documentation_versions(version_id) ON DELETE CASCADE,
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    heading TEXT,
    content TEXT NOT NULL,
    source_reference TEXT NOT NULL,
    UNIQUE(version_id, ordinal)
);

CREATE TABLE feed_sets (
    feed_set_id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspaces(workspace_id),
    policy_version TEXT NOT NULL,
    state TEXT NOT NULL,
    config_json TEXT NOT NULL CHECK (json_valid(config_json)),
    created_at_ms INTEGER NOT NULL,
    updated_at_ms INTEGER NOT NULL
);

CREATE TABLE feed_cursors (
    feed_set_id TEXT PRIMARY KEY REFERENCES feed_sets(feed_set_id),
    cursor_value TEXT,
    cursor_version INTEGER NOT NULL DEFAULT 0 CHECK (cursor_version >= 0),
    last_run_id TEXT,
    committed_at_ms INTEGER,
    metadata_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json))
);

CREATE TABLE watcher_runs (
    watcher_run_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES sessions(session_id),
    feed_set_id TEXT NOT NULL REFERENCES feed_sets(feed_set_id),
    lease_id TEXT REFERENCES leases(lease_id),
    state TEXT NOT NULL,
    started_at_ms INTEGER NOT NULL,
    heartbeat_at_ms INTEGER NOT NULL,
    maximum_runtime_at_ms INTEGER NOT NULL,
    completed_at_ms INTEGER,
    request_count INTEGER NOT NULL DEFAULT 0 CHECK (request_count >= 0),
    consumed_cost_units INTEGER NOT NULL DEFAULT 0 CHECK (consumed_cost_units >= 0),
    cost_unit TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json))
);

CREATE INDEX idx_watcher_runs_state ON watcher_runs(state, maximum_runtime_at_ms);
"""

DOCUMENTATION_FTS = r"""
CREATE VIRTUAL TABLE documentation_chunks_fts USING fts5(
    chunk_id UNINDEXED,
    heading,
    content,
    source_reference UNINDEXED,
    tokenize = 'unicode61 remove_diacritics 2'
);
"""


RESOURCE_AFFINITY_AUTHORITY = r"""
ALTER TABLE external_resources RENAME TO external_resources_v1;

CREATE TABLE external_resources (
    resource_id TEXT PRIMARY KEY,
    service_id TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    provider_resource_id TEXT NOT NULL,
    principal_id TEXT NOT NULL REFERENCES principals(principal_id),
    quota_scope_id TEXT NOT NULL REFERENCES quota_scopes(quota_scope_id),
    credential_id TEXT REFERENCES credentials(credential_id),
    credential_generation INTEGER CHECK (
        credential_generation IS NULL OR credential_generation > 0
    ),
    pool_id TEXT REFERENCES pools(pool_id),
    creating_request_id TEXT NOT NULL REFERENCES invocations(request_id),
    owner_session_id TEXT REFERENCES sessions(session_id),
    owner_workspace_id TEXT REFERENCES workspaces(workspace_id),
    owner_root_run_id TEXT REFERENCES root_runs(root_run_id),
    state TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL,
    updated_at_ms INTEGER NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json)),
    CHECK (
        state <> 'ACTIVE'
        OR (
            credential_id IS NOT NULL
            AND credential_generation IS NOT NULL
            AND pool_id IS NOT NULL
            AND owner_session_id IS NOT NULL
            AND owner_workspace_id IS NOT NULL
            AND owner_root_run_id IS NOT NULL
        )
    ),
    UNIQUE(service_id, provider_resource_id)
);

INSERT INTO external_resources(
    resource_id, service_id, resource_type, provider_resource_id,
    principal_id, quota_scope_id, credential_id, credential_generation,
    pool_id, creating_request_id, owner_session_id, owner_workspace_id,
    owner_root_run_id, state, created_at_ms, updated_at_ms, metadata_json
)
SELECT er.resource_id, er.service_id, er.resource_type, er.provider_resource_id,
       er.principal_id, er.quota_scope_id, er.credential_id, c.generation,
       NULL, er.creating_request_id, i.session_id, s.workspace_id,
       i.root_run_id, 'OWNER_REBIND_REQUIRED', er.created_at_ms,
       er.updated_at_ms, er.metadata_json
  FROM external_resources_v1 AS er
  LEFT JOIN credentials AS c ON c.credential_id = er.credential_id
  LEFT JOIN invocations AS i ON i.request_id = er.creating_request_id
  LEFT JOIN sessions AS s ON s.session_id = i.session_id;

DROP TABLE external_resources_v1;

CREATE INDEX idx_external_resources_owner
ON external_resources(owner_session_id, owner_root_run_id, state);

CREATE INDEX idx_external_resources_principal
ON external_resources(principal_id, quota_scope_id, state);

CREATE INDEX idx_external_resources_lookup
ON external_resources(service_id, resource_type, provider_resource_id, state);
"""


QUOTA_BALANCE_WATERMARK = r"""
ALTER TABLE quota_scopes
ADD COLUMN balance_as_of_ms INTEGER CHECK (
    balance_as_of_ms IS NULL OR balance_as_of_ms >= 0
);

ALTER TABLE quota_scopes
ADD COLUMN balance_snapshot_id TEXT REFERENCES quota_snapshots(snapshot_id);

UPDATE quota_scopes
   SET last_known_remaining_units = (
           SELECT qsnap.remaining_units
             FROM quota_snapshots AS qsnap
            WHERE qsnap.quota_scope_id = quota_scopes.quota_scope_id
              AND qsnap.remaining_units IS NOT NULL
            ORDER BY qsnap.captured_at_ms DESC, qsnap.snapshot_id DESC
            LIMIT 1
       ),
       balance_as_of_ms = (
           SELECT qsnap.captured_at_ms
             FROM quota_snapshots AS qsnap
            WHERE qsnap.quota_scope_id = quota_scopes.quota_scope_id
              AND qsnap.remaining_units IS NOT NULL
            ORDER BY qsnap.captured_at_ms DESC, qsnap.snapshot_id DESC
            LIMIT 1
       ),
       balance_snapshot_id = (
           SELECT qsnap.snapshot_id
             FROM quota_snapshots AS qsnap
            WHERE qsnap.quota_scope_id = quota_scopes.quota_scope_id
              AND qsnap.remaining_units IS NOT NULL
            ORDER BY qsnap.captured_at_ms DESC, qsnap.snapshot_id DESC
            LIMIT 1
       )
 WHERE EXISTS (
           SELECT 1
             FROM quota_snapshots AS qsnap
            WHERE qsnap.quota_scope_id = quota_scopes.quota_scope_id
              AND qsnap.remaining_units IS NOT NULL
       );

CREATE INDEX idx_quota_reservations_accounting
ON quota_reservations(quota_scope_id, state, reconciled_at_ms);
"""


DURABLE_ROOT_RUN_BUDGETS = r"""
CREATE TABLE budget_reservations (
    budget_reservation_id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL REFERENCES invocations(request_id),
    root_run_id TEXT NOT NULL REFERENCES root_runs(root_run_id),
    amount_units INTEGER NOT NULL CHECK (amount_units > 0),
    actual_units INTEGER CHECK (actual_units >= 0),
    unit TEXT NOT NULL,
    state TEXT NOT NULL CHECK (
        state IN ('ACTIVE', 'PENDING_RECONCILIATION', 'RECONCILED')
    ),
    created_at_ms INTEGER NOT NULL,
    reconciled_at_ms INTEGER,
    UNIQUE(request_id, unit)
);

CREATE INDEX idx_budget_reservations_accounting
ON budget_reservations(root_run_id, unit, state);
"""


ASYNC_ATTEMPT_CHECKPOINTS = r"""
ALTER TABLE attempts
ADD COLUMN resource_type TEXT CHECK (
    resource_type IS NULL OR (length(resource_type) BETWEEN 1 AND 64)
);

ALTER TABLE attempts
ADD COLUMN provider_resource_id TEXT CHECK (
    provider_resource_id IS NULL OR (length(provider_resource_id) BETWEEN 1 AND 128)
);

ALTER TABLE attempts
ADD COLUMN credential_generation INTEGER CHECK (
    credential_generation IS NULL OR credential_generation > 0
);

ALTER TABLE attempts
ADD COLUMN pool_id TEXT REFERENCES pools(pool_id);

CREATE TRIGGER attempts_async_checkpoint_insert
BEFORE INSERT ON attempts
WHEN NOT (
    (
        NEW.resource_type IS NULL
        AND NEW.provider_resource_id IS NULL
        AND NEW.credential_generation IS NULL
        AND NEW.pool_id IS NULL
    )
    OR
    (
        NEW.resource_type IS NOT NULL
        AND NEW.provider_resource_id IS NOT NULL
        AND NEW.credential_generation IS NOT NULL
        AND NEW.pool_id IS NOT NULL
        AND NEW.state = 'SUCCEEDED'
        AND NEW.error_class = 'none'
    )
)
BEGIN
    SELECT RAISE(ABORT, 'invalid asynchronous attempt checkpoint');
END;

CREATE TRIGGER attempts_async_checkpoint_update
BEFORE UPDATE ON attempts
WHEN NOT (
    (
        NEW.resource_type IS NULL
        AND NEW.provider_resource_id IS NULL
        AND NEW.credential_generation IS NULL
        AND NEW.pool_id IS NULL
    )
    OR
    (
        NEW.resource_type IS NOT NULL
        AND NEW.provider_resource_id IS NOT NULL
        AND NEW.credential_generation IS NOT NULL
        AND NEW.pool_id IS NOT NULL
        AND NEW.state = 'SUCCEEDED'
        AND NEW.error_class = 'none'
    )
)
BEGIN
    SELECT RAISE(ABORT, 'invalid asynchronous attempt checkpoint');
END;

CREATE INDEX idx_attempts_async_checkpoint
ON attempts(request_id, state, provider_resource_id)
WHERE provider_resource_id IS NOT NULL;
"""


ASYNC_ATTEMPT_CHECKPOINT_IMMUTABILITY = r"""
CREATE TRIGGER attempts_async_checkpoint_immutable
BEFORE UPDATE ON attempts
WHEN (
    OLD.resource_type IS NOT NULL
    OR OLD.provider_resource_id IS NOT NULL
    OR OLD.credential_generation IS NOT NULL
    OR OLD.pool_id IS NOT NULL
)
AND (
    NEW.attempt_id IS NOT OLD.attempt_id
    OR NEW.request_id IS NOT OLD.request_id
    OR NEW.ordinal IS NOT OLD.ordinal
    OR NEW.credential_id IS NOT OLD.credential_id
    OR NEW.principal_id IS NOT OLD.principal_id
    OR NEW.quota_scope_id IS NOT OLD.quota_scope_id
    OR NEW.completed_at_ms IS NOT OLD.completed_at_ms
    OR NEW.resource_type IS NOT OLD.resource_type
    OR NEW.provider_resource_id IS NOT OLD.provider_resource_id
    OR NEW.credential_generation IS NOT OLD.credential_generation
    OR NEW.pool_id IS NOT OLD.pool_id
)
BEGIN
    SELECT RAISE(ABORT, 'asynchronous attempt checkpoint is immutable');
END;
"""


CREDENTIAL_LIFECYCLE = r"""
CREATE TABLE credential_mutations (
    mutation_id TEXT PRIMARY KEY,
    operation TEXT NOT NULL,
    credential_id TEXT,
    replacement_credential_id TEXT,
    state TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL,
    updated_at_ms INTEGER NOT NULL,
    completed_at_ms INTEGER,
    metadata_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json)),
    result_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(result_json))
);

CREATE INDEX idx_credential_mutations_state_time
ON credential_mutations(state, updated_at_ms);

CREATE TABLE emergency_unlock_records (
    unlock_id TEXT PRIMARY KEY CHECK (length(unlock_id) BETWEEN 16 AND 160),
    mutation_id TEXT NOT NULL UNIQUE REFERENCES credential_mutations(mutation_id),
    last_mutation_id TEXT NOT NULL,
    audit_event_id TEXT NOT NULL,
    credential_id TEXT NOT NULL CHECK (length(credential_id) BETWEEN 1 AND 160),
    credential_alias TEXT NOT NULL CHECK (length(credential_alias) BETWEEN 1 AND 160),
    credential_generation INTEGER NOT NULL CHECK (credential_generation = 1),
    principal_id TEXT NOT NULL CHECK (length(principal_id) BETWEEN 1 AND 160),
    principal_alias TEXT NOT NULL CHECK (length(principal_alias) BETWEEN 1 AND 160),
    quota_scope_id TEXT NOT NULL CHECK (length(quota_scope_id) BETWEEN 1 AND 160),
    quota_scope_alias TEXT NOT NULL CHECK (length(quota_scope_alias) BETWEEN 1 AND 160),
    service_id TEXT NOT NULL CHECK (length(service_id) BETWEEN 1 AND 160),
    pool_id TEXT NOT NULL REFERENCES pools(pool_id),
    session_id TEXT NOT NULL REFERENCES sessions(session_id),
    root_run_id TEXT NOT NULL REFERENCES root_runs(root_run_id),
    state TEXT NOT NULL CHECK (state IN ('ACTIVE', 'CANCELLED', 'EXPIRED', 'RELOCKED')),
    maximum_requests INTEGER NOT NULL CHECK (maximum_requests BETWEEN 1 AND 25),
    maximum_credits INTEGER NOT NULL CHECK (maximum_credits BETWEEN 1 AND 100),
    maximum_concurrency INTEGER NOT NULL CHECK (maximum_concurrency = 1),
    created_at_ms INTEGER NOT NULL,
    updated_at_ms INTEGER NOT NULL,
    expires_at_ms INTEGER NOT NULL,
    closed_at_ms INTEGER,
    metadata_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json)),
    CHECK (expires_at_ms > created_at_ms),
    CHECK (expires_at_ms - created_at_ms <= 900000)
);

CREATE INDEX idx_emergency_unlock_records_state_expiry
ON emergency_unlock_records(state, expires_at_ms);

CREATE UNIQUE INDEX idx_emergency_unlock_records_single_active
ON emergency_unlock_records((1)) WHERE state = 'ACTIVE';

ALTER TABLE attempts ADD COLUMN emergency_unlock_id TEXT
    REFERENCES emergency_unlock_records(unlock_id);
ALTER TABLE attempts ADD COLUMN emergency_credential_id TEXT;
ALTER TABLE attempts ADD COLUMN emergency_principal_id TEXT;
ALTER TABLE attempts ADD COLUMN emergency_quota_scope_id TEXT;
ALTER TABLE attempts ADD COLUMN emergency_pool_id TEXT REFERENCES pools(pool_id);
ALTER TABLE attempts ADD COLUMN emergency_credential_generation INTEGER;
ALTER TABLE attempts ADD COLUMN dispatch_credential_generation INTEGER;
ALTER TABLE attempts ADD COLUMN dispatch_pool_id TEXT REFERENCES pools(pool_id);

CREATE TRIGGER attempts_dispatch_authority_shape_insert
BEFORE INSERT ON attempts
WHEN (
    (NEW.dispatch_credential_generation IS NULL) != (NEW.dispatch_pool_id IS NULL)
    OR (
        NEW.emergency_unlock_id IS NULL
        AND (
            NEW.dispatch_credential_generation IS NULL
            OR NEW.dispatch_pool_id IS NULL
        )
    )
    OR (
        NEW.dispatch_credential_generation IS NOT NULL
        AND NEW.dispatch_credential_generation <= 0
    )
    OR (
        NEW.emergency_unlock_id IS NOT NULL
        AND (
            NEW.dispatch_credential_generation IS NOT NULL
            OR NEW.dispatch_pool_id IS NOT NULL
        )
    )
)
BEGIN
    SELECT RAISE(ABORT, 'invalid attempt dispatch authority shape');
END;

CREATE TRIGGER attempts_dispatch_authority_shape_update
BEFORE UPDATE ON attempts
WHEN (
    (NEW.dispatch_credential_generation IS NULL) != (NEW.dispatch_pool_id IS NULL)
    OR (
        NEW.dispatch_credential_generation IS NOT NULL
        AND NEW.dispatch_credential_generation <= 0
    )
    OR (
        NEW.emergency_unlock_id IS NOT NULL
        AND (
            NEW.dispatch_credential_generation IS NOT NULL
            OR NEW.dispatch_pool_id IS NOT NULL
        )
    )
)
BEGIN
    SELECT RAISE(ABORT, 'invalid attempt dispatch authority shape');
END;

CREATE TRIGGER attempts_dispatch_authority_immutable
BEFORE UPDATE ON attempts
WHEN NEW.dispatch_credential_generation IS NOT OLD.dispatch_credential_generation
    OR NEW.dispatch_pool_id IS NOT OLD.dispatch_pool_id
    OR (
        OLD.resource_type IS NULL
        AND OLD.provider_resource_id IS NULL
        AND OLD.credential_generation IS NULL
        AND OLD.pool_id IS NULL
        AND (
            NEW.credential_id IS NOT OLD.credential_id
            OR NEW.principal_id IS NOT OLD.principal_id
            OR NEW.quota_scope_id IS NOT OLD.quota_scope_id
        )
    )
BEGIN
    SELECT RAISE(ABORT, 'attempt dispatch authority is immutable');
END;

CREATE TRIGGER attempts_emergency_authority_shape_insert
BEFORE INSERT ON attempts
WHEN NOT (
    (
        NEW.emergency_unlock_id IS NULL
        AND NEW.emergency_credential_id IS NULL
        AND NEW.emergency_principal_id IS NULL
        AND NEW.emergency_quota_scope_id IS NULL
        AND NEW.emergency_pool_id IS NULL
        AND NEW.emergency_credential_generation IS NULL
    )
    OR
    (
        NEW.emergency_unlock_id IS NOT NULL
        AND NEW.emergency_credential_id IS NOT NULL
        AND NEW.emergency_principal_id IS NOT NULL
        AND NEW.emergency_quota_scope_id IS NOT NULL
        AND NEW.emergency_pool_id IS NOT NULL
        AND NEW.emergency_credential_generation IS NOT NULL
        AND NEW.credential_id IS NULL
        AND NEW.principal_id IS NULL
        AND NEW.quota_scope_id IS NULL
        AND NEW.resource_type IS NULL
        AND NEW.provider_resource_id IS NULL
        AND NEW.credential_generation IS NULL
        AND NEW.pool_id IS NULL
        AND NEW.dispatch_credential_generation IS NULL
        AND NEW.dispatch_pool_id IS NULL
    )
)
BEGIN
    SELECT RAISE(ABORT, 'invalid emergency attempt authority shape');
END;

CREATE TRIGGER attempts_emergency_authority_shape_update
BEFORE UPDATE ON attempts
WHEN NOT (
    (
        NEW.emergency_unlock_id IS NULL
        AND NEW.emergency_credential_id IS NULL
        AND NEW.emergency_principal_id IS NULL
        AND NEW.emergency_quota_scope_id IS NULL
        AND NEW.emergency_pool_id IS NULL
        AND NEW.emergency_credential_generation IS NULL
    )
    OR
    (
        NEW.emergency_unlock_id IS NOT NULL
        AND NEW.emergency_credential_id IS NOT NULL
        AND NEW.emergency_principal_id IS NOT NULL
        AND NEW.emergency_quota_scope_id IS NOT NULL
        AND NEW.emergency_pool_id IS NOT NULL
        AND NEW.emergency_credential_generation IS NOT NULL
        AND NEW.credential_id IS NULL
        AND NEW.principal_id IS NULL
        AND NEW.quota_scope_id IS NULL
        AND NEW.resource_type IS NULL
        AND NEW.provider_resource_id IS NULL
        AND NEW.credential_generation IS NULL
        AND NEW.pool_id IS NULL
        AND NEW.dispatch_credential_generation IS NULL
        AND NEW.dispatch_pool_id IS NULL
    )
)
BEGIN
    SELECT RAISE(ABORT, 'invalid emergency attempt authority shape');
END;

CREATE TRIGGER attempts_emergency_authority_insert
BEFORE INSERT ON attempts
WHEN NEW.emergency_unlock_id IS NOT NULL
AND NOT EXISTS (
    SELECT 1
      FROM emergency_unlock_records AS eu
      JOIN invocations AS i ON i.request_id = NEW.request_id
      JOIN pools AS p ON p.pool_id = eu.pool_id
      JOIN sessions AS s
        ON s.session_id = eu.session_id
       AND s.session_id = i.session_id
      JOIN clients AS c ON c.client_id = s.client_id
      JOIN root_runs AS rr
        ON rr.root_run_id = eu.root_run_id
       AND rr.root_run_id = i.root_run_id
       AND rr.session_id = s.session_id
     WHERE eu.unlock_id = NEW.emergency_unlock_id
       AND eu.state = 'ACTIVE'
       AND NEW.started_at_ms < eu.expires_at_ms
       AND p.alias = 'emergency-locked'
       AND p.state IN ('ACTIVE', 'ENABLED')
       AND p.automatic_use = 0
       AND p.service_id = eu.service_id
       AND s.state = 'ACTIVE'
       AND NEW.started_at_ms < s.absolute_expires_at_ms
       AND c.unattended = 0
       AND rr.state = 'ACTIVE'
       AND eu.credential_id = NEW.emergency_credential_id
       AND eu.principal_id = NEW.emergency_principal_id
       AND eu.quota_scope_id = NEW.emergency_quota_scope_id
       AND eu.pool_id = NEW.emergency_pool_id
       AND eu.credential_generation = NEW.emergency_credential_generation
       AND eu.session_id = i.session_id
       AND eu.root_run_id = i.root_run_id
       AND eu.service_id = i.service_id
       AND i.operation != 'firecrawl.crawl.start'
)
BEGIN
    SELECT RAISE(ABORT, 'invalid emergency attempt authority');
END;

CREATE TRIGGER attempts_emergency_authority_immutable
BEFORE UPDATE ON attempts
WHEN NEW.emergency_unlock_id IS NOT OLD.emergency_unlock_id
    OR NEW.emergency_credential_id IS NOT OLD.emergency_credential_id
    OR NEW.emergency_principal_id IS NOT OLD.emergency_principal_id
    OR NEW.emergency_quota_scope_id IS NOT OLD.emergency_quota_scope_id
    OR NEW.emergency_pool_id IS NOT OLD.emergency_pool_id
    OR NEW.emergency_credential_generation IS NOT OLD.emergency_credential_generation
BEGIN
    SELECT RAISE(ABORT, 'emergency attempt authority is immutable');
END;

-- Databases created before terminal resource-state coupling retained ACTIVE
-- affinity rows after a job reached a known terminal state.  Advance only rows
-- whose complete job, invocation, owner, and generation/pool authority agree;
-- ambiguous or incomplete authority remains ACTIVE and therefore fail-closed.
WITH terminal_resource_backfill AS (
    SELECT er.resource_id,
           CASE j.state
               WHEN 'SUCCEEDED' THEN 'COMPLETED'
               WHEN 'FAILED' THEN 'FAILED'
               WHEN 'CANCELLED' THEN 'CANCELLED'
           END AS terminal_state,
           j.completed_at_ms AS terminal_at_ms
      FROM external_resources AS er
      JOIN jobs AS j
        ON j.request_id = er.creating_request_id
       AND j.service_id = er.service_id
       AND j.provider_job_id = er.provider_resource_id
       AND j.principal_id = er.principal_id
       AND j.quota_scope_id = er.quota_scope_id
       AND j.credential_id = er.credential_id
      JOIN invocations AS i
        ON i.request_id = j.request_id
       AND i.service_id = j.service_id
       AND i.operation = j.operation
       AND i.state = 'SUCCEEDED'
      JOIN sessions AS s
        ON s.session_id = i.session_id
      JOIN root_runs AS rr
        ON rr.root_run_id = i.root_run_id
       AND rr.session_id = i.session_id
     WHERE er.state = 'ACTIVE'
       AND j.state IN ('SUCCEEDED', 'FAILED', 'CANCELLED')
       AND j.completed_at_ms IS NOT NULL
       AND j.completed_at_ms >= er.created_at_ms
       AND json_extract(j.metadata_json, '$.resource_type') = er.resource_type
       AND json_extract(j.metadata_json, '$.credential_generation') = er.credential_generation
       AND json_extract(j.metadata_json, '$.pool_id') = er.pool_id
       AND er.owner_session_id = i.session_id
       AND er.owner_workspace_id = s.workspace_id
       AND er.owner_root_run_id = i.root_run_id
)
UPDATE external_resources
   SET state = (
           SELECT terminal_state
             FROM terminal_resource_backfill AS backfill
            WHERE backfill.resource_id = external_resources.resource_id
       ),
       updated_at_ms = (
           SELECT terminal_at_ms
             FROM terminal_resource_backfill AS backfill
            WHERE backfill.resource_id = external_resources.resource_id
       )
 WHERE resource_id IN (SELECT resource_id FROM terminal_resource_backfill);
"""


CANONICAL_DECIMAL_CREDIT_OBSERVATIONS = r"""
-- Validate every v8 value that migration 9 will anchor or transform before
-- adding a column.  A failed guard insert aborts the surrounding IMMEDIATE
-- transaction, including all schema changes and the migration ledger row.
CREATE TABLE gatehouse_migration9_validation_guard (
    valid INTEGER NOT NULL CHECK (valid = 1)
);

INSERT INTO gatehouse_migration9_validation_guard(valid)
SELECT 0
 WHERE EXISTS (
    SELECT 1
      FROM quota_snapshots
     WHERE typeof(snapshot_id) != 'text'
        OR length(CAST(snapshot_id AS BLOB)) NOT BETWEEN 1 AND 160
        OR length(CAST(snapshot_id AS BLOB)) != length(snapshot_id)
        OR typeof(quota_scope_id) != 'text'
        OR length(CAST(quota_scope_id AS BLOB)) NOT BETWEEN 1 AND 160
        OR length(CAST(quota_scope_id AS BLOB)) != length(quota_scope_id)
        OR typeof(unit) != 'text'
        OR length(CAST(unit AS BLOB)) NOT BETWEEN 1 AND 64
        OR length(CAST(unit AS BLOB)) != length(unit)
        OR typeof(captured_at_ms) != 'integer'
        OR captured_at_ms < 0
        OR (
            remaining_units IS NOT NULL
            AND (
                typeof(remaining_units) != 'integer'
                OR remaining_units < 0
                OR remaining_units > 9223372036854775807
            )
        )
        OR (
            plan_total_units IS NOT NULL
            AND (
                typeof(plan_total_units) != 'integer'
                OR plan_total_units < 0
                OR plan_total_units > 9223372036854775807
            )
        )
 );

INSERT INTO gatehouse_migration9_validation_guard(valid)
SELECT 0
 WHERE EXISTS (
    SELECT 1
      FROM quota_scopes
     WHERE (
            last_known_remaining_units IS NOT NULL
            AND (
                typeof(last_known_remaining_units) != 'integer'
                OR last_known_remaining_units < 0
                OR last_known_remaining_units > 9223372036854775807
            )
        )
        OR (
            balance_as_of_ms IS NOT NULL
            AND (
                typeof(balance_as_of_ms) != 'integer'
                OR balance_as_of_ms < 0
            )
        )
        OR (
            balance_snapshot_id IS NOT NULL
            AND (
                typeof(balance_snapshot_id) != 'text'
                OR length(CAST(balance_snapshot_id AS BLOB)) NOT BETWEEN 1 AND 160
                OR length(CAST(balance_snapshot_id AS BLOB)) != length(balance_snapshot_id)
            )
        )
        OR NOT (
            (
                last_known_remaining_units IS NULL
                AND balance_as_of_ms IS NULL
                AND balance_snapshot_id IS NULL
            )
            OR (
                last_known_remaining_units IS NOT NULL
                AND balance_snapshot_id IS NULL
            )
            OR (
                last_known_remaining_units IS NOT NULL
                AND balance_as_of_ms IS NOT NULL
                AND balance_snapshot_id IS NOT NULL
            )
        )
 );

-- A non-null snapshot identifier claims authoritative balance provenance.  It
-- must already identify the same scope, unit, capture instant, and projection.
INSERT INTO gatehouse_migration9_validation_guard(valid)
SELECT 0
 WHERE EXISTS (
    SELECT 1
      FROM quota_scopes AS scope
     WHERE scope.balance_snapshot_id IS NOT NULL
       AND NOT EXISTS (
            SELECT 1
              FROM quota_snapshots AS snapshot
             WHERE snapshot.snapshot_id = scope.balance_snapshot_id
               AND snapshot.quota_scope_id = scope.quota_scope_id
               AND snapshot.unit = scope.unit
               AND snapshot.captured_at_ms = scope.balance_as_of_ms
               AND snapshot.remaining_units = scope.last_known_remaining_units
               AND snapshot.remaining_units IS NOT NULL
       )
 );

INSERT INTO gatehouse_migration9_validation_guard(valid)
SELECT 0
 WHERE EXISTS (
    SELECT 1
      FROM reconciliation_items
     WHERE (
            provider_delta_units IS NOT NULL
            AND (
                typeof(provider_delta_units) != 'integer'
                OR provider_delta_units NOT BETWEEN -9223372036854775808
                                                AND 9223372036854775807
            )
        )
        OR (
            ledger_delta_units IS NOT NULL
            AND (
                typeof(ledger_delta_units) != 'integer'
                OR ledger_delta_units < 0
                OR ledger_delta_units > 9223372036854775807
            )
        )
        OR typeof(manual_adjustment_units) != 'integer'
        OR manual_adjustment_units NOT BETWEEN -9223372036854775808
                                              AND 9223372036854775807
        OR (
            unexplained_delta_units IS NOT NULL
            AND (
                typeof(unexplained_delta_units) != 'integer'
                OR unexplained_delta_units NOT BETWEEN -9223372036854775808
                                                   AND 9223372036854775807
            )
        )
 );

-- json_extract returns SQLite REAL for an out-of-range JSON integer.  Requiring
-- both JSON type integer and SQLite storage type integer proves that the legacy
-- tolerance can be converted without floating-point routing or rounding.
INSERT INTO gatehouse_migration9_validation_guard(valid)
SELECT 0
 WHERE EXISTS (
    SELECT 1
      FROM reconciliation_items
     WHERE typeof(details_json) != 'text'
        OR json_valid(details_json) != 1
        OR json_type(details_json, '$') != 'object'
        OR (
            SELECT count(*)
              FROM json_each(details_json)
             WHERE key = 'allowed_tolerance_units'
        ) != 1
        OR json_type(details_json, '$.allowed_tolerance_units') != 'integer'
        OR typeof(json_extract(details_json, '$.allowed_tolerance_units')) != 'integer'
        OR json_extract(details_json, '$.allowed_tolerance_units') < 0
        OR json_extract(details_json, '$.allowed_tolerance_units') > 9223372036854775807
 );

DROP TABLE gatehouse_migration9_validation_guard;

-- A legacy v8 cache without a snapshot anchor is not a provider observation.
-- Clear only the balance triplet; reservations and all other scope state remain.
UPDATE quota_scopes
   SET last_known_remaining_units = NULL,
       balance_as_of_ms = NULL,
       balance_snapshot_id = NULL
 WHERE last_known_remaining_units IS NOT NULL
   AND balance_snapshot_id IS NULL;

ALTER TABLE quota_snapshots
ADD COLUMN observed_remaining_units_decimal TEXT NULL;

ALTER TABLE quota_snapshots
ADD COLUMN observed_plan_total_units_decimal TEXT NULL;

ALTER TABLE reconciliation_items
ADD COLUMN provider_delta_units_decimal TEXT NULL;

ALTER TABLE reconciliation_items
ADD COLUMN unexplained_delta_units_decimal TEXT NULL;

ALTER TABLE reconciliation_items
ADD COLUMN allowed_tolerance_units_decimal TEXT NULL;

UPDATE quota_snapshots
   SET observed_remaining_units_decimal = CASE
           WHEN remaining_units IS NULL THEN NULL
           ELSE CAST(remaining_units AS TEXT)
       END,
       observed_plan_total_units_decimal = CASE
           WHEN plan_total_units IS NULL THEN NULL
           ELSE CAST(plan_total_units AS TEXT)
       END;

UPDATE reconciliation_items
   SET provider_delta_units_decimal = CASE
           WHEN provider_delta_units IS NULL THEN NULL
           ELSE CAST(provider_delta_units AS TEXT)
       END,
       unexplained_delta_units_decimal = CASE
           WHEN unexplained_delta_units IS NULL THEN NULL
           ELSE CAST(unexplained_delta_units AS TEXT)
       END,
       allowed_tolerance_units_decimal = CAST(
           json_extract(details_json, '$.allowed_tolerance_units') AS TEXT
       );

UPDATE reconciliation_items
   SET details_json = json_set(
           details_json,
           '$.allowed_tolerance_units',
           CAST(json_extract(details_json, '$.allowed_tolerance_units') AS TEXT)
       );

CREATE TRIGGER quota_snapshots_decimal_shape_insert
BEFORE INSERT ON quota_snapshots
WHEN
    (NEW.remaining_units IS NULL) != (NEW.observed_remaining_units_decimal IS NULL)
    OR (NEW.plan_total_units IS NULL) != (NEW.observed_plan_total_units_decimal IS NULL)
    OR (
        NEW.remaining_units IS NOT NULL
        AND (
            typeof(NEW.remaining_units) != 'integer'
            OR NEW.remaining_units < 0
            OR NEW.remaining_units > 9223372036854775807
        )
    )
    OR (
        NEW.plan_total_units IS NOT NULL
        AND (
            typeof(NEW.plan_total_units) != 'integer'
            OR NEW.plan_total_units < 0
            OR NEW.plan_total_units > 9223372036854775807
        )
    )
    OR (
        NEW.observed_remaining_units_decimal IS NOT NULL
        AND (
            typeof(NEW.observed_remaining_units_decimal) != 'text'
            OR length(CAST(NEW.observed_remaining_units_decimal AS BLOB)) NOT BETWEEN 1 AND 258
            OR length(CAST(NEW.observed_remaining_units_decimal AS BLOB))
                != length(NEW.observed_remaining_units_decimal)
        )
    )
    OR (
        NEW.observed_plan_total_units_decimal IS NOT NULL
        AND (
            typeof(NEW.observed_plan_total_units_decimal) != 'text'
            OR length(CAST(NEW.observed_plan_total_units_decimal AS BLOB)) NOT BETWEEN 1 AND 258
            OR length(CAST(NEW.observed_plan_total_units_decimal AS BLOB))
                != length(NEW.observed_plan_total_units_decimal)
        )
    )
    OR typeof(NEW.captured_at_ms) != 'integer'
    OR NEW.captured_at_ms < 0
    OR NOT EXISTS (
        SELECT 1
          FROM quota_scopes AS scope
         WHERE scope.quota_scope_id = NEW.quota_scope_id
           AND scope.unit = NEW.unit
    )
BEGIN
    SELECT RAISE(ABORT, 'invalid quota snapshot decimal shape');
END;

CREATE TRIGGER quota_snapshots_decimal_shape_update
BEFORE UPDATE ON quota_snapshots
WHEN
    (NEW.remaining_units IS NULL) != (NEW.observed_remaining_units_decimal IS NULL)
    OR (NEW.plan_total_units IS NULL) != (NEW.observed_plan_total_units_decimal IS NULL)
    OR (
        NEW.remaining_units IS NOT NULL
        AND (
            typeof(NEW.remaining_units) != 'integer'
            OR NEW.remaining_units < 0
            OR NEW.remaining_units > 9223372036854775807
        )
    )
    OR (
        NEW.plan_total_units IS NOT NULL
        AND (
            typeof(NEW.plan_total_units) != 'integer'
            OR NEW.plan_total_units < 0
            OR NEW.plan_total_units > 9223372036854775807
        )
    )
    OR (
        NEW.observed_remaining_units_decimal IS NOT NULL
        AND (
            typeof(NEW.observed_remaining_units_decimal) != 'text'
            OR length(CAST(NEW.observed_remaining_units_decimal AS BLOB)) NOT BETWEEN 1 AND 258
            OR length(CAST(NEW.observed_remaining_units_decimal AS BLOB))
                != length(NEW.observed_remaining_units_decimal)
        )
    )
    OR (
        NEW.observed_plan_total_units_decimal IS NOT NULL
        AND (
            typeof(NEW.observed_plan_total_units_decimal) != 'text'
            OR length(CAST(NEW.observed_plan_total_units_decimal AS BLOB)) NOT BETWEEN 1 AND 258
            OR length(CAST(NEW.observed_plan_total_units_decimal AS BLOB))
                != length(NEW.observed_plan_total_units_decimal)
        )
    )
    OR typeof(NEW.captured_at_ms) != 'integer'
    OR NEW.captured_at_ms < 0
    OR NOT EXISTS (
        SELECT 1
          FROM quota_scopes AS scope
         WHERE scope.quota_scope_id = NEW.quota_scope_id
           AND scope.unit = NEW.unit
    )
BEGIN
    SELECT RAISE(ABORT, 'invalid quota snapshot decimal shape');
END;

CREATE TRIGGER quota_snapshots_observation_immutable
BEFORE UPDATE ON quota_snapshots
WHEN NEW.snapshot_id IS NOT OLD.snapshot_id
    OR NEW.quota_scope_id IS NOT OLD.quota_scope_id
    OR NEW.remaining_units IS NOT OLD.remaining_units
    OR NEW.plan_total_units IS NOT OLD.plan_total_units
    OR NEW.observed_remaining_units_decimal IS NOT OLD.observed_remaining_units_decimal
    OR NEW.observed_plan_total_units_decimal IS NOT OLD.observed_plan_total_units_decimal
    OR NEW.unit IS NOT OLD.unit
    OR NEW.period_start_ms IS NOT OLD.period_start_ms
    OR NEW.period_end_ms IS NOT OLD.period_end_ms
    OR NEW.captured_at_ms IS NOT OLD.captured_at_ms
    OR NEW.source IS NOT OLD.source
    OR NEW.metadata_json IS NOT OLD.metadata_json
BEGIN
    SELECT RAISE(ABORT, 'quota snapshot observation is immutable');
END;

CREATE TRIGGER reconciliation_decimal_shape_insert
BEFORE INSERT ON reconciliation_items
WHEN
    (
        NEW.provider_delta_units IS NOT NULL
        AND (
            typeof(NEW.provider_delta_units) != 'integer'
            OR NEW.provider_delta_units NOT BETWEEN -9223372036854775808
                                                AND 9223372036854775807
            OR NEW.provider_delta_units_decimal IS NULL
        )
    )
    OR (
        NEW.ledger_delta_units IS NOT NULL
        AND (
            typeof(NEW.ledger_delta_units) != 'integer'
            OR NEW.ledger_delta_units < 0
            OR NEW.ledger_delta_units > 9223372036854775807
        )
    )
    OR typeof(NEW.manual_adjustment_units) != 'integer'
    OR NEW.manual_adjustment_units NOT BETWEEN -9223372036854775808
                                               AND 9223372036854775807
    OR (
        NEW.unexplained_delta_units IS NOT NULL
        AND (
            typeof(NEW.unexplained_delta_units) != 'integer'
            OR NEW.unexplained_delta_units NOT BETWEEN -9223372036854775808
                                                   AND 9223372036854775807
            OR NEW.unexplained_delta_units_decimal IS NULL
        )
    )
    OR NEW.allowed_tolerance_units_decimal IS NULL
    OR (
        NEW.provider_delta_units_decimal IS NOT NULL
        AND (
            typeof(NEW.provider_delta_units_decimal) != 'text'
            OR length(CAST(NEW.provider_delta_units_decimal AS BLOB)) NOT BETWEEN 1 AND 385
            OR length(CAST(NEW.provider_delta_units_decimal AS BLOB))
                != length(NEW.provider_delta_units_decimal)
        )
    )
    OR (
        NEW.unexplained_delta_units_decimal IS NOT NULL
        AND (
            typeof(NEW.unexplained_delta_units_decimal) != 'text'
            OR length(CAST(NEW.unexplained_delta_units_decimal AS BLOB)) NOT BETWEEN 1 AND 385
            OR length(CAST(NEW.unexplained_delta_units_decimal AS BLOB))
                != length(NEW.unexplained_delta_units_decimal)
        )
    )
    OR typeof(NEW.allowed_tolerance_units_decimal) != 'text'
    OR length(CAST(NEW.allowed_tolerance_units_decimal AS BLOB)) NOT BETWEEN 1 AND 385
    OR length(CAST(NEW.allowed_tolerance_units_decimal AS BLOB))
        != length(NEW.allowed_tolerance_units_decimal)
BEGIN
    SELECT RAISE(ABORT, 'invalid reconciliation decimal shape');
END;

CREATE TRIGGER reconciliation_decimal_shape_update
BEFORE UPDATE ON reconciliation_items
WHEN
    (
        NEW.provider_delta_units IS NOT NULL
        AND (
            typeof(NEW.provider_delta_units) != 'integer'
            OR NEW.provider_delta_units NOT BETWEEN -9223372036854775808
                                                AND 9223372036854775807
            OR NEW.provider_delta_units_decimal IS NULL
        )
    )
    OR (
        NEW.ledger_delta_units IS NOT NULL
        AND (
            typeof(NEW.ledger_delta_units) != 'integer'
            OR NEW.ledger_delta_units < 0
            OR NEW.ledger_delta_units > 9223372036854775807
        )
    )
    OR typeof(NEW.manual_adjustment_units) != 'integer'
    OR NEW.manual_adjustment_units NOT BETWEEN -9223372036854775808
                                               AND 9223372036854775807
    OR (
        NEW.unexplained_delta_units IS NOT NULL
        AND (
            typeof(NEW.unexplained_delta_units) != 'integer'
            OR NEW.unexplained_delta_units NOT BETWEEN -9223372036854775808
                                                   AND 9223372036854775807
            OR NEW.unexplained_delta_units_decimal IS NULL
        )
    )
    OR NEW.allowed_tolerance_units_decimal IS NULL
    OR (
        NEW.provider_delta_units_decimal IS NOT NULL
        AND (
            typeof(NEW.provider_delta_units_decimal) != 'text'
            OR length(CAST(NEW.provider_delta_units_decimal AS BLOB)) NOT BETWEEN 1 AND 385
            OR length(CAST(NEW.provider_delta_units_decimal AS BLOB))
                != length(NEW.provider_delta_units_decimal)
        )
    )
    OR (
        NEW.unexplained_delta_units_decimal IS NOT NULL
        AND (
            typeof(NEW.unexplained_delta_units_decimal) != 'text'
            OR length(CAST(NEW.unexplained_delta_units_decimal AS BLOB)) NOT BETWEEN 1 AND 385
            OR length(CAST(NEW.unexplained_delta_units_decimal AS BLOB))
                != length(NEW.unexplained_delta_units_decimal)
        )
    )
    OR typeof(NEW.allowed_tolerance_units_decimal) != 'text'
    OR length(CAST(NEW.allowed_tolerance_units_decimal AS BLOB)) NOT BETWEEN 1 AND 385
    OR length(CAST(NEW.allowed_tolerance_units_decimal AS BLOB))
        != length(NEW.allowed_tolerance_units_decimal)
BEGIN
    SELECT RAISE(ABORT, 'invalid reconciliation decimal shape');
END;

CREATE TRIGGER quota_scopes_balance_authority_insert
BEFORE INSERT ON quota_scopes
WHEN NOT (
    (
        NEW.last_known_remaining_units IS NULL
        AND NEW.balance_as_of_ms IS NULL
        AND NEW.balance_snapshot_id IS NULL
    )
    OR (
        typeof(NEW.last_known_remaining_units) = 'integer'
        AND NEW.last_known_remaining_units BETWEEN 0 AND 9223372036854775807
        AND typeof(NEW.balance_as_of_ms) = 'integer'
        AND NEW.balance_as_of_ms >= 0
        AND typeof(NEW.balance_snapshot_id) = 'text'
        AND length(CAST(NEW.balance_snapshot_id AS BLOB)) BETWEEN 1 AND 160
        AND length(CAST(NEW.balance_snapshot_id AS BLOB)) = length(NEW.balance_snapshot_id)
        AND EXISTS (
            SELECT 1
              FROM quota_snapshots AS snapshot
             WHERE snapshot.snapshot_id = NEW.balance_snapshot_id
               AND snapshot.quota_scope_id = NEW.quota_scope_id
               AND snapshot.unit = NEW.unit
               AND snapshot.captured_at_ms = NEW.balance_as_of_ms
               AND snapshot.remaining_units = NEW.last_known_remaining_units
               AND snapshot.remaining_units IS NOT NULL
        )
    )
)
BEGIN
    SELECT RAISE(ABORT, 'invalid quota scope balance authority');
END;

CREATE TRIGGER quota_scopes_balance_authority_update
BEFORE UPDATE ON quota_scopes
WHEN NOT (
    (
        NEW.last_known_remaining_units IS NULL
        AND NEW.balance_as_of_ms IS NULL
        AND NEW.balance_snapshot_id IS NULL
    )
    OR (
        typeof(NEW.last_known_remaining_units) = 'integer'
        AND NEW.last_known_remaining_units BETWEEN 0 AND 9223372036854775807
        AND typeof(NEW.balance_as_of_ms) = 'integer'
        AND NEW.balance_as_of_ms >= 0
        AND typeof(NEW.balance_snapshot_id) = 'text'
        AND length(CAST(NEW.balance_snapshot_id AS BLOB)) BETWEEN 1 AND 160
        AND length(CAST(NEW.balance_snapshot_id AS BLOB)) = length(NEW.balance_snapshot_id)
        AND EXISTS (
            SELECT 1
              FROM quota_snapshots AS snapshot
             WHERE snapshot.snapshot_id = NEW.balance_snapshot_id
               AND snapshot.quota_scope_id = NEW.quota_scope_id
               AND snapshot.unit = NEW.unit
               AND snapshot.captured_at_ms = NEW.balance_as_of_ms
               AND snapshot.remaining_units = NEW.last_known_remaining_units
               AND snapshot.remaining_units IS NOT NULL
        )
    )
)
BEGIN
    SELECT RAISE(ABORT, 'invalid quota scope balance authority');
END;
"""


PROVIDER_ACCOUNTS_DURABLE_QUOTA_STATE = r"""
-- Migration 10 adds provider-neutral identity, quota-dimension, observation,
-- and durable health-state provenance without rewriting any v1-v9 table.
CREATE TABLE gatehouse_migration10_validation_guard (
    valid INTEGER NOT NULL CHECK (valid = 1)
);

INSERT INTO gatehouse_migration10_validation_guard(valid)
SELECT 0
 WHERE EXISTS (
    SELECT 1
      FROM quota_scopes
     WHERE typeof(quota_scope_id) != 'text'
        OR length(CAST(quota_scope_id AS BLOB)) NOT BETWEEN 1 AND 160
        OR length(CAST(quota_scope_id AS BLOB)) != length(quota_scope_id)
        OR typeof(unit) != 'text'
        OR length(CAST(unit AS BLOB)) NOT BETWEEN 1 AND 64
        OR length(CAST(unit AS BLOB)) != length(unit)
        OR state NOT IN (
            'HEALTHY', 'EXHAUSTED', 'UNKNOWN', 'DISABLED', 'QUARANTINED', 'COOLDOWN'
        )
 );

INSERT INTO gatehouse_migration10_validation_guard(valid)
SELECT 0
 WHERE EXISTS (
    SELECT 1
      FROM principals
     WHERE typeof(principal_id) != 'text'
        OR length(CAST(principal_id AS BLOB)) NOT BETWEEN 1 AND 160
        OR length(CAST(principal_id AS BLOB)) != length(principal_id)
 );

INSERT INTO gatehouse_migration10_validation_guard(valid)
SELECT 0
 WHERE EXISTS (
    SELECT 1
      FROM credentials
     WHERE typeof(credential_id) != 'text'
        OR length(CAST(credential_id AS BLOB)) NOT BETWEEN 1 AND 160
        OR length(CAST(credential_id AS BLOB)) != length(credential_id)
        OR typeof(generation) != 'integer'
        OR generation <= 0
 );

DROP TABLE gatehouse_migration10_validation_guard;

ALTER TABLE principals
ADD COLUMN identity_kind TEXT NOT NULL DEFAULT 'LEGACY' CHECK (
    identity_kind IN ('LEGACY', 'ACCOUNT', 'TEAM', 'PROJECT', 'USER', 'ORGANIZATION')
);

ALTER TABLE credentials
ADD COLUMN credential_role TEXT NOT NULL DEFAULT 'WORKLOAD' CHECK (
    credential_role IN ('WORKLOAD', 'INFERENCE', 'MANAGEMENT', 'OBSERVER')
);

ALTER TABLE quota_scopes
ADD COLUMN scope_kind TEXT NOT NULL DEFAULT 'LEGACY' CHECK (
    scope_kind IN (
        'LEGACY', 'ACCOUNT', 'TEAM', 'PROJECT', 'KEY_BUDGET', 'RATE_BUCKET'
    )
);

ALTER TABLE quota_scopes
ADD COLUMN state_generation INTEGER NOT NULL DEFAULT 0 CHECK (state_generation >= 0);

ALTER TABLE quota_scopes
ADD COLUMN state_changed_at_ms INTEGER NOT NULL DEFAULT 0 CHECK (state_changed_at_ms >= 0);

ALTER TABLE quota_scopes
ADD COLUMN state_reason_code TEXT NOT NULL DEFAULT 'LEGACY_MIGRATION' CHECK (
    length(state_reason_code) BETWEEN 1 AND 96
);

ALTER TABLE quota_scopes
ADD COLUMN cooldown_until_ms INTEGER CHECK (
    cooldown_until_ms IS NULL OR cooldown_until_ms >= 0
);

ALTER TABLE quota_scopes
ADD COLUMN exhausted_at_ms INTEGER CHECK (
    exhausted_at_ms IS NULL OR exhausted_at_ms >= 0
);

ALTER TABLE quota_scopes
ADD COLUMN recovered_at_ms INTEGER CHECK (
    recovered_at_ms IS NULL OR recovered_at_ms >= 0
);

CREATE TABLE quota_dimensions (
    quota_dimension_id TEXT PRIMARY KEY,
    quota_scope_id TEXT NOT NULL REFERENCES quota_scopes(quota_scope_id),
    name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 96),
    native_unit TEXT NOT NULL CHECK (length(native_unit) BETWEEN 1 AND 64),
    counter_kind TEXT NOT NULL CHECK (
        counter_kind IN ('LEGACY', 'BALANCE', 'BUDGET', 'RATE', 'TOKEN', 'REQUEST')
    ),
    reset_window_kind TEXT NOT NULL CHECK (
        reset_window_kind IN ('NONE', 'FIXED', 'ROLLING', 'PROVIDER')
    ),
    is_primary INTEGER NOT NULL DEFAULT 0 CHECK (is_primary IN (0, 1)),
    state TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (state IN ('ACTIVE', 'DISABLED')),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= created_at_ms),
    metadata_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json)),
    UNIQUE(quota_scope_id, name)
);

CREATE UNIQUE INDEX uq_quota_dimensions_one_primary
ON quota_dimensions(quota_scope_id) WHERE is_primary = 1;

CREATE INDEX idx_quota_dimensions_scope_state
ON quota_dimensions(quota_scope_id, state, name);

INSERT INTO quota_dimensions(
    quota_dimension_id, quota_scope_id, name, native_unit, counter_kind,
    reset_window_kind, is_primary, state, created_at_ms, updated_at_ms
)
SELECT 'dimension_legacy_primary:' || quota_scope_id,
       quota_scope_id, 'legacy-primary', unit, 'LEGACY', 'NONE', 1, 'ACTIVE', 0, 0
  FROM quota_scopes;

CREATE TRIGGER quota_scopes_primary_dimension_insert
AFTER INSERT ON quota_scopes
BEGIN
    INSERT INTO quota_dimensions(
        quota_dimension_id, quota_scope_id, name, native_unit, counter_kind,
        reset_window_kind, is_primary, state, created_at_ms, updated_at_ms
    ) VALUES (
        'dimension_legacy_primary:' || NEW.quota_scope_id,
        NEW.quota_scope_id, 'legacy-primary', NEW.unit, 'LEGACY', 'NONE',
        1, 'ACTIVE', 0, 0
    );
END;

ALTER TABLE quota_snapshots
ADD COLUMN quota_dimension_id TEXT REFERENCES quota_dimensions(quota_dimension_id);

ALTER TABLE quota_snapshots
ADD COLUMN credential_id TEXT REFERENCES credentials(credential_id);

ALTER TABLE quota_snapshots
ADD COLUMN credential_generation INTEGER CHECK (
    credential_generation IS NULL OR credential_generation > 0
);

ALTER TABLE quota_snapshots
ADD COLUMN stale_at_ms INTEGER CHECK (stale_at_ms IS NULL OR stale_at_ms >= 0);

ALTER TABLE quota_snapshots
ADD COLUMN observation_kind TEXT NOT NULL DEFAULT 'LEGACY' CHECK (
    observation_kind IN ('LEGACY', 'SCRIPTED', 'AUTHENTICATED')
);

ALTER TABLE quota_snapshots
ADD COLUMN used_units INTEGER CHECK (used_units IS NULL OR used_units >= 0);

ALTER TABLE quota_snapshots
ADD COLUMN observed_used_units_decimal TEXT;

UPDATE quota_snapshots
   SET quota_dimension_id = 'dimension_legacy_primary:' || quota_scope_id;

-- Only Gatehouse's exact built-in no-network synthetic observation is
-- grandfathered as non-expiring authority. Every other v9 observation stays
-- LEGACY and therefore fails the v10 freshness fence until re-observed.
UPDATE quota_snapshots
   SET observation_kind = 'SCRIPTED'
 WHERE snapshot_id = 'snapshot_gatehouse_scripted_no_network_v1'
   AND source = 'scripted-no-network-synthetic'
   AND json_valid(metadata_json) = 1
   AND json_type(metadata_json, '$') = 'object'
   AND (SELECT COUNT(*) FROM json_each(metadata_json)) = 3
   AND json_type(metadata_json, '$.network') = 'false'
   AND json_type(metadata_json, '$.synthetic') = char(116, 114, 117, 101)
   AND json_extract(metadata_json, '$.transport') = 'scripted'
   AND EXISTS (
       SELECT 1
         FROM quota_scopes AS scope
         JOIN principals AS principal ON principal.principal_id = scope.principal_id
        WHERE scope.quota_scope_id = quota_snapshots.quota_scope_id
          AND scope.metadata_json = '{"transport":"scripted","network":false}'
          AND principal.service_id = 'firecrawl'
   );

CREATE TRIGGER quota_snapshots_v10_shape_insert
BEFORE INSERT ON quota_snapshots
WHEN
    NEW.quota_dimension_id IS NULL
    OR NOT EXISTS (
        SELECT 1
          FROM quota_dimensions AS dimension
         WHERE dimension.quota_dimension_id = NEW.quota_dimension_id
           AND dimension.quota_scope_id = NEW.quota_scope_id
           AND dimension.native_unit = NEW.unit
           AND dimension.state = 'ACTIVE'
    )
    OR (NEW.credential_id IS NULL) != (NEW.credential_generation IS NULL)
    OR (NEW.used_units IS NULL) != (NEW.observed_used_units_decimal IS NULL)
    OR (
        NEW.used_units IS NOT NULL
        AND (
            typeof(NEW.used_units) != 'integer'
            OR NEW.used_units < 0
            OR typeof(NEW.observed_used_units_decimal) != 'text'
            OR length(CAST(NEW.observed_used_units_decimal AS BLOB)) NOT BETWEEN 1 AND 258
            OR length(CAST(NEW.observed_used_units_decimal AS BLOB))
                != length(NEW.observed_used_units_decimal)
        )
    )
    OR NOT (
        (
            NEW.observation_kind = 'LEGACY'
            AND NEW.credential_id IS NULL
            AND NEW.stale_at_ms IS NULL
        )
        OR (
            NEW.observation_kind = 'SCRIPTED'
            AND NEW.snapshot_id = 'snapshot_gatehouse_scripted_no_network_v1'
            AND NEW.source = 'scripted-no-network-synthetic'
            AND json_valid(NEW.metadata_json) = 1
            AND json_type(NEW.metadata_json, '$') = 'object'
            AND (SELECT COUNT(*) FROM json_each(NEW.metadata_json)) = 3
            AND json_type(NEW.metadata_json, '$.network') = 'false'
            AND json_type(NEW.metadata_json, '$.synthetic') = char(116, 114, 117, 101)
            AND json_extract(NEW.metadata_json, '$.transport') = 'scripted'
            AND NEW.credential_id IS NULL
            AND NEW.stale_at_ms IS NULL
            AND EXISTS (
                SELECT 1
                  FROM quota_scopes AS scope
                  JOIN principals AS principal
                    ON principal.principal_id = scope.principal_id
                 WHERE scope.quota_scope_id = NEW.quota_scope_id
                   AND scope.metadata_json = '{"transport":"scripted","network":false}'
                   AND principal.service_id = 'firecrawl'
            )
        )
        OR (
            NEW.observation_kind = 'AUTHENTICATED'
            AND NEW.credential_id IS NOT NULL
            AND typeof(NEW.credential_generation) = 'integer'
            AND NEW.credential_generation > 0
            AND typeof(NEW.stale_at_ms) = 'integer'
            AND NEW.stale_at_ms > NEW.captured_at_ms
            AND EXISTS (
                SELECT 1
                  FROM credentials AS credential
                 WHERE credential.credential_id = NEW.credential_id
                   AND credential.quota_scope_id = NEW.quota_scope_id
                   AND credential.generation = NEW.credential_generation
            )
        )
    )
BEGIN
    SELECT RAISE(ABORT, 'invalid quota snapshot v10 provenance');
END;

CREATE TRIGGER quota_snapshots_v10_shape_update
BEFORE UPDATE ON quota_snapshots
WHEN
    NEW.quota_dimension_id IS NULL
    OR NOT EXISTS (
        SELECT 1
          FROM quota_dimensions AS dimension
         WHERE dimension.quota_dimension_id = NEW.quota_dimension_id
           AND dimension.quota_scope_id = NEW.quota_scope_id
           AND dimension.native_unit = NEW.unit
           AND dimension.state = 'ACTIVE'
    )
    OR (NEW.credential_id IS NULL) != (NEW.credential_generation IS NULL)
    OR (NEW.used_units IS NULL) != (NEW.observed_used_units_decimal IS NULL)
    OR (
        NEW.used_units IS NOT NULL
        AND (
            typeof(NEW.used_units) != 'integer'
            OR NEW.used_units < 0
            OR typeof(NEW.observed_used_units_decimal) != 'text'
            OR length(CAST(NEW.observed_used_units_decimal AS BLOB)) NOT BETWEEN 1 AND 258
            OR length(CAST(NEW.observed_used_units_decimal AS BLOB))
                != length(NEW.observed_used_units_decimal)
        )
    )
    OR NOT (
        (
            NEW.observation_kind = 'LEGACY'
            AND NEW.credential_id IS NULL
            AND NEW.stale_at_ms IS NULL
        )
        OR (
            NEW.observation_kind = 'SCRIPTED'
            AND NEW.snapshot_id = 'snapshot_gatehouse_scripted_no_network_v1'
            AND NEW.source = 'scripted-no-network-synthetic'
            AND json_valid(NEW.metadata_json) = 1
            AND json_type(NEW.metadata_json, '$') = 'object'
            AND (SELECT COUNT(*) FROM json_each(NEW.metadata_json)) = 3
            AND json_type(NEW.metadata_json, '$.network') = 'false'
            AND json_type(NEW.metadata_json, '$.synthetic') = char(116, 114, 117, 101)
            AND json_extract(NEW.metadata_json, '$.transport') = 'scripted'
            AND NEW.credential_id IS NULL
            AND NEW.stale_at_ms IS NULL
            AND EXISTS (
                SELECT 1
                  FROM quota_scopes AS scope
                  JOIN principals AS principal
                    ON principal.principal_id = scope.principal_id
                 WHERE scope.quota_scope_id = NEW.quota_scope_id
                   AND scope.metadata_json = '{"transport":"scripted","network":false}'
                   AND principal.service_id = 'firecrawl'
            )
        )
        OR (
            NEW.observation_kind = 'AUTHENTICATED'
            AND NEW.credential_id IS NOT NULL
            AND typeof(NEW.credential_generation) = 'integer'
            AND NEW.credential_generation > 0
            AND typeof(NEW.stale_at_ms) = 'integer'
            AND NEW.stale_at_ms > NEW.captured_at_ms
            AND EXISTS (
                SELECT 1
                  FROM credentials AS credential
                 WHERE credential.credential_id = NEW.credential_id
                   AND credential.quota_scope_id = NEW.quota_scope_id
                   AND credential.generation = NEW.credential_generation
            )
        )
    )
BEGIN
    SELECT RAISE(ABORT, 'invalid quota snapshot v10 provenance');
END;

CREATE TRIGGER quota_snapshots_v10_immutable
BEFORE UPDATE ON quota_snapshots
WHEN NEW.quota_dimension_id IS NOT OLD.quota_dimension_id
    OR NEW.credential_id IS NOT OLD.credential_id
    OR NEW.credential_generation IS NOT OLD.credential_generation
    OR NEW.stale_at_ms IS NOT OLD.stale_at_ms
    OR NEW.observation_kind IS NOT OLD.observation_kind
    OR NEW.used_units IS NOT OLD.used_units
    OR NEW.observed_used_units_decimal IS NOT OLD.observed_used_units_decimal
BEGIN
    SELECT RAISE(ABORT, 'quota snapshot v10 provenance is immutable');
END;

CREATE TABLE quota_scope_state_events (
    event_id TEXT PRIMARY KEY,
    quota_scope_id TEXT NOT NULL REFERENCES quota_scopes(quota_scope_id),
    generation INTEGER NOT NULL CHECK (generation >= 0),
    previous_state TEXT,
    new_state TEXT NOT NULL CHECK (
        new_state IN (
            'HEALTHY', 'EXHAUSTED', 'UNKNOWN', 'DISABLED', 'QUARANTINED', 'COOLDOWN'
        )
    ),
    reason_code TEXT NOT NULL CHECK (length(reason_code) BETWEEN 1 AND 96),
    source_kind TEXT NOT NULL CHECK (
        source_kind IN (
            'PROVIDER_RESPONSE', 'AUTHENTICATED_OBSERVATION', 'OPERATOR',
            'MIGRATION', 'SYSTEM'
        )
    ),
    snapshot_id TEXT REFERENCES quota_snapshots(snapshot_id),
    credential_id TEXT REFERENCES credentials(credential_id),
    credential_generation INTEGER CHECK (
        credential_generation IS NULL OR credential_generation > 0
    ),
    request_id TEXT REFERENCES invocations(request_id),
    attempt_id TEXT REFERENCES attempts(attempt_id),
    actor_id TEXT,
    occurred_at_ms INTEGER NOT NULL CHECK (occurred_at_ms >= 0),
    metadata_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json)),
    CHECK ((credential_id IS NULL) = (credential_generation IS NULL)),
    CHECK (
        (
            generation = 0
            AND previous_state IS NULL
            AND source_kind IN ('MIGRATION', 'SYSTEM', 'OPERATOR')
        )
        OR (generation > 0 AND previous_state IS NOT NULL)
    ),
    UNIQUE(quota_scope_id, generation)
);

CREATE INDEX idx_quota_scope_state_events_scope_time
ON quota_scope_state_events(quota_scope_id, occurred_at_ms, generation);

INSERT INTO quota_scope_state_events(
    event_id, quota_scope_id, generation, previous_state, new_state,
    reason_code, source_kind, occurred_at_ms
)
SELECT 'state_migration_v10:' || quota_scope_id,
       quota_scope_id, 0, NULL, state, 'LEGACY_MIGRATION', 'MIGRATION', 0
  FROM quota_scopes
 WHERE state IN (
     'HEALTHY', 'EXHAUSTED', 'UNKNOWN', 'DISABLED', 'QUARANTINED', 'COOLDOWN'
 );

CREATE TRIGGER quota_scope_state_events_immutable_update
BEFORE UPDATE ON quota_scope_state_events
BEGIN
    SELECT RAISE(ABORT, 'quota scope state event is immutable');
END;

CREATE TRIGGER quota_scope_state_events_immutable_delete
BEFORE DELETE ON quota_scope_state_events
BEGIN
    SELECT RAISE(ABORT, 'quota scope state event is immutable');
END;

ALTER TABLE circuit_breakers
ADD COLUMN generation INTEGER NOT NULL DEFAULT 0 CHECK (generation >= 0);

ALTER TABLE circuit_breakers
ADD COLUMN updated_at_ms INTEGER NOT NULL DEFAULT 0 CHECK (updated_at_ms >= 0);

ALTER TABLE circuit_breakers
ADD COLUMN recovery_policy TEXT NOT NULL DEFAULT 'TIMER' CHECK (
    recovery_policy IN ('TIMER', 'AUTHENTICATED_POSITIVE', 'OPERATOR')
);

CREATE TABLE quota_observation_schedules (
    schedule_id TEXT PRIMARY KEY,
    quota_scope_id TEXT NOT NULL UNIQUE REFERENCES quota_scopes(quota_scope_id),
    observer_credential_id TEXT REFERENCES credentials(credential_id),
    observer_credential_generation INTEGER CHECK (
        observer_credential_generation IS NULL OR observer_credential_generation > 0
    ),
    state TEXT NOT NULL DEFAULT 'DISABLED' CHECK (
        state IN ('DISABLED', 'ENABLED', 'PAUSED')
    ),
    interval_ms INTEGER NOT NULL CHECK (interval_ms BETWEEN 60000 AND 604800000),
    freshness_ttl_ms INTEGER NOT NULL CHECK (
        freshness_ttl_ms BETWEEN 60000 AND 604800000
    ),
    next_due_at_ms INTEGER CHECK (next_due_at_ms IS NULL OR next_due_at_ms >= 0),
    last_started_at_ms INTEGER CHECK (last_started_at_ms IS NULL OR last_started_at_ms >= 0),
    last_completed_at_ms INTEGER CHECK (last_completed_at_ms IS NULL OR last_completed_at_ms >= 0),
    last_snapshot_id TEXT REFERENCES quota_snapshots(snapshot_id),
    consecutive_failures INTEGER NOT NULL DEFAULT 0 CHECK (consecutive_failures >= 0),
    last_error_class TEXT,
    generation INTEGER NOT NULL DEFAULT 1 CHECK (generation > 0),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= created_at_ms),
    metadata_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json)),
    CHECK (
        (observer_credential_id IS NULL) =
        (observer_credential_generation IS NULL)
    )
);

CREATE INDEX idx_quota_observation_schedules_due
ON quota_observation_schedules(state, next_due_at_ms, quota_scope_id);
"""


RUNAWAY_QUARANTINE_BURST_AUTHORITY = r"""
-- Migration 11 replaces timer-healed, process-local runaway blocking with a
-- durable session/root-run/service quarantine and an explicitly bounded
-- operator-authorized burst capability.  It is append-only over v1-v10.
CREATE TABLE runaway_quarantines (
    quarantine_id TEXT PRIMARY KEY CHECK (
        length(CAST(quarantine_id AS BLOB)) BETWEEN 1 AND 160
        AND length(CAST(quarantine_id AS BLOB)) = length(quarantine_id)
    ),
    session_id TEXT NOT NULL REFERENCES sessions(session_id),
    root_run_id TEXT NOT NULL REFERENCES root_runs(root_run_id),
    service_id TEXT NOT NULL CHECK (
        length(CAST(service_id AS BLOB)) BETWEEN 1 AND 64
        AND length(CAST(service_id AS BLOB)) = length(service_id)
    ),
    state TEXT NOT NULL CHECK (
        state IN ('OPEN', 'AUTHORIZED', 'DENIED', 'EXPIRED', 'EXHAUSTED')
    ),
    trigger_reason TEXT NOT NULL CHECK (
        trigger_reason IN (
            'REPEATED_EQUIVALENT', 'AGGREGATE_BURST', 'DETECTOR_CAPACITY'
        )
    ),
    trigger_operation TEXT NOT NULL CHECK (
        length(CAST(trigger_operation AS BLOB)) BETWEEN 1 AND 160
        AND length(CAST(trigger_operation AS BLOB)) = length(trigger_operation)
    ),
    generation INTEGER NOT NULL DEFAULT 1 CHECK (generation > 0),
    opened_at_ms INTEGER NOT NULL CHECK (opened_at_ms >= 0),
    updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= opened_at_ms),
    decided_at_ms INTEGER CHECK (decided_at_ms IS NULL OR decided_at_ms >= opened_at_ms),
    expires_at_ms INTEGER CHECK (expires_at_ms IS NULL OR expires_at_ms > opened_at_ms),
    decision_actor_id TEXT CHECK (
        decision_actor_id IS NULL
        OR (
            length(CAST(decision_actor_id AS BLOB)) BETWEEN 1 AND 160
            AND length(CAST(decision_actor_id AS BLOB)) = length(decision_actor_id)
        )
    ),
    decision_reason_fingerprint TEXT CHECK (
        decision_reason_fingerprint IS NULL
        OR (
            length(decision_reason_fingerprint) = 64
            AND decision_reason_fingerprint NOT GLOB '*[^0-9a-f]*'
        )
    ),
    decision_reason_supplied INTEGER NOT NULL DEFAULT 0 CHECK (
        decision_reason_supplied IN (0, 1)
    ),
    maximum_requests INTEGER CHECK (maximum_requests BETWEEN 1 AND 25),
    remaining_requests INTEGER CHECK (remaining_requests BETWEEN 0 AND maximum_requests),
    maximum_credits INTEGER CHECK (maximum_credits BETWEEN 1 AND 100),
    remaining_credits INTEGER CHECK (remaining_credits BETWEEN 0 AND maximum_credits),
    maximum_concurrency INTEGER CHECK (maximum_concurrency BETWEEN 1 AND 8),
    active_concurrency INTEGER NOT NULL DEFAULT 0 CHECK (
        active_concurrency >= 0
        AND (maximum_concurrency IS NULL OR active_concurrency <= maximum_concurrency)
    ),
    operations_json TEXT NOT NULL DEFAULT '[]' CHECK (
        json_valid(operations_json)
        AND json_type(operations_json) = 'array'
        AND json_array_length(operations_json) BETWEEN 0 AND 16
    ),
    metadata_json TEXT NOT NULL DEFAULT '{}' CHECK (
        json_valid(metadata_json) AND json_type(metadata_json) = 'object'
    ),
    UNIQUE(session_id, root_run_id, service_id),
    CHECK (
        (
            state = 'OPEN'
            AND decided_at_ms IS NULL
            AND expires_at_ms IS NULL
            AND decision_actor_id IS NULL
            AND decision_reason_fingerprint IS NULL
            AND decision_reason_supplied = 0
            AND maximum_requests IS NULL
            AND remaining_requests IS NULL
            AND maximum_credits IS NULL
            AND remaining_credits IS NULL
            AND maximum_concurrency IS NULL
            AND active_concurrency = 0
            AND operations_json = '[]'
        )
        OR (
            state = 'DENIED'
            AND decided_at_ms IS NOT NULL
            AND expires_at_ms IS NULL
            AND decision_actor_id IS NOT NULL
            AND decision_reason_fingerprint IS NOT NULL
            AND decision_reason_supplied = 1
            AND maximum_requests IS NULL
            AND remaining_requests IS NULL
            AND maximum_credits IS NULL
            AND remaining_credits IS NULL
            AND maximum_concurrency IS NULL
            AND operations_json = '[]'
        )
        OR (
            state IN ('AUTHORIZED', 'EXPIRED', 'EXHAUSTED')
            AND decided_at_ms IS NOT NULL
            AND expires_at_ms IS NOT NULL
            AND decision_actor_id IS NOT NULL
            AND decision_reason_fingerprint IS NOT NULL
            AND decision_reason_supplied = 1
            AND maximum_requests IS NOT NULL
            AND remaining_requests IS NOT NULL
            AND maximum_credits IS NOT NULL
            AND remaining_credits IS NOT NULL
            AND maximum_concurrency IS NOT NULL
            AND json_array_length(operations_json) BETWEEN 1 AND 16
        )
    )
);

CREATE INDEX idx_runaway_quarantines_state_time
ON runaway_quarantines(state, updated_at_ms, quarantine_id);

CREATE TRIGGER runaway_quarantines_owner_insert
BEFORE INSERT ON runaway_quarantines
WHEN NOT EXISTS (
    SELECT 1 FROM root_runs
     WHERE root_run_id = NEW.root_run_id AND session_id = NEW.session_id
)
BEGIN
    SELECT RAISE(ABORT, 'runaway quarantine owner mismatch');
END;

CREATE TRIGGER runaway_quarantines_owner_update
BEFORE UPDATE OF session_id, root_run_id ON runaway_quarantines
WHEN NOT EXISTS (
    SELECT 1 FROM root_runs
     WHERE root_run_id = NEW.root_run_id AND session_id = NEW.session_id
)
BEGIN
    SELECT RAISE(ABORT, 'runaway quarantine owner mismatch');
END;

CREATE TABLE runaway_burst_permits (
    permit_id TEXT PRIMARY KEY CHECK (
        length(CAST(permit_id AS BLOB)) BETWEEN 1 AND 160
        AND length(CAST(permit_id AS BLOB)) = length(permit_id)
    ),
    quarantine_id TEXT NOT NULL REFERENCES runaway_quarantines(quarantine_id),
    authorization_generation INTEGER NOT NULL CHECK (authorization_generation > 0),
    request_id TEXT NOT NULL UNIQUE REFERENCES invocations(request_id),
    operation TEXT NOT NULL CHECK (
        length(CAST(operation AS BLOB)) BETWEEN 1 AND 160
        AND length(CAST(operation AS BLOB)) = length(operation)
    ),
    reserved_credits INTEGER NOT NULL CHECK (reserved_credits >= 0),
    observed_actual_credits INTEGER CHECK (observed_actual_credits >= 0),
    actual_cost_state TEXT NOT NULL DEFAULT 'PENDING' CHECK (
        actual_cost_state IN ('PENDING', 'KNOWN', 'NOT_REPORTED', 'UNKNOWN')
    ),
    state TEXT NOT NULL CHECK (state IN ('ACTIVE', 'SETTLED', 'ORPHANED')),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    settled_at_ms INTEGER CHECK (settled_at_ms IS NULL OR settled_at_ms >= created_at_ms),
    CHECK (
        (
            state = 'ACTIVE' AND settled_at_ms IS NULL
            AND actual_cost_state = 'PENDING' AND observed_actual_credits IS NULL
        )
        OR (
            state = 'SETTLED' AND settled_at_ms IS NOT NULL
            AND actual_cost_state IN ('KNOWN', 'NOT_REPORTED', 'UNKNOWN')
            AND (
                (actual_cost_state = 'KNOWN' AND observed_actual_credits IS NOT NULL)
                OR (actual_cost_state != 'KNOWN' AND observed_actual_credits IS NULL)
            )
        )
        OR (
            state = 'ORPHANED' AND settled_at_ms IS NOT NULL
            AND actual_cost_state = 'UNKNOWN' AND observed_actual_credits IS NULL
        )
    )
);

CREATE INDEX idx_runaway_burst_permits_active
ON runaway_burst_permits(quarantine_id, state, authorization_generation);

CREATE TRIGGER runaway_burst_permits_authority_insert
BEFORE INSERT ON runaway_burst_permits
WHEN NOT EXISTS (
    SELECT 1
      FROM runaway_quarantines AS quarantine
      JOIN invocations AS invocation ON invocation.request_id = NEW.request_id
     WHERE quarantine.quarantine_id = NEW.quarantine_id
       AND quarantine.state = 'AUTHORIZED'
       AND quarantine.generation = NEW.authorization_generation
       AND quarantine.session_id = invocation.session_id
       AND quarantine.root_run_id = invocation.root_run_id
       AND quarantine.service_id = invocation.service_id
       AND invocation.operation = NEW.operation
       AND quarantine.expires_at_ms > NEW.created_at_ms
       AND quarantine.remaining_requests > 0
       AND quarantine.remaining_credits >= NEW.reserved_credits
       AND quarantine.active_concurrency < quarantine.maximum_concurrency
)
BEGIN
    SELECT RAISE(ABORT, 'runaway burst permit authority mismatch');
END;
"""


PROVIDER_QUOTA_SCOPE_IDENTITIES = r"""
-- Migration 12 binds each supported provider-native quota owner to exactly one
-- Gatehouse quota scope.  Only a keyed fingerprint is retained; provider team
-- identifiers never enter SQLite.  Bindings survive account tombstoning and
-- are immutable so a removed account cannot later be double-counted.
CREATE TABLE provider_quota_scope_identities (
    provider_identity_id TEXT PRIMARY KEY CHECK (
        length(CAST(provider_identity_id AS BLOB)) BETWEEN 1 AND 160
        AND length(CAST(provider_identity_id AS BLOB)) = length(provider_identity_id)
    ),
    provider_id TEXT NOT NULL CHECK (
        length(CAST(provider_id AS BLOB)) BETWEEN 1 AND 64
        AND length(CAST(provider_id AS BLOB)) = length(provider_id)
    ),
    identity_kind TEXT NOT NULL CHECK (
        identity_kind IN (
            'ACCOUNT', 'TEAM', 'PROJECT', 'USER', 'ORGANIZATION',
            'KEY_BUDGET', 'RATE_BUCKET'
        )
    ),
    identity_fingerprint BLOB NOT NULL CHECK (
        typeof(identity_fingerprint) = 'blob' AND length(identity_fingerprint) = 32
    ),
    principal_id TEXT NOT NULL REFERENCES principals(principal_id),
    quota_scope_id TEXT NOT NULL UNIQUE REFERENCES quota_scopes(quota_scope_id),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    metadata_json TEXT NOT NULL DEFAULT '{}' CHECK (
        json_valid(metadata_json) AND json_type(metadata_json) = 'object'
    ),
    UNIQUE(provider_id, identity_kind, identity_fingerprint)
);

CREATE TRIGGER provider_quota_scope_identities_authority_insert
BEFORE INSERT ON provider_quota_scope_identities
WHEN NOT EXISTS (
    SELECT 1
      FROM principals AS principal
      JOIN quota_scopes AS scope
        ON scope.principal_id = principal.principal_id
     WHERE principal.principal_id = NEW.principal_id
       AND scope.quota_scope_id = NEW.quota_scope_id
       AND principal.service_id = NEW.provider_id
       AND scope.scope_kind != 'LEGACY'
)
BEGIN
    SELECT RAISE(ABORT, 'provider quota identity authority mismatch');
END;

CREATE TRIGGER provider_quota_scope_identities_immutable_update
BEFORE UPDATE ON provider_quota_scope_identities
BEGIN
    SELECT RAISE(ABORT, 'provider quota identity is immutable');
END;

CREATE TRIGGER provider_quota_scope_identities_retained_delete
BEFORE DELETE ON provider_quota_scope_identities
BEGIN
    SELECT RAISE(ABORT, 'provider quota identity is retained');
END;
"""


MIGRATIONS: tuple[Migration, ...] = (
    Migration(version=1, name="initial_gatehouse_schema", sql=INITIAL_SCHEMA),
    Migration(version=2, name="documentation_full_text_index", sql=DOCUMENTATION_FTS),
    Migration(
        version=3,
        name="resource_affinity_authority",
        sql=RESOURCE_AFFINITY_AUTHORITY,
    ),
    Migration(
        version=4,
        name="quota_balance_watermark",
        sql=QUOTA_BALANCE_WATERMARK,
    ),
    Migration(
        version=5,
        name="durable_root_run_budgets",
        sql=DURABLE_ROOT_RUN_BUDGETS,
    ),
    Migration(
        version=6,
        name="async_attempt_checkpoints",
        sql=ASYNC_ATTEMPT_CHECKPOINTS,
    ),
    Migration(
        version=7,
        name="async_attempt_checkpoint_immutability",
        sql=ASYNC_ATTEMPT_CHECKPOINT_IMMUTABILITY,
    ),
    Migration(
        version=8,
        name="credential_lifecycle",
        sql=CREDENTIAL_LIFECYCLE,
    ),
    Migration(
        version=9,
        name="canonical_decimal_credit_observations",
        sql=CANONICAL_DECIMAL_CREDIT_OBSERVATIONS,
    ),
    Migration(
        version=10,
        name="provider_accounts_durable_quota_state",
        sql=PROVIDER_ACCOUNTS_DURABLE_QUOTA_STATE,
    ),
    Migration(
        version=11,
        name="runaway_quarantine_burst_authority",
        sql=RUNAWAY_QUARANTINE_BURST_AUTHORITY,
    ),
    Migration(
        version=12,
        name="provider_quota_scope_identities",
        sql=PROVIDER_QUOTA_SCOPE_IDENTITIES,
    ),
)


def _validate_migrations(migrations: tuple[Migration, ...]) -> None:
    expected = list(range(1, len(migrations) + 1))
    actual = [migration.version for migration in migrations]
    if actual != expected:
        raise MigrationOrderError(f"migration versions must be contiguous from 1; got {actual!r}")
    if len({migration.name for migration in migrations}) != len(migrations):
        raise MigrationOrderError("migration names must be unique")


def apply_migrations(
    connection: sqlite3.Connection,
    *,
    migrations: tuple[Migration, ...] = MIGRATIONS,
    now_ms: int | None = None,
) -> int:
    """Verify applied checksums and atomically apply every pending migration."""

    _validate_migrations(migrations)
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            checksum_sha256 TEXT NOT NULL,
            applied_at_ms INTEGER NOT NULL
        )
        """
    )
    applied_rows = connection.execute(
        "SELECT version, name, checksum_sha256 FROM schema_migrations ORDER BY version"
    ).fetchall()
    configured = {migration.version: migration for migration in migrations}
    for row in applied_rows:
        version = int(row["version"])
        migration = configured.get(version)
        if migration is None:
            raise MigrationDriftError(f"database contains unknown migration version {version}")
        if row["name"] != migration.name or row["checksum_sha256"] != migration.checksum:
            raise MigrationDriftError(f"migration {version} no longer matches the database")

    applied_versions = {int(row["version"]) for row in applied_rows}
    applied_at = int(time.time() * 1_000) if now_ms is None else now_ms
    for migration in migrations:
        if migration.version in applied_versions:
            continue
        escaped_name = migration.name.replace("'", "''")
        script = (
            "BEGIN IMMEDIATE;\n"
            f"{migration.sql}\n"
            "INSERT INTO schema_migrations(version, name, checksum_sha256, applied_at_ms) "
            f"VALUES ({migration.version}, '{escaped_name}', "
            f"'{migration.checksum}', {int(applied_at)});\n"
            f"PRAGMA user_version = {migration.version};\n"
            "COMMIT;"
        )
        try:
            connection.executescript(script)
        except BaseException:
            if connection.in_transaction:
                connection.rollback()
            raise

    version = int(connection.execute("PRAGMA user_version").fetchone()[0])
    expected_version = migrations[-1].version if migrations else 0
    if version != expected_version:
        raise MigrationError(
            f"database reports schema version {version}, expected {expected_version}"
        )
    return version


def open_migrated_database(
    path: str | Path,
    *,
    busy_timeout_ms: int = DEFAULT_BUSY_TIMEOUT_MS,
) -> sqlite3.Connection:
    """Open a configured connection and bring it to the current schema."""

    connection = connect_database(path, busy_timeout_ms=busy_timeout_ms)
    try:
        apply_migrations(connection)
    except BaseException:
        connection.close()
        raise
    return connection
