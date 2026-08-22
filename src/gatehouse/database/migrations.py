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
