"""Crash-safe SQLite persistence for invocation lifecycle metadata."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Callable, Mapping
from typing import cast

from gatehouse.core.ids import (
    AttemptId,
    CredentialId,
    PoolId,
    PrincipalId,
    QuotaScopeId,
    RequestId,
    RootRunId,
    SessionId,
)
from gatehouse.core.states import INVOCATION_TRANSITIONS, InvocationState
from gatehouse.database.connection import transaction
from gatehouse.database.quota_state import (
    QuotaTransitionStatus,
    SqliteQuotaStateRepository,
)
from gatehouse.providers import ProviderErrorClass

from .models import (
    AttemptEvent,
    InvocationStartEvent,
    InvocationStateEvent,
    InvocationValidatedEvent,
)

_PROVISIONAL_FINGERPRINT_DOMAIN = b"gatehouse/provisional-request-fingerprint/v0\x00"
_PROVISIONAL_FINGERPRINT_STATE = "PROVISIONAL_REQUEST_BOUND"
_FINAL_FINGERPRINT_STATE = "FINAL"
_INTERNAL_ACCOUNTING_CLASS = "internal_resource_reconciliation"
_INTERNAL_RESOURCE_OPERATIONS = frozenset({"firecrawl.crawl.status", "firecrawl.crawl.cancel"})
_ASYNC_RESOURCE_TYPES = {"firecrawl.crawl.start": "crawl"}
_SAFE_STATE_METADATA_KEYS = frozenset(
    {
        "coalesced_from_request_id",
        "pool_id",
        "provider_handoff",
        "quota_expired",
        "session_authority_invalidated",
    }
)


class InvocationPersistenceConflictError(RuntimeError):
    """Durable invocation facts conflict with a replayed lifecycle event."""


class InvocationRequestLimitExceeded(RuntimeError):
    """A new request would exceed its root run's durable request allowance."""


def _unique_accounting_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("root-run accounting contains a duplicate key")
        result[key] = value
    return result


def _accounting_json(raw: object, *, field: str) -> dict[str, int]:
    try:
        value = json.loads(str(raw), object_pairs_hook=_unique_accounting_object)
    except (TypeError, ValueError) as error:
        raise InvocationPersistenceConflictError(f"{field} is not valid JSON") from error
    if not isinstance(value, dict) or len(value) > 32:
        raise InvocationPersistenceConflictError(f"{field} is not a bounded object")
    result: dict[str, int] = {}
    for key, amount in value.items():
        if (
            not isinstance(key, str)
            or not key
            or len(key) > 64
            or isinstance(amount, bool)
            or not isinstance(amount, int)
            or not 0 <= amount < (1 << 63)
        ):
            raise InvocationPersistenceConflictError(f"{field} is invalid")
        result[key] = amount
    return result


def _encoded_accounting(value: Mapping[str, int]) -> str:
    encoded = json.dumps(dict(value), sort_keys=True, separators=(",", ":"))
    if len(encoded.encode("utf-8")) > 4_096:
        raise InvocationPersistenceConflictError("root-run accounting exceeds its bound")
    return encoded


def _default_attempt_id() -> str:
    return str(AttemptId.new())


def _metadata_json(metadata: Mapping[str, object]) -> str:
    return json.dumps(dict(metadata), sort_keys=True, separators=(",", ":"))


def _load_metadata(raw: object) -> dict[str, object]:
    try:
        value = json.loads(str(raw))
    except (TypeError, ValueError) as exc:
        raise InvocationPersistenceConflictError("invocation metadata is not valid JSON") from exc
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise InvocationPersistenceConflictError("invocation metadata is not an object")
    return value


def _provisional_fingerprint(request_id: str) -> bytes:
    return hashlib.sha256(_PROVISIONAL_FINGERPRINT_DOMAIN + request_id.encode("ascii")).digest()


def _safe_state_metadata(metadata: Mapping[str, object]) -> dict[str, object]:
    unexpected = set(metadata) - _SAFE_STATE_METADATA_KEYS
    if unexpected:
        raise ValueError("invocation state metadata contains an unsupported field")
    safe = dict(metadata)
    identifier_types = {
        "coalesced_from_request_id": RequestId,
        "pool_id": PoolId,
    }
    for identifier_key, identifier_type in identifier_types.items():
        value = safe.get(identifier_key)
        if value is None:
            continue
        if not isinstance(value, str):
            raise ValueError("invocation state metadata identifier is invalid")
        try:
            identifier_type(value)
        except (TypeError, ValueError) as exc:
            raise ValueError("invocation state metadata identifier is invalid") from exc
    for boolean_key in (
        "provider_handoff",
        "quota_expired",
        "session_authority_invalidated",
    ):
        value = safe.get(boolean_key)
        if value is not None and not isinstance(value, bool):
            raise ValueError("invocation state metadata flag is invalid")
    return safe


class SqliteInvocationRepository:
    """Persist body-free invocation facts using explicit short transactions.

    The initial fingerprint is deliberately not a semantic request fingerprint. It
    is a deterministic request-ID-bound placeholder marked with version ``0`` and
    is replaced after canonical validation. The repository never accepts an access
    token, request payload, provider response body, or authorization material.
    """

    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        attempt_id_factory: Callable[[], str] = _default_attempt_id,
    ) -> None:
        self._connection = connection
        self._attempt_id_factory = attempt_id_factory

    @property
    def transaction_active(self) -> bool:
        return bool(self._connection.in_transaction)

    async def begin_invocation(self, event: InvocationStartEvent) -> None:
        if event.internal_resource_reconciliation and (
            event.service_id != "firecrawl" or event.operation not in _INTERNAL_RESOURCE_OPERATIONS
        ):
            raise ValueError("internal reconciliation is restricted to resource-bound operations")
        request_id = str(event.request_id)
        provisional = _provisional_fingerprint(request_id)
        with transaction(self._connection, "IMMEDIATE"):
            owner = self._connection.execute(
                """
                SELECT rr.session_id, rr.state, rr.budget_json, rr.consumed_json
                  FROM root_runs AS rr
                  JOIN sessions AS s ON s.session_id = rr.session_id
                 WHERE rr.root_run_id = ? AND s.session_id = ?
                """,
                (str(event.root_run_id), str(event.session_id)),
            ).fetchone()
            if owner is None:
                raise InvocationPersistenceConflictError(
                    "invocation root run does not belong to the session"
                )

            existing = self._connection.execute(
                "SELECT * FROM invocations WHERE request_id = ?",
                (request_id,),
            ).fetchone()
            if existing is None:
                if not event.internal_resource_reconciliation and str(owner["state"]) != "ACTIVE":
                    raise InvocationPersistenceConflictError(
                        "a new invocation requires an active root run"
                    )
                if not event.internal_resource_reconciliation:
                    budget = _accounting_json(
                        owner["budget_json"],
                        field="root-run budget",
                    )
                    consumed = _accounting_json(
                        owner["consumed_json"],
                        field="root-run consumption",
                    )
                    configured_limit = budget.get("requests")
                    request_limit = event.request_limit
                    if configured_limit is not None:
                        request_limit = (
                            configured_limit
                            if request_limit is None
                            else min(request_limit, configured_limit)
                        )
                    consumed_requests = consumed.get("requests", 0)
                    if request_limit is not None and consumed_requests >= request_limit:
                        raise InvocationRequestLimitExceeded(
                            "root-run request allowance is exhausted"
                        )
                    if consumed_requests >= (1 << 63) - 1:
                        raise InvocationPersistenceConflictError(
                            "root-run request counter is exhausted"
                        )
                    consumed["requests"] = consumed_requests + 1
                    updated = self._connection.execute(
                        """
                        UPDATE root_runs
                           SET consumed_json = ?
                         WHERE root_run_id = ? AND session_id = ?
                           AND state = 'ACTIVE' AND consumed_json = ?
                        """,
                        (
                            _encoded_accounting(consumed),
                            str(event.root_run_id),
                            str(event.session_id),
                            str(owner["consumed_json"]),
                        ),
                    )
                    if updated.rowcount != 1:
                        raise InvocationPersistenceConflictError(
                            "root-run request consumption changed concurrently"
                        )
                metadata = {"fingerprint_state": _PROVISIONAL_FINGERPRINT_STATE}
                if event.internal_resource_reconciliation:
                    metadata["accounting_class"] = _INTERNAL_ACCOUNTING_CLASS
                self._connection.execute(
                    """
                    INSERT INTO invocations(
                        request_id, session_id, root_run_id, service_id, operation,
                        request_fingerprint, fingerprint_version,
                        canonicalization_version, state, priority_class,
                        request_size_bytes, queue_deadline_ms, received_at_ms,
                        metadata_json
                    ) VALUES (?, ?, ?, ?, ?, ?, 0, 0, 'RECEIVED', ?, 0, ?, ?, ?)
                    """,
                    (
                        request_id,
                        str(event.session_id),
                        str(event.root_run_id),
                        event.service_id,
                        event.operation,
                        provisional,
                        event.priority.value,
                        event.queue_deadline_ms,
                        event.occurred_at_ms,
                        _metadata_json(metadata),
                    ),
                )
                return
            self._require_matching_start(existing, event, provisional)

    async def record_validated(self, event: InvocationValidatedEvent) -> None:
        with transaction(self._connection, "IMMEDIATE"):
            row = self._connection.execute(
                "SELECT * FROM invocations WHERE request_id = ?",
                (str(event.request_id),),
            ).fetchone()
            if row is None:
                raise InvocationPersistenceConflictError(
                    "validated invocation parent does not exist"
                )

            fingerprint = event.fingerprint
            current_versions = (
                int(row["fingerprint_version"]),
                int(row["canonicalization_version"]),
            )
            expected_versions = (
                fingerprint.fingerprint_version,
                fingerprint.canonicalization_version,
            )
            if current_versions != (0, 0):
                if (
                    current_versions != expected_versions
                    or bytes(row["request_fingerprint"]) != fingerprint.digest
                    or int(row["request_size_bytes"]) != event.request_size_bytes
                    or row["estimated_cost_units"] is None
                    or int(row["estimated_cost_units"]) != event.estimated_cost_units
                    or str(row["cost_unit"]) != event.cost_unit
                ):
                    raise InvocationPersistenceConflictError("validated invocation facts changed")
                return

            metadata = _load_metadata(row["metadata_json"])
            metadata["fingerprint_state"] = _FINAL_FINGERPRINT_STATE
            updated = self._connection.execute(
                """
                UPDATE invocations
                   SET request_fingerprint = ?, fingerprint_version = ?,
                       canonicalization_version = ?, request_size_bytes = ?,
                       estimated_cost_units = ?, cost_unit = ?, metadata_json = ?
                 WHERE request_id = ?
                   AND fingerprint_version = 0
                   AND canonicalization_version = 0
                """,
                (
                    fingerprint.digest,
                    fingerprint.fingerprint_version,
                    fingerprint.canonicalization_version,
                    event.request_size_bytes,
                    event.estimated_cost_units,
                    event.cost_unit,
                    _metadata_json(metadata),
                    str(event.request_id),
                ),
            )
            if updated.rowcount != 1:
                raise InvocationPersistenceConflictError(
                    "provisional invocation fingerprint changed concurrently"
                )

    async def record_state(self, event: InvocationStateEvent) -> None:
        safe_event_metadata = _safe_state_metadata(event.metadata)
        with transaction(self._connection, "IMMEDIATE"):
            row = self._connection.execute(
                "SELECT * FROM invocations WHERE request_id = ?",
                (str(event.request_id),),
            ).fetchone()
            if row is None:
                raise InvocationPersistenceConflictError("invocation state parent does not exist")
            try:
                current = InvocationState(str(row["state"]))
            except ValueError as exc:
                raise InvocationPersistenceConflictError(
                    "persisted invocation state is invalid"
                ) from exc
            state_changed = current is not event.state
            if state_changed and not INVOCATION_TRANSITIONS.can_transition(
                current,
                event.state,
            ):
                raise InvocationPersistenceConflictError(
                    f"durable invocation transition is invalid: "
                    f"{current.value} -> {event.state.value}"
                )

            metadata = _load_metadata(row["metadata_json"])
            metadata.update(safe_event_metadata)
            terminal = INVOCATION_TRANSITIONS.is_terminal(event.state)
            started_at_ms = row["started_at_ms"]
            if started_at_ms is None and event.state in {
                InvocationState.DISPATCHING,
                InvocationState.RUNNING,
            }:
                started_at_ms = event.occurred_at_ms
            completed_at_ms = row["completed_at_ms"]
            if completed_at_ms is None and terminal:
                completed_at_ms = event.occurred_at_ms
            self._connection.execute(
                """
                UPDATE invocations
                   SET state = ?, started_at_ms = ?, completed_at_ms = ?,
                       metadata_json = ?
                 WHERE request_id = ?
                """,
                (
                    event.state.value,
                    started_at_ms,
                    completed_at_ms,
                    _metadata_json(metadata),
                    str(event.request_id),
                ),
            )
            self._record_queue_transition(row, event, state_changed=state_changed)

    async def record_attempt(self, event: AttemptEvent) -> None:
        with transaction(self._connection, "IMMEDIATE"):
            invocation = self._connection.execute(
                "SELECT * FROM invocations WHERE request_id = ?",
                (str(event.request_id),),
            ).fetchone()
            if invocation is None:
                raise InvocationPersistenceConflictError("attempt invocation parent does not exist")
            self._require_attempt_cost_matches_invocation(invocation, event)
            existing = self._connection.execute(
                "SELECT * FROM attempts WHERE request_id = ? AND ordinal = ?",
                (str(event.request_id), event.ordinal),
            ).fetchone()

            if event.emergency_unlock_id is not None:
                authority = self._require_emergency_attempt_authority(
                    invocation,
                    event,
                    existing=existing,
                )
                durable_authority: tuple[object, ...] = (
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    event.emergency_unlock_id,
                    str(authority["credential_id"]),
                    str(authority["principal_id"]),
                    str(authority["quota_scope_id"]),
                    str(authority["pool_id"]),
                    int(authority["credential_generation"]),
                    None,
                    None,
                )
            else:
                if existing is not None and existing["emergency_unlock_id"] is not None:
                    raise InvocationPersistenceConflictError("attempt authority changed")
                if event.dispatch_credential_generation is None or event.dispatch_pool_id is None:
                    raise InvocationPersistenceConflictError(
                        "attempt dispatch authority is missing"
                    )
                authority = self._connection.execute(
                    """
                    SELECT c.principal_id, c.quota_scope_id, c.generation,
                           p.service_id AS principal_service_id,
                           q.principal_id AS quota_principal_id,
                           pl.service_id AS pool_service_id,
                           pm.quota_scope_id AS pool_quota_scope_id
                      FROM credentials AS c
                      JOIN principals AS p ON p.principal_id = c.principal_id
                      JOIN quota_scopes AS q ON q.quota_scope_id = c.quota_scope_id
                      JOIN pools AS pl ON pl.pool_id = ?
                      JOIN pool_members AS pm
                        ON pm.pool_id = pl.pool_id
                       AND pm.quota_scope_id = c.quota_scope_id
                     WHERE c.credential_id = ?
                    """,
                    (event.dispatch_pool_id, event.credential_id),
                ).fetchone()
                exact_dispatch_authority = (
                    event.quota_scope_id,
                    (
                        event.dispatch_credential_generation
                        if existing is None
                        else int(authority["generation"])
                        if authority is not None
                        else None
                    ),
                    str(invocation["service_id"]),
                    str(authority["principal_id"]) if authority is not None else None,
                    str(invocation["service_id"]),
                    event.quota_scope_id,
                )
                durable_dispatch_authority = (
                    str(authority["quota_scope_id"]) if authority is not None else None,
                    int(authority["generation"]) if authority is not None else None,
                    str(authority["principal_service_id"]) if authority is not None else None,
                    str(authority["quota_principal_id"]) if authority is not None else None,
                    str(authority["pool_service_id"]) if authority is not None else None,
                    str(authority["pool_quota_scope_id"]) if authority is not None else None,
                )
                if authority is None or durable_dispatch_authority != exact_dispatch_authority:
                    raise InvocationPersistenceConflictError(
                        "attempt dispatch authority is invalid"
                    )
                if existing is not None:
                    stored_dispatch = (
                        existing["dispatch_credential_generation"],
                        existing["dispatch_pool_id"],
                    )
                    incoming_dispatch = (
                        event.dispatch_credential_generation,
                        event.dispatch_pool_id,
                    )
                    if stored_dispatch != incoming_dispatch:
                        raise InvocationPersistenceConflictError(
                            "attempt dispatch authority changed"
                        )
                self._require_async_checkpoint_authority(
                    invocation,
                    authority,
                    event,
                    existing=existing,
                )
                durable_authority = (
                    event.credential_id,
                    str(authority["principal_id"]),
                    event.quota_scope_id,
                    event.resource_type,
                    event.provider_resource_id,
                    event.credential_generation,
                    event.pool_id,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    event.dispatch_credential_generation,
                    event.dispatch_pool_id,
                )

            if existing is None:
                attempt_id = self._attempt_id_factory()
                if not attempt_id or len(attempt_id) > 128:
                    raise ValueError("attempt identifier factory returned an invalid value")
                terminal = INVOCATION_TRANSITIONS.is_terminal(event.state)
                self._connection.execute(
                    """
                    INSERT INTO attempts(
                        attempt_id, request_id, ordinal, credential_id,
                        principal_id, quota_scope_id, state, provider_status_code,
                        provider_request_id, error_class, estimated_cost_units,
                        actual_cost_units, cost_unit, started_at_ms,
                        completed_at_ms, latency_ms, resource_type,
                        provider_resource_id, credential_generation, pool_id,
                        emergency_unlock_id, emergency_credential_id,
                        emergency_principal_id, emergency_quota_scope_id,
                        emergency_pool_id, emergency_credential_generation,
                        dispatch_credential_generation, dispatch_pool_id
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                              ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        attempt_id,
                        str(event.request_id),
                        event.ordinal,
                        durable_authority[0],
                        durable_authority[1],
                        durable_authority[2],
                        event.state.value,
                        event.provider_status_code,
                        event.provider_request_id,
                        event.error_class.value if event.error_class is not None else None,
                        event.estimated_cost_units,
                        event.actual_cost_units,
                        event.cost_unit,
                        event.occurred_at_ms,
                        event.occurred_at_ms if terminal else None,
                        event.latency_ms,
                        *durable_authority[3:],
                    ),
                )
            else:
                attempt_id = str(existing["attempt_id"])
                self._update_attempt(existing, event, authority)
            self._record_actual_cost(event)
            if (
                event.state is InvocationState.FAILED
                and event.error_class is ProviderErrorClass.QUOTA_EXHAUSTED
                and event.emergency_unlock_id is None
            ):
                transition = SqliteQuotaStateRepository(
                    self._connection
                ).mark_definitive_exhaustion_in_transaction(
                    quota_scope_id=event.quota_scope_id,
                    now_ms=event.occurred_at_ms,
                    credential_id=event.credential_id,
                    credential_generation=event.dispatch_credential_generation,
                    request_id=str(event.request_id),
                    attempt_id=attempt_id,
                )
                if transition.status not in {
                    QuotaTransitionStatus.TRANSITIONED,
                    QuotaTransitionStatus.UNCHANGED,
                }:
                    raise InvocationPersistenceConflictError(
                        "definitive quota exhaustion could not be persisted"
                    )

    @staticmethod
    def _require_matching_start(
        row: sqlite3.Row,
        event: InvocationStartEvent,
        provisional: bytes,
    ) -> None:
        durable = (
            str(row["session_id"]),
            str(row["root_run_id"]),
            str(row["service_id"]),
            str(row["operation"]),
            str(row["priority_class"]),
            int(row["queue_deadline_ms"]),
        )
        replayed = (
            str(event.session_id),
            str(event.root_run_id),
            event.service_id,
            event.operation,
            event.priority.value,
            event.queue_deadline_ms,
        )
        if durable != replayed:
            raise InvocationPersistenceConflictError("invocation identity changed")
        metadata = _load_metadata(row["metadata_json"])
        accounting_class = metadata.get("accounting_class")
        if accounting_class not in {None, _INTERNAL_ACCOUNTING_CLASS}:
            raise InvocationPersistenceConflictError("invocation accounting class is invalid")
        internal = accounting_class == _INTERNAL_ACCOUNTING_CLASS
        if internal is not event.internal_resource_reconciliation:
            raise InvocationPersistenceConflictError("invocation accounting class changed")
        versions = (
            int(row["fingerprint_version"]),
            int(row["canonicalization_version"]),
        )
        if versions == (0, 0) and bytes(row["request_fingerprint"]) != provisional:
            raise InvocationPersistenceConflictError("provisional invocation fingerprint changed")
        if (versions[0] == 0) != (versions[1] == 0):
            raise InvocationPersistenceConflictError(
                "invocation fingerprint versions are inconsistent"
            )

    def _record_queue_transition(
        self,
        invocation: sqlite3.Row,
        event: InvocationStateEvent,
        *,
        state_changed: bool,
    ) -> None:
        request_id = str(event.request_id)
        if event.state is InvocationState.QUEUED:
            queue_metadata = _metadata_json(event.metadata)
            queue_id = f"queue_{request_id.removeprefix('req_')}"
            self._connection.execute(
                """
                INSERT INTO queue_entries(
                    queue_id, request_id, state, priority_class, session_id,
                    root_run_id, service_id, operation, estimated_cost_units,
                    cost_unit, enqueued_at_ms, deadline_ms, metadata_json
                ) VALUES (?, ?, 'QUEUED', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(request_id) DO UPDATE SET
                    state = 'QUEUED', priority_class = excluded.priority_class,
                    session_id = excluded.session_id,
                    root_run_id = excluded.root_run_id,
                    service_id = excluded.service_id,
                    operation = excluded.operation,
                    estimated_cost_units = excluded.estimated_cost_units,
                    cost_unit = excluded.cost_unit,
                    enqueued_at_ms = excluded.enqueued_at_ms,
                    deadline_ms = excluded.deadline_ms,
                    claimed_at_ms = NULL,
                    claim_owner = NULL,
                    claim_expires_at_ms = NULL,
                    metadata_json = excluded.metadata_json
                """,
                (
                    queue_id,
                    request_id,
                    str(invocation["priority_class"]),
                    str(invocation["session_id"]),
                    str(invocation["root_run_id"]),
                    str(invocation["service_id"]),
                    str(invocation["operation"]),
                    invocation["estimated_cost_units"],
                    invocation["cost_unit"],
                    event.occurred_at_ms,
                    int(invocation["queue_deadline_ms"]),
                    queue_metadata,
                ),
            )
            return
        if event.state is InvocationState.DISPATCHING:
            updated = self._connection.execute(
                """
                UPDATE queue_entries
                   SET state = 'CLAIMED', claimed_at_ms = ?,
                       claim_owner = 'invocation-coordinator',
                       claim_expires_at_ms = deadline_ms,
                       dispatch_attempts = dispatch_attempts + ?
                 WHERE request_id = ?
                """,
                (event.occurred_at_ms, int(state_changed), request_id),
            )
            if updated.rowcount != 1:
                raise InvocationPersistenceConflictError(
                    "dispatching invocation has no durable queue entry"
                )
            return
        if INVOCATION_TRANSITIONS.is_terminal(event.state):
            self._connection.execute(
                """
                UPDATE queue_entries
                   SET state = ?, claim_owner = NULL, claim_expires_at_ms = NULL
                 WHERE request_id = ?
                """,
                (event.state.value, request_id),
            )

    @staticmethod
    def _require_attempt_cost_matches_invocation(
        invocation: sqlite3.Row,
        event: AttemptEvent,
    ) -> None:
        if event.estimated_cost_units is not None:
            stored = invocation["estimated_cost_units"]
            if stored is not None and int(stored) != event.estimated_cost_units:
                raise InvocationPersistenceConflictError(
                    "attempt estimated cost differs from invocation"
                )
        if event.cost_unit is not None:
            stored_unit = invocation["cost_unit"]
            if stored_unit is not None and str(stored_unit) != event.cost_unit:
                raise InvocationPersistenceConflictError(
                    "attempt cost unit differs from invocation"
                )

    def _require_emergency_attempt_authority(
        self,
        invocation: sqlite3.Row,
        event: AttemptEvent,
        *,
        existing: sqlite3.Row | None,
    ) -> sqlite3.Row:
        if str(invocation["operation"]) in _ASYNC_RESOURCE_TYPES:
            raise InvocationPersistenceConflictError(
                "emergency authority cannot create asynchronous resources"
            )
        if any(
            value is not None
            for value in (
                event.resource_type,
                event.provider_resource_id,
                event.credential_generation,
            )
        ):
            raise InvocationPersistenceConflictError(
                "emergency authority cannot persist asynchronous checkpoints"
            )

        authority = cast(
            sqlite3.Row | None,
            self._connection.execute(
                """
                SELECT eu.*, p.service_id AS pool_service_id,
                       p.alias AS pool_alias, p.state AS pool_state,
                       p.automatic_use AS pool_automatic_use,
                       s.state AS session_state,
                       s.absolute_expires_at_ms AS session_expires_at_ms,
                       c.unattended,
                       rr.state AS root_state
                  FROM emergency_unlock_records AS eu
                  JOIN pools AS p ON p.pool_id = eu.pool_id
                  JOIN sessions AS s ON s.session_id = eu.session_id
                  JOIN clients AS c ON c.client_id = s.client_id
                  JOIN root_runs AS rr
                    ON rr.root_run_id = eu.root_run_id
                   AND rr.session_id = s.session_id
                 WHERE eu.unlock_id = ?
                """,
                (event.emergency_unlock_id,),
            ).fetchone(),
        )
        if authority is None:
            raise InvocationPersistenceConflictError("emergency attempt authority is invalid")

        try:
            unlock_id = str(authority["unlock_id"])
            credential_id = str(CredentialId(str(authority["credential_id"])))
            principal_id = str(PrincipalId(str(authority["principal_id"])))
            quota_scope_id = str(QuotaScopeId(str(authority["quota_scope_id"])))
            pool_id = str(PoolId(str(authority["pool_id"])))
            session_id = str(SessionId(str(authority["session_id"])))
            root_run_id = str(RootRunId(str(authority["root_run_id"])))
            generation = int(authority["credential_generation"])
            expires_at_ms = int(authority["expires_at_ms"])
            bounded_text = (
                unlock_id,
                str(authority["credential_alias"]),
                str(authority["principal_alias"]),
                str(authority["quota_scope_alias"]),
                str(authority["service_id"]),
            )
            if (
                not 16 <= len(unlock_id) <= 160
                or any(
                    not 1 <= len(value) <= 160
                    or value != value.strip()
                    or not all(character.isprintable() for character in value)
                    for value in bounded_text[1:]
                )
                or generation != 1
            ):
                raise ValueError
        except (TypeError, ValueError) as exc:
            raise InvocationPersistenceConflictError(
                "emergency attempt authority is invalid"
            ) from exc

        exact_authority = (
            unlock_id == event.emergency_unlock_id
            and credential_id == event.credential_id
            and quota_scope_id == event.quota_scope_id
            and pool_id == event.pool_id
            and session_id == str(invocation["session_id"])
            and root_run_id == str(invocation["root_run_id"])
            and str(authority["service_id"]) == str(invocation["service_id"])
            and str(authority["pool_service_id"]) == str(invocation["service_id"])
        )
        if not exact_authority or not principal_id:
            raise InvocationPersistenceConflictError("emergency attempt authority is invalid")

        unlock_open = (
            str(authority["state"]) == "ACTIVE"
            and event.occurred_at_ms < expires_at_ms
            and str(authority["pool_alias"]) == "emergency-locked"
            and str(authority["pool_state"]) in {"ACTIVE", "ENABLED"}
            and int(authority["pool_automatic_use"]) == 0
            and str(authority["session_state"]) == "ACTIVE"
            and event.occurred_at_ms < int(authority["session_expires_at_ms"])
            and int(authority["unattended"]) == 0
            and str(authority["root_state"]) == "ACTIVE"
        )
        if existing is None and not unlock_open:
            raise InvocationPersistenceConflictError(
                "emergency unlock is not active for attempt admission"
            )
        if (
            existing is not None
            and not unlock_open
            and not INVOCATION_TRANSITIONS.is_terminal(event.state)
        ):
            raise InvocationPersistenceConflictError(
                "relocked emergency attempt requires a terminal update"
            )
        return authority

    def _require_async_checkpoint_authority(
        self,
        invocation: sqlite3.Row,
        credential: sqlite3.Row,
        event: AttemptEvent,
        *,
        existing: sqlite3.Row | None,
    ) -> None:
        del credential
        incoming_dispatch = (
            event.dispatch_credential_generation,
            event.dispatch_pool_id,
        )
        if (
            existing is not None
            and (
                existing["dispatch_credential_generation"],
                existing["dispatch_pool_id"],
            )
            != incoming_dispatch
        ):
            raise InvocationPersistenceConflictError("attempt dispatch authority changed")
        operation = str(invocation["operation"])
        expected_resource_type = _ASYNC_RESOURCE_TYPES.get(operation)
        checkpoint = (
            event.resource_type,
            event.provider_resource_id,
            event.credential_generation,
            event.pool_id,
        )
        has_checkpoint = any(value is not None for value in checkpoint)
        if expected_resource_type is None:
            if has_checkpoint:
                raise InvocationPersistenceConflictError(
                    "non-asynchronous attempt cannot carry a resource checkpoint"
                )
            return
        if event.state is not InvocationState.SUCCEEDED:
            if has_checkpoint:
                raise InvocationPersistenceConflictError(
                    "non-successful attempt cannot carry a resource checkpoint"
                )
            return
        if not all(value is not None for value in checkpoint):
            raise InvocationPersistenceConflictError(
                "successful asynchronous attempt is missing its resource checkpoint"
            )
        if event.resource_type != expected_resource_type:
            raise InvocationPersistenceConflictError(
                "asynchronous attempt resource type does not match its operation"
            )
        if (
            event.credential_generation != event.dispatch_credential_generation
            or event.pool_id != event.dispatch_pool_id
        ):
            raise InvocationPersistenceConflictError(
                "asynchronous checkpoint differs from dispatch authority"
            )
        pool = self._connection.execute(
            """
            SELECT p.service_id, pm.quota_scope_id
              FROM pools AS p
              JOIN pool_members AS pm
                ON pm.pool_id = p.pool_id
               AND pm.quota_scope_id = ?
             WHERE p.pool_id = ?
            """,
            (event.quota_scope_id, event.pool_id),
        ).fetchone()
        if pool is None or (
            str(pool["service_id"]) != str(invocation["service_id"])
            or str(pool["quota_scope_id"]) != event.quota_scope_id
        ):
            raise InvocationPersistenceConflictError(
                "asynchronous attempt pool authority is invalid"
            )

    def _update_attempt(
        self,
        row: sqlite3.Row,
        event: AttemptEvent,
        authority: sqlite3.Row,
    ) -> None:
        if event.emergency_unlock_id is not None:
            stored_emergency_authority = (
                row["emergency_unlock_id"],
                row["emergency_credential_id"],
                row["emergency_principal_id"],
                row["emergency_quota_scope_id"],
                row["emergency_pool_id"],
                row["emergency_credential_generation"],
            )
            expected_emergency_authority = (
                event.emergency_unlock_id,
                event.credential_id,
                str(authority["principal_id"]),
                event.quota_scope_id,
                event.pool_id,
                int(authority["credential_generation"]),
            )
            if (
                stored_emergency_authority != expected_emergency_authority
                or row["credential_id"] is not None
                or row["principal_id"] is not None
                or row["quota_scope_id"] is not None
            ):
                raise InvocationPersistenceConflictError("attempt authority changed")
        elif (
            row["emergency_unlock_id"] is not None
            or str(row["credential_id"]) != event.credential_id
            or str(row["quota_scope_id"]) != event.quota_scope_id
        ):
            raise InvocationPersistenceConflictError("attempt authority changed")
        try:
            current = InvocationState(str(row["state"]))
        except ValueError as exc:
            raise InvocationPersistenceConflictError("persisted attempt state is invalid") from exc
        if current is not event.state and not INVOCATION_TRANSITIONS.can_transition(
            current,
            event.state,
        ):
            raise InvocationPersistenceConflictError(
                f"durable attempt transition is invalid: {current.value} -> {event.state.value}"
            )

        incoming_error = event.error_class.value if event.error_class is not None else None
        pairs = (
            ("provider_status_code", event.provider_status_code),
            ("provider_request_id", event.provider_request_id),
            ("error_class", incoming_error),
            ("estimated_cost_units", event.estimated_cost_units),
            ("actual_cost_units", event.actual_cost_units),
            ("cost_unit", event.cost_unit),
            ("latency_ms", event.latency_ms),
        )
        for column, incoming in pairs:
            stored = row[column]
            if stored is not None and incoming is not None and stored != incoming:
                raise InvocationPersistenceConflictError(f"attempt {column} changed")
        stored_checkpoint = (
            row["resource_type"],
            row["provider_resource_id"],
            row["credential_generation"],
            row["pool_id"],
        )
        checkpoint_pool_id = None if event.emergency_unlock_id is not None else event.pool_id
        incoming_checkpoint = (
            event.resource_type,
            event.provider_resource_id,
            event.credential_generation,
            checkpoint_pool_id,
        )
        if any(value is not None for value in stored_checkpoint) and (
            stored_checkpoint != incoming_checkpoint
        ):
            raise InvocationPersistenceConflictError(
                "attempt asynchronous resource checkpoint changed"
            )
        completed_at_ms = row["completed_at_ms"]
        if completed_at_ms is None and INVOCATION_TRANSITIONS.is_terminal(event.state):
            completed_at_ms = event.occurred_at_ms
        self._connection.execute(
            """
            UPDATE attempts
               SET state = ?, provider_status_code = COALESCE(?, provider_status_code),
                   provider_request_id = COALESCE(?, provider_request_id),
                   error_class = COALESCE(?, error_class),
                   estimated_cost_units = COALESCE(?, estimated_cost_units),
                   actual_cost_units = COALESCE(?, actual_cost_units),
                   cost_unit = COALESCE(?, cost_unit),
                   completed_at_ms = ?, latency_ms = COALESCE(?, latency_ms),
                   resource_type = COALESCE(?, resource_type),
                   provider_resource_id = COALESCE(?, provider_resource_id),
                   credential_generation = COALESCE(?, credential_generation),
                   pool_id = COALESCE(?, pool_id)
             WHERE request_id = ? AND ordinal = ?
            """,
            (
                event.state.value,
                event.provider_status_code,
                event.provider_request_id,
                incoming_error,
                event.estimated_cost_units,
                event.actual_cost_units,
                event.cost_unit,
                completed_at_ms,
                event.latency_ms,
                event.resource_type,
                event.provider_resource_id,
                event.credential_generation,
                checkpoint_pool_id,
                str(event.request_id),
                event.ordinal,
            ),
        )

    def _record_actual_cost(self, event: AttemptEvent) -> None:
        if event.actual_cost_units is None:
            return
        total = int(
            self._connection.execute(
                """
                SELECT COALESCE(SUM(actual_cost_units), 0)
                  FROM attempts
                 WHERE request_id = ?
                """,
                (str(event.request_id),),
            ).fetchone()[0]
        )
        self._connection.execute(
            """
            UPDATE invocations
               SET actual_cost_units = ?
             WHERE request_id = ?
            """,
            (total, str(event.request_id)),
        )
