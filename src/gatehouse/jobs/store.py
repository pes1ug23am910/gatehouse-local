"""Owner-fenced SQLite persistence for provider-backed asynchronous jobs."""

from __future__ import annotations

import asyncio
import json
import re
import sqlite3
from collections.abc import Mapping
from typing import Any

from gatehouse.core.clock import FixedUtcClock, require_utc_ms
from gatehouse.core.ids import (
    CredentialId,
    EntropySource,
    JobId,
    PoolId,
    PrincipalId,
    QuotaScopeId,
    RequestId,
    RootRunId,
    SessionId,
    WorkspaceId,
)
from gatehouse.database.connection import transaction
from gatehouse.routing import ResourceAffinity

from .models import TERMINAL_JOB_STATES, JobAwaitResult, JobOwner, JobRecord, JobState

_METADATA_SCHEMA_VERSION = 1
_MAX_METADATA_BYTES = 4_096
_MAXIMUM_LIST_LIMIT = 500
_MAXIMUM_PROVIDER_STATUS_LENGTH = 64
_PROVIDER_STATUS_PATTERN = re.compile(r"^[A-Za-z0-9_.:-]+$")
_REQUIRED_METADATA_KEYS = frozenset(
    {
        "schema_version",
        "revision",
        "resource_type",
        "credential_generation",
        "pool_id",
    }
)
_OPTIONAL_METADATA_KEYS = frozenset(
    {
        "provider_status",
        "provider_status_observed_at_ms",
        "cancel_requested_at_ms",
        "settlement_target_state",
        "settlement_actual_cost_units",
        "settlement_observed_at_ms",
    }
)
_KNOWN_METADATA_KEYS = _REQUIRED_METADATA_KEYS | _OPTIONAL_METADATA_KEYS

_ALLOWED_TRANSITIONS: dict[JobState, frozenset[JobState]] = {
    JobState.CREATED: frozenset(
        {
            JobState.RUNNING,
            JobState.POLLING,
            JobState.CANCELLING,
            JobState.RECOVERING,
            JobState.SUCCEEDED,
            JobState.FAILED,
            JobState.CANCELLED,
            JobState.UNKNOWN,
        }
    ),
    JobState.RUNNING: frozenset(
        {
            JobState.POLLING,
            JobState.CANCELLING,
            JobState.RECOVERING,
            JobState.SUCCEEDED,
            JobState.FAILED,
            JobState.CANCELLED,
            JobState.UNKNOWN,
        }
    ),
    JobState.POLLING: frozenset(
        {
            JobState.RUNNING,
            JobState.CANCELLING,
            JobState.RECOVERING,
            JobState.SUCCEEDED,
            JobState.FAILED,
            JobState.CANCELLED,
            JobState.UNKNOWN,
        }
    ),
    JobState.CANCELLING: frozenset(
        {
            JobState.RUNNING,
            JobState.RECOVERING,
            JobState.SUCCEEDED,
            JobState.FAILED,
            JobState.CANCELLED,
            JobState.UNKNOWN,
        }
    ),
    JobState.RECOVERING: frozenset(
        {
            JobState.RUNNING,
            JobState.POLLING,
            JobState.CANCELLING,
            JobState.SUCCEEDED,
            JobState.FAILED,
            JobState.CANCELLED,
            JobState.UNKNOWN,
        }
    ),
    JobState.SETTLING: TERMINAL_JOB_STATES,
    JobState.SUCCEEDED: frozenset(),
    JobState.FAILED: frozenset(),
    JobState.CANCELLED: frozenset(),
    JobState.UNKNOWN: frozenset(),
}


class JobStoreError(RuntimeError):
    """Base class for durable job-store failures."""


class JobConflictError(JobStoreError):
    """A request or provider resource already names another durable job."""


class JobCorruptionError(JobStoreError):
    """Persisted job state could not be safely mapped to an authority fact."""


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("job metadata contains a duplicate key")
        result[key] = value
    return result


def _required_text(value: object, *, field: str, maximum_length: int) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum_length:
        raise ValueError(f"job {field} must be a non-empty bounded string")
    return value


def _required_integer(value: object, *, field: str, positive: bool = False) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"job {field} must be an integer")
    result = int(value)
    if positive and result <= 0:
        raise ValueError(f"job {field} must be positive")
    return result


def _optional_timestamp(value: object, *, field: str) -> int | None:
    if value is None:
        return None
    return require_utc_ms(_required_integer(value, field=field))


def _validate_provider_status(value: str | None) -> str | None:
    if value is None:
        return None
    if (
        not value
        or len(value) > _MAXIMUM_PROVIDER_STATUS_LENGTH
        or _PROVIDER_STATUS_PATTERN.fullmatch(value) is None
    ):
        raise ValueError("provider status must be a bounded status token")
    return value


def _decode_metadata(raw: object) -> dict[str, object]:
    if not isinstance(raw, str):
        raise ValueError("job metadata must be text")
    if len(raw.encode("utf-8")) > _MAX_METADATA_BYTES:
        raise ValueError("job metadata exceeds its persistence bound")
    decoded: Any = json.loads(raw, object_pairs_hook=_unique_object)
    if not isinstance(decoded, dict):
        raise ValueError("job metadata must be a JSON object")
    result = {str(key): value for key, value in decoded.items()}
    keys = frozenset(result)
    if not _REQUIRED_METADATA_KEYS <= keys or not keys <= _KNOWN_METADATA_KEYS:
        raise ValueError("job metadata has missing or unknown fields")
    if (
        _required_integer(
            result["schema_version"],
            field="metadata schema version",
        )
        != _METADATA_SCHEMA_VERSION
    ):
        raise ValueError("job metadata schema version is unsupported")
    _required_integer(result["revision"], field="revision", positive=True)
    _required_text(result["resource_type"], field="resource_type", maximum_length=64)
    _required_integer(
        result["credential_generation"],
        field="credential_generation",
        positive=True,
    )
    PoolId(_required_text(result["pool_id"], field="pool_id", maximum_length=160))
    status_value = result.get("provider_status")
    if status_value is not None and not isinstance(status_value, str):
        raise ValueError("job provider status must be text")
    provider_status = _validate_provider_status(status_value)
    observed_at_ms = _optional_timestamp(
        result.get("provider_status_observed_at_ms"),
        field="provider_status_observed_at_ms",
    )
    if (provider_status is None) != (observed_at_ms is None):
        raise ValueError("job provider status and observation time must be paired")
    _optional_timestamp(
        result.get("cancel_requested_at_ms"),
        field="cancel_requested_at_ms",
    )
    target_value = result.get("settlement_target_state")
    actual_value = result.get("settlement_actual_cost_units")
    settlement_observed_value = result.get("settlement_observed_at_ms")
    checkpoint_present = any(
        value is not None for value in (target_value, actual_value, settlement_observed_value)
    )
    if checkpoint_present:
        if not isinstance(target_value, str):
            raise ValueError("job settlement target must be text")
        if JobState(target_value) not in TERMINAL_JOB_STATES:
            raise ValueError("job settlement target must be terminal")
        actual_units = _required_integer(
            actual_value,
            field="settlement_actual_cost_units",
        )
        if actual_units < 0 or actual_units >= (1 << 63):
            raise ValueError("job settlement usage is outside its integer bound")
        if (
            _optional_timestamp(
                settlement_observed_value,
                field="settlement_observed_at_ms",
            )
            is None
        ):
            raise ValueError("job settlement observation is required")
    return result


def _encode_metadata(
    *,
    revision: int,
    resource_type: str,
    credential_generation: int,
    pool_id: PoolId,
    provider_status: str | None,
    provider_status_observed_at_ms: int | None,
    cancel_requested_at_ms: int | None,
    settlement_target_state: JobState | None = None,
    settlement_actual_cost_units: int | None = None,
    settlement_observed_at_ms: int | None = None,
) -> str:
    _required_integer(revision, field="revision", positive=True)
    _required_text(resource_type, field="resource_type", maximum_length=64)
    _required_integer(
        credential_generation,
        field="credential_generation",
        positive=True,
    )
    provider_status = _validate_provider_status(provider_status)
    if provider_status_observed_at_ms is not None:
        require_utc_ms(provider_status_observed_at_ms)
    if (provider_status is None) != (provider_status_observed_at_ms is None):
        raise ValueError("provider status and observation time must be paired")
    if cancel_requested_at_ms is not None:
        require_utc_ms(cancel_requested_at_ms)
    settlement_values = (
        settlement_target_state,
        settlement_actual_cost_units,
        settlement_observed_at_ms,
    )
    if any(value is not None for value in settlement_values):
        if not all(value is not None for value in settlement_values):
            raise ValueError("job settlement checkpoint must be complete")
        assert settlement_target_state is not None
        assert settlement_actual_cost_units is not None
        assert settlement_observed_at_ms is not None
        if settlement_target_state not in TERMINAL_JOB_STATES:
            raise ValueError("job settlement target must be terminal")
        if (
            isinstance(settlement_actual_cost_units, bool)
            or not isinstance(settlement_actual_cost_units, int)
            or settlement_actual_cost_units < 0
            or settlement_actual_cost_units >= (1 << 63)
        ):
            raise ValueError("job settlement usage is outside its integer bound")
        require_utc_ms(settlement_observed_at_ms)

    metadata: dict[str, object] = {
        "schema_version": _METADATA_SCHEMA_VERSION,
        "revision": revision,
        "resource_type": resource_type,
        "credential_generation": credential_generation,
        "pool_id": str(pool_id),
    }
    if provider_status is not None:
        metadata["provider_status"] = provider_status
        metadata["provider_status_observed_at_ms"] = provider_status_observed_at_ms
    if cancel_requested_at_ms is not None:
        metadata["cancel_requested_at_ms"] = cancel_requested_at_ms
    if settlement_target_state is not None:
        metadata["settlement_target_state"] = settlement_target_state.value
        metadata["settlement_actual_cost_units"] = settlement_actual_cost_units
        metadata["settlement_observed_at_ms"] = settlement_observed_at_ms
    encoded = json.dumps(metadata, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    if len(encoded.encode("utf-8")) > _MAX_METADATA_BYTES:
        raise ValueError("job metadata exceeds its persistence bound")
    return encoded


def _row_integer(row: sqlite3.Row, name: str, *, optional: bool = False) -> int | None:
    value: Any = row[name]
    if value is None and optional:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"persisted job {name} must be an integer")
    return int(value)


def _row_timestamp(row: sqlite3.Row, name: str, *, optional: bool = False) -> int | None:
    value = _row_integer(row, name, optional=optional)
    return None if value is None else require_utc_ms(value)


def _row_text(row: sqlite3.Row, name: str) -> str:
    value: Any = row[name]
    if not isinstance(value, str) or not value:
        raise ValueError(f"persisted job {name} must be non-empty text")
    return value


class SqliteJobStore:
    """Persist jobs with exact session/root/workspace and affinity fencing."""

    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        entropy: EntropySource | None = None,
        maximum_await_ms: int = 30_000,
    ) -> None:
        if maximum_await_ms <= 0 or maximum_await_ms > 60_000:
            raise ValueError("maximum_await_ms is outside the supported bound")
        self.connection = connection
        self._entropy = entropy
        self._maximum_await_ms = maximum_await_ms
        self._events: dict[JobId, asyncio.Event] = {}

    async def create_from_affinity(
        self,
        affinity: ResourceAffinity,
        *,
        maximum_runtime_at_ms: int,
        next_poll_at_ms: int | None = None,
        provider_status: str | None = None,
    ) -> JobRecord:
        """Create once after proving a successful invocation and exact affinity."""

        maximum_runtime_at_ms = require_utc_ms(maximum_runtime_at_ms)
        if maximum_runtime_at_ms < affinity.bound_at_ms:
            raise ValueError("job maximum runtime cannot precede resource binding")
        if next_poll_at_ms is not None:
            next_poll_at_ms = require_utc_ms(next_poll_at_ms)
            if not affinity.bound_at_ms <= next_poll_at_ms <= maximum_runtime_at_ms:
                raise ValueError("initial poll time is outside the job runtime")
        provider_status = _validate_provider_status(provider_status)

        with transaction(self.connection, "IMMEDIATE"):
            existing_key = self.connection.execute(
                """
                SELECT job_id, request_id
                  FROM jobs
                 WHERE service_id = ? AND provider_job_id = ?
                """,
                affinity.provider_key,
            ).fetchone()
            if existing_key is not None:
                return self._resolve_existing(existing_key, affinity)

            existing_request = self.connection.execute(
                "SELECT job_id FROM jobs WHERE request_id = ? LIMIT 1",
                (str(affinity.creating_request_id),),
            ).fetchone()
            if existing_request is not None:
                raise JobConflictError(
                    "invocation is already resolved to another provider resource"
                )

            authority = self._verified_authority(affinity)
            created_at_ms = _row_timestamp(authority, "created_at_ms")
            if created_at_ms is None:
                raise JobConflictError("resource affinity has an invalid creation time")
            if maximum_runtime_at_ms < created_at_ms:
                raise ValueError("job maximum runtime cannot precede durable resource binding")
            if next_poll_at_ms is not None and next_poll_at_ms < created_at_ms:
                raise ValueError("initial poll time precedes durable resource binding")
            operation = _row_text(authority, "operation")
            job_id = self._new_job_id(created_at_ms)
            metadata = _encode_metadata(
                revision=1,
                resource_type=affinity.resource_type,
                credential_generation=affinity.credential_generation,
                pool_id=affinity.pool_id,
                provider_status=provider_status,
                provider_status_observed_at_ms=(
                    created_at_ms if provider_status is not None else None
                ),
                cancel_requested_at_ms=None,
            )
            self.connection.execute(
                """
                INSERT INTO jobs(
                    job_id, request_id, service_id, operation, state,
                    provider_job_id, principal_id, quota_scope_id,
                    credential_id, next_poll_at_ms, maximum_runtime_at_ms,
                    created_at_ms, completed_at_ms, metadata_json
                ) VALUES (?, ?, ?, ?, 'CREATED', ?, ?, ?, ?, ?, ?, ?, NULL, ?)
                """,
                (
                    str(job_id),
                    str(affinity.creating_request_id),
                    affinity.service_id,
                    operation,
                    affinity.provider_resource_id,
                    str(affinity.principal_id),
                    str(affinity.quota_scope_id),
                    str(affinity.credential_id),
                    next_poll_at_ms,
                    maximum_runtime_at_ms,
                    created_at_ms,
                    metadata,
                ),
            )
            row = self._select_owned(job_id, self._owner_from_affinity(affinity))
            if row is None:
                raise JobConflictError("new job did not preserve its durable authority")
            record = self._record_from_row(row)
        self._notify(job_id)
        return record

    async def load(self, job_id: JobId, *, owner: JobOwner) -> JobRecord | None:
        row = self._select_owned(job_id, owner)
        return None if row is None else self._record_from_row(row)

    async def list(
        self,
        *,
        owner: JobOwner,
        limit: int = 100,
    ) -> tuple[JobRecord, ...]:
        if limit <= 0 or limit > _MAXIMUM_LIST_LIMIT:
            raise ValueError("job list limit is outside the supported bound")
        rows = self.connection.execute(
            """
            SELECT j.job_id, j.request_id, j.service_id, j.operation, j.state,
                   j.provider_job_id, j.principal_id, j.quota_scope_id,
                   j.credential_id, j.next_poll_at_ms,
                   j.maximum_runtime_at_ms, j.created_at_ms,
                   j.completed_at_ms, j.metadata_json,
                   er.resource_type, er.credential_generation, er.pool_id,
                   i.session_id AS owner_session_id,
                   s.workspace_id AS owner_workspace_id,
                   i.root_run_id AS owner_root_run_id
              FROM jobs AS j
              JOIN invocations AS i
                ON i.request_id = j.request_id
               AND i.service_id = j.service_id
               AND i.operation = j.operation
               AND i.state = 'SUCCEEDED'
              JOIN sessions AS s ON s.session_id = i.session_id
              JOIN root_runs AS rr
                ON rr.root_run_id = i.root_run_id
               AND rr.session_id = i.session_id
              JOIN external_resources AS er
                ON er.creating_request_id = i.request_id
               AND er.service_id = j.service_id
               AND er.provider_resource_id = j.provider_job_id
               AND er.principal_id = j.principal_id
               AND er.quota_scope_id = j.quota_scope_id
               AND er.credential_id = j.credential_id
               AND er.owner_session_id = i.session_id
               AND er.owner_workspace_id = s.workspace_id
               AND er.owner_root_run_id = i.root_run_id
               AND er.state = 'ACTIVE'
             WHERE i.session_id = ?
               AND s.workspace_id = ?
               AND i.root_run_id = ?
             ORDER BY j.created_at_ms DESC, j.job_id DESC
             LIMIT ?
            """,
            (
                str(owner.session_id),
                str(owner.workspace_id),
                str(owner.root_run_id),
                limit,
            ),
        ).fetchall()
        return tuple(self._record_from_row(row) for row in rows)

    async def list_due(
        self,
        *,
        now_ms: int,
        limit: int = 100,
    ) -> tuple[JobRecord, ...]:
        """Return bounded due work with owner authority reconstructed from SQLite.

        This is an internal supervisor query, not an end-user lookup.  Every row is
        still joined through the successful creating invocation, exact active
        resource affinity, session, workspace, and root run before it is returned.
        A caller must claim a returned record with :meth:`compare_and_set` before
        contacting a provider.
        """

        now_ms = require_utc_ms(now_ms)
        if limit <= 0 or limit > _MAXIMUM_LIST_LIMIT:
            raise ValueError("due-job list limit is outside the supported bound")
        rows = self.connection.execute(
            """
            SELECT j.job_id, j.request_id, j.service_id, j.operation, j.state,
                   j.provider_job_id, j.principal_id, j.quota_scope_id,
                   j.credential_id, j.next_poll_at_ms,
                   j.maximum_runtime_at_ms, j.created_at_ms,
                   j.completed_at_ms, j.metadata_json,
                   er.resource_type, er.credential_generation, er.pool_id,
                   i.session_id AS owner_session_id,
                   s.workspace_id AS owner_workspace_id,
                   i.root_run_id AS owner_root_run_id
              FROM jobs AS j
              JOIN invocations AS i
                ON i.request_id = j.request_id
               AND i.service_id = j.service_id
               AND i.operation = j.operation
               AND i.state = 'SUCCEEDED'
              JOIN sessions AS s ON s.session_id = i.session_id
              JOIN root_runs AS rr
                ON rr.root_run_id = i.root_run_id
               AND rr.session_id = i.session_id
              JOIN external_resources AS er
                ON er.creating_request_id = i.request_id
               AND er.service_id = j.service_id
               AND er.provider_resource_id = j.provider_job_id
               AND er.principal_id = j.principal_id
               AND er.quota_scope_id = j.quota_scope_id
               AND er.credential_id = j.credential_id
               AND er.owner_session_id = i.session_id
               AND er.owner_workspace_id = s.workspace_id
               AND er.owner_root_run_id = i.root_run_id
               AND er.state = 'ACTIVE'
             WHERE j.state IN (
                 'CREATED', 'RUNNING', 'POLLING', 'CANCELLING', 'RECOVERING',
                 'SETTLING'
             )
               AND (j.next_poll_at_ms IS NULL OR j.next_poll_at_ms <= ?)
             ORDER BY COALESCE(j.next_poll_at_ms, j.created_at_ms),
                      j.created_at_ms, j.job_id
             LIMIT ?
            """,
            (now_ms, limit),
        ).fetchall()
        return tuple(self._record_from_row(row) for row in rows)

    async def recover_orphaned_resources(
        self,
        *,
        maximum_runtime_ms_by_client_id: Mapping[str, int],
        now_ms: int,
        maximum_orphans: int = 1_000,
    ) -> int:
        """Materialize jobs for successful resource bindings left by a crash."""

        now_ms = require_utc_ms(now_ms)
        if maximum_orphans <= 0 or maximum_orphans > 10_000:
            raise ValueError("job orphan recovery bound is outside the supported range")
        rows = self.connection.execute(
            """
            SELECT er.service_id, er.resource_type, er.provider_resource_id,
                   er.principal_id, er.quota_scope_id, er.credential_id,
                   er.credential_generation, er.pool_id, er.creating_request_id,
                   er.owner_session_id, er.owner_workspace_id,
                   er.owner_root_run_id, er.created_at_ms, s.client_id
              FROM external_resources AS er
              JOIN invocations AS i
                ON i.request_id = er.creating_request_id
               AND i.session_id = er.owner_session_id
               AND i.root_run_id = er.owner_root_run_id
               AND i.service_id = er.service_id
               AND i.state = 'SUCCEEDED'
              JOIN sessions AS s
                ON s.session_id = i.session_id
               AND s.workspace_id = er.owner_workspace_id
              LEFT JOIN jobs AS j ON j.request_id = i.request_id
             WHERE er.state = 'ACTIVE'
               AND er.resource_type = 'crawl'
               AND i.operation LIKE '%.crawl.start'
               AND j.job_id IS NULL
             ORDER BY er.created_at_ms, er.resource_id
             LIMIT ?
            """,
            (maximum_orphans + 1,),
        ).fetchall()
        if len(rows) > maximum_orphans:
            raise JobCorruptionError("orphaned provider jobs exceed the recovery bound")
        recovered = 0
        for row in rows:
            client_id = _row_text(row, "client_id")
            duration_ms = maximum_runtime_ms_by_client_id.get(client_id)
            if (
                isinstance(duration_ms, bool)
                or not isinstance(duration_ms, int)
                or duration_ms <= 0
            ):
                raise JobCorruptionError(
                    "orphaned provider job has no configured runtime authority"
                )
            bound_at_ms = _row_timestamp(row, "created_at_ms")
            if bound_at_ms is None:
                raise JobCorruptionError("orphaned provider job has no binding time")
            maximum_runtime_at_ms = require_utc_ms(bound_at_ms + duration_ms)
            try:
                fact = ResourceAffinity(
                    service_id=_row_text(row, "service_id"),
                    resource_type=_row_text(row, "resource_type"),
                    provider_resource_id=_row_text(row, "provider_resource_id"),
                    principal_id=PrincipalId(_row_text(row, "principal_id")),
                    quota_scope_id=QuotaScopeId(_row_text(row, "quota_scope_id")),
                    credential_id=CredentialId(_row_text(row, "credential_id")),
                    credential_generation=int(row["credential_generation"]),
                    pool_id=PoolId(_row_text(row, "pool_id")),
                    creating_request_id=RequestId(_row_text(row, "creating_request_id")),
                    owner_session_id=SessionId(_row_text(row, "owner_session_id")),
                    owner_workspace_id=WorkspaceId(_row_text(row, "owner_workspace_id")),
                    owner_root_run_id=RootRunId(_row_text(row, "owner_root_run_id")),
                    bound_at_ms=bound_at_ms,
                )
            except (TypeError, ValueError) as error:
                raise JobCorruptionError(
                    "orphaned provider job has invalid durable authority"
                ) from error
            await self.create_from_affinity(
                fact,
                maximum_runtime_at_ms=maximum_runtime_at_ms,
                next_poll_at_ms=min(
                    maximum_runtime_at_ms,
                    max(now_ms, bound_at_ms),
                ),
            )
            recovered += 1
        return recovered

    def validate_startup_integrity(
        self,
        *,
        supported_operation_resource_types: Mapping[str, str] | None = None,
        maximum_nonterminal_jobs: int = 10_000,
    ) -> int:
        """Fail closed when a live job cannot reconstruct its complete authority.

        SQLite foreign keys only prove that individual identifiers exist.  They do
        not prove, for example, that a credential belongs to the job's principal and
        quota scope, or that an active resource belongs to the invocation's exact
        session, workspace, and root run.  Normal owner-fenced queries intentionally
        omit rows that fail those joins, so startup must enumerate every nonterminal
        job independently and reject any row that would otherwise disappear.
        """

        if maximum_nonterminal_jobs <= 0 or maximum_nonterminal_jobs > 100_000:
            raise ValueError("job startup integrity bound is outside the supported range")
        supported = (
            None
            if supported_operation_resource_types is None
            else dict(supported_operation_resource_types)
        )
        if supported is not None and any(
            not operation or not resource_type for operation, resource_type in supported.items()
        ):
            raise ValueError("supported job operations must have resource types")

        rows = self.connection.execute(
            """
            SELECT j.job_id, j.request_id, j.service_id, j.operation, j.state,
                   j.provider_job_id, j.principal_id, j.quota_scope_id,
                   j.credential_id, j.next_poll_at_ms,
                   j.maximum_runtime_at_ms, j.created_at_ms,
                   j.completed_at_ms, j.metadata_json,
                   er.resource_type, er.credential_generation, er.pool_id,
                   er.owner_session_id, er.owner_workspace_id,
                   er.owner_root_run_id,
                   i.request_id AS invocation_request_id,
                   i.service_id AS invocation_service_id,
                   i.operation AS invocation_operation,
                   i.state AS invocation_state,
                   i.session_id AS invocation_session_id,
                   i.root_run_id AS invocation_root_run_id,
                   s.workspace_id AS session_workspace_id,
                   rr.session_id AS root_session_id,
                   er.creating_request_id AS resource_creating_request_id,
                   er.service_id AS resource_service_id,
                   er.provider_resource_id AS resource_provider_resource_id,
                   er.principal_id AS resource_principal_id,
                   er.quota_scope_id AS resource_quota_scope_id,
                   er.credential_id AS resource_credential_id,
                   er.state AS resource_state,
                   er.created_at_ms AS resource_created_at_ms,
                   p.service_id AS principal_service_id,
                   qs.principal_id AS quota_principal_id,
                   c.principal_id AS credential_principal_id,
                   c.quota_scope_id AS credential_quota_scope_id,
                   pl.service_id AS pool_service_id,
                   pm.quota_scope_id AS pool_member_quota_scope_id
              FROM jobs AS j
              LEFT JOIN invocations AS i ON i.request_id = j.request_id
              LEFT JOIN sessions AS s ON s.session_id = i.session_id
              LEFT JOIN root_runs AS rr ON rr.root_run_id = i.root_run_id
              LEFT JOIN external_resources AS er
                ON er.creating_request_id = j.request_id
               AND er.service_id = j.service_id
               AND er.provider_resource_id = j.provider_job_id
              LEFT JOIN principals AS p ON p.principal_id = er.principal_id
              LEFT JOIN quota_scopes AS qs
                ON qs.quota_scope_id = er.quota_scope_id
              LEFT JOIN credentials AS c ON c.credential_id = er.credential_id
              LEFT JOIN pools AS pl ON pl.pool_id = er.pool_id
              LEFT JOIN pool_members AS pm
                ON pm.pool_id = er.pool_id
               AND pm.quota_scope_id = er.quota_scope_id
             WHERE j.state NOT IN ('SUCCEEDED', 'FAILED', 'CANCELLED', 'UNKNOWN')
             ORDER BY j.created_at_ms, j.job_id
             LIMIT ?
            """,
            (maximum_nonterminal_jobs + 1,),
        ).fetchall()
        if len(rows) > maximum_nonterminal_jobs:
            raise JobCorruptionError("nonterminal jobs exceed the startup integrity bound")

        for row in rows:
            if not isinstance(row, sqlite3.Row):
                raise TypeError("job store requires sqlite3.Row results")
            try:
                record = self._record_from_row(row)
                expected = (
                    str(record.request_id),
                    record.service_id,
                    record.operation,
                    "SUCCEEDED",
                    str(record.owner.session_id),
                    str(record.owner.root_run_id),
                    str(record.owner.workspace_id),
                    str(record.owner.session_id),
                    str(record.request_id),
                    record.service_id,
                    record.provider_resource_id,
                    str(record.principal_id),
                    str(record.quota_scope_id),
                    str(record.credential_id),
                    "ACTIVE",
                    record.created_at_ms,
                    record.service_id,
                    str(record.principal_id),
                    str(record.principal_id),
                    str(record.quota_scope_id),
                    record.service_id,
                    str(record.quota_scope_id),
                )
                actual = tuple(
                    row[name]
                    for name in (
                        "invocation_request_id",
                        "invocation_service_id",
                        "invocation_operation",
                        "invocation_state",
                        "invocation_session_id",
                        "invocation_root_run_id",
                        "session_workspace_id",
                        "root_session_id",
                        "resource_creating_request_id",
                        "resource_service_id",
                        "resource_provider_resource_id",
                        "resource_principal_id",
                        "resource_quota_scope_id",
                        "resource_credential_id",
                        "resource_state",
                        "resource_created_at_ms",
                        "principal_service_id",
                        "quota_principal_id",
                        "credential_principal_id",
                        "credential_quota_scope_id",
                        "pool_service_id",
                        "pool_member_quota_scope_id",
                    )
                )
                if actual != expected:
                    raise ValueError("job authority chain is inconsistent")
                if supported is not None and supported.get(record.operation) != (
                    record.resource_type
                ):
                    raise ValueError("job operation is not supported for its resource type")
            except (JobCorruptionError, KeyError, TypeError, ValueError) as error:
                raise JobCorruptionError("nonterminal job has invalid durable authority") from error
        return len(rows)

    async def compare_and_set(
        self,
        *,
        expected: JobRecord,
        owner: JobOwner,
        target_state: JobState,
        observed_at_ms: int,
        provider_status: str | None = None,
        next_poll_at_ms: int | None = None,
    ) -> JobRecord | None:
        """Apply a provider observation only if the entire expected record is current."""

        observed_at_ms = require_utc_ms(observed_at_ms)
        provider_status = _validate_provider_status(provider_status)
        if target_state is JobState.SETTLING or expected.state is JobState.SETTLING:
            raise ValueError("settlement checkpoints require the dedicated store workflow")
        if expected.owner != owner:
            return None
        if observed_at_ms < expected.created_at_ms:
            raise ValueError("provider observation cannot precede job creation")
        if next_poll_at_ms is not None:
            next_poll_at_ms = require_utc_ms(next_poll_at_ms)
        if target_state not in TERMINAL_JOB_STATES:
            if observed_at_ms > expected.maximum_runtime_at_ms:
                raise ValueError("non-terminal update exceeds the maximum runtime")
            if next_poll_at_ms is not None and not (
                observed_at_ms <= next_poll_at_ms <= expected.maximum_runtime_at_ms
            ):
                raise ValueError("next poll time is outside the remaining runtime")
        elif next_poll_at_ms is not None:
            raise ValueError("terminal jobs cannot retain a next poll time")

        with transaction(self.connection, "IMMEDIATE"):
            row = self._select_owned(expected.job_id, owner)
            if row is None:
                return None
            current = self._record_from_row(row)
            if current != expected:
                return None
            if (
                target_state is not current.state
                and target_state not in _ALLOWED_TRANSITIONS[current.state]
            ):
                raise ValueError(f"invalid job state transition: {current.state} -> {target_state}")

            new_provider_status = (
                current.provider_status if provider_status is None else provider_status
            )
            new_observed_at_ms = (
                current.provider_status_observed_at_ms
                if provider_status is None
                else observed_at_ms
            )
            completed_at_ms = observed_at_ms if target_state in TERMINAL_JOB_STATES else None
            new_next_poll_at_ms = None if target_state in TERMINAL_JOB_STATES else next_poll_at_ms
            metadata = _encode_metadata(
                revision=current.revision + 1,
                resource_type=current.resource_type,
                credential_generation=current.credential_generation,
                pool_id=current.pool_id,
                provider_status=new_provider_status,
                provider_status_observed_at_ms=new_observed_at_ms,
                cancel_requested_at_ms=current.cancel_requested_at_ms,
            )
            updated = self.connection.execute(
                """
                UPDATE jobs
                   SET state = ?, next_poll_at_ms = ?, completed_at_ms = ?,
                       metadata_json = ?
                 WHERE job_id = ? AND state = ? AND metadata_json = ?
                """,
                (
                    target_state.value,
                    new_next_poll_at_ms,
                    completed_at_ms,
                    metadata,
                    str(current.job_id),
                    current.state.value,
                    _row_text(row, "metadata_json"),
                ),
            )
            if updated.rowcount != 1:
                return None
            replacement_row = self._select_owned(current.job_id, owner)
            if replacement_row is None:
                raise JobCorruptionError("updated job lost its durable owner authority")
            replacement = self._record_from_row(replacement_row)
        self._notify(expected.job_id)
        return replacement

    async def prepare_settlement(
        self,
        *,
        expected: JobRecord,
        owner: JobOwner,
        target_state: JobState,
        actual_cost_units: int,
        observed_at_ms: int,
        provider_status: str | None = None,
    ) -> JobRecord | None:
        """Persist terminal usage before touching either accounting ledger."""

        observed_at_ms = require_utc_ms(observed_at_ms)
        provider_status = _validate_provider_status(provider_status)
        if expected.owner != owner:
            return None
        if expected.state is JobState.SETTLING or expected.terminal:
            raise ValueError("only an active observed job can enter settlement")
        if target_state not in TERMINAL_JOB_STATES:
            raise ValueError("job settlement target must be terminal")
        if (
            isinstance(actual_cost_units, bool)
            or not isinstance(actual_cost_units, int)
            or actual_cost_units < 0
            or actual_cost_units >= (1 << 63)
        ):
            raise ValueError("job settlement usage is outside its integer bound")
        if observed_at_ms < expected.created_at_ms:
            raise ValueError("provider observation cannot precede job creation")

        with transaction(self.connection, "IMMEDIATE"):
            row = self._select_owned(expected.job_id, owner)
            if row is None:
                return None
            current = self._record_from_row(row)
            if current != expected:
                return None
            if target_state not in _ALLOWED_TRANSITIONS[current.state]:
                raise ValueError(
                    f"invalid job settlement transition: {current.state} -> {target_state}"
                )
            new_provider_status = (
                current.provider_status if provider_status is None else provider_status
            )
            new_observed_at_ms = (
                current.provider_status_observed_at_ms
                if provider_status is None
                else observed_at_ms
            )
            metadata = _encode_metadata(
                revision=current.revision + 1,
                resource_type=current.resource_type,
                credential_generation=current.credential_generation,
                pool_id=current.pool_id,
                provider_status=new_provider_status,
                provider_status_observed_at_ms=new_observed_at_ms,
                cancel_requested_at_ms=current.cancel_requested_at_ms,
                settlement_target_state=target_state,
                settlement_actual_cost_units=actual_cost_units,
                settlement_observed_at_ms=observed_at_ms,
            )
            updated = self.connection.execute(
                """
                UPDATE jobs
                   SET state = 'SETTLING', next_poll_at_ms = ?,
                       completed_at_ms = NULL, metadata_json = ?
                 WHERE job_id = ? AND state = ? AND metadata_json = ?
                """,
                (
                    observed_at_ms,
                    metadata,
                    str(current.job_id),
                    current.state.value,
                    _row_text(row, "metadata_json"),
                ),
            )
            if updated.rowcount != 1:
                return None
            replacement_row = self._select_owned(current.job_id, owner)
            if replacement_row is None:
                raise JobCorruptionError("settling job lost its durable owner authority")
            replacement = self._record_from_row(replacement_row)
        self._notify(expected.job_id)
        return replacement

    async def complete_settlement(
        self,
        *,
        expected: JobRecord,
        owner: JobOwner,
    ) -> JobRecord | None:
        """Commit a previously checkpointed terminal state after ledger settlement."""

        if expected.owner != owner:
            return None
        if (
            expected.state is not JobState.SETTLING
            or expected.settlement_target_state is None
            or expected.settlement_observed_at_ms is None
        ):
            raise ValueError("job does not own a complete settlement checkpoint")
        with transaction(self.connection, "IMMEDIATE"):
            row = self._select_owned(expected.job_id, owner)
            if row is None:
                return None
            current = self._record_from_row(row)
            if current != expected:
                return None
            target_state = current.settlement_target_state
            completed_at_ms = current.settlement_observed_at_ms
            assert target_state is not None
            assert completed_at_ms is not None
            metadata = _encode_metadata(
                revision=current.revision + 1,
                resource_type=current.resource_type,
                credential_generation=current.credential_generation,
                pool_id=current.pool_id,
                provider_status=current.provider_status,
                provider_status_observed_at_ms=current.provider_status_observed_at_ms,
                cancel_requested_at_ms=current.cancel_requested_at_ms,
            )
            updated = self.connection.execute(
                """
                UPDATE jobs
                   SET state = ?, next_poll_at_ms = NULL, completed_at_ms = ?,
                       metadata_json = ?
                 WHERE job_id = ? AND state = 'SETTLING' AND metadata_json = ?
                """,
                (
                    target_state.value,
                    completed_at_ms,
                    metadata,
                    str(current.job_id),
                    _row_text(row, "metadata_json"),
                ),
            )
            if updated.rowcount != 1:
                return None
            replacement_row = self._select_owned(current.job_id, owner)
            if replacement_row is None:
                raise JobCorruptionError("settled job lost its durable owner authority")
            replacement = self._record_from_row(replacement_row)
        self._notify(expected.job_id)
        return replacement

    async def request_cancellation(
        self,
        job_id: JobId,
        *,
        owner: JobOwner,
        now_ms: int,
    ) -> JobRecord | None:
        """Request cancellation once without contacting the provider."""

        now_ms = require_utc_ms(now_ms)
        with transaction(self.connection, "IMMEDIATE"):
            row = self._select_owned(job_id, owner)
            if row is None:
                return None
            current = self._record_from_row(row)
            if current.terminal or current.state in {
                JobState.CANCELLING,
                JobState.SETTLING,
            }:
                return current
            if now_ms < current.created_at_ms:
                raise ValueError("cancellation cannot precede job creation")
            metadata = _encode_metadata(
                revision=current.revision + 1,
                resource_type=current.resource_type,
                credential_generation=current.credential_generation,
                pool_id=current.pool_id,
                provider_status=current.provider_status,
                provider_status_observed_at_ms=current.provider_status_observed_at_ms,
                cancel_requested_at_ms=now_ms,
            )
            updated = self.connection.execute(
                """
                UPDATE jobs
                   SET state = 'CANCELLING', next_poll_at_ms = ?,
                       completed_at_ms = NULL, metadata_json = ?
                 WHERE job_id = ? AND state = ? AND metadata_json = ?
                """,
                (
                    now_ms,
                    metadata,
                    str(job_id),
                    current.state.value,
                    _row_text(row, "metadata_json"),
                ),
            )
            if updated.rowcount != 1:
                return None
            replacement_row = self._select_owned(job_id, owner)
            if replacement_row is None:
                raise JobCorruptionError("cancelling job lost its durable owner authority")
            replacement = self._record_from_row(replacement_row)
        self._notify(job_id)
        return replacement

    async def await_update(
        self,
        job_id: JobId,
        *,
        owner: JobOwner,
        after_revision: int,
        maximum_wait_ms: int,
    ) -> JobAwaitResult:
        """Wait within a bound, always resolving the result from SQLite."""

        if after_revision < 0:
            raise ValueError("after_revision must be non-negative")
        if maximum_wait_ms <= 0 or maximum_wait_ms > self._maximum_await_ms:
            raise ValueError("maximum_wait_ms is outside the configured bound")

        initial = await self.load(job_id, owner=owner)
        if initial is None:
            return JobAwaitResult(record=None, changed=False, timed_out=False)
        if initial.revision > after_revision:
            return JobAwaitResult(record=initial, changed=True, timed_out=False)

        event = self._event_for(job_id)
        reread = await self.load(job_id, owner=owner)
        if reread is None:
            return JobAwaitResult(record=None, changed=False, timed_out=False)
        if reread.revision > after_revision:
            return JobAwaitResult(record=reread, changed=True, timed_out=False)

        timed_out = False
        try:
            await asyncio.wait_for(event.wait(), timeout=maximum_wait_ms / 1_000)
        except TimeoutError:
            timed_out = True

        final = await self.load(job_id, owner=owner)
        changed = final is not None and final.revision > after_revision
        return JobAwaitResult(
            record=final,
            changed=changed,
            timed_out=timed_out and not changed,
        )

    def _resolve_existing(
        self,
        key_row: sqlite3.Row,
        affinity: ResourceAffinity,
    ) -> JobRecord:
        if _row_text(key_row, "request_id") != str(affinity.creating_request_id):
            raise JobConflictError("provider resource is already resolved to another invocation")
        try:
            job_id = JobId(_row_text(key_row, "job_id"))
        except (TypeError, ValueError) as error:
            raise JobConflictError("provider resource has an invalid durable job") from error
        row = self._select_owned(job_id, self._owner_from_affinity(affinity))
        if row is None:
            raise JobConflictError("provider resource is already resolved with different authority")
        try:
            record = self._record_from_row(row)
        except JobCorruptionError as error:
            raise JobConflictError("provider resource has invalid durable authority") from error
        expected_authority = (
            affinity.service_id,
            affinity.resource_type,
            affinity.provider_resource_id,
            affinity.principal_id,
            affinity.quota_scope_id,
            affinity.credential_id,
            affinity.credential_generation,
            affinity.pool_id,
            affinity.creating_request_id,
            affinity.owner_session_id,
            affinity.owner_workspace_id,
            affinity.owner_root_run_id,
        )
        actual_authority = (
            record.service_id,
            record.resource_type,
            record.provider_resource_id,
            record.principal_id,
            record.quota_scope_id,
            record.credential_id,
            record.credential_generation,
            record.pool_id,
            record.request_id,
            record.owner.session_id,
            record.owner.workspace_id,
            record.owner.root_run_id,
        )
        if actual_authority != expected_authority:
            raise JobConflictError("provider resource is already resolved with different authority")
        return record

    def _verified_authority(self, affinity: ResourceAffinity) -> sqlite3.Row:
        row = self.connection.execute(
            """
            SELECT i.operation, er.created_at_ms,
                   i.service_id, i.state, i.session_id, i.root_run_id,
                   s.workspace_id, er.resource_type, er.provider_resource_id,
                   er.principal_id, er.quota_scope_id, er.credential_id,
                   er.credential_generation, er.pool_id, er.creating_request_id,
                   er.owner_session_id, er.owner_workspace_id,
                   er.owner_root_run_id, er.state AS resource_state
              FROM invocations AS i
              JOIN sessions AS s ON s.session_id = i.session_id
              JOIN root_runs AS rr
                ON rr.root_run_id = i.root_run_id
               AND rr.session_id = i.session_id
              JOIN external_resources AS er
                ON er.creating_request_id = i.request_id
               AND er.service_id = ?
               AND er.resource_type = ?
               AND er.provider_resource_id = ?
             WHERE i.request_id = ?
            """,
            (
                affinity.service_id,
                affinity.resource_type,
                affinity.provider_resource_id,
                str(affinity.creating_request_id),
            ),
        ).fetchone()
        expected = (
            affinity.service_id,
            "SUCCEEDED",
            str(affinity.owner_session_id),
            str(affinity.owner_root_run_id),
            str(affinity.owner_workspace_id),
            affinity.resource_type,
            affinity.provider_resource_id,
            str(affinity.principal_id),
            str(affinity.quota_scope_id),
            str(affinity.credential_id),
            affinity.credential_generation,
            str(affinity.pool_id),
            str(affinity.creating_request_id),
            str(affinity.owner_session_id),
            str(affinity.owner_workspace_id),
            str(affinity.owner_root_run_id),
            "ACTIVE",
        )
        if row is None or tuple(row)[2:] != expected:
            raise JobConflictError(
                "job authority does not match a successful invocation and active affinity"
            )
        if not isinstance(row, sqlite3.Row):
            raise TypeError("job store requires sqlite3.Row results")
        return row

    def _select_owned(self, job_id: JobId, owner: JobOwner) -> sqlite3.Row | None:
        row: object = self.connection.execute(
            """
            SELECT j.job_id, j.request_id, j.service_id, j.operation, j.state,
                   j.provider_job_id, j.principal_id, j.quota_scope_id,
                   j.credential_id, j.next_poll_at_ms,
                   j.maximum_runtime_at_ms, j.created_at_ms,
                   j.completed_at_ms, j.metadata_json,
                   er.resource_type, er.credential_generation, er.pool_id,
                   i.session_id AS owner_session_id,
                   s.workspace_id AS owner_workspace_id,
                   i.root_run_id AS owner_root_run_id
              FROM jobs AS j
              JOIN invocations AS i
                ON i.request_id = j.request_id
               AND i.service_id = j.service_id
               AND i.operation = j.operation
               AND i.state = 'SUCCEEDED'
              JOIN sessions AS s ON s.session_id = i.session_id
              JOIN root_runs AS rr
                ON rr.root_run_id = i.root_run_id
               AND rr.session_id = i.session_id
              JOIN external_resources AS er
                ON er.creating_request_id = i.request_id
               AND er.service_id = j.service_id
               AND er.provider_resource_id = j.provider_job_id
               AND er.principal_id = j.principal_id
               AND er.quota_scope_id = j.quota_scope_id
               AND er.credential_id = j.credential_id
               AND er.owner_session_id = i.session_id
               AND er.owner_workspace_id = s.workspace_id
               AND er.owner_root_run_id = i.root_run_id
               AND er.state = 'ACTIVE'
             WHERE j.job_id = ?
               AND i.session_id = ?
               AND s.workspace_id = ?
               AND i.root_run_id = ?
            """,
            (
                str(job_id),
                str(owner.session_id),
                str(owner.workspace_id),
                str(owner.root_run_id),
            ),
        ).fetchone()
        if row is None:
            return None
        if not isinstance(row, sqlite3.Row):
            raise TypeError("job store requires sqlite3.Row results")
        return row

    @staticmethod
    def _record_from_row(row: sqlite3.Row) -> JobRecord:
        try:
            metadata = _decode_metadata(row["metadata_json"])
            resource_type = _row_text(row, "resource_type")
            credential_generation = _row_integer(row, "credential_generation")
            pool_id = PoolId(_row_text(row, "pool_id"))
            if resource_type != metadata["resource_type"]:
                raise ValueError("job resource type metadata does not match affinity")
            if credential_generation != metadata["credential_generation"]:
                raise ValueError("job credential generation metadata does not match affinity")
            if str(pool_id) != metadata["pool_id"]:
                raise ValueError("job pool metadata does not match affinity")
            provider_status_value = metadata.get("provider_status")
            provider_status = (
                None
                if provider_status_value is None
                else _required_text(
                    provider_status_value,
                    field="provider_status",
                    maximum_length=_MAXIMUM_PROVIDER_STATUS_LENGTH,
                )
            )
            settlement_target_value = metadata.get("settlement_target_state")
            settlement_target_state = (
                None
                if settlement_target_value is None
                else JobState(
                    _required_text(
                        settlement_target_value,
                        field="settlement_target_state",
                        maximum_length=32,
                    )
                )
            )
            settlement_actual_value = metadata.get("settlement_actual_cost_units")
            settlement_actual_cost_units = (
                None
                if settlement_actual_value is None
                else _required_integer(
                    settlement_actual_value,
                    field="settlement_actual_cost_units",
                )
            )
            maximum_runtime_at_ms = _row_timestamp(row, "maximum_runtime_at_ms")
            created_at_ms = _row_timestamp(row, "created_at_ms")
            if maximum_runtime_at_ms is None or created_at_ms is None:
                raise ValueError("job runtime timestamps are required")
            if credential_generation is None:
                raise ValueError("job credential generation is required")
            return JobRecord(
                job_id=JobId(_row_text(row, "job_id")),
                request_id=RequestId(_row_text(row, "request_id")),
                service_id=_row_text(row, "service_id"),
                operation=_row_text(row, "operation"),
                state=JobState(_row_text(row, "state")),
                provider_resource_id=_row_text(row, "provider_job_id"),
                resource_type=resource_type,
                principal_id=PrincipalId(_row_text(row, "principal_id")),
                quota_scope_id=QuotaScopeId(_row_text(row, "quota_scope_id")),
                credential_id=CredentialId(_row_text(row, "credential_id")),
                credential_generation=credential_generation,
                pool_id=pool_id,
                owner=JobOwner(
                    session_id=SessionId(_row_text(row, "owner_session_id")),
                    workspace_id=WorkspaceId(_row_text(row, "owner_workspace_id")),
                    root_run_id=RootRunId(_row_text(row, "owner_root_run_id")),
                ),
                revision=_required_integer(
                    metadata["revision"],
                    field="revision",
                    positive=True,
                ),
                provider_status=provider_status,
                provider_status_observed_at_ms=_optional_timestamp(
                    metadata.get("provider_status_observed_at_ms"),
                    field="provider_status_observed_at_ms",
                ),
                cancel_requested_at_ms=_optional_timestamp(
                    metadata.get("cancel_requested_at_ms"),
                    field="cancel_requested_at_ms",
                ),
                next_poll_at_ms=_row_timestamp(row, "next_poll_at_ms", optional=True),
                maximum_runtime_at_ms=maximum_runtime_at_ms,
                created_at_ms=created_at_ms,
                completed_at_ms=_row_timestamp(row, "completed_at_ms", optional=True),
                settlement_target_state=settlement_target_state,
                settlement_actual_cost_units=settlement_actual_cost_units,
                settlement_observed_at_ms=_optional_timestamp(
                    metadata.get("settlement_observed_at_ms"),
                    field="settlement_observed_at_ms",
                ),
            )
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
            raise JobCorruptionError("persisted job has invalid state or authority") from error

    def _new_job_id(self, created_at_ms: int) -> JobId:
        clock = FixedUtcClock(created_at_ms)
        if self._entropy is None:
            return JobId.new(clock=clock)
        return JobId.new(clock=clock, entropy=self._entropy)

    @staticmethod
    def _owner_from_affinity(affinity: ResourceAffinity) -> JobOwner:
        return JobOwner(
            session_id=affinity.owner_session_id,
            workspace_id=affinity.owner_workspace_id,
            root_run_id=affinity.owner_root_run_id,
        )

    def _event_for(self, job_id: JobId) -> asyncio.Event:
        event = self._events.get(job_id)
        if event is None:
            event = asyncio.Event()
            self._events[job_id] = event
        return event

    def _notify(self, job_id: JobId) -> None:
        event = self._events.get(job_id)
        if event is None:
            return
        self._events[job_id] = asyncio.Event()
        event.set()
