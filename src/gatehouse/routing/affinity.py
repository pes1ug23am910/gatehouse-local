"""Crash-persistable affinity facts for asynchronous provider resources."""

from __future__ import annotations

import asyncio
import sqlite3
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

from gatehouse.core.clock import require_utc_ms
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
from gatehouse.database.connection import transaction


class ResourceAffinityConflictError(RuntimeError):
    """A provider resource was already bound to different authority facts."""


@dataclass(frozen=True, slots=True)
class ResourceAffinity:
    service_id: str
    resource_type: str
    provider_resource_id: str
    principal_id: PrincipalId
    quota_scope_id: QuotaScopeId
    credential_id: CredentialId
    credential_generation: int
    pool_id: PoolId
    creating_request_id: RequestId
    owner_session_id: SessionId
    owner_workspace_id: WorkspaceId
    owner_root_run_id: RootRunId
    bound_at_ms: int

    def __post_init__(self) -> None:
        if not self.service_id or not self.resource_type or not self.provider_resource_id:
            raise ValueError("resource affinity identifiers are required")
        if len(self.provider_resource_id) > 128:
            raise ValueError("provider resource identifier is too long")
        if self.credential_generation <= 0:
            raise ValueError("credential generation must be positive")
        require_utc_ms(self.bound_at_ms)

    @property
    def key(self) -> tuple[str, str, str]:
        return self.service_id, self.resource_type, self.provider_resource_id

    @property
    def provider_key(self) -> tuple[str, str]:
        return self.service_id, self.provider_resource_id

    @property
    def authority(self) -> tuple[object, ...]:
        """Return the immutable authority facts, excluding the observation time."""

        return (
            *self.key,
            self.principal_id,
            self.quota_scope_id,
            self.credential_id,
            self.credential_generation,
            self.pool_id,
            self.creating_request_id,
            self.owner_session_id,
            self.owner_workspace_id,
            self.owner_root_run_id,
        )


class ResourceAffinityStore(Protocol):
    async def get(
        self,
        *,
        service_id: str,
        resource_type: str,
        provider_resource_id: str,
        owner_session_id: SessionId,
        owner_workspace_id: WorkspaceId,
        owner_root_run_id: RootRunId,
    ) -> ResourceAffinity | None: ...

    async def get_by_request(
        self,
        *,
        service_id: str,
        resource_type: str,
        creating_request_id: RequestId,
        owner_session_id: SessionId,
        owner_workspace_id: WorkspaceId,
        owner_root_run_id: RootRunId,
    ) -> ResourceAffinity | None: ...

    async def bind(self, affinity: ResourceAffinity) -> ResourceAffinity: ...


class InMemoryResourceAffinityStore:
    """Bounded-process implementation useful before a durable adapter is wired."""

    def __init__(self, *, maximum_entries: int = 10_000) -> None:
        if maximum_entries <= 0:
            raise ValueError("maximum_entries must be positive")
        self.maximum_entries = maximum_entries
        self._items: dict[tuple[str, str], ResourceAffinity] = {}
        self._lock = asyncio.Lock()

    async def get(
        self,
        *,
        service_id: str,
        resource_type: str,
        provider_resource_id: str,
        owner_session_id: SessionId,
        owner_workspace_id: WorkspaceId,
        owner_root_run_id: RootRunId,
    ) -> ResourceAffinity | None:
        async with self._lock:
            affinity = self._items.get((service_id, provider_resource_id))
            if affinity is None or (
                affinity.resource_type != resource_type
                or affinity.owner_session_id != owner_session_id
                or affinity.owner_workspace_id != owner_workspace_id
                or affinity.owner_root_run_id != owner_root_run_id
            ):
                return None
            return affinity

    async def bind(self, affinity: ResourceAffinity) -> ResourceAffinity:
        async with self._lock:
            existing = self._items.get(affinity.provider_key)
            if existing is not None:
                if existing.authority != affinity.authority:
                    raise ResourceAffinityConflictError(
                        "provider resource is already bound to another authority"
                    )
                return existing
            if len(self._items) >= self.maximum_entries:
                raise RuntimeError("resource affinity capacity is exhausted")
            self._items[affinity.provider_key] = affinity
            return affinity

    async def get_by_request(
        self,
        *,
        service_id: str,
        resource_type: str,
        creating_request_id: RequestId,
        owner_session_id: SessionId,
        owner_workspace_id: WorkspaceId,
        owner_root_run_id: RootRunId,
    ) -> ResourceAffinity | None:
        async with self._lock:
            matches = [
                affinity
                for affinity in self._items.values()
                if affinity.service_id == service_id
                and affinity.resource_type == resource_type
                and affinity.creating_request_id == creating_request_id
                and affinity.owner_session_id == owner_session_id
                and affinity.owner_workspace_id == owner_workspace_id
                and affinity.owner_root_run_id == owner_root_run_id
            ]
            if len(matches) > 1:
                raise ResourceAffinityConflictError(
                    "one invocation is bound to multiple provider resources"
                )
            return matches[0] if matches else None

    @property
    def entry_count(self) -> int:
        return len(self._items)


class SqliteResourceAffinityStore:
    """Durable, owner-fenced resource affinity backed by Gatehouse SQLite."""

    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        identifier: Callable[[], str] | None = None,
    ) -> None:
        self._connection = connection
        self._identifier = identifier or (lambda: f"resource_{uuid.uuid4().hex}")

    async def get(
        self,
        *,
        service_id: str,
        resource_type: str,
        provider_resource_id: str,
        owner_session_id: SessionId,
        owner_workspace_id: WorkspaceId,
        owner_root_run_id: RootRunId,
    ) -> ResourceAffinity | None:
        row = self._connection.execute(
            """
            SELECT service_id, resource_type, provider_resource_id,
                   principal_id, quota_scope_id, credential_id,
                   credential_generation, pool_id, creating_request_id,
                   owner_session_id, owner_workspace_id, owner_root_run_id,
                   created_at_ms
              FROM external_resources
             WHERE service_id = ?
               AND resource_type = ?
               AND provider_resource_id = ?
               AND owner_session_id = ?
               AND owner_workspace_id = ?
               AND owner_root_run_id = ?
               AND state = 'ACTIVE'
            """,
            (
                service_id,
                resource_type,
                provider_resource_id,
                str(owner_session_id),
                str(owner_workspace_id),
                str(owner_root_run_id),
            ),
        ).fetchone()
        if row is None:
            return None
        try:
            return self._from_row(row)
        except (TypeError, ValueError):
            # Corrupt or incomplete authority must never become an authorization fact.
            return None

    async def get_by_request(
        self,
        *,
        service_id: str,
        resource_type: str,
        creating_request_id: RequestId,
        owner_session_id: SessionId,
        owner_workspace_id: WorkspaceId,
        owner_root_run_id: RootRunId,
    ) -> ResourceAffinity | None:
        """Recover one binding through exact request authority, including terminal state.

        This lookup exists only for idempotent request materialization. Provider
        operations must use :meth:`get`, which remains restricted to ACTIVE
        resources.
        """

        rows = self._connection.execute(
            """
            SELECT service_id, resource_type, provider_resource_id,
                   principal_id, quota_scope_id, credential_id,
                   credential_generation, pool_id, creating_request_id,
                   owner_session_id, owner_workspace_id, owner_root_run_id,
                   created_at_ms
              FROM external_resources
             WHERE service_id = ?
               AND resource_type = ?
               AND creating_request_id = ?
               AND owner_session_id = ?
               AND owner_workspace_id = ?
               AND owner_root_run_id = ?
               AND state IN ('ACTIVE', 'COMPLETED', 'FAILED', 'CANCELLED')
             LIMIT 2
            """,
            (
                service_id,
                resource_type,
                str(creating_request_id),
                str(owner_session_id),
                str(owner_workspace_id),
                str(owner_root_run_id),
            ),
        ).fetchall()
        if len(rows) > 1:
            raise ResourceAffinityConflictError(
                "one invocation is bound to multiple provider resources"
            )
        if not rows:
            return None
        try:
            return self._from_row(rows[0])
        except (TypeError, ValueError):
            # Corrupt authority must never become an idempotency or ownership fact.
            return None

    async def bind(self, affinity: ResourceAffinity) -> ResourceAffinity:
        with transaction(self._connection, "IMMEDIATE"):
            self._verify_authority_chain(affinity)
            existing = self._select_key(affinity)
            if existing is not None:
                return self._idempotent_or_conflict(existing, affinity)

            resource_id = self._identifier()
            if not resource_id or len(resource_id) > 128:
                raise ValueError("resource identifier is required and bounded")
            try:
                self._connection.execute(
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
                        resource_id,
                        affinity.service_id,
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
                        affinity.bound_at_ms,
                        affinity.bound_at_ms,
                    ),
                )
            except sqlite3.IntegrityError:
                # Another process can win the immutable key between transactions on
                # separate connections. Only an authority-identical winner is safe.
                existing = self._select_key(affinity)
                if existing is None:
                    raise
                return self._idempotent_or_conflict(existing, affinity)
        return affinity

    def _select_key(self, affinity: ResourceAffinity) -> sqlite3.Row | None:
        row: object = self._connection.execute(
            """
            SELECT service_id, resource_type, provider_resource_id,
                   principal_id, quota_scope_id, credential_id,
                   credential_generation, pool_id, creating_request_id,
                   owner_session_id, owner_workspace_id, owner_root_run_id,
                   created_at_ms, state
             FROM external_resources
             WHERE service_id = ?
               AND provider_resource_id = ?
            """,
            affinity.provider_key,
        ).fetchone()
        if row is None:
            return None
        if not isinstance(row, sqlite3.Row):
            raise TypeError("resource affinity store requires sqlite3.Row results")
        return row

    def _idempotent_or_conflict(
        self,
        row: sqlite3.Row,
        affinity: ResourceAffinity,
    ) -> ResourceAffinity:
        if str(row["state"]) != "ACTIVE":
            raise ResourceAffinityConflictError(
                "provider resource has a quarantined legacy authority binding"
            )
        try:
            existing = self._from_row(row)
        except (TypeError, ValueError) as error:
            raise ResourceAffinityConflictError(
                "provider resource has invalid persisted authority"
            ) from error
        if existing.authority != affinity.authority:
            raise ResourceAffinityConflictError(
                "provider resource is already bound to another authority"
            )
        return existing

    def _verify_authority_chain(self, affinity: ResourceAffinity) -> None:
        row = self._connection.execute(
            """
            SELECT i.service_id AS invocation_service_id,
                   i.session_id AS invocation_session_id,
                   i.root_run_id AS invocation_root_run_id,
                   s.workspace_id AS session_workspace_id,
                   rr.session_id AS root_session_id,
                   p.service_id AS principal_service_id,
                   q.principal_id AS quota_principal_id,
                   c.principal_id AS credential_principal_id,
                   c.quota_scope_id AS credential_quota_scope_id,
                   pl.service_id AS pool_service_id,
                   pm.quota_scope_id AS pool_quota_scope_id
              FROM invocations AS i
              JOIN sessions AS s ON s.session_id = i.session_id
              JOIN root_runs AS rr ON rr.root_run_id = i.root_run_id
              JOIN principals AS p ON p.principal_id = ?
              JOIN quota_scopes AS q ON q.quota_scope_id = ?
              JOIN credentials AS c ON c.credential_id = ?
              JOIN pools AS pl ON pl.pool_id = ?
              JOIN pool_members AS pm
                ON pm.pool_id = pl.pool_id AND pm.quota_scope_id = q.quota_scope_id
              JOIN attempts AS a
                ON a.request_id = i.request_id
               AND a.credential_id = c.credential_id
               AND a.principal_id = p.principal_id
               AND a.quota_scope_id = q.quota_scope_id
               AND a.state = 'SUCCEEDED'
               AND a.error_class = 'none'
               AND a.resource_type = ?
               AND a.provider_resource_id = ?
               AND a.credential_generation = ?
               AND a.pool_id = pl.pool_id
               AND (
                   a.dispatch_credential_generation IS NULL
                   OR a.dispatch_credential_generation = a.credential_generation
               )
               AND (
                   a.dispatch_pool_id IS NULL
                   OR a.dispatch_pool_id = a.pool_id
               )
             WHERE i.request_id = ?
            """,
            (
                str(affinity.principal_id),
                str(affinity.quota_scope_id),
                str(affinity.credential_id),
                str(affinity.pool_id),
                affinity.resource_type,
                affinity.provider_resource_id,
                affinity.credential_generation,
                str(affinity.creating_request_id),
            ),
        ).fetchone()
        expected = (
            affinity.service_id,
            str(affinity.owner_session_id),
            str(affinity.owner_root_run_id),
            str(affinity.owner_workspace_id),
            str(affinity.owner_session_id),
            affinity.service_id,
            str(affinity.principal_id),
            str(affinity.principal_id),
            str(affinity.quota_scope_id),
            affinity.service_id,
            str(affinity.quota_scope_id),
        )
        if row is None or tuple(row) != expected:
            raise ResourceAffinityConflictError(
                "resource affinity authority does not match durable ownership"
            )

    @staticmethod
    def _from_row(row: sqlite3.Row) -> ResourceAffinity:
        return ResourceAffinity(
            service_id=str(row["service_id"]),
            resource_type=str(row["resource_type"]),
            provider_resource_id=str(row["provider_resource_id"]),
            principal_id=PrincipalId(str(row["principal_id"])),
            quota_scope_id=QuotaScopeId(str(row["quota_scope_id"])),
            credential_id=CredentialId(str(row["credential_id"])),
            credential_generation=int(row["credential_generation"]),
            pool_id=PoolId(str(row["pool_id"])),
            creating_request_id=RequestId(str(row["creating_request_id"])),
            owner_session_id=SessionId(str(row["owner_session_id"])),
            owner_workspace_id=WorkspaceId(str(row["owner_workspace_id"])),
            owner_root_run_id=RootRunId(str(row["owner_root_run_id"])),
            bound_at_ms=int(row["created_at_ms"]),
        )
