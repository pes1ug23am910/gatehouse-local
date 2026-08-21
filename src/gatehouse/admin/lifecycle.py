"""Authenticated, metadata-only credential lifecycle orchestration."""

from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from dataclasses import asdict, dataclass
from typing import Literal, cast

from gatehouse.core.clock import SYSTEM_UTC_CLOCK
from gatehouse.core.ids import CredentialId, EventId
from gatehouse.core.states import CREDENTIAL_TRANSITIONS, CredentialState
from gatehouse.credentials import (
    CredentialAlreadyExistsError,
    CredentialMetadata,
    CredentialNotFoundError,
    KeyStore,
)
from gatehouse.credentials.emergency import (
    EmergencyUnlockManager,
    EmergencyUnlockState,
    EmergencyUnlockStatus,
)
from gatehouse.credentials.validation import is_admissible_firecrawl_secret
from gatehouse.database.connection import transaction

from .models import (
    CredentialMutationResult,
    CredentialProvisionRequest,
    CredentialRotationRequest,
    CredentialStateChangeRequest,
    EmergencyUnlockCancelRequest,
    EmergencyUnlockRequest,
    EmergencyUnlockView,
)

_MAXIMUM_SECRET_BYTES = 16 * 1_024
_STATE_REASON_DOMAIN = b"gatehouse:credential-state-reason:v1"
_EMERGENCY_UNLOCK_REASON_DOMAIN = b"gatehouse:emergency-unlock-reason:v1"
_EMERGENCY_CANCEL_REASON_DOMAIN = b"gatehouse:emergency-cancel-reason:v1"
_ASYNC_CREATE_OPERATIONS = ("firecrawl.crawl.start",)
_ACTIVE_JOB_STATES = (
    "CREATED",
    "RUNNING",
    "POLLING",
    "CANCELLING",
    "RECOVERING",
    "SETTLING",
)
_PERSISTED_SECRET_BOUNDARY_LITERALS = (
    "PREPARED",
    "CUSTODY_CREATED",
    "DURABLE_DRAINED",
    "DURABLE_STATE_CHANGED",
    "MEMORY_UNLOCKED",
    "COMMITTED",
    "ROLLED_BACK",
    "CLEANUP_REQUIRED",
    "AMBIGUOUS_CUSTODY",
    "HEALTHY",
    "DRAINING",
    "DISABLED",
    "QUARANTINED",
    "RETIRED",
    "ACTIVE",
    "CANCELLED",
    "EXPIRED",
    "RELOCKED",
    "UNKNOWN",
    "INFO",
    "firecrawl",
    "credential.provisioned",
    "credential.rotated",
    "credential.disabled",
    "credential.quarantined",
    "credential.retired",
    "credential.rotation_recovery_failed",
    "emergency.unlocked",
    "emergency.cancelled",
    "emergency.expired",
    "emergency.relocked_after_memory_loss",
    "provision",
    "rotate",
    "disable",
    "quarantine",
    "retire",
    "unlock",
    "cancel",
    "dpapi-current-user",
    "memory-test",
    "mutation_id",
    "operation",
    "credential_id",
    "replacement_credential_id",
    "actor_id",
    "metadata_json",
    "result_json",
    "custody_intent_alias",
    "custody_expires_at_ms",
    "custody_generation",
    "custody_principal_id",
    "custody_quota_scope_id",
    "custody_state",
    "audit_event_id",
    "event_id",
    "event_type",
    "severity",
    "service_id",
    "preserve",
    "payload_json",
    "state",
    "generation",
    "alias",
    "principal_id",
    "principal_alias",
    "quota_scope_id",
    "quota_scope_alias",
    "pool_id",
    "pool_alias",
    "pool_ids",
    "expires_at_ms",
    "acted_at_ms",
    "exclusive_usage",
    "logical_alias",
    "rotation_successor_id",
    "rotation_predecessor_id",
    "last_local_action",
    "last_action_at_ms",
    "reason_supplied",
    "unlock_id",
    "session_id",
    "root_run_id",
    "maximum_requests",
    "maximum_credits",
    "maximum_concurrency",
    "remaining_requests",
    "remaining_credits",
    "remaining_concurrency",
    1,
)

_CredentialAction = Literal["provision", "rotate", "disable", "quarantine", "retire"]


@dataclass(frozen=True, slots=True)
class _CredentialRoute:
    service_id: str
    principal_alias: str
    quota_scope_alias: str
    pool_id: str
    pool_alias: str
    pool_ids: tuple[str, ...]


class CredentialLifecycleError(RuntimeError):
    """A lifecycle mutation failed without exposing secret or custody details."""


class CredentialLifecycleConflict(CredentialLifecycleError):
    """The requested mutation lost a durable compare-and-set race."""


class CredentialLifecycleFailure(CredentialLifecycleError):
    """The mutation could not be completed safely."""


def _json(value: Mapping[str, object] | None = None) -> str:
    return json.dumps(value or {}, sort_keys=True, separators=(",", ":"))


def _reason_fingerprint(reason: str, *, domain: bytes) -> str:
    digest = hashlib.sha256()
    digest.update(domain)
    digest.update(b"\x00")
    digest.update(reason.encode("utf-8"))
    return digest.hexdigest()


def _new_custody_intent_alias() -> str:
    return f"pending-{secrets.token_hex(24)}"


def _contains_active_secret(value: object, secret: bytearray) -> bool:
    if not secret:
        return False
    if isinstance(value, str):
        encoded = bytearray(value.encode("utf-8", "surrogatepass"))
        try:
            return encoded.find(secret) >= 0
        finally:
            encoded[:] = b"\x00" * len(encoded)
    if value is None:
        encoded = bytearray(b"null")
        try:
            return encoded.find(secret) >= 0
        finally:
            encoded[:] = b"\x00" * len(encoded)
    if isinstance(value, (bool, int, float)):
        encoded = bytearray(json.dumps(value, separators=(",", ":")).encode("ascii"))
        try:
            return encoded.find(secret) >= 0
        finally:
            encoded[:] = b"\x00" * len(encoded)
    if isinstance(value, Mapping):
        return any(
            _contains_active_secret(key, secret) or _contains_active_secret(item, secret)
            for key, item in value.items()
        )
    if isinstance(value, (list, tuple)):
        return any(_contains_active_secret(item, secret) for item in value)
    return False


def _serialized_credential_metadata(metadata: CredentialMetadata) -> str:
    return json.dumps(asdict(metadata), sort_keys=True, separators=(",", ":"))


def _metadata(raw: object) -> dict[str, object]:
    if not isinstance(raw, str):
        return {}
    try:
        decoded = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    return dict(decoded) if isinstance(decoded, dict) else {}


def _required_integer(value: object, *, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise CredentialLifecycleFailure(f"credential {field} is invalid")
    return value


def _optional_integer(value: object, *, field: str) -> int | None:
    if value is None:
        return None
    return _required_integer(value, field=field)


def _remaining_concurrency(value: object) -> Literal[0, 1]:
    if isinstance(value, bool) or not isinstance(value, int):
        raise CredentialLifecycleFailure("emergency concurrency is invalid")
    if value == 0:
        return 0
    if value == 1:
        return 1
    raise CredentialLifecycleFailure("emergency concurrency is invalid")


class SqliteCredentialLifecycleService:
    """Coordinate short SQLite transactions with recoverable KeyStore changes."""

    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        persistent_key_store: KeyStore,
        emergency_manager: EmergencyUnlockManager | None = None,
        now_ms: Callable[[], int] = SYSTEM_UTC_CLOCK.now_ms,
        credential_id_factory: Callable[[], str] = lambda: str(CredentialId.new()),
        event_id_factory: Callable[[], str] = lambda: str(EventId.new()),
    ) -> None:
        self.connection = connection
        self._key_store = persistent_key_store
        self._emergency = emergency_manager
        self._now_ms = now_ms
        self._credential_id_factory = credential_id_factory
        self._event_id_factory = event_id_factory

    @staticmethod
    def _wipe(secret: bytearray) -> None:
        secret[:] = b"\x00" * len(secret)

    @staticmethod
    def _validate_secret(secret: bytearray) -> None:
        if not is_admissible_firecrawl_secret(secret, maximum_bytes=_MAXIMUM_SECRET_BYTES):
            raise CredentialLifecycleFailure(
                "credential secret is outside the accepted provider namespace"
            )

    def _route(
        self,
        *,
        principal_id: str,
        quota_scope_id: str,
        pool_id: str,
    ) -> _CredentialRoute:
        row = self.connection.execute(
            """
            SELECT p.service_id, p.alias AS principal_alias,
                   q.alias AS quota_scope_alias, pl.alias AS pool_alias
              FROM principals AS p
              JOIN quota_scopes AS q
                ON q.principal_id = p.principal_id
               AND q.quota_scope_id = ?
              JOIN pool_members AS pm
                ON pm.quota_scope_id = q.quota_scope_id
               AND pm.pool_id = ?
               AND pm.enabled = 1
              JOIN pools AS pl
                ON pl.pool_id = pm.pool_id
               AND pl.service_id = p.service_id
             WHERE p.principal_id = ? AND p.enabled = 1
               AND q.state NOT IN ('DISABLED', 'QUARANTINED')
               AND pl.state IN ('ACTIVE', 'ENABLED')
            """,
            (quota_scope_id, pool_id, principal_id),
        ).fetchone()
        if row is None or str(row["service_id"]) != "firecrawl":
            raise CredentialLifecycleFailure("credential routing metadata is unavailable")
        pools = tuple(
            str(item[0])
            for item in self.connection.execute(
                """
                SELECT pm.pool_id
                  FROM pool_members AS pm
                  JOIN pools AS p ON p.pool_id = pm.pool_id
                 WHERE pm.quota_scope_id = ? AND pm.enabled = 1
                   AND p.service_id = ? AND p.state IN ('ACTIVE', 'ENABLED')
                 ORDER BY pm.pool_id
                """,
                (quota_scope_id, str(row["service_id"])),
            )
        )
        return _CredentialRoute(
            service_id=str(row["service_id"]),
            principal_alias=str(row["principal_alias"]),
            quota_scope_alias=str(row["quota_scope_alias"]),
            pool_id=pool_id,
            pool_alias=str(row["pool_alias"]),
            pool_ids=pools,
        )

    def _credential_route_metadata(
        self,
        *,
        principal_id: str,
        quota_scope_id: str,
    ) -> _CredentialRoute:
        rows = self.connection.execute(
            """
            SELECT p.service_id, p.alias AS principal_alias,
                   q.alias AS quota_scope_alias, pm.pool_id,
                   pl.alias AS pool_alias
              FROM principals AS p
              JOIN quota_scopes AS q
                ON q.principal_id = p.principal_id
               AND q.quota_scope_id = ?
              JOIN pool_members AS pm
                ON pm.quota_scope_id = q.quota_scope_id
              JOIN pools AS pl
                ON pl.pool_id = pm.pool_id
               AND pl.service_id = p.service_id
             WHERE p.principal_id = ?
             ORDER BY pm.pool_id
            """,
            (quota_scope_id, principal_id),
        ).fetchall()
        if not rows or str(rows[0]["service_id"]) != "firecrawl":
            raise CredentialLifecycleFailure("credential routing metadata is unavailable")
        primary = rows[0]
        return _CredentialRoute(
            service_id=str(primary["service_id"]),
            principal_alias=str(primary["principal_alias"]),
            quota_scope_alias=str(primary["quota_scope_alias"]),
            pool_id=str(primary["pool_id"]),
            pool_alias=str(primary["pool_alias"]),
            pool_ids=tuple(str(row["pool_id"]) for row in rows),
        )

    def _mutation(self, mutation_id: str, operation: str) -> sqlite3.Row | None:
        raw_row: object = self.connection.execute(
            "SELECT * FROM credential_mutations WHERE mutation_id = ?",
            (mutation_id,),
        ).fetchone()
        if raw_row is not None and not isinstance(raw_row, sqlite3.Row):
            raise TypeError("credential lifecycle requires sqlite3.Row results")
        row = raw_row
        if row is not None and str(row["operation"]) != operation:
            raise CredentialLifecycleConflict("mutation identifier is already bound")
        return row

    @staticmethod
    def _require_mutation_binding(
        row: sqlite3.Row | None,
        *,
        credential_id: str | None,
        metadata: Mapping[str, object],
    ) -> None:
        if row is None:
            return
        if credential_id is not None and row["credential_id"] != credential_id:
            raise CredentialLifecycleConflict("mutation identifier is already bound")
        stored = _metadata(row["metadata_json"])
        if any(key not in stored or stored[key] != value for key, value in metadata.items()):
            raise CredentialLifecycleConflict("mutation identifier is already bound")

    @staticmethod
    def _completed(
        row: sqlite3.Row | None,
        *,
        active_secret: bytearray | None = None,
    ) -> CredentialMutationResult | None:
        if row is None or str(row["state"]) != "COMMITTED":
            return None
        raw_result = str(row["result_json"])
        if active_secret is not None and _contains_active_secret(raw_result, active_secret):
            raise CredentialLifecycleFailure("credential result overlaps secret material")
        result: CredentialMutationResult | None = None
        try:
            result = CredentialMutationResult.model_validate_json(raw_result)
        except (TypeError, ValueError):
            pass
        if result is None:
            raise CredentialLifecycleFailure("credential mutation result is invalid")
        if active_secret is not None and _contains_active_secret(
            result.model_dump_json(exclude_none=False),
            active_secret,
        ):
            raise CredentialLifecycleFailure("credential result overlaps secret material")
        return result

    def _prepare(
        self,
        *,
        mutation_id: str,
        operation: str,
        credential_id: str | None,
        replacement_credential_id: str | None,
        actor_id: str,
        metadata: Mapping[str, object],
        active_secret: bytearray | None = None,
    ) -> None:
        now = self._now_ms()
        metadata_json = _json(metadata)
        if active_secret is not None and _contains_active_secret(
            (
                mutation_id,
                operation,
                credential_id,
                replacement_credential_id,
                "PREPARED",
                actor_id,
                now,
                metadata_json,
                "{}",
            ),
            active_secret,
        ):
            raise CredentialLifecycleFailure("credential metadata overlaps secret material")
        with transaction(self.connection, "IMMEDIATE"):
            existing = self._mutation(mutation_id, operation)
            if existing is not None and str(existing["state"]) not in {
                "ROLLED_BACK",
                "FAILED",
            }:
                raise CredentialLifecycleConflict("credential mutation is already active")
            if existing is None:
                self.connection.execute(
                    """
                    INSERT INTO credential_mutations(
                        mutation_id, operation, credential_id, replacement_credential_id,
                        state, actor_id, created_at_ms, updated_at_ms, metadata_json
                    ) VALUES (?, ?, ?, ?, 'PREPARED', ?, ?, ?, ?)
                    """,
                    (
                        mutation_id,
                        operation,
                        credential_id,
                        replacement_credential_id,
                        actor_id,
                        now,
                        now,
                        metadata_json,
                    ),
                )
            else:
                self.connection.execute(
                    """
                    UPDATE credential_mutations
                       SET credential_id = ?, replacement_credential_id = ?,
                           state = 'PREPARED', actor_id = ?, updated_at_ms = ?,
                           completed_at_ms = NULL, metadata_json = ?, result_json = '{}'
                     WHERE mutation_id = ? AND state IN ('ROLLED_BACK', 'FAILED')
                    """,
                    (
                        credential_id,
                        replacement_credential_id,
                        actor_id,
                        now,
                        metadata_json,
                        mutation_id,
                    ),
                )

    def _mark_rolled_back(
        self,
        mutation_id: str,
        *,
        active_secret: bytearray | None = None,
    ) -> None:
        now = self._now_ms()
        if active_secret is not None and _contains_active_secret(
            ("ROLLED_BACK", now, mutation_id),
            active_secret,
        ):
            return
        with suppress(sqlite3.Error):
            with transaction(self.connection, "IMMEDIATE"):
                self.connection.execute(
                    """
                    UPDATE credential_mutations
                       SET state = 'ROLLED_BACK', updated_at_ms = ?, completed_at_ms = ?
                     WHERE mutation_id = ? AND state != 'COMMITTED'
                    """,
                    (now, now, mutation_id),
                )

    def _mark_cleanup_required(
        self,
        mutation_id: str,
        *,
        active_secret: bytearray | None = None,
    ) -> None:
        now = self._now_ms()
        if active_secret is not None and _contains_active_secret(
            ("CLEANUP_REQUIRED", now, mutation_id),
            active_secret,
        ):
            return
        with suppress(sqlite3.Error):
            with transaction(self.connection, "IMMEDIATE"):
                self.connection.execute(
                    """
                    UPDATE credential_mutations
                       SET state = 'CLEANUP_REQUIRED', updated_at_ms = ?
                     WHERE mutation_id = ? AND state != 'COMMITTED'
                    """,
                    (now, mutation_id),
                )

    def _advance_mutation_phase(
        self,
        mutation_id: str,
        operation: str,
        *,
        expected_state: str,
        next_state: str,
        active_secret: bytearray | None = None,
    ) -> None:
        with transaction(self.connection, "IMMEDIATE"):
            row = self.connection.execute(
                """
                SELECT metadata_json FROM credential_mutations
                 WHERE mutation_id = ? AND operation = ? AND state = ?
                """,
                (mutation_id, operation, expected_state),
            ).fetchone()
            if row is None:
                raise CredentialLifecycleConflict("credential mutation lost its custody fence")
            metadata = _metadata(row["metadata_json"])
            metadata["custody_created"] = True
            now = self._now_ms()
            metadata_json = _json(metadata)
            if active_secret is not None and _contains_active_secret(
                (
                    mutation_id,
                    operation,
                    expected_state,
                    next_state,
                    now,
                    metadata_json,
                ),
                active_secret,
            ):
                raise CredentialLifecycleFailure("credential metadata overlaps secret material")
            updated = self.connection.execute(
                """
                UPDATE credential_mutations
                   SET state = ?, updated_at_ms = ?, metadata_json = ?
                 WHERE mutation_id = ? AND operation = ? AND state = ?
                """,
                (
                    next_state,
                    now,
                    metadata_json,
                    mutation_id,
                    operation,
                    expected_state,
                ),
            )
            if updated.rowcount != 1:
                raise CredentialLifecycleConflict("credential mutation lost its custody fence")

    async def _remove_new_custody(self, credential_id: str, *, complete: bool) -> bool:
        try:
            if complete:
                await self._key_store.delete(credential_id)
            else:
                await self._key_store.discard_partial(credential_id)
            return True
        except CredentialNotFoundError:
            try:
                await self._key_store.discard_partial(credential_id)
            except Exception:
                return False
            return True
        except Exception:
            if not complete:
                return False
            try:
                return await self._key_store.discard_partial(credential_id)
            except Exception:
                return False

    async def _matches_custody_intent(
        self,
        credential_id: str,
        journal: Mapping[str, object],
    ) -> bool:
        intent_alias = journal.get("custody_intent_alias")
        if not isinstance(intent_alias, str) or not intent_alias.startswith("pending-"):
            return False
        try:
            item = {
                metadata.credential_id: metadata
                for metadata in await self._key_store.list_metadata()
            }.get(credential_id)
        except Exception:
            return False
        if item is None:
            return False
        return (
            item.alias == intent_alias
            and item.principal_id == journal.get("custody_principal_id")
            and item.quota_scope_id == journal.get("custody_quota_scope_id")
            and item.state == journal.get("custody_state")
            and item.generation == journal.get("custody_generation")
            and item.expires_at_ms == journal.get("custody_expires_at_ms")
        )

    async def _discard_staged_custody(
        self,
        credential_id: str,
        journal: Mapping[str, object],
    ) -> bool:
        intent_alias = journal.get("custody_intent_alias")
        if not isinstance(intent_alias, str) or not intent_alias.startswith("pending-"):
            return False
        try:
            return await self._key_store.discard_staged(
                credential_id,
                staged_alias=intent_alias,
            )
        except Exception:
            return False

    def _result(
        self,
        *,
        mutation_id: str,
        credential_id: str,
        alias: str,
        action: _CredentialAction,
        state: str,
        generation: int,
        principal_id: str,
        quota_scope_id: str,
        route: _CredentialRoute,
        expires_at_ms: int | None,
        audit_event_id: str,
        acted_at_ms: int,
    ) -> CredentialMutationResult:
        return CredentialMutationResult(
            mutation_id=mutation_id,
            credential_id=credential_id,
            alias=alias,
            action=action,
            state=state,
            generation=generation,
            principal_id=principal_id,
            principal_alias=route.principal_alias,
            quota_scope_id=quota_scope_id,
            quota_scope_alias=route.quota_scope_alias,
            pool_id=route.pool_id,
            pool_alias=route.pool_alias,
            expires_at_ms=expires_at_ms,
            audit_event_id=audit_event_id,
            acted_at_ms=acted_at_ms,
        )

    def _commit_mutation(
        self,
        *,
        mutation_id: str,
        operation: str,
        result: CredentialMutationResult,
        actor_id: str,
        payload: Mapping[str, object],
        expected_state: str = "PREPARED",
        active_secret: bytearray | None = None,
    ) -> None:
        now = result.acted_at_ms
        payload_json = _json({**payload, "actor_id": actor_id, "mutation_id": mutation_id})
        result_json = result.model_dump_json(exclude_none=False)
        if active_secret is not None and _contains_active_secret(
            (
                result.audit_event_id,
                now,
                operation,
                "INFO",
                "firecrawl",
                1,
                payload_json,
                "COMMITTED",
                result_json,
                mutation_id,
                expected_state,
            ),
            active_secret,
        ):
            raise CredentialLifecycleFailure("credential metadata overlaps secret material")
        self.connection.execute(
            """
            INSERT INTO audit_events(
                event_id, occurred_at_ms, event_type, severity,
                service_id, operation, preserve, payload_json
            ) VALUES (?, ?, ?, 'INFO', 'firecrawl', ?, 1, ?)
            """,
            (
                result.audit_event_id,
                now,
                operation,
                operation,
                payload_json,
            ),
        )
        updated = self.connection.execute(
            """
            UPDATE credential_mutations
               SET state = 'COMMITTED', updated_at_ms = ?, completed_at_ms = ?,
                   result_json = ?
             WHERE mutation_id = ? AND operation = ? AND state = ?
            """,
            (
                now,
                now,
                result_json,
                mutation_id,
                operation,
                expected_state,
            ),
        )
        if updated.rowcount != 1:
            raise CredentialLifecycleConflict("credential mutation lost its durable fence")

    @staticmethod
    def _backend(reference: str) -> str:
        if reference.startswith("dpapi-current-user://"):
            return "dpapi-current-user"
        if reference.startswith("memory://"):
            return "memory-test"
        raise CredentialLifecycleFailure("credential custody reference is unsupported")

    async def provision_credential(
        self,
        request: CredentialProvisionRequest,
        secret: bytearray,
        actor_id: str,
    ) -> CredentialMutationResult:
        try:
            operation = "credential.provisioned"
            binding = {
                "alias": request.alias,
                "exclusive_usage": request.exclusive_usage,
                "expires_at_ms": request.expires_at_ms,
                "pool_id": request.pool_id,
                "principal_id": request.principal_id,
                "quota_scope_id": request.quota_scope_id,
            }
            self._validate_secret(secret)
            if _contains_active_secret(
                (
                    _PERSISTED_SECRET_BOUNDARY_LITERALS,
                    binding,
                    request.mutation_id,
                    actor_id,
                ),
                secret,
            ):
                raise CredentialLifecycleFailure("credential metadata overlaps secret material")
            existing = self._mutation(request.mutation_id, operation)
            self._require_mutation_binding(
                existing,
                credential_id=None,
                metadata=binding,
            )
            completed = self._completed(existing, active_secret=secret)
            if completed is not None:
                return completed
            now = self._now_ms()
            if request.expires_at_ms is not None and request.expires_at_ms <= now:
                raise CredentialLifecycleFailure("credential expiry must be in the future")
            route = self._route(
                principal_id=request.principal_id,
                quota_scope_id=request.quota_scope_id,
                pool_id=request.pool_id,
            )
            duplicate = self.connection.execute(
                "SELECT 1 FROM credentials WHERE principal_id = ? AND alias = ?",
                (request.principal_id, request.alias),
            ).fetchone()
            if duplicate is not None:
                raise CredentialLifecycleConflict("credential alias is already in use")
            credential_id = self._credential_id_factory()
            custody_intent_alias = _new_custody_intent_alias()
            audit_id = self._event_id_factory()
            if _contains_active_secret(
                (
                    credential_id,
                    custody_intent_alias,
                    audit_id,
                    route.principal_alias,
                    route.quota_scope_alias,
                    route.pool_id,
                    route.pool_alias,
                    route.pool_ids,
                    now,
                    1,
                ),
                secret,
            ):
                raise CredentialLifecycleFailure("credential metadata overlaps secret material")
            self._prepare(
                mutation_id=request.mutation_id,
                operation=operation,
                credential_id=credential_id,
                replacement_credential_id=None,
                actor_id=actor_id,
                metadata={
                    **binding,
                    "custody_expires_at_ms": request.expires_at_ms,
                    "custody_generation": 1,
                    "custody_intent_alias": custody_intent_alias,
                    "custody_principal_id": request.principal_id,
                    "custody_quota_scope_id": request.quota_scope_id,
                    "custody_state": "HEALTHY",
                },
                active_secret=secret,
            )
            metadata = CredentialMetadata(
                credential_id=credential_id,
                principal_id=request.principal_id,
                quota_scope_id=request.quota_scope_id,
                alias=custody_intent_alias,
                state="HEALTHY",
                generation=1,
                expires_at_ms=request.expires_at_ms,
            )
            reference = ""
            custody_collision = False
            custody_failed = False
            try:
                reference = await self._key_store.put(metadata, cast(bytes, secret))
            except CredentialAlreadyExistsError:
                custody_collision = True
            except Exception:
                custody_failed = True
            if custody_collision:
                self._mark_cleanup_required(request.mutation_id, active_secret=secret)
                raise CredentialLifecycleConflict("credential custody identifier is already in use")
            if custody_failed:
                self._mark_cleanup_required(request.mutation_id, active_secret=secret)
                raise CredentialLifecycleFailure("credential custody could not be committed")
            if _contains_active_secret(reference, secret):
                if await self._remove_new_custody(credential_id, complete=True):
                    self._mark_rolled_back(request.mutation_id, active_secret=secret)
                else:
                    self._mark_cleanup_required(request.mutation_id, active_secret=secret)
                raise CredentialLifecycleFailure("credential custody metadata is invalid")
            try:
                self._advance_mutation_phase(
                    request.mutation_id,
                    operation,
                    expected_state="PREPARED",
                    next_state="CUSTODY_CREATED",
                    active_secret=secret,
                )
            except Exception:
                if await self._remove_new_custody(credential_id, complete=True):
                    self._mark_rolled_back(request.mutation_id, active_secret=secret)
                else:
                    self._mark_cleanup_required(request.mutation_id, active_secret=secret)
                raise
            custody_metadata_failed = False
            committed_metadata = CredentialMetadata(
                credential_id=credential_id,
                principal_id=request.principal_id,
                quota_scope_id=request.quota_scope_id,
                alias=request.alias,
                state="HEALTHY",
                generation=1,
                secret_reference=reference,
                expires_at_ms=request.expires_at_ms,
            )
            if _contains_active_secret(_serialized_credential_metadata(committed_metadata), secret):
                if await self._remove_new_custody(credential_id, complete=True):
                    self._mark_rolled_back(request.mutation_id, active_secret=secret)
                else:
                    self._mark_cleanup_required(request.mutation_id, active_secret=secret)
                raise CredentialLifecycleFailure("credential custody metadata is invalid")
            try:
                await self._key_store.update_metadata(
                    committed_metadata,
                    expected_generation=1,
                )
            except Exception:
                custody_metadata_failed = True
            if custody_metadata_failed:
                if await self._remove_new_custody(credential_id, complete=True):
                    self._mark_rolled_back(request.mutation_id, active_secret=secret)
                else:
                    self._mark_cleanup_required(request.mutation_id, active_secret=secret)
                raise CredentialLifecycleFailure("credential custody metadata could not be staged")

            result = self._result(
                mutation_id=request.mutation_id,
                credential_id=credential_id,
                alias=request.alias,
                action="provision",
                state="HEALTHY",
                generation=1,
                principal_id=request.principal_id,
                quota_scope_id=request.quota_scope_id,
                route=route,
                expires_at_ms=request.expires_at_ms,
                audit_event_id=audit_id,
                acted_at_ms=now,
            )
            try:
                backend = self._backend(reference)
                credential_metadata_json = _json({"logical_alias": request.alias})
                if _contains_active_secret(
                    (
                        credential_id,
                        request.principal_id,
                        request.quota_scope_id,
                        request.alias,
                        backend,
                        reference,
                        "HEALTHY",
                        1,
                        int(request.exclusive_usage),
                        request.expires_at_ms,
                        now,
                        credential_metadata_json,
                    ),
                    secret,
                ):
                    raise CredentialLifecycleFailure("credential metadata overlaps secret material")
                with transaction(self.connection, "IMMEDIATE"):
                    self._route(
                        principal_id=request.principal_id,
                        quota_scope_id=request.quota_scope_id,
                        pool_id=request.pool_id,
                    )
                    self.connection.execute(
                        """
                        INSERT INTO credentials(
                            credential_id, principal_id, quota_scope_id, alias,
                            secret_backend, secret_reference, state, generation,
                            exclusive_usage, expires_at_ms, created_at_ms, metadata_json
                        ) VALUES (?, ?, ?, ?, ?, ?, 'HEALTHY', 1, ?, ?, ?, ?)
                        """,
                        (
                            credential_id,
                            request.principal_id,
                            request.quota_scope_id,
                            request.alias,
                            backend,
                            reference,
                            int(request.exclusive_usage),
                            request.expires_at_ms,
                            now,
                            credential_metadata_json,
                        ),
                    )
                    self._commit_mutation(
                        mutation_id=request.mutation_id,
                        operation=operation,
                        result=result,
                        actor_id=actor_id,
                        payload={
                            "credential_id": credential_id,
                            "generation": 1,
                            "principal_id": request.principal_id,
                            "quota_scope_id": request.quota_scope_id,
                            "pool_ids": list(route.pool_ids),
                            "state": "HEALTHY",
                        },
                        expected_state="CUSTODY_CREATED",
                        active_secret=secret,
                    )
            except CredentialLifecycleConflict:
                if await self._remove_new_custody(credential_id, complete=True):
                    self._mark_rolled_back(request.mutation_id, active_secret=secret)
                else:
                    self._mark_cleanup_required(request.mutation_id, active_secret=secret)
                raise
            except Exception as error:
                if await self._remove_new_custody(credential_id, complete=True):
                    self._mark_rolled_back(request.mutation_id, active_secret=secret)
                else:
                    self._mark_cleanup_required(request.mutation_id, active_secret=secret)
                if isinstance(error, sqlite3.IntegrityError):
                    raise CredentialLifecycleConflict(
                        "credential metadata conflicts with an existing route"
                    ) from error
                raise CredentialLifecycleFailure(
                    "credential metadata could not be committed"
                ) from error
            return result
        finally:
            self._wipe(secret)

    def _active_lease(self, credential_id: str) -> bool:
        return (
            self.connection.execute(
                """
                SELECT 1 FROM leases
                 WHERE lease_type = 'provider-credential'
                   AND (
                       lease_key = ?
                       OR json_extract(metadata_json, '$.credential_id') = ?
                   )
                   AND state = 'ACTIVE' AND expires_at_ms > ? LIMIT 1
                """,
                (credential_id, credential_id, self._now_ms()),
            ).fetchone()
            is not None
        )

    @staticmethod
    def _rotated_alias(alias: str, generation: int, credential_id: str) -> str:
        suffix = f"~g{generation}~{credential_id[-8:]}"
        return alias[: max(1, 160 - len(suffix))] + suffix

    async def rotate_credential(
        self,
        credential_id: str,
        request: CredentialRotationRequest,
        secret: bytearray,
        actor_id: str,
    ) -> CredentialMutationResult:
        operation = "credential.rotated"
        try:
            binding = {
                "old_credential_id": credential_id,
                "requested_expires_at_ms": request.expires_at_ms,
            }
            self._validate_secret(secret)
            if _contains_active_secret(
                (
                    _PERSISTED_SECRET_BOUNDARY_LITERALS,
                    binding,
                    request.mutation_id,
                    actor_id,
                ),
                secret,
            ):
                raise CredentialLifecycleFailure("credential metadata overlaps secret material")
            existing = self._mutation(request.mutation_id, operation)
            self._require_mutation_binding(
                existing,
                credential_id=credential_id,
                metadata=binding,
            )
            completed = self._completed(existing, active_secret=secret)
            if completed is not None:
                return completed
            old = self.connection.execute(
                "SELECT * FROM credentials WHERE credential_id = ?",
                (credential_id,),
            ).fetchone()
            if old is None:
                raise CredentialLifecycleFailure("credential does not exist")
            if str(old["state"]) != "HEALTHY" or self._active_lease(credential_id):
                raise CredentialLifecycleConflict("credential is not ready for rotation")
            generation = int(old["generation"])
            now = self._now_ms()
            expires_at_ms = (
                int(old["expires_at_ms"])
                if request.expires_at_ms is None and old["expires_at_ms"] is not None
                else request.expires_at_ms
            )
            if expires_at_ms is not None and expires_at_ms <= now:
                raise CredentialLifecycleFailure("credential expiry must be in the future")
            replacement_id = self._credential_id_factory()
            logical_alias = str(_metadata(old["metadata_json"]).get("logical_alias", old["alias"]))
            old_internal_alias = self._rotated_alias(logical_alias, generation, credential_id)
            custody_intent_alias = _new_custody_intent_alias()
            audit_id = self._event_id_factory()
            if _contains_active_secret(
                (
                    replacement_id,
                    logical_alias,
                    old_internal_alias,
                    custody_intent_alias,
                    audit_id,
                    str(old["alias"]),
                    str(old["principal_id"]),
                    str(old["quota_scope_id"]),
                    str(old["secret_reference"]),
                    generation,
                    generation + 1,
                    now,
                    expires_at_ms,
                    bool(old["exclusive_usage"]),
                ),
                secret,
            ):
                raise CredentialLifecycleFailure("credential metadata overlaps secret material")
            self._prepare(
                mutation_id=request.mutation_id,
                operation=operation,
                credential_id=credential_id,
                replacement_credential_id=replacement_id,
                actor_id=actor_id,
                metadata={
                    **binding,
                    "replacement_credential_id": replacement_id,
                    "old_alias": str(old["alias"]),
                    "old_generation": generation,
                    "old_state": str(old["state"]),
                    "custody_expires_at_ms": expires_at_ms,
                    "custody_generation": generation + 1,
                    "custody_intent_alias": custody_intent_alias,
                    "custody_principal_id": str(old["principal_id"]),
                    "custody_quota_scope_id": str(old["quota_scope_id"]),
                    "custody_state": "HEALTHY",
                },
                active_secret=secret,
            )
            replacement_metadata = CredentialMetadata(
                credential_id=replacement_id,
                principal_id=str(old["principal_id"]),
                quota_scope_id=str(old["quota_scope_id"]),
                alias=custody_intent_alias,
                state="HEALTHY",
                generation=generation + 1,
                expires_at_ms=expires_at_ms,
            )
            reference = ""
            custody_collision = False
            custody_failed = False
            try:
                reference = await self._key_store.put(replacement_metadata, cast(bytes, secret))
            except CredentialAlreadyExistsError:
                custody_collision = True
            except Exception:
                custody_failed = True
            if custody_collision:
                self._mark_cleanup_required(request.mutation_id, active_secret=secret)
                raise CredentialLifecycleConflict(
                    "replacement custody identifier is already in use"
                )
            if custody_failed:
                self._mark_cleanup_required(request.mutation_id, active_secret=secret)
                raise CredentialLifecycleFailure("credential rotation custody failed")
            if _contains_active_secret(reference, secret):
                if await self._remove_new_custody(replacement_id, complete=True):
                    self._mark_rolled_back(request.mutation_id, active_secret=secret)
                else:
                    self._mark_cleanup_required(request.mutation_id, active_secret=secret)
                raise CredentialLifecycleFailure("credential custody metadata is invalid")
            try:
                self._advance_mutation_phase(
                    request.mutation_id,
                    operation,
                    expected_state="PREPARED",
                    next_state="CUSTODY_CREATED",
                    active_secret=secret,
                )
            except Exception:
                if await self._remove_new_custody(replacement_id, complete=True):
                    self._mark_rolled_back(request.mutation_id, active_secret=secret)
                else:
                    self._mark_cleanup_required(request.mutation_id, active_secret=secret)
                raise
            custody_metadata_failed = False
            replacement_metadata = CredentialMetadata(
                credential_id=replacement_id,
                principal_id=str(old["principal_id"]),
                quota_scope_id=str(old["quota_scope_id"]),
                alias=logical_alias,
                state="HEALTHY",
                generation=generation + 1,
                secret_reference=reference,
                expires_at_ms=expires_at_ms,
            )
            if _contains_active_secret(
                _serialized_credential_metadata(replacement_metadata),
                secret,
            ):
                if await self._remove_new_custody(replacement_id, complete=True):
                    self._mark_rolled_back(request.mutation_id, active_secret=secret)
                else:
                    self._mark_cleanup_required(request.mutation_id, active_secret=secret)
                raise CredentialLifecycleFailure("credential custody metadata is invalid")
            try:
                await self._key_store.update_metadata(
                    replacement_metadata,
                    expected_generation=generation + 1,
                )
            except Exception:
                custody_metadata_failed = True
            if custody_metadata_failed:
                if await self._remove_new_custody(replacement_id, complete=True):
                    self._mark_rolled_back(request.mutation_id, active_secret=secret)
                else:
                    self._mark_cleanup_required(request.mutation_id, active_secret=secret)
                raise CredentialLifecycleFailure("credential rotation metadata could not be staged")

            route: _CredentialRoute
            locked_old: sqlite3.Row
            old_json: dict[str, object]
            try:
                with transaction(self.connection, "IMMEDIATE"):
                    locked = self.connection.execute(
                        "SELECT * FROM credentials WHERE credential_id = ?",
                        (credential_id,),
                    ).fetchone()
                    if (
                        locked is None
                        or str(locked["state"]) != "HEALTHY"
                        or int(locked["generation"]) != generation
                        or str(locked["alias"]) != str(old["alias"])
                    ):
                        raise CredentialLifecycleConflict(
                            "credential rotation lost its state fence"
                        )
                    if self._active_lease(credential_id):
                        raise CredentialLifecycleConflict("credential is not ready for rotation")
                    route = self._route(
                        principal_id=str(locked["principal_id"]),
                        quota_scope_id=str(locked["quota_scope_id"]),
                        pool_id=self._primary_pool(str(locked["quota_scope_id"])),
                    )
                    if _contains_active_secret(
                        (
                            route.principal_alias,
                            route.quota_scope_alias,
                            route.pool_id,
                            route.pool_alias,
                            route.pool_ids,
                        ),
                        secret,
                    ):
                        raise CredentialLifecycleFailure(
                            "credential metadata overlaps secret material"
                        )
                    old_json = _metadata(locked["metadata_json"])
                    old_json.update(
                        {
                            "logical_alias": logical_alias,
                            "rotation_successor_id": replacement_id,
                            "last_local_action": "drain-for-rotation",
                            "last_action_at_ms": now,
                        }
                    )
                    old_metadata_json = _json(old_json)
                    if _contains_active_secret(
                        (
                            old_internal_alias,
                            "DRAINING",
                            old_metadata_json,
                            credential_id,
                            generation,
                            str(old["alias"]),
                            "DURABLE_DRAINED",
                            now,
                            request.mutation_id,
                            operation,
                            "CUSTODY_CREATED",
                        ),
                        secret,
                    ):
                        raise CredentialLifecycleFailure(
                            "credential metadata overlaps secret material"
                        )
                    updated = self.connection.execute(
                        """
                        UPDATE credentials
                           SET alias = ?, state = 'DRAINING', metadata_json = ?
                         WHERE credential_id = ? AND state = 'HEALTHY'
                           AND generation = ? AND alias = ?
                        """,
                        (
                            old_internal_alias,
                            old_metadata_json,
                            credential_id,
                            generation,
                            str(old["alias"]),
                        ),
                    )
                    if updated.rowcount != 1:
                        raise CredentialLifecycleConflict(
                            "credential rotation lost its state fence"
                        )
                    phase = self.connection.execute(
                        """
                        UPDATE credential_mutations
                           SET state = 'DURABLE_DRAINED', updated_at_ms = ?
                         WHERE mutation_id = ? AND operation = ?
                           AND state = 'CUSTODY_CREATED'
                        """,
                        (now, request.mutation_id, operation),
                    )
                    if phase.rowcount != 1:
                        raise CredentialLifecycleConflict(
                            "credential mutation lost its durable fence"
                        )
                    locked_old = locked
            except Exception as error:
                if await self._remove_new_custody(replacement_id, complete=True):
                    self._mark_rolled_back(request.mutation_id, active_secret=secret)
                else:
                    self._mark_cleanup_required(request.mutation_id, active_secret=secret)
                if isinstance(error, CredentialLifecycleConflict):
                    raise
                if isinstance(error, sqlite3.IntegrityError):
                    raise CredentialLifecycleConflict(
                        "credential rotation alias is unavailable"
                    ) from error
                raise CredentialLifecycleFailure(
                    "credential rotation could not acquire its durable fence"
                ) from error

            draining_metadata = CredentialMetadata(
                credential_id=credential_id,
                principal_id=str(locked_old["principal_id"]),
                quota_scope_id=str(locked_old["quota_scope_id"]),
                alias=old_internal_alias,
                state="DRAINING",
                generation=generation,
                secret_reference=str(locked_old["secret_reference"]),
                expires_at_ms=(
                    None
                    if locked_old["expires_at_ms"] is None
                    else int(locked_old["expires_at_ms"])
                ),
            )
            custody_failed = _contains_active_secret(
                _serialized_credential_metadata(draining_metadata),
                secret,
            )
            if not custody_failed:
                try:
                    await self._key_store.update_metadata(
                        draining_metadata,
                        expected_generation=generation,
                    )
                except Exception:
                    custody_failed = True
            if custody_failed:
                await self._rollback_rotation(
                    old,
                    replacement_id,
                    request.mutation_id,
                    audit_event_id=audit_id,
                    active_secret=secret,
                )
                raise CredentialLifecycleFailure("credential rotation custody failed")

            result = self._result(
                mutation_id=request.mutation_id,
                credential_id=replacement_id,
                alias=logical_alias,
                action="rotate",
                state="HEALTHY",
                generation=generation + 1,
                principal_id=str(old["principal_id"]),
                quota_scope_id=str(old["quota_scope_id"]),
                route=route,
                expires_at_ms=expires_at_ms,
                audit_event_id=audit_id,
                acted_at_ms=now,
            )
            try:
                backend = self._backend(reference)
                successor_metadata_json = _json(
                    {
                        "logical_alias": logical_alias,
                        "rotation_predecessor_id": credential_id,
                    }
                )
                if _contains_active_secret(
                    (
                        replacement_id,
                        str(old["principal_id"]),
                        str(old["quota_scope_id"]),
                        logical_alias,
                        backend,
                        reference,
                        "HEALTHY",
                        generation + 1,
                        int(old["exclusive_usage"]),
                        expires_at_ms,
                        now,
                        successor_metadata_json,
                    ),
                    secret,
                ):
                    raise CredentialLifecycleFailure("credential metadata overlaps secret material")
                with transaction(self.connection, "IMMEDIATE"):
                    owner = self.connection.execute(
                        """
                        SELECT 1 FROM credentials
                         WHERE credential_id = ? AND state = 'DRAINING'
                           AND generation = ?
                           AND json_extract(metadata_json, '$.rotation_successor_id') = ?
                        """,
                        (credential_id, generation, replacement_id),
                    ).fetchone()
                    if owner is None:
                        raise CredentialLifecycleConflict(
                            "credential rotation lost its durable ownership"
                        )
                    self.connection.execute(
                        """
                        INSERT INTO credentials(
                            credential_id, principal_id, quota_scope_id, alias,
                            secret_backend, secret_reference, state, generation,
                            exclusive_usage, expires_at_ms, created_at_ms, metadata_json
                        ) VALUES (?, ?, ?, ?, ?, ?, 'HEALTHY', ?, ?, ?, ?, ?)
                        """,
                        (
                            replacement_id,
                            str(old["principal_id"]),
                            str(old["quota_scope_id"]),
                            logical_alias,
                            backend,
                            reference,
                            generation + 1,
                            int(old["exclusive_usage"]),
                            expires_at_ms,
                            now,
                            successor_metadata_json,
                        ),
                    )
                    self._commit_mutation(
                        mutation_id=request.mutation_id,
                        operation=operation,
                        result=result,
                        actor_id=actor_id,
                        payload={
                            "credential_id": replacement_id,
                            "predecessor_id": credential_id,
                            "generation": generation + 1,
                            "principal_id": str(old["principal_id"]),
                            "quota_scope_id": str(old["quota_scope_id"]),
                            "pool_ids": list(route.pool_ids),
                            "state": "HEALTHY",
                        },
                        expected_state="DURABLE_DRAINED",
                        active_secret=secret,
                    )
            except CredentialLifecycleConflict:
                await self._rollback_rotation(
                    old,
                    replacement_id,
                    request.mutation_id,
                    audit_event_id=audit_id,
                    active_secret=secret,
                )
                raise
            except Exception as error:
                await self._rollback_rotation(
                    old,
                    replacement_id,
                    request.mutation_id,
                    audit_event_id=audit_id,
                    active_secret=secret,
                )
                if isinstance(error, sqlite3.IntegrityError):
                    raise CredentialLifecycleConflict(
                        "credential rotation lost its winner"
                    ) from error
                raise CredentialLifecycleFailure(
                    "credential rotation could not be committed"
                ) from error
            return result
        finally:
            self._wipe(secret)

    def _primary_pool(self, quota_scope_id: str) -> str:
        row = self.connection.execute(
            """
            SELECT pm.pool_id
              FROM pool_members AS pm JOIN pools AS p ON p.pool_id = pm.pool_id
             WHERE pm.quota_scope_id = ? AND pm.enabled = 1
               AND p.state IN ('ACTIVE', 'ENABLED')
             ORDER BY pm.pool_id LIMIT 1
            """,
            (quota_scope_id,),
        ).fetchone()
        if row is None:
            raise CredentialLifecycleFailure("credential has no active pool")
        return str(row[0])

    async def _restore_metadata(
        self,
        row: sqlite3.Row | Mapping[str, object],
        *,
        expected_generation: int | None = None,
        active_secret: bytearray | None = None,
    ) -> None:
        if expected_generation is None:
            stored = {
                item.credential_id: item for item in await self._key_store.list_metadata()
            }.get(str(row["credential_id"]))
            if stored is None:
                raise CredentialLifecycleFailure("credential custody metadata is unavailable")
            expected_generation = stored.generation
        restored = CredentialMetadata(
            credential_id=str(row["credential_id"]),
            principal_id=str(row["principal_id"]),
            quota_scope_id=str(row["quota_scope_id"]),
            alias=str(row["alias"]),
            state=str(row["state"]),
            generation=_required_integer(row["generation"], field="generation"),
            secret_reference=str(row["secret_reference"]),
            expires_at_ms=_optional_integer(row["expires_at_ms"], field="expiry"),
        )
        if active_secret is not None and _contains_active_secret(
            _serialized_credential_metadata(restored),
            active_secret,
        ):
            raise CredentialLifecycleFailure("credential custody metadata is invalid")
        await self._key_store.update_metadata(
            restored,
            expected_generation=expected_generation,
        )

    async def _rollback_rotation(
        self,
        old: sqlite3.Row | Mapping[str, object],
        replacement_id: str,
        mutation_id: str,
        *,
        audit_event_id: str | None = None,
        active_secret: bytearray | None = None,
    ) -> None:
        restored_custody = True
        try:
            await self._restore_metadata(
                old,
                expected_generation=_required_integer(old["generation"], field="generation"),
                active_secret=active_secret,
            )
        except Exception:
            restored_custody = False

        restored_durable = False
        if restored_custody:
            now = self._now_ms()
            try:
                with transaction(self.connection, "IMMEDIATE"):
                    current = self.connection.execute(
                        "SELECT * FROM credentials WHERE credential_id = ?",
                        (str(old["credential_id"]),),
                    ).fetchone()
                    if current is None:
                        raise CredentialLifecycleFailure(
                            "rotation predecessor metadata is unavailable"
                        )
                    current_json = _metadata(current["metadata_json"])
                    owns_drain = current_json.get(
                        "rotation_successor_id"
                    ) == replacement_id and str(current["state"]) in {"DRAINING", "UNKNOWN"}
                    already_restored = (
                        str(current["state"]) == str(old["state"])
                        and str(current["alias"]) == str(old["alias"])
                        and _required_integer(current["generation"], field="generation")
                        == _required_integer(old["generation"], field="generation")
                    )
                    if not owns_drain and not already_restored:
                        raise CredentialLifecycleConflict(
                            "rotation recovery lost durable ownership"
                        )
                    current_json.pop("rotation_successor_id", None)
                    current_json.update(
                        {
                            "last_action_at_ms": now,
                            "last_local_action": "rotation-rolled-back",
                        }
                    )
                    current_metadata_json = _json(current_json)
                    if active_secret is not None and _contains_active_secret(
                        (
                            str(old["alias"]),
                            str(old["state"]),
                            _required_integer(old["generation"], field="generation"),
                            current_metadata_json,
                            str(old["credential_id"]),
                            str(current["state"]),
                            _required_integer(current["generation"], field="generation"),
                        ),
                        active_secret,
                    ):
                        raise CredentialLifecycleFailure(
                            "credential metadata overlaps secret material"
                        )
                    updated = self.connection.execute(
                        """
                        UPDATE credentials
                           SET alias = ?, state = ?, generation = ?, metadata_json = ?
                         WHERE credential_id = ? AND state = ? AND generation = ?
                        """,
                        (
                            str(old["alias"]),
                            str(old["state"]),
                            _required_integer(old["generation"], field="generation"),
                            current_metadata_json,
                            str(old["credential_id"]),
                            str(current["state"]),
                            _required_integer(current["generation"], field="generation"),
                        ),
                    )
                    if updated.rowcount != 1:
                        raise CredentialLifecycleConflict(
                            "rotation recovery lost durable ownership"
                        )
                    restored_durable = True
            except Exception:
                restored_durable = False
        if not restored_durable:
            now = self._now_ms()
            with suppress(sqlite3.Error):
                with transaction(self.connection, "IMMEDIATE"):
                    current = self.connection.execute(
                        "SELECT state, generation, metadata_json FROM credentials "
                        "WHERE credential_id = ?",
                        (str(old["credential_id"]),),
                    ).fetchone()
                    if (
                        current is not None
                        and str(current["state"]) == "DRAINING"
                        and _metadata(current["metadata_json"]).get("rotation_successor_id")
                        == replacement_id
                    ):
                        next_generation = int(current["generation"]) + 1
                        updated = self.connection.execute(
                            """
                            UPDATE credentials
                               SET state = 'UNKNOWN', generation = ?
                             WHERE credential_id = ? AND state = 'DRAINING'
                               AND generation = ?
                            """,
                            (
                                next_generation,
                                str(old["credential_id"]),
                                int(current["generation"]),
                            ),
                        )
                        if updated.rowcount == 1:
                            self._insert_audit(
                                event_type="credential.rotation_recovery_failed",
                                credential_id=str(old["credential_id"]),
                                state="UNKNOWN",
                                generation=next_generation,
                                actor_id="system-recovery",
                                mutation_id=mutation_id,
                                now_ms=now,
                                event_id=audit_event_id,
                                active_secret=active_secret,
                            )

        cleaned = await self._remove_new_custody(replacement_id, complete=True)
        if restored_custody and restored_durable and cleaned:
            self._mark_rolled_back(mutation_id, active_secret=active_secret)
        else:
            self._mark_cleanup_required(mutation_id, active_secret=active_secret)

    def _insert_audit(
        self,
        *,
        event_type: str,
        credential_id: str,
        state: str,
        generation: int,
        actor_id: str,
        mutation_id: str,
        now_ms: int,
        event_id: str | None = None,
        active_secret: bytearray | None = None,
    ) -> str:
        resolved_event_id = self._event_id_factory() if event_id is None else event_id
        payload_json = _json(
            {
                "actor_id": actor_id,
                "credential_id": credential_id,
                "generation": generation,
                "mutation_id": mutation_id,
                "state": state,
            }
        )
        if active_secret is not None and _contains_active_secret(
            (
                resolved_event_id,
                now_ms,
                event_type,
                "INFO",
                "firecrawl",
                1,
                state,
                generation,
                payload_json,
            ),
            active_secret,
        ):
            raise CredentialLifecycleFailure("credential metadata overlaps secret material")
        self.connection.execute(
            """
            INSERT INTO audit_events(
                event_id, occurred_at_ms, event_type, severity,
                service_id, operation, preserve, payload_json
            ) VALUES (?, ?, ?, 'INFO', 'firecrawl', ?, 1, ?)
            """,
            (
                resolved_event_id,
                now_ms,
                event_type,
                event_type,
                payload_json,
            ),
        )
        return resolved_event_id

    def _nonterminal_job(self, credential_id: str) -> bool:
        placeholders = ",".join("?" for _ in _ACTIVE_JOB_STATES)
        return (
            self.connection.execute(
                f"SELECT 1 FROM jobs WHERE credential_id = ? AND state IN ({placeholders}) LIMIT 1",  # noqa: S608
                (credential_id, *_ACTIVE_JOB_STATES),
            ).fetchone()
            is not None
        )

    def _unresolved_external_resource(self, credential_id: str) -> bool:
        return (
            self.connection.execute(
                """
                SELECT 1 FROM external_resources
                 WHERE credential_id = ?
                   AND state NOT IN ('COMPLETED', 'FAILED', 'CANCELLED')
                 LIMIT 1
                """,
                (credential_id,),
            ).fetchone()
            is not None
        )

    def _unmaterialized_async_resource(self, credential_id: str) -> bool:
        return (
            self.connection.execute(
                """
                SELECT 1
                  FROM attempts AS a
                  JOIN invocations AS i ON i.request_id = a.request_id
                 JOIN sessions AS s ON s.session_id = i.session_id
                 WHERE a.credential_id = ?
                   AND a.state = 'SUCCEEDED'
                   AND i.state IN ('RUNNING', 'UNKNOWN')
                   AND a.resource_type IS NOT NULL
                   AND a.provider_resource_id IS NOT NULL
                   AND a.credential_generation IS NOT NULL
                   AND a.pool_id IS NOT NULL
                   AND NOT EXISTS (
                       SELECT 1
                         FROM external_resources AS er
                        WHERE er.service_id = i.service_id
                          AND er.resource_type = a.resource_type
                          AND er.provider_resource_id = a.provider_resource_id
                          AND er.principal_id = a.principal_id
                          AND er.quota_scope_id = a.quota_scope_id
                          AND er.credential_id = a.credential_id
                          AND er.credential_generation = a.credential_generation
                          AND er.pool_id = a.pool_id
                          AND er.creating_request_id = a.request_id
                          AND er.owner_session_id = i.session_id
                          AND er.owner_workspace_id = s.workspace_id
                          AND er.owner_root_run_id = i.root_run_id
                   )
                 LIMIT 1
                """,
                (credential_id,),
            ).fetchone()
            is not None
        )

    def _ambiguous_async_handoff(self, credential_id: str) -> bool:
        return (
            self.connection.execute(
                """
                SELECT 1
                  FROM attempts AS a
                  JOIN invocations AS i ON i.request_id = a.request_id
                 WHERE a.credential_id = ?
                   AND i.operation = ?
                   AND i.state IN ('RUNNING', 'UNKNOWN')
                   AND a.state IN ('RUNNING', 'UNKNOWN', 'SUCCEEDED')
                   AND a.resource_type IS NULL
                   AND a.provider_resource_id IS NULL
                   AND a.credential_generation IS NULL
                   AND a.pool_id IS NULL
                 LIMIT 1
                """,
                (credential_id, _ASYNC_CREATE_OPERATIONS[0]),
            ).fetchone()
            is not None
        )

    def _active_work(self, credential_id: str) -> bool:
        return any(
            (
                self._active_lease(credential_id),
                self._nonterminal_job(credential_id),
                self._unresolved_external_resource(credential_id),
                self._unmaterialized_async_resource(credential_id),
                self._ambiguous_async_handoff(credential_id),
            )
        )

    async def change_credential_state(
        self,
        credential_id: str,
        request: CredentialStateChangeRequest,
        actor_id: str,
    ) -> CredentialMutationResult:
        action = request.action
        target_by_action = {
            "disable": CredentialState.DISABLED,
            "quarantine": CredentialState.QUARANTINED,
            "retire": CredentialState.RETIRED,
        }
        target = target_by_action.get(action)
        if target is None:
            raise CredentialLifecycleFailure("credential action is unsupported")
        operation = {
            "disable": "credential.disabled",
            "quarantine": "credential.quarantined",
            "retire": "credential.retired",
        }[action]
        binding = {
            "action": action,
            "credential_id": credential_id,
            "reason_fingerprint": _reason_fingerprint(
                request.reason,
                domain=_STATE_REASON_DOMAIN,
            ),
        }
        existing = self._mutation(request.mutation_id, operation)
        self._require_mutation_binding(
            existing,
            credential_id=credential_id,
            metadata=binding,
        )
        completed = self._completed(existing)
        if completed is not None:
            return completed
        row = self.connection.execute(
            "SELECT * FROM credentials WHERE credential_id = ?", (credential_id,)
        ).fetchone()
        if row is None:
            raise CredentialLifecycleFailure("credential does not exist")
        current = CredentialState(str(row["state"]))
        if not CREDENTIAL_TRANSITIONS.can_transition(current, target):
            raise CredentialLifecycleConflict("credential state transition is unavailable")
        if action == "retire" and self._active_work(credential_id):
            raise CredentialLifecycleConflict("credential still owns active work")
        generation = int(row["generation"])
        next_generation = generation + 1
        now = self._now_ms()
        logical_alias = str(_metadata(row["metadata_json"]).get("logical_alias", row["alias"]))
        route = self._credential_route_metadata(
            principal_id=str(row["principal_id"]),
            quota_scope_id=str(row["quota_scope_id"]),
        )
        self._prepare(
            mutation_id=request.mutation_id,
            operation=operation,
            credential_id=credential_id,
            replacement_credential_id=None,
            actor_id=actor_id,
            metadata={
                **binding,
                "next_generation": next_generation,
                "old_generation": generation,
                "pool_ids": list(route.pool_ids),
                "target_state": target.value,
            },
        )
        audit_id = self._event_id_factory()
        result = self._result(
            mutation_id=request.mutation_id,
            credential_id=credential_id,
            alias=logical_alias,
            action=action,
            state=target.value,
            generation=next_generation,
            principal_id=str(row["principal_id"]),
            quota_scope_id=str(row["quota_scope_id"]),
            route=route,
            expires_at_ms=(None if row["expires_at_ms"] is None else int(row["expires_at_ms"])),
            audit_event_id=audit_id,
            acted_at_ms=now,
        )
        updated_metadata = CredentialMetadata(
            credential_id=credential_id,
            principal_id=str(row["principal_id"]),
            quota_scope_id=str(row["quota_scope_id"]),
            alias=str(row["alias"]),
            state=target.value,
            generation=next_generation,
            secret_reference=str(row["secret_reference"]),
            expires_at_ms=(None if row["expires_at_ms"] is None else int(row["expires_at_ms"])),
        )
        metadata_json = _metadata(row["metadata_json"])
        metadata_json.update(
            {
                "logical_alias": logical_alias,
                "last_action_at_ms": now,
                "last_local_action": action,
                "reason_supplied": bool(request.reason),
            }
        )
        try:
            with transaction(self.connection, "IMMEDIATE"):
                locked = self.connection.execute(
                    "SELECT state, generation FROM credentials WHERE credential_id = ?",
                    (credential_id,),
                ).fetchone()
                if (
                    locked is None
                    or str(locked["state"]) != current.value
                    or int(locked["generation"]) != generation
                ):
                    raise CredentialLifecycleConflict("credential mutation lost its state fence")
                if action == "retire" and self._active_work(credential_id):
                    raise CredentialLifecycleConflict("credential still owns active work")
                updated = self.connection.execute(
                    """
                    UPDATE credentials
                       SET state = ?, generation = ?, metadata_json = ?
                     WHERE credential_id = ? AND state = ? AND generation = ?
                    """,
                    (
                        target.value,
                        next_generation,
                        _json(metadata_json),
                        credential_id,
                        current.value,
                        generation,
                    ),
                )
                if updated.rowcount != 1:
                    raise CredentialLifecycleConflict("credential mutation lost its state fence")
                journal = self.connection.execute(
                    """
                    SELECT metadata_json FROM credential_mutations
                     WHERE mutation_id = ? AND operation = ? AND state = 'PREPARED'
                    """,
                    (request.mutation_id, operation),
                ).fetchone()
                if journal is None:
                    raise CredentialLifecycleConflict("credential mutation lost its durable fence")
                journal_metadata = _metadata(journal["metadata_json"])
                journal_metadata["durable_state_changed"] = True
                phase = self.connection.execute(
                    """
                    UPDATE credential_mutations
                       SET state = 'DURABLE_STATE_CHANGED', updated_at_ms = ?,
                           metadata_json = ?, result_json = ?
                     WHERE mutation_id = ? AND operation = ? AND state = 'PREPARED'
                    """,
                    (
                        now,
                        _json(journal_metadata),
                        result.model_dump_json(exclude_none=False),
                        request.mutation_id,
                        operation,
                    ),
                )
                if phase.rowcount != 1:
                    raise CredentialLifecycleConflict("credential mutation lost its durable fence")
        except Exception:
            self._mark_rolled_back(request.mutation_id)
            raise

        custody_failed = False
        try:
            await self._key_store.update_metadata(
                updated_metadata,
                expected_generation=generation,
            )
        except Exception:
            custody_failed = True
        if custody_failed:
            self._mark_cleanup_required(request.mutation_id)
            raise CredentialLifecycleFailure("credential custody state could not be changed")

        try:
            with transaction(self.connection, "IMMEDIATE"):
                self._commit_mutation(
                    mutation_id=request.mutation_id,
                    operation=operation,
                    result=result,
                    actor_id=actor_id,
                    payload={
                        "credential_id": credential_id,
                        "generation": next_generation,
                        "principal_id": str(row["principal_id"]),
                        "quota_scope_id": str(row["quota_scope_id"]),
                        "pool_ids": list(route.pool_ids),
                        "state": target.value,
                    },
                    expected_state="DURABLE_STATE_CHANGED",
                )
        except Exception:
            self._mark_cleanup_required(request.mutation_id)
            raise
        if action == "retire":
            cleanup_failed = False
            try:
                await self._key_store.delete(credential_id)
            except Exception:
                cleanup_failed = True
            if cleanup_failed:
                raise CredentialLifecycleFailure(
                    "credential was retired locally but custody cleanup is pending"
                )
        return result

    @staticmethod
    def _completed_emergency(
        row: sqlite3.Row | None,
        *,
        active_secret: bytearray | None = None,
    ) -> EmergencyUnlockView | None:
        if row is None or str(row["state"]) != "COMMITTED":
            return None
        raw_result = str(row["result_json"])
        if active_secret is not None and _contains_active_secret(raw_result, active_secret):
            raise CredentialLifecycleFailure("emergency result overlaps secret material")
        result: EmergencyUnlockView | None = None
        try:
            result = EmergencyUnlockView.model_validate_json(raw_result)
        except (TypeError, ValueError):
            pass
        if result is None:
            raise CredentialLifecycleFailure("emergency mutation result is invalid")
        if active_secret is not None and _contains_active_secret(
            result.model_dump_json(exclude_none=False),
            active_secret,
        ):
            raise CredentialLifecycleFailure("emergency result overlaps secret material")
        return result

    def _emergency_authority(self, request: EmergencyUnlockRequest) -> sqlite3.Row:
        now = self._now_ms()
        raw_row: object = self.connection.execute(
            """
            SELECT p.alias AS pool_alias, s.state AS session_state,
                   s.absolute_expires_at_ms, c.unattended,
                   r.state AS root_state, r.budget_json, r.consumed_json
              FROM pools AS p
              JOIN sessions AS s ON s.session_id = ?
              JOIN clients AS c ON c.client_id = s.client_id
              JOIN root_runs AS r
                ON r.root_run_id = ? AND r.session_id = s.session_id
             WHERE p.pool_id = ? AND p.service_id = ?
               AND p.alias = 'emergency-locked'
               AND p.automatic_use = 0
               AND p.state IN ('ACTIVE', 'ENABLED')
            """,
            (
                request.session_id,
                request.root_run_id,
                request.pool_id,
                request.service,
            ),
        ).fetchone()
        if raw_row is not None and not isinstance(raw_row, sqlite3.Row):
            raise TypeError("credential lifecycle requires sqlite3.Row results")
        row = raw_row
        if (
            row is None
            or str(row["session_state"]) != "ACTIVE"
            or int(row["absolute_expires_at_ms"]) <= now
            or int(row["unattended"]) != 0
            or str(row["root_state"]) != "ACTIVE"
        ):
            raise CredentialLifecycleFailure("emergency authority is unavailable")
        budgets = _metadata(row["budget_json"])
        consumed = _metadata(row["consumed_json"])
        request_remaining = _required_integer(
            budgets.get("requests", 0), field="request budget"
        ) - _required_integer(consumed.get("requests", 0), field="request consumption")
        credit_remaining = _required_integer(
            budgets.get("credits", 0), field="credit budget"
        ) - _required_integer(consumed.get("credits", 0), field="credit consumption")
        if request.maximum_requests > max(0, request_remaining) or request.maximum_credits > max(
            0, credit_remaining
        ):
            raise CredentialLifecycleFailure("emergency ceilings exceed root authority")
        return row

    def _commit_emergency_mutation(
        self,
        *,
        mutation_id: str,
        operation: str,
        result: EmergencyUnlockView,
        actor_id: str,
        payload: Mapping[str, object],
        expected_state: str = "PREPARED",
        active_secret: bytearray | None = None,
    ) -> None:
        payload_json = _json(
            {
                **payload,
                "actor_id": actor_id,
                "mutation_id": mutation_id,
            }
        )
        result_json = result.model_dump_json(exclude_none=False)
        if active_secret is not None and _contains_active_secret(
            (
                result.audit_event_id,
                result.acted_at_ms,
                operation,
                "INFO",
                result.session_id,
                result.root_run_id,
                "firecrawl",
                1,
                payload_json,
                "COMMITTED",
                result_json,
                mutation_id,
                expected_state,
            ),
            active_secret,
        ):
            raise CredentialLifecycleFailure("emergency metadata overlaps secret material")
        self.connection.execute(
            """
            INSERT INTO audit_events(
                event_id, occurred_at_ms, event_type, severity,
                session_id, root_run_id, service_id, operation,
                preserve, payload_json
            ) VALUES (?, ?, ?, 'INFO', ?, ?, 'firecrawl', ?, 1, ?)
            """,
            (
                result.audit_event_id,
                result.acted_at_ms,
                operation,
                result.session_id,
                result.root_run_id,
                operation,
                payload_json,
            ),
        )
        updated = self.connection.execute(
            """
            UPDATE credential_mutations
               SET state = 'COMMITTED', updated_at_ms = ?, completed_at_ms = ?,
                   result_json = ?
             WHERE mutation_id = ? AND operation = ? AND state = ?
            """,
            (
                result.acted_at_ms,
                result.acted_at_ms,
                result_json,
                mutation_id,
                operation,
                expected_state,
            ),
        )
        if updated.rowcount != 1:
            raise CredentialLifecycleConflict("emergency mutation lost its durable fence")

    async def unlock_emergency(
        self,
        request: EmergencyUnlockRequest,
        secret: bytearray,
        actor_id: str,
    ) -> EmergencyUnlockView:
        operation = "emergency.unlocked"
        try:
            binding = {
                "alias": request.alias,
                "duration_ms": request.duration_ms,
                "maximum_concurrency": request.maximum_concurrency,
                "maximum_credits": request.maximum_credits,
                "maximum_requests": request.maximum_requests,
                "pool_id": request.pool_id,
                "reason_fingerprint": _reason_fingerprint(
                    request.reason,
                    domain=_EMERGENCY_UNLOCK_REASON_DOMAIN,
                ),
                "root_run_id": request.root_run_id,
                "service_id": request.service,
                "session_id": request.session_id,
            }
            self._validate_secret(secret)
            request_content = request.model_dump(mode="json")
            request_overlaps_secret = _contains_active_secret(
                (_PERSISTED_SECRET_BOUNDARY_LITERALS, request_content, actor_id),
                secret,
            )
            request_content.clear()
            if request_overlaps_secret:
                raise CredentialLifecycleFailure("emergency metadata overlaps secret material")
            existing = self._mutation(request.mutation_id, operation)
            self._require_mutation_binding(
                existing,
                credential_id=None,
                metadata=binding,
            )
            completed = self._completed_emergency(existing, active_secret=secret)
            if completed is not None:
                return completed
            if self._emergency is None:
                raise CredentialLifecycleFailure("emergency custody is unavailable")
            await self._synchronize_emergency_expiry(active_secret=secret)
            authority = self._emergency_authority(request)
            audit_id = self._event_id_factory()
            if _contains_active_secret((str(authority["pool_alias"]), audit_id), secret):
                raise CredentialLifecycleFailure("emergency metadata overlaps secret material")
            self._prepare(
                mutation_id=request.mutation_id,
                operation=operation,
                credential_id=None,
                replacement_credential_id=None,
                actor_id=actor_id,
                metadata=binding,
                active_secret=secret,
            )
            unlock_denied = False
            try:
                projection = await self._emergency.unlock(
                    secret=secret,
                    service_id=request.service,
                    pool_name=str(authority["pool_alias"]),
                    pool_id=request.pool_id,
                    session_id=request.session_id,
                    root_run_id=request.root_run_id,
                    interactive=True,
                    duration_ms=request.duration_ms,
                    maximum_requests=request.maximum_requests,
                    maximum_credits=request.maximum_credits,
                    maximum_concurrency=request.maximum_concurrency,
                    credential_alias=request.alias,
                )
            except Exception:
                unlock_denied = True
            if unlock_denied:
                self._mark_rolled_back(request.mutation_id, active_secret=secret)
                raise CredentialLifecycleFailure("emergency unlock was denied")

            try:
                now = self._now_ms()
                principal_alias = f"emergency-{projection.unlock_id[-24:]}"
                quota_scope_alias = principal_alias
                if _contains_active_secret(
                    (
                        projection.unlock_id,
                        projection.credential_id,
                        projection.principal_id,
                        projection.quota_scope_id,
                        projection.alias,
                        projection.service_id,
                        projection.pool_id,
                        projection.pool_name,
                        projection.session_id,
                        projection.root_run_id,
                        projection.expires_at_ms,
                        projection.remaining_requests,
                        projection.remaining_credits,
                        projection.available_concurrency,
                        projection.maximum_requests,
                        projection.maximum_credits,
                        projection.maximum_concurrency,
                        principal_alias,
                        quota_scope_alias,
                        now,
                        1,
                    ),
                    secret,
                ):
                    raise CredentialLifecycleFailure("emergency metadata overlaps secret material")
                phase_metadata = {
                    **binding,
                    "credential_id": projection.credential_id,
                    "expires_at_ms": projection.expires_at_ms,
                    "principal_id": projection.principal_id,
                    "quota_scope_id": projection.quota_scope_id,
                    "unlock_id": projection.unlock_id,
                }
                phase_metadata_json = _json(phase_metadata)
                if _contains_active_secret(
                    (
                        projection.credential_id,
                        "MEMORY_UNLOCKED",
                        now,
                        phase_metadata_json,
                        request.mutation_id,
                        operation,
                        "PREPARED",
                    ),
                    secret,
                ):
                    raise CredentialLifecycleFailure("emergency metadata overlaps secret material")
                with transaction(self.connection, "IMMEDIATE"):
                    phase = self.connection.execute(
                        """
                        UPDATE credential_mutations
                           SET credential_id = ?, state = 'MEMORY_UNLOCKED',
                               updated_at_ms = ?, metadata_json = ?
                         WHERE mutation_id = ? AND operation = ? AND state = 'PREPARED'
                        """,
                        (
                            projection.credential_id,
                            now,
                            phase_metadata_json,
                            request.mutation_id,
                            operation,
                        ),
                    )
                    if phase.rowcount != 1:
                        raise CredentialLifecycleConflict(
                            "emergency mutation lost its memory fence"
                        )
                result = EmergencyUnlockView(
                    mutation_id=request.mutation_id,
                    unlock_id=projection.unlock_id,
                    credential_id=projection.credential_id,
                    action="unlock",
                    state="ACTIVE",
                    generation=1,
                    service="firecrawl",
                    alias=request.alias,
                    principal_id=projection.principal_id,
                    principal_alias=principal_alias,
                    quota_scope_id=projection.quota_scope_id,
                    quota_scope_alias=quota_scope_alias,
                    pool_id=request.pool_id,
                    pool_alias=str(authority["pool_alias"]),
                    session_id=request.session_id,
                    root_run_id=request.root_run_id,
                    expires_at_ms=projection.expires_at_ms,
                    remaining_requests=projection.remaining_requests,
                    remaining_credits=projection.remaining_credits,
                    remaining_concurrency=_remaining_concurrency(projection.available_concurrency),
                    acted_at_ms=now,
                    audit_event_id=audit_id,
                )
                record_metadata_json = _json({"reason_supplied": bool(request.reason)})
                if _contains_active_secret(
                    (
                        projection.unlock_id,
                        request.mutation_id,
                        audit_id,
                        projection.credential_id,
                        request.alias,
                        1,
                        projection.principal_id,
                        principal_alias,
                        projection.quota_scope_id,
                        quota_scope_alias,
                        "firecrawl",
                        request.pool_id,
                        request.session_id,
                        request.root_run_id,
                        "ACTIVE",
                        request.maximum_requests,
                        request.maximum_credits,
                        now,
                        projection.expires_at_ms,
                        record_metadata_json,
                        result.model_dump_json(exclude_none=False),
                    ),
                    secret,
                ):
                    raise CredentialLifecycleFailure("emergency metadata overlaps secret material")
                with transaction(self.connection, "IMMEDIATE"):
                    if (
                        self.connection.execute(
                            """
                        SELECT 1 FROM emergency_unlock_records
                         WHERE state = 'ACTIVE' LIMIT 1
                        """
                        ).fetchone()
                        is not None
                    ):
                        raise CredentialLifecycleConflict("another emergency unlock is active")
                    self._emergency_authority(request)
                    self.connection.execute(
                        """
                        INSERT INTO emergency_unlock_records(
                            unlock_id, mutation_id, last_mutation_id,
                            audit_event_id, credential_id, credential_alias,
                            credential_generation, principal_id, principal_alias,
                            quota_scope_id, quota_scope_alias, service_id, pool_id,
                            session_id, root_run_id, state, maximum_requests,
                            maximum_credits, maximum_concurrency, created_at_ms,
                            updated_at_ms, expires_at_ms, metadata_json
                        ) VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, 'firecrawl',
                                  ?, ?, ?, 'ACTIVE', ?, ?, 1, ?, ?, ?, ?)
                        """,
                        (
                            projection.unlock_id,
                            request.mutation_id,
                            request.mutation_id,
                            audit_id,
                            projection.credential_id,
                            request.alias,
                            projection.principal_id,
                            principal_alias,
                            projection.quota_scope_id,
                            quota_scope_alias,
                            request.pool_id,
                            request.session_id,
                            request.root_run_id,
                            request.maximum_requests,
                            request.maximum_credits,
                            now,
                            now,
                            projection.expires_at_ms,
                            record_metadata_json,
                        ),
                    )
                    self._commit_emergency_mutation(
                        mutation_id=request.mutation_id,
                        operation=operation,
                        result=result,
                        actor_id=actor_id,
                        payload={
                            "credential_id": projection.credential_id,
                            "generation": 1,
                            "pool_id": request.pool_id,
                            "state": "ACTIVE",
                            "unlock_id": projection.unlock_id,
                        },
                        expected_state="MEMORY_UNLOCKED",
                        active_secret=secret,
                    )
            except CredentialLifecycleConflict:
                durable_conflict = True
                durable_failure = False
            except Exception:
                durable_conflict = False
                durable_failure = True
            else:
                durable_conflict = False
                durable_failure = False
            if durable_conflict or durable_failure:
                memory_cleanup_failed = False
                try:
                    await self._emergency.cancel(projection.unlock_id)
                except Exception:
                    memory_cleanup_failed = True
                if memory_cleanup_failed:
                    self._mark_cleanup_required(request.mutation_id, active_secret=secret)
                else:
                    self._mark_rolled_back(request.mutation_id, active_secret=secret)
                if durable_conflict:
                    raise CredentialLifecycleConflict("emergency unlock lost its durable fence")
                raise CredentialLifecycleFailure("emergency unlock metadata could not be committed")
            return result
        finally:
            self._wipe(secret)

    async def _read_emergency_status(self) -> EmergencyUnlockStatus | None:
        if self._emergency is None:
            return None
        status_failed = False
        try:
            status = await self._emergency.status()
        except Exception:
            status_failed = True
            status = None
        if status_failed:
            raise CredentialLifecycleFailure("emergency status is unavailable")
        return status

    async def _synchronize_emergency_expiry(
        self,
        *,
        active_secret: bytearray | None = None,
    ) -> int:
        status = await self._read_emergency_status()
        memory_cleanup_failed = False
        if status is not None and status.state is EmergencyUnlockState.ACTIVE:
            unlock_id = status.unlock_id
            if unlock_id is None:
                raise CredentialLifecycleFailure("emergency status is unavailable")
            durable = self.connection.execute(
                """
                SELECT 1 FROM emergency_unlock_records
                 WHERE unlock_id = ? AND state = 'ACTIVE'
                """,
                (unlock_id,),
            ).fetchone()
            if durable is not None:
                return 0
            manager = self._emergency
            if manager is None:
                raise CredentialLifecycleFailure("emergency status is unavailable")
            try:
                await manager.cancel(unlock_id)
            except Exception:
                memory_cleanup_failed = True
        now = self._now_ms()
        relocked = 0
        with transaction(self.connection, "IMMEDIATE"):
            active = self.connection.execute(
                """
                SELECT unlock_id, credential_id, credential_generation,
                       expires_at_ms, last_mutation_id
                  FROM emergency_unlock_records
                 WHERE state = 'ACTIVE'
                """
            ).fetchall()
            for row in active:
                credential_id = str(row["credential_id"])
                expired = int(row["expires_at_ms"]) <= now
                durable_state = "EXPIRED" if expired else "RELOCKED"
                event_type = (
                    "emergency.expired" if expired else "emergency.relocked_after_memory_loss"
                )
                audit_id = self._insert_audit(
                    event_type=event_type,
                    credential_id=credential_id,
                    state=durable_state,
                    generation=int(row["credential_generation"]),
                    actor_id="system-expiry" if expired else "system-recovery",
                    mutation_id=str(row["last_mutation_id"]),
                    now_ms=now,
                    active_secret=active_secret,
                )
                self.connection.execute(
                    """
                    UPDATE emergency_unlock_records
                       SET state = ?, audit_event_id = ?,
                           updated_at_ms = ?, closed_at_ms = ?
                      WHERE unlock_id = ? AND state = 'ACTIVE'
                    """,
                    (
                        durable_state,
                        audit_id,
                        now,
                        now,
                        str(row["unlock_id"]),
                    ),
                )
                relocked += 1
        if memory_cleanup_failed:
            raise CredentialLifecycleFailure("emergency memory cleanup is incomplete")
        return relocked

    def _emergency_view(
        self,
        row: sqlite3.Row,
        *,
        remaining_requests: int = 0,
        remaining_credits: int = 0,
        remaining_concurrency: int = 0,
    ) -> EmergencyUnlockView:
        state = str(row["state"])
        return EmergencyUnlockView(
            mutation_id=str(row["last_mutation_id"]),
            unlock_id=str(row["unlock_id"]),
            credential_id=str(row["credential_id"]),
            action="unlock" if state == "ACTIVE" else "cancel",
            state=state,
            generation=int(row["credential_generation"]),
            service="firecrawl",
            alias=str(row["credential_alias"]),
            principal_id=str(row["principal_id"]),
            principal_alias=str(row["principal_alias"]),
            quota_scope_id=str(row["quota_scope_id"]),
            quota_scope_alias=str(row["quota_scope_alias"]),
            pool_id=str(row["pool_id"]),
            pool_alias=str(row["pool_alias"]),
            session_id=str(row["session_id"]),
            root_run_id=str(row["root_run_id"]),
            expires_at_ms=int(row["expires_at_ms"]),
            remaining_requests=remaining_requests,
            remaining_credits=remaining_credits,
            remaining_concurrency=_remaining_concurrency(remaining_concurrency),
            acted_at_ms=int(row["updated_at_ms"]),
            audit_event_id=str(row["audit_event_id"]),
        )

    def _emergency_row(self, unlock_id: str) -> sqlite3.Row | None:
        raw_row: object = self.connection.execute(
            """
            SELECT eu.*, pl.alias AS pool_alias
              FROM emergency_unlock_records AS eu
              JOIN pools AS pl ON pl.pool_id = eu.pool_id
             WHERE eu.unlock_id = ?
            """,
            (unlock_id,),
        ).fetchone()
        if raw_row is not None and not isinstance(raw_row, sqlite3.Row):
            raise TypeError("credential lifecycle requires sqlite3.Row results")
        return raw_row

    async def cancel_emergency_unlock(
        self,
        unlock_id: str,
        request: EmergencyUnlockCancelRequest,
        actor_id: str,
    ) -> EmergencyUnlockView:
        operation = "emergency.cancelled"
        binding = {
            "reason_fingerprint": _reason_fingerprint(
                request.reason,
                domain=_EMERGENCY_CANCEL_REASON_DOMAIN,
            ),
            "unlock_id": unlock_id,
        }
        existing = self._mutation(request.mutation_id, operation)
        self._require_mutation_binding(
            existing,
            credential_id=None,
            metadata=binding,
        )
        completed = self._completed_emergency(existing)
        if completed is not None:
            return completed
        if self._emergency is None:
            raise CredentialLifecycleFailure("emergency custody is unavailable")
        await self._synchronize_emergency_expiry()
        row = self._emergency_row(unlock_id)
        if row is None:
            raise CredentialLifecycleFailure("emergency unlock does not exist")
        self._prepare(
            mutation_id=request.mutation_id,
            operation=operation,
            credential_id=str(row["credential_id"]),
            replacement_credential_id=None,
            actor_id=actor_id,
            metadata=binding,
        )
        memory_cleanup_failed = False
        try:
            await self._emergency.cancel(unlock_id)
        except Exception:
            memory_cleanup_failed = True
        if memory_cleanup_failed:
            self._mark_cleanup_required(request.mutation_id)
            raise CredentialLifecycleFailure("emergency cancellation could not be completed")
        now = self._now_ms()
        audit_id = self._event_id_factory()
        result = self._emergency_view(row).model_copy(
            update={
                "mutation_id": request.mutation_id,
                "action": "cancel",
                "state": "CANCELLED",
                "acted_at_ms": now,
                "audit_event_id": audit_id,
            }
        )
        try:
            with transaction(self.connection, "IMMEDIATE"):
                phase = self.connection.execute(
                    """
                    UPDATE credential_mutations
                       SET state = 'MEMORY_RELOCKED', updated_at_ms = ?,
                           result_json = ?
                     WHERE mutation_id = ? AND operation = ? AND state = 'PREPARED'
                    """,
                    (
                        now,
                        result.model_dump_json(exclude_none=False),
                        request.mutation_id,
                        operation,
                    ),
                )
                if phase.rowcount != 1:
                    raise CredentialLifecycleConflict("emergency mutation lost its memory fence")
            with transaction(self.connection, "IMMEDIATE"):
                updated = self.connection.execute(
                    """
                    UPDATE emergency_unlock_records
                       SET state = 'CANCELLED', last_mutation_id = ?,
                           audit_event_id = ?, updated_at_ms = ?, closed_at_ms = ?
                     WHERE unlock_id = ? AND state = ?
                    """,
                    (
                        request.mutation_id,
                        audit_id,
                        now,
                        now,
                        unlock_id,
                        str(row["state"]),
                    ),
                )
                if updated.rowcount != 1:
                    raise CredentialLifecycleConflict(
                        "emergency cancellation lost its durable fence"
                    )
                self._commit_emergency_mutation(
                    mutation_id=request.mutation_id,
                    operation=operation,
                    result=result,
                    actor_id=actor_id,
                    payload={
                        "credential_id": str(row["credential_id"]),
                        "generation": result.generation,
                        "state": "CANCELLED",
                        "unlock_id": unlock_id,
                    },
                    expected_state="MEMORY_RELOCKED",
                )
        except Exception:
            self._mark_cleanup_required(request.mutation_id)
            raise
        return result

    async def list_emergency_unlocks(
        self,
        *,
        limit: int,
    ) -> Sequence[EmergencyUnlockView]:
        if not 1 <= limit <= 100:
            raise ValueError("emergency unlock list limit is outside its bound")
        await self._synchronize_emergency_expiry()
        status = await self._read_emergency_status()
        rows = self.connection.execute(
            """
            SELECT eu.*, pl.alias AS pool_alias
              FROM emergency_unlock_records AS eu
              JOIN pools AS pl ON pl.pool_id = eu.pool_id
             ORDER BY eu.created_at_ms DESC, eu.unlock_id DESC LIMIT ?
            """,
            (limit,),
        ).fetchall()
        result: list[EmergencyUnlockView] = []
        for row in rows:
            remaining_requests = 0
            remaining_credits = 0
            remaining_concurrency: Literal[0, 1] = 0
            if (
                status is not None
                and status.state is EmergencyUnlockState.ACTIVE
                and status.unlock_id == str(row["unlock_id"])
            ):
                remaining_requests = status.remaining_requests
                remaining_credits = status.remaining_credits
                remaining_concurrency = _remaining_concurrency(status.available_concurrency)
            result.append(
                self._emergency_view(
                    row,
                    remaining_requests=remaining_requests,
                    remaining_credits=remaining_credits,
                    remaining_concurrency=remaining_concurrency,
                )
            )
        return tuple(result)

    async def close_emergency(self) -> int:
        """Destroy process-local custody and durably relock its route on shutdown."""

        memory_cleanup_failed = False
        if self._emergency is not None:
            try:
                await self._emergency.close()
            except Exception:
                memory_cleanup_failed = True
        now = self._now_ms()
        relocked = 0
        with transaction(self.connection, "IMMEDIATE"):
            active = self.connection.execute(
                """
                SELECT unlock_id, credential_id, credential_generation,
                       last_mutation_id
                  FROM emergency_unlock_records WHERE state = 'ACTIVE'
                """
            ).fetchall()
            for row in active:
                audit_id = self._insert_audit(
                    event_type="emergency.relocked_on_shutdown",
                    credential_id=str(row["credential_id"]),
                    state="RELOCKED",
                    generation=int(row["credential_generation"]),
                    actor_id="system-shutdown",
                    mutation_id=str(row["last_mutation_id"]),
                    now_ms=now,
                )
                self.connection.execute(
                    """
                    UPDATE emergency_unlock_records
                       SET state = 'RELOCKED', audit_event_id = ?,
                           updated_at_ms = ?, closed_at_ms = ?
                     WHERE unlock_id = ? AND state = 'ACTIVE'
                    """,
                    (audit_id, now, now, str(row["unlock_id"])),
                )
                relocked += 1
        if memory_cleanup_failed:
            raise CredentialLifecycleFailure("emergency memory cleanup is incomplete")
        return relocked

    async def recover_incomplete_mutations(self) -> int:
        """Recover staged custody, finish fail-closed states, and relock memory authority."""

        rows = self.connection.execute(
            """
            SELECT mutation_id, operation, credential_id, replacement_credential_id,
                   state, actor_id, metadata_json, result_json
              FROM credential_mutations
             WHERE state IN (
                 'PREPARED', 'CUSTODY_CREATED', 'DURABLE_DRAINED',
                 'DURABLE_STATE_CHANGED', 'MEMORY_UNLOCKED',
                 'MEMORY_RELOCKED', 'CLEANUP_REQUIRED'
             )
              ORDER BY created_at_ms, mutation_id
            """
        ).fetchall()
        recovered = 0
        for row in rows:
            operation = str(row["operation"])
            mutation_id = str(row["mutation_id"])
            phase = str(row["state"])
            journal = _metadata(row["metadata_json"])
            if operation.startswith("emergency."):
                self._mark_rolled_back(mutation_id)
                recovered += 1
                continue
            if operation in {"credential.provisioned", "credential.rotated"} and (
                phase == "PREPARED"
                or (phase == "CLEANUP_REQUIRED" and journal.get("custody_created") is not True)
            ):
                candidate = (
                    row["credential_id"]
                    if operation == "credential.provisioned"
                    else row["replacement_credential_id"]
                )
                cleaned = False
                if candidate is not None:
                    candidate_id = str(candidate)
                    cleaned = await self._discard_staged_custody(candidate_id, journal)
                    if not cleaned and await self._matches_custody_intent(
                        candidate_id,
                        journal,
                    ):
                        cleaned = await self._remove_new_custody(candidate_id, complete=True)
                if cleaned:
                    self._mark_rolled_back(mutation_id)
                    recovered += 1
                else:
                    self._mark_cleanup_required(mutation_id)
                continue
            cleaned = True
            if operation == "credential.provisioned" and row["credential_id"] is not None:
                candidate = str(row["credential_id"])
                durable = self.connection.execute(
                    "SELECT 1 FROM credentials WHERE credential_id = ?",
                    (candidate,),
                ).fetchone()
                if durable is None:
                    cleaned = await self._remove_new_custody(candidate, complete=True)
                else:
                    cleaned = False
            elif operation == "credential.rotated":
                replacement = row["replacement_credential_id"]
                predecessor = row["credential_id"]
                if replacement is None or predecessor is None:
                    cleaned = False
                else:
                    replacement_id = str(replacement)
                    predecessor_id = str(predecessor)
                    durable_replacement = self.connection.execute(
                        "SELECT 1 FROM credentials WHERE credential_id = ?",
                        (replacement_id,),
                    ).fetchone()
                    durable = self.connection.execute(
                        "SELECT * FROM credentials WHERE credential_id = ?",
                        (predecessor_id,),
                    ).fetchone()
                    durable_json = {} if durable is None else _metadata(durable["metadata_json"])
                    needs_durable_rollback = (
                        durable is not None
                        and durable_json.get("rotation_successor_id") == replacement_id
                        and str(durable["state"]) in {"DRAINING", "UNKNOWN"}
                    )
                    if durable_replacement is not None:
                        cleaned = False
                    elif needs_durable_rollback:
                        old_alias = journal.get(
                            "old_alias",
                            durable_json.get("logical_alias"),
                        )
                        old_generation = journal.get(
                            "old_generation",
                            durable["generation"],
                        )
                        if (
                            not isinstance(old_alias, str)
                            or not old_alias
                            or isinstance(old_generation, bool)
                            or not isinstance(old_generation, int)
                            or old_generation <= 0
                        ):
                            cleaned = False
                        else:
                            old_snapshot: dict[str, object] = {
                                "alias": old_alias,
                                "credential_id": predecessor_id,
                                "expires_at_ms": durable["expires_at_ms"],
                                "generation": old_generation,
                                "principal_id": durable["principal_id"],
                                "quota_scope_id": durable["quota_scope_id"],
                                "secret_reference": durable["secret_reference"],
                                "state": str(journal.get("old_state", "HEALTHY")),
                            }
                            await self._rollback_rotation(
                                old_snapshot,
                                replacement_id,
                                mutation_id,
                            )
                            final = self.connection.execute(
                                "SELECT state FROM credential_mutations WHERE mutation_id = ?",
                                (mutation_id,),
                            ).fetchone()
                            if final is not None and str(final["state"]) == "ROLLED_BACK":
                                recovered += 1
                            continue
                    elif durable is not None:
                        try:
                            await self._restore_metadata(durable)
                        except Exception:
                            cleaned = False
                        else:
                            cleaned = await self._remove_new_custody(
                                replacement_id,
                                complete=True,
                            )
            elif operation.startswith("credential.") and row["credential_id"] is not None:
                durable = self.connection.execute(
                    "SELECT * FROM credentials WHERE credential_id = ?",
                    (str(row["credential_id"]),),
                ).fetchone()
                if durable is not None:
                    durable_changed = journal.get("durable_state_changed") is True
                    if phase in {"DURABLE_STATE_CHANGED", "CLEANUP_REQUIRED"} and durable_changed:
                        try:
                            stored = {
                                item.credential_id: item
                                for item in await self._key_store.list_metadata()
                            }.get(str(durable["credential_id"]))
                            if stored is None and operation != "credential.retired":
                                raise CredentialLifecycleFailure(
                                    "credential custody metadata is unavailable"
                                )
                            if stored is not None:
                                await self._restore_metadata(
                                    durable,
                                    expected_generation=stored.generation,
                                )
                            pending = CredentialMutationResult.model_validate_json(
                                str(row["result_json"])
                            )
                            pool_ids = journal.get("pool_ids")
                            if not (
                                isinstance(pool_ids, list)
                                and pool_ids
                                and all(isinstance(item, str) for item in pool_ids)
                            ):
                                pool_ids = [pending.pool_id]
                            with transaction(self.connection, "IMMEDIATE"):
                                self._commit_mutation(
                                    mutation_id=mutation_id,
                                    operation=operation,
                                    result=pending,
                                    actor_id=str(row["actor_id"]),
                                    payload={
                                        "credential_id": pending.credential_id,
                                        "generation": pending.generation,
                                        "principal_id": pending.principal_id,
                                        "quota_scope_id": pending.quota_scope_id,
                                        "pool_ids": pool_ids,
                                        "state": pending.state,
                                    },
                                    expected_state=phase,
                                )
                        except Exception:
                            cleaned = False
                        else:
                            if operation == "credential.retired":
                                cleaned = await self._remove_new_custody(
                                    str(durable["credential_id"]),
                                    complete=True,
                                )
                            else:
                                cleaned = True
                    elif phase == "PREPARED":
                        self._mark_rolled_back(mutation_id)
                        recovered += 1
                        continue
                    else:
                        cleaned = False
            if cleaned:
                current = self.connection.execute(
                    "SELECT state FROM credential_mutations WHERE mutation_id = ?",
                    (mutation_id,),
                ).fetchone()
                if current is not None and str(current["state"]) != "COMMITTED":
                    self._mark_rolled_back(mutation_id)
                recovered += 1
            else:
                self._mark_cleanup_required(mutation_id)

        try:
            stored_ids = {item.credential_id for item in await self._key_store.list_metadata()}
        except Exception:
            stored_ids = set()
        for row in self.connection.execute(
            """
            SELECT credential_id FROM credentials
             WHERE state = 'RETIRED'
               AND secret_backend IN ('dpapi-current-user', 'memory-test')
            """
        ):
            credential_id = str(row["credential_id"])
            if credential_id in stored_ids:
                if await self._remove_new_custody(credential_id, complete=True):
                    recovered += 1
                continue
            try:
                partial_removed = await self._key_store.discard_partial(credential_id)
            except Exception:
                partial_removed = False
            if partial_removed:
                recovered += 1
        relocked = await self._synchronize_emergency_expiry()
        return recovered + relocked
