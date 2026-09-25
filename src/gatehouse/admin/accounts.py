"""Transactional Firecrawl account onboarding and redacted lifecycle operations."""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import sqlite3
import uuid
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from typing import Literal, Protocol, cast

from gatehouse.core.clock import SYSTEM_UTC_CLOCK
from gatehouse.core.ids import CredentialId, EventId, PoolId, PrincipalId, QuotaScopeId
from gatehouse.credentials import (
    CredentialAlreadyExistsError,
    CredentialMetadata,
    CredentialNotFoundError,
    KeyStore,
)
from gatehouse.database.connection import transaction
from gatehouse.database.observation_intents import SqliteObservationIntentStore
from gatehouse.database.quota_state import QuotaTransitionStatus, SqliteQuotaStateRepository

from .lifecycle import (
    CredentialLifecycleConflict,
    CredentialLifecycleFailure,
    SqliteCredentialLifecycleService,
    _contains_active_secret,
    _metadata,
    _serialized_credential_metadata,
)
from .models import (
    AccountAddRequest,
    AccountMutationResult,
    AccountObservationChangeRequest,
    AccountObservationMutationResult,
    AccountRefreshRequest,
    AccountRotationRequest,
    AccountStateChangeRequest,
    AccountStatus,
    CredentialMutationResult,
    CredentialRotationRequest,
    CredentialStateChangeRequest,
    CredentialValidationResult,
)

_MAXIMUM_SECRET_BYTES = 16 * 1_024
_DEFAULT_OBSERVATION_INTERVAL_MS = 15 * 60 * 1_000
_DEFAULT_FRESHNESS_TTL_MS = 60 * 60 * 1_000
_ACCOUNT_REASON_DOMAIN = b"gatehouse:account-state-reason:v1"
_OBSERVATION_REASON_DOMAIN = b"gatehouse:account-observation-reason:v1"
_PROVIDER_QUOTA_IDENTITY_DOMAIN = b"gatehouse:provider-quota-scope-identity:v1"
_CREDENTIAL_RETIRE_REASON = "account removal"
_OPERATOR_OBSERVATION_SOURCE = "account-manual-refresh"
_CODE_OWNED_OBSERVATION_SOURCES = frozenset(
    {
        _OPERATOR_OBSERVATION_SOURCE,
        "scheduled-firecrawl-credit-observation",
        "admin-credential-validation",
    }
)
_ACCOUNT_JOURNAL_STATES = (
    "ACCOUNT_PREPARED",
    "ACCOUNT_CUSTODY_CREATED",
    "ACCOUNT_CLEANUP_REQUIRED",
    "ACCOUNT_STATE_PREPARED",
    "ACCOUNT_REFRESH_PREPARED",
)
_VisibleAccountState = Literal[
    "HEALTHY",
    "EXHAUSTED",
    "UNKNOWN",
    "DISABLED",
    "QUARANTINED",
]
_AccountStateAction = Literal["disable", "recover"]


class AccountLifecycleConflict(CredentialLifecycleConflict):
    """An alias, mutation binding, or durable state fence conflicts."""


class AccountLifecycleFailure(CredentialLifecycleFailure):
    """An account operation failed without exposing custody details."""


class AccountRefreshUnavailable(AccountLifecycleFailure):
    """The separately gated authenticated observer is unavailable."""


class AccountObservationCollector(Protocol):
    """A fixed, bounded collector with no generic authenticated HTTP surface."""

    async def observe_credential(
        self,
        credential_id: str,
        *,
        expected_generation: int,
        actor_id: str,
        source: str,
        freshness_ttl_ms: int,
        request_id: str | None = None,
    ) -> CredentialValidationResult: ...


def _json(value: Mapping[str, object] | None = None) -> str:
    return json.dumps(value or {}, sort_keys=True, separators=(",", ":"))


def _identifier(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex}"


def _account_entity_identifier(prefix: str) -> str:
    typed_factories = {
        "principal": PrincipalId.new,
        "quota": QuotaScopeId.new,
        "pool": PoolId.new,
    }
    factory = typed_factories.get(prefix)
    return _identifier(prefix) if factory is None else str(factory())


def _reason_fingerprint(reason: str, *, domain: bytes) -> str:
    digest = hashlib.sha256()
    digest.update(domain)
    digest.update(b"\x00")
    digest.update(reason.encode("utf-8"))
    return digest.hexdigest()


def _retirement_mutation_id(mutation_id: str, credential_id: str) -> str:
    digest = hashlib.sha256()
    digest.update(b"gatehouse:account-remove-retire:v1\x00")
    digest.update(mutation_id.encode("utf-8"))
    digest.update(b"\x00")
    digest.update(credential_id.encode("utf-8"))
    return f"account-retire-{digest.hexdigest()}"


def _scrub_exception(error: BaseException) -> None:
    error.args = ()
    error.__traceback__ = None
    error.__cause__ = None
    error.__context__ = None


class SqliteAccountLifecycleService(SqliteCredentialLifecycleService):
    """Own the Firecrawl account graph while reusing hardened credential custody sagas."""

    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        persistent_key_store: KeyStore,
        provider_identity_hmac_key: bytes,
        quota_state: SqliteQuotaStateRepository | None = None,
        observation_collector: AccountObservationCollector | None = None,
        manual_refresh_enabled: bool = False,
        observation_interval_ms: int = _DEFAULT_OBSERVATION_INTERVAL_MS,
        freshness_ttl_ms: int = _DEFAULT_FRESHNESS_TTL_MS,
        now_ms: Callable[[], int] = SYSTEM_UTC_CLOCK.now_ms,
        credential_id_factory: Callable[[], str] = lambda: str(CredentialId.new()),
        event_id_factory: Callable[[], str] = lambda: str(EventId.new()),
        entity_id_factory: Callable[[str], str] = _account_entity_identifier,
    ) -> None:
        if type(provider_identity_hmac_key) is not bytes or len(provider_identity_hmac_key) != 32:
            raise ValueError("provider identity HMAC key must contain exactly 256 bits")
        if not 60_000 <= observation_interval_ms <= 604_800_000:
            raise ValueError("observation interval is outside its bound")
        if not 60_000 <= freshness_ttl_ms <= 604_800_000:
            raise ValueError("observation freshness is outside its bound")
        super().__init__(
            connection,
            persistent_key_store=persistent_key_store,
            now_ms=now_ms,
            credential_id_factory=credential_id_factory,
            event_id_factory=event_id_factory,
        )
        self._quota_state = quota_state or SqliteQuotaStateRepository(connection)
        self._observation_collector = observation_collector
        self._manual_refresh_enabled = manual_refresh_enabled
        self._observation_interval_ms = observation_interval_ms
        self._freshness_ttl_ms = freshness_ttl_ms
        self._entity_id_factory = entity_id_factory
        self._provider_identity_hmac_key = provider_identity_hmac_key

    @staticmethod
    def _validate_alias(alias: str) -> str:
        if (
            type(alias) is not str
            or not 1 <= len(alias) <= 160
            or not alias.isascii()
            or not alias[0].isalnum()
            or any(not (character.isalnum() or character in "_.:-") for character in alias)
        ):
            raise AccountLifecycleFailure("account alias is invalid")
        return alias

    @staticmethod
    def _validate_identity(value: str, *, field: str) -> str:
        if type(value) is not str or not value or len(value) > 160:
            raise AccountLifecycleFailure(f"{field} is invalid")
        return value

    @staticmethod
    def _validate_provider_team_id(value: str) -> str:
        if (
            type(value) is not str
            or not 1 <= len(value) <= 160
            or not value.isascii()
            or any(not "!" <= character <= "~" for character in value)
        ):
            raise AccountLifecycleFailure("provider team identifier is invalid")
        return value

    def _provider_team_fingerprint(self, provider_team_id: str) -> bytes:
        normalized = self._validate_provider_team_id(provider_team_id)
        message = b"\x00".join(
            (
                _PROVIDER_QUOTA_IDENTITY_DOMAIN,
                b"firecrawl",
                b"TEAM",
                normalized.encode("ascii"),
            )
        )
        return hmac.new(self._provider_identity_hmac_key, message, hashlib.sha256).digest()

    def _safe_now(self) -> int:
        value = self._now_ms()
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise AccountLifecycleFailure("account clock is invalid")
        return value

    def _new_id(self, prefix: str) -> str:
        return self._validate_identity(
            self._entity_id_factory(prefix),
            field="generated identifier",
        )

    def _journal(self, mutation_id: str, operation: str) -> sqlite3.Row | None:
        row = self.connection.execute(
            "SELECT * FROM credential_mutations WHERE mutation_id = ?",
            (mutation_id,),
        ).fetchone()
        if row is not None and not isinstance(row, sqlite3.Row):
            raise TypeError("account lifecycle requires sqlite3.Row results")
        if row is not None and str(row["operation"]) != operation:
            raise AccountLifecycleConflict("mutation identifier is already bound")
        return row

    @staticmethod
    def _require_binding(row: sqlite3.Row | None, binding: Mapping[str, object]) -> None:
        if row is None:
            return
        stored = _metadata(row["metadata_json"])
        if any(key not in stored or stored[key] != value for key, value in binding.items()):
            raise AccountLifecycleConflict("mutation identifier is already bound")

    @staticmethod
    def _require_actor_binding(row: sqlite3.Row | None, actor_id: str) -> None:
        if row is not None and str(row["actor_id"]) != actor_id:
            raise AccountLifecycleConflict("mutation identifier is already bound")

    @staticmethod
    def _completed_account(
        row: sqlite3.Row | None,
        *,
        active_secret: bytearray | None = None,
    ) -> AccountMutationResult | None:
        if row is None or str(row["state"]) != "COMMITTED":
            return None
        raw = str(row["result_json"])
        if active_secret is not None and _contains_active_secret(raw, active_secret):
            raise AccountLifecycleFailure("account result overlaps secret material")
        try:
            result = AccountMutationResult.model_validate_json(raw)
        except (TypeError, ValueError) as error:
            raise AccountLifecycleFailure("account mutation result is invalid") from error
        if active_secret is not None and _contains_active_secret(
            result.model_dump_json(exclude_none=False), active_secret
        ):
            raise AccountLifecycleFailure("account result overlaps secret material")
        return result

    @staticmethod
    def _completed_observation(
        row: sqlite3.Row | None,
    ) -> AccountObservationMutationResult | None:
        if row is None or str(row["state"]) != "COMMITTED":
            return None
        try:
            return AccountObservationMutationResult.model_validate_json(str(row["result_json"]))
        except (TypeError, ValueError) as error:
            raise AccountLifecycleFailure("account observation result is invalid") from error

    @staticmethod
    def _completed_status(row: sqlite3.Row | None) -> AccountStatus | None:
        if row is None or str(row["state"]) != "COMMITTED":
            return None
        try:
            return AccountStatus.model_validate_json(str(row["result_json"]))
        except (TypeError, ValueError) as error:
            raise AccountLifecycleFailure("account refresh result is invalid") from error

    def _prepare_account_mutation(
        self,
        *,
        mutation_id: str,
        operation: str,
        actor_id: str,
        state: str,
        credential_id: str | None,
        metadata: Mapping[str, object],
        active_secret: bytearray | None = None,
    ) -> sqlite3.Row:
        now = self._safe_now()
        metadata_json = _json(metadata)
        if active_secret is not None and _contains_active_secret(
            (mutation_id, operation, actor_id, state, credential_id, metadata_json),
            active_secret,
        ):
            raise AccountLifecycleFailure("account metadata overlaps secret material")
        with transaction(self.connection, "IMMEDIATE"):
            existing = self._journal(mutation_id, operation)
            if existing is not None and str(existing["state"]) not in {"ROLLED_BACK", "FAILED"}:
                return existing
            if existing is None:
                self.connection.execute(
                    """
                    INSERT INTO credential_mutations(
                        mutation_id, operation, credential_id, state, actor_id,
                        created_at_ms, updated_at_ms, metadata_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        mutation_id,
                        operation,
                        credential_id,
                        state,
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
                       SET credential_id = ?, replacement_credential_id = NULL,
                           state = ?, actor_id = ?, updated_at_ms = ?,
                           completed_at_ms = NULL, metadata_json = ?, result_json = '{}'
                     WHERE mutation_id = ? AND state IN ('ROLLED_BACK', 'FAILED')
                    """,
                    (credential_id, state, actor_id, now, metadata_json, mutation_id),
                )
            prepared = self._journal(mutation_id, operation)
            if prepared is None:
                raise AccountLifecycleFailure("account mutation journal is unavailable")
            return prepared

    def _mark_account_rolled_back(self, mutation_id: str) -> None:
        with suppress(sqlite3.Error):
            now = self._safe_now()
            with transaction(self.connection, "IMMEDIATE"):
                self.connection.execute(
                    """
                    UPDATE credential_mutations
                       SET state = 'ROLLED_BACK', updated_at_ms = ?, completed_at_ms = ?
                     WHERE mutation_id = ? AND state != 'COMMITTED'
                    """,
                    (now, now, mutation_id),
                )

    def _mark_account_cleanup_required(self, mutation_id: str) -> None:
        with suppress(sqlite3.Error):
            now = self._safe_now()
            with transaction(self.connection, "IMMEDIATE"):
                self.connection.execute(
                    """
                    UPDATE credential_mutations
                       SET state = 'ACCOUNT_CLEANUP_REQUIRED', updated_at_ms = ?
                     WHERE mutation_id = ? AND state != 'COMMITTED'
                    """,
                    (now, mutation_id),
                )

    def _insert_audit_locked(
        self,
        *,
        event_id: str,
        event_type: str,
        actor_id: str,
        mutation_id: str,
        alias: str,
        now_ms: int,
        extra: Mapping[str, object] | None = None,
        active_secret: bytearray | None = None,
    ) -> None:
        payload = {
            "actor_id": actor_id,
            "alias": alias,
            "mutation_id": mutation_id,
            **(extra or {}),
        }
        payload_json = _json(payload)
        if active_secret is not None and _contains_active_secret(
            (event_id, event_type, payload_json), active_secret
        ):
            raise AccountLifecycleFailure("account audit metadata overlaps secret material")
        self.connection.execute(
            """
            INSERT INTO audit_events(
                event_id, occurred_at_ms, event_type, severity,
                service_id, operation, preserve, payload_json
            ) VALUES (?, ?, ?, 'INFO', 'firecrawl', ?, 1, ?)
            """,
            (event_id, now_ms, event_type, event_type, payload_json),
        )

    def _commit_result_locked(
        self,
        *,
        mutation_id: str,
        operation: str,
        expected_state: str,
        result: AccountMutationResult | AccountObservationMutationResult | AccountStatus,
        actor_id: str,
        alias: str,
        audit_event_id: str,
        now_ms: int,
        audit_extra: Mapping[str, object] | None = None,
        active_secret: bytearray | None = None,
    ) -> None:
        result_json = result.model_dump_json(exclude_none=False)
        if active_secret is not None and _contains_active_secret(result_json, active_secret):
            raise AccountLifecycleFailure("account result overlaps secret material")
        self._insert_audit_locked(
            event_id=audit_event_id,
            event_type=operation,
            actor_id=actor_id,
            mutation_id=mutation_id,
            alias=alias,
            now_ms=now_ms,
            extra=audit_extra,
            active_secret=active_secret,
        )
        updated = self.connection.execute(
            """
            UPDATE credential_mutations
               SET state = 'COMMITTED', updated_at_ms = ?, completed_at_ms = ?,
                   result_json = ?
             WHERE mutation_id = ? AND operation = ? AND state = ?
            """,
            (now_ms, now_ms, result_json, mutation_id, operation, expected_state),
        )
        if updated.rowcount != 1:
            raise AccountLifecycleConflict("account mutation lost its durable fence")

    def _account(self, alias: str) -> sqlite3.Row | None:
        alias = self._validate_alias(alias)
        raw: object = self.connection.execute(
            """
            SELECT principal.principal_id, principal.alias,
                   scope.quota_scope_id, scope.state, scope.unit,
                   pool.pool_id, pool.alias AS pool_alias,
                   member.priority
              FROM principals AS principal
              JOIN quota_scopes AS scope ON scope.principal_id = principal.principal_id
              JOIN pool_members AS member ON member.quota_scope_id = scope.quota_scope_id
              JOIN pools AS pool ON pool.pool_id = member.pool_id
             WHERE principal.service_id = 'firecrawl'
               AND principal.identity_kind = 'ACCOUNT'
               AND scope.scope_kind = 'TEAM'
               AND principal.alias = ? AND principal.enabled = 1
             ORDER BY member.priority, pool.alias, pool.pool_id
             LIMIT 1
            """,
            (alias,),
        ).fetchone()
        if raw is not None and not isinstance(raw, sqlite3.Row):
            raise TypeError("account lifecycle requires sqlite3.Row results")
        return raw

    def _require_account(self, alias: str) -> sqlite3.Row:
        row = self._account(alias)
        if row is None:
            raise AccountLifecycleFailure("account does not exist")
        return row

    def _current_credential(self, quota_scope_id: str) -> sqlite3.Row:
        raw: object = self.connection.execute(
            """
            SELECT credential_id, generation, state, expires_at_ms
              FROM credentials
             WHERE quota_scope_id = ? AND credential_role = 'WORKLOAD'
               AND state != 'RETIRED'
             ORDER BY generation DESC, created_at_ms DESC, credential_id DESC
             LIMIT 1
            """,
            (quota_scope_id,),
        ).fetchone()
        if raw is not None and not isinstance(raw, sqlite3.Row):
            raise TypeError("account lifecycle requires sqlite3.Row results")
        if raw is None:
            raise AccountLifecycleFailure("account workload credential is unavailable")
        return raw

    def _account_generation(self, quota_scope_id: str) -> int:
        row = self.connection.execute(
            """
            SELECT MAX(generation) AS generation FROM credentials
             WHERE quota_scope_id = ? AND credential_role = 'WORKLOAD'
            """,
            (quota_scope_id,),
        ).fetchone()
        if row is None or row["generation"] is None:
            raise AccountLifecycleFailure("account workload credential is unavailable")
        return int(row["generation"])

    def _status_for_row(self, account: sqlite3.Row, *, now_ms: int) -> AccountStatus:
        quota_scope_id = str(account["quota_scope_id"])
        status = self._quota_state.status(quota_scope_id=quota_scope_id, now_ms=now_ms)
        if status is None:
            raise AccountLifecycleFailure("account quota status is unavailable")
        state: _VisibleAccountState
        raw_state = status.state.value
        state = "UNKNOWN" if raw_state == "COOLDOWN" else cast(_VisibleAccountState, raw_state)
        current = self.connection.execute(
            "SELECT credential_id, generation FROM credentials WHERE quota_scope_id = ? "
            "AND credential_role = 'WORKLOAD' AND state != 'RETIRED' "
            "ORDER BY generation DESC, created_at_ms DESC, credential_id DESC LIMIT 1",
            (quota_scope_id,),
        ).fetchone()
        unresolved = current is not None and SqliteObservationIntentStore(
            self.connection,
        ).has_unresolved(str(current["credential_id"]), int(current["generation"]))
        if unresolved and state not in {"DISABLED", "QUARANTINED", "EXHAUSTED"}:
            state = "UNKNOWN"
        complete_observation = (
            status.exact_remaining is not None
            and status.observed_at_ms is not None
            and status.stale_at_ms is not None
            and status.source in _CODE_OWNED_OBSERVATION_SOURCES
        )
        if not complete_observation:
            if state not in {"DISABLED", "QUARANTINED", "EXHAUSTED"}:
                state = "UNKNOWN"
            return AccountStatus(
                alias=str(account["alias"]),
                state=state,
                remaining_decimal=None,
                plan_decimal=None,
                unit=str(account["unit"]),
                observed_at_ms=None,
                staleness_ms=None,
                stale=True,
                source=None,
            )
        assert status.observed_at_ms is not None
        return AccountStatus(
            alias=str(account["alias"]),
            state=state,
            remaining_decimal=status.exact_remaining,
            plan_decimal=status.exact_plan_total,
            unit=str(account["unit"]),
            observed_at_ms=status.observed_at_ms,
            staleness_ms=max(0, now_ms - status.observed_at_ms),
            stale=status.stale or unresolved,
            source=status.source,
        )

    async def add_account(
        self,
        request: AccountAddRequest,
        secret: bytearray,
        actor_id: str,
    ) -> AccountMutationResult:
        operation = "account.added"
        try:
            identity_fingerprint = self._provider_team_fingerprint(request.provider_team_id)
            binding = {
                "provider": request.provider,
                "provider_identity_fingerprint": identity_fingerprint.hex(),
                "alias": request.alias,
                "pool_alias": request.pool_alias,
                "priority": request.priority,
                "expires_at_ms": request.expires_at_ms,
            }
            self._validate_secret(secret)
            self._validate_alias(request.alias)
            self._validate_alias(request.pool_alias)
            self._validate_identity(actor_id, field="actor identifier")
            if _contains_active_secret(
                (binding, request.provider_team_id, request.mutation_id, actor_id),
                secret,
            ):
                raise AccountLifecycleFailure("account metadata overlaps secret material")
            existing = self._journal(request.mutation_id, operation)
            self._require_binding(existing, binding)
            self._require_actor_binding(existing, actor_id)
            completed = self._completed_account(existing, active_secret=secret)
            if completed is not None:
                return completed
            if existing is not None and str(existing["state"]) not in {"ROLLED_BACK", "FAILED"}:
                raise AccountLifecycleConflict("account mutation is already active")
            now = self._safe_now()
            if request.expires_at_ms is not None and request.expires_at_ms <= now:
                raise AccountLifecycleFailure("credential expiry must be in the future")
            duplicate = self.connection.execute(
                "SELECT 1 FROM principals WHERE service_id = 'firecrawl' AND alias = ?",
                (request.alias,),
            ).fetchone()
            if duplicate is not None:
                raise AccountLifecycleConflict("account alias is already in use")
            duplicate_identity = self.connection.execute(
                """
                SELECT 1 FROM provider_quota_scope_identities
                 WHERE provider_id = 'firecrawl' AND identity_kind = 'TEAM'
                   AND identity_fingerprint = ?
                """,
                (identity_fingerprint,),
            ).fetchone()
            if duplicate_identity is not None:
                raise AccountLifecycleConflict("provider quota identity is already onboarded")
            pool = self.connection.execute(
                """
                SELECT service_id, state, selection_strategy FROM pools
                 WHERE service_id = 'firecrawl' AND alias = ?
                """,
                (request.pool_alias,),
            ).fetchone()
            if pool is not None and (
                str(pool["service_id"]) != "firecrawl"
                or str(pool["state"]) not in {"ACTIVE", "ENABLED"}
                or str(pool["selection_strategy"]) != "fill_first"
            ):
                raise AccountLifecycleConflict("account pool is not a Firecrawl fill-first pool")

            principal_id = self._new_id("principal")
            quota_scope_id = self._new_id("quota")
            pool_id = self._new_id("pool") if pool is None else ""
            schedule_id = self._new_id("quota_schedule")
            provider_identity_id = self._new_id("provider_identity")
            credential_id = self._credential_id_factory()
            custody_alias = f"pending-{secrets.token_hex(24)}"
            state_event_id = self._event_id_factory()
            audit_event_id = self._event_id_factory()
            journal_metadata = {
                **binding,
                "principal_id": principal_id,
                "quota_scope_id": quota_scope_id,
                "pool_id": pool_id,
                "schedule_id": schedule_id,
                "provider_identity_id": provider_identity_id,
                "custody_intent_alias": custody_alias,
                "custody_generation": 1,
                "custody_expires_at_ms": request.expires_at_ms,
                "custody_principal_id": principal_id,
                "custody_quota_scope_id": quota_scope_id,
                "custody_state": "HEALTHY",
                "state_event_id": state_event_id,
                "audit_event_id": audit_event_id,
            }
            if _contains_active_secret(journal_metadata, secret):
                raise AccountLifecycleFailure("account metadata overlaps secret material")
            self._prepare_account_mutation(
                mutation_id=request.mutation_id,
                operation=operation,
                actor_id=actor_id,
                state="ACCOUNT_PREPARED",
                credential_id=credential_id,
                metadata=journal_metadata,
                active_secret=secret,
            )
            staged_metadata = CredentialMetadata(
                credential_id=credential_id,
                principal_id=principal_id,
                quota_scope_id=quota_scope_id,
                alias=custody_alias,
                state="HEALTHY",
                generation=1,
                expires_at_ms=request.expires_at_ms,
            )
            try:
                reference = await self._key_store.put(staged_metadata, cast(bytes, secret))
            except CredentialAlreadyExistsError as error:
                self._mark_account_cleanup_required(request.mutation_id)
                raise AccountLifecycleConflict(
                    "account credential custody identifier is already in use"
                ) from error
            except Exception as error:
                _scrub_exception(error)
                self._mark_account_cleanup_required(request.mutation_id)
                raise AccountLifecycleFailure(
                    "account credential custody could not be committed"
                ) from None
            if _contains_active_secret(reference, secret):
                await self._rollback_new_custody(request.mutation_id, credential_id)
                raise AccountLifecycleFailure("account credential custody metadata is invalid")
            try:
                with transaction(self.connection, "IMMEDIATE"):
                    journal = self.connection.execute(
                        """
                        SELECT metadata_json FROM credential_mutations
                         WHERE mutation_id = ? AND operation = ?
                           AND state = 'ACCOUNT_PREPARED'
                        """,
                        (request.mutation_id, operation),
                    ).fetchone()
                    if journal is None:
                        raise AccountLifecycleConflict("account mutation lost its custody fence")
                    custody_metadata = _metadata(journal["metadata_json"])
                    custody_metadata["custody_created"] = True
                    custody_metadata_json = _json(custody_metadata)
                    if _contains_active_secret(custody_metadata_json, secret):
                        raise AccountLifecycleFailure(
                            "account custody metadata overlaps secret material"
                        )
                    advanced = self.connection.execute(
                        """
                        UPDATE credential_mutations
                           SET state = 'ACCOUNT_CUSTODY_CREATED', updated_at_ms = ?,
                               metadata_json = ?
                         WHERE mutation_id = ? AND operation = ?
                           AND state = 'ACCOUNT_PREPARED'
                        """,
                        (
                            now,
                            custody_metadata_json,
                            request.mutation_id,
                            operation,
                        ),
                    )
                    if advanced.rowcount != 1:
                        raise AccountLifecycleConflict("account mutation lost its custody fence")
            except Exception:
                await self._rollback_new_custody(request.mutation_id, credential_id)
                raise

            committed_metadata = CredentialMetadata(
                credential_id=credential_id,
                principal_id=principal_id,
                quota_scope_id=quota_scope_id,
                alias=request.alias,
                state="HEALTHY",
                generation=1,
                secret_reference=reference,
                expires_at_ms=request.expires_at_ms,
            )
            if _contains_active_secret(_serialized_credential_metadata(committed_metadata), secret):
                await self._rollback_new_custody(request.mutation_id, credential_id)
                raise AccountLifecycleFailure("account credential custody metadata is invalid")
            try:
                await self._key_store.update_metadata(committed_metadata, expected_generation=1)
            except Exception as error:
                _scrub_exception(error)
                await self._rollback_new_custody(request.mutation_id, credential_id)
                raise AccountLifecycleFailure(
                    "account credential custody metadata could not be staged"
                ) from None

            result = AccountMutationResult(
                alias=request.alias,
                action="add",
                state="UNKNOWN",
                pool_alias=request.pool_alias,
                priority=request.priority,
                generation=1,
                acted_at_ms=now,
                audit_event_id=audit_event_id,
            )
            try:
                backend = self._backend(reference)
                with transaction(self.connection, "IMMEDIATE"):
                    if (
                        self.connection.execute(
                            "SELECT 1 FROM principals WHERE service_id = 'firecrawl' AND alias = ?",
                            (request.alias,),
                        ).fetchone()
                        is not None
                    ):
                        raise AccountLifecycleConflict("account alias is already in use")
                    locked_pool = self.connection.execute(
                        """
                        SELECT pool_id, service_id, state, selection_strategy
                          FROM pools
                         WHERE service_id = 'firecrawl' AND alias = ?
                        """,
                        (request.pool_alias,),
                    ).fetchone()
                    if locked_pool is None:
                        resolved_pool_id = pool_id
                        self.connection.execute(
                            """
                            INSERT INTO pools(
                                pool_id, service_id, alias, state, selection_strategy,
                                automatic_use, config_json
                            ) VALUES (?, 'firecrawl', ?, 'ACTIVE', 'fill_first', 1,
                                      '{"automatic_failover_within_pool":false}')
                            """,
                            (resolved_pool_id, request.pool_alias),
                        )
                    else:
                        if (
                            str(locked_pool["service_id"]) != "firecrawl"
                            or str(locked_pool["state"]) not in {"ACTIVE", "ENABLED"}
                            or str(locked_pool["selection_strategy"]) != "fill_first"
                        ):
                            raise AccountLifecycleConflict(
                                "account pool is not a Firecrawl fill-first pool"
                            )
                        resolved_pool_id = str(locked_pool["pool_id"])
                    self.connection.execute(
                        """
                        INSERT INTO principals(
                            principal_id, service_id, alias, enabled, metadata_json,
                            created_at_ms, updated_at_ms, identity_kind
                        ) VALUES (?, 'firecrawl', ?, 1, ?, ?, ?, 'ACCOUNT')
                        """,
                        (
                            principal_id,
                            request.alias,
                            _json({"provider": "firecrawl", "tombstoned": False}),
                            now,
                            now,
                        ),
                    )
                    self.connection.execute(
                        """
                        INSERT INTO quota_scopes(
                            quota_scope_id, principal_id, alias, state, unit,
                            configured_floor_units, metadata_json, scope_kind,
                            state_generation, state_changed_at_ms, state_reason_code
                        ) VALUES (?, ?, ?, 'UNKNOWN', 'credits', 0, ?, 'TEAM', 0, ?,
                                  'ACCOUNT_ONBOARDED')
                        """,
                        (
                            quota_scope_id,
                            principal_id,
                            request.alias,
                            _json({"provider": "firecrawl", "tombstoned": False}),
                            now,
                        ),
                    )
                    self.connection.execute(
                        """
                        UPDATE quota_dimensions
                           SET name = 'account_credits', native_unit = 'credits',
                               counter_kind = 'BALANCE', reset_window_kind = 'PROVIDER',
                               updated_at_ms = ?
                         WHERE quota_scope_id = ? AND is_primary = 1
                        """,
                        (now, quota_scope_id),
                    )
                    self.connection.execute(
                        """
                        INSERT INTO provider_quota_scope_identities(
                            provider_identity_id, provider_id, identity_kind,
                            identity_fingerprint, principal_id, quota_scope_id,
                            created_at_ms, metadata_json
                        ) VALUES (?, 'firecrawl', 'TEAM', ?, ?, ?, ?, '{}')
                        """,
                        (
                            provider_identity_id,
                            identity_fingerprint,
                            principal_id,
                            quota_scope_id,
                            now,
                        ),
                    )
                    self.connection.execute(
                        """
                        INSERT INTO credentials(
                            credential_id, principal_id, quota_scope_id, alias,
                            secret_backend, secret_reference, state, generation,
                            exclusive_usage, expires_at_ms, created_at_ms,
                            metadata_json, credential_role
                        ) VALUES (?, ?, ?, ?, ?, ?, 'HEALTHY', 1, 1, ?, ?, ?, 'WORKLOAD')
                        """,
                        (
                            credential_id,
                            principal_id,
                            quota_scope_id,
                            request.alias,
                            backend,
                            reference,
                            request.expires_at_ms,
                            now,
                            _json({"logical_alias": request.alias}),
                        ),
                    )
                    self.connection.execute(
                        """
                        INSERT INTO pool_members(
                            pool_id, quota_scope_id, priority, cost_rank, enabled
                        ) VALUES (?, ?, ?, ?, 1)
                        """,
                        (resolved_pool_id, quota_scope_id, request.priority, request.priority),
                    )
                    self.connection.execute(
                        """
                        INSERT INTO quota_observation_schedules(
                            schedule_id, quota_scope_id, observer_credential_id,
                            observer_credential_generation, state, interval_ms,
                            freshness_ttl_ms, generation, created_at_ms, updated_at_ms,
                            metadata_json
                        ) VALUES (?, ?, ?, 1, 'DISABLED', ?, ?, 1, ?, ?, '{}')
                        """,
                        (
                            schedule_id,
                            quota_scope_id,
                            credential_id,
                            self._observation_interval_ms,
                            self._freshness_ttl_ms,
                            now,
                            now,
                        ),
                    )
                    self.connection.execute(
                        """
                        INSERT INTO quota_scope_state_events(
                            event_id, quota_scope_id, generation, previous_state,
                            new_state, reason_code, source_kind, actor_id,
                            occurred_at_ms, metadata_json
                        ) VALUES (?, ?, 0, NULL, 'UNKNOWN', 'ACCOUNT_ONBOARDED',
                                  'OPERATOR', ?, ?, '{}')
                        """,
                        (state_event_id, quota_scope_id, actor_id, now),
                    )
                    self._commit_result_locked(
                        mutation_id=request.mutation_id,
                        operation=operation,
                        expected_state="ACCOUNT_CUSTODY_CREATED",
                        result=result,
                        actor_id=actor_id,
                        alias=request.alias,
                        audit_event_id=audit_event_id,
                        now_ms=now,
                        audit_extra={
                            "pool_alias": request.pool_alias,
                            "priority": request.priority,
                            "state": "UNKNOWN",
                        },
                        active_secret=secret,
                    )
            except Exception as error:
                await self._rollback_new_custody(request.mutation_id, credential_id)
                if isinstance(error, AccountLifecycleConflict):
                    raise
                if isinstance(error, sqlite3.IntegrityError):
                    raise AccountLifecycleConflict(
                        "account metadata conflicts with an existing route"
                    ) from error
                if isinstance(error, AccountLifecycleFailure):
                    raise
                raise AccountLifecycleFailure("account metadata could not be committed") from error
            return result
        finally:
            self._wipe(secret)

    async def _cleanup_new_custody(self, credential_id: str) -> bool:
        try:
            await self._key_store.delete(credential_id)
            return True
        except CredentialNotFoundError:
            try:
                return await self._key_store.discard_partial(credential_id)
            except Exception:
                return False
        except Exception:
            try:
                return await self._key_store.discard_partial(credential_id)
            except Exception:
                return False

    async def _rollback_new_custody(self, mutation_id: str, credential_id: str) -> None:
        if await self._cleanup_new_custody(credential_id):
            self._mark_account_rolled_back(mutation_id)
        else:
            self._mark_account_cleanup_required(mutation_id)

    async def list_accounts(self, *, limit: int) -> Sequence[AccountStatus]:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 1_000:
            raise AccountLifecycleFailure("account list limit is invalid")
        now = self._safe_now()
        rows = self.connection.execute(
            """
            SELECT principal.principal_id, principal.alias,
                   scope.quota_scope_id, scope.state, scope.unit
              FROM principals AS principal
              JOIN quota_scopes AS scope ON scope.principal_id = principal.principal_id
             WHERE principal.service_id = 'firecrawl'
               AND principal.identity_kind = 'ACCOUNT'
               AND scope.scope_kind = 'TEAM'
               AND principal.enabled = 1
             ORDER BY principal.alias
             LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return tuple(self._status_for_row(row, now_ms=now) for row in rows)

    async def get_account_status(self, alias: str) -> AccountStatus | None:
        account = self._account(alias)
        if account is None:
            return None
        return self._status_for_row(account, now_ms=self._safe_now())

    async def rotate_account(
        self,
        alias: str,
        request: AccountRotationRequest,
        secret: bytearray,
        actor_id: str,
    ) -> AccountMutationResult:
        try:
            alias = self._validate_alias(alias)
            existing = self._journal(request.mutation_id, "credential.rotated")
            self._require_actor_binding(existing, actor_id)
            completed: AccountMutationResult | None
            try:
                completed = self._completed_account(existing, active_secret=secret)
            except AccountLifecycleFailure:
                if existing is None or str(existing["state"]) != "COMMITTED":
                    raise
                try:
                    CredentialMutationResult.model_validate_json(str(existing["result_json"]))
                except (TypeError, ValueError):
                    raise AccountLifecycleFailure("account rotation result is invalid") from None
                completed = None
            if completed is not None:
                if completed.alias != alias or completed.action != "rotate":
                    raise AccountLifecycleConflict("mutation identifier is already bound")
                return completed
            credential_id: str
            if existing is not None:
                stored_binding = _metadata(existing["metadata_json"])
                if stored_binding.get("requested_expires_at_ms") != request.expires_at_ms:
                    raise AccountLifecycleConflict("mutation identifier is already bound")
                raw_credential_id = existing["credential_id"]
                if raw_credential_id is None:
                    raise AccountLifecycleConflict("mutation identifier is already bound")
                credential_id = str(raw_credential_id)
                bound = self.connection.execute(
                    """
                    SELECT 1
                      FROM credentials AS credential
                      JOIN principals AS principal
                        ON principal.principal_id = credential.principal_id
                     WHERE credential.credential_id = ? AND principal.alias = ?
                       AND principal.service_id = 'firecrawl'
                    """,
                    (credential_id, alias),
                ).fetchone()
                if bound is None:
                    raise AccountLifecycleConflict("mutation identifier is already bound")
            else:
                account = self._require_account(alias)
                current = self._current_credential(str(account["quota_scope_id"]))
                credential_id = str(current["credential_id"])
            credential_result = await super().rotate_credential(
                credential_id,
                CredentialRotationRequest(
                    mutation_id=request.mutation_id,
                    expires_at_ms=request.expires_at_ms,
                ),
                secret,
                actor_id,
            )
            account = self._require_account(alias)
            with transaction(self.connection, "IMMEDIATE"):
                updated = self.connection.execute(
                    """
                    UPDATE quota_observation_schedules
                       SET observer_credential_id = ?, observer_credential_generation = ?,
                           generation = generation + 1, updated_at_ms = ?
                     WHERE quota_scope_id = ?
                    """,
                    (
                        credential_result.credential_id,
                        credential_result.generation,
                        credential_result.acted_at_ms,
                        str(account["quota_scope_id"]),
                    ),
                )
                if updated.rowcount != 1:
                    raise AccountLifecycleFailure("account observation schedule is unavailable")
            state = self._status_for_row(account, now_ms=self._safe_now()).state
            result = AccountMutationResult(
                alias=alias,
                action="rotate",
                state=state,
                pool_alias=credential_result.pool_alias,
                priority=int(account["priority"]),
                generation=credential_result.generation,
                acted_at_ms=credential_result.acted_at_ms,
                audit_event_id=credential_result.audit_event_id,
            )
            with transaction(self.connection, "IMMEDIATE"):
                updated = self.connection.execute(
                    """
                    UPDATE credential_mutations SET result_json = ?
                     WHERE mutation_id = ? AND operation = 'credential.rotated'
                       AND state = 'COMMITTED'
                    """,
                    (result.model_dump_json(exclude_none=False), request.mutation_id),
                )
                if updated.rowcount != 1:
                    raise AccountLifecycleConflict("account rotation lost its result fence")
            return result
        finally:
            self._wipe(secret)

    async def change_account_state(
        self,
        alias: str,
        request: AccountStateChangeRequest,
        actor_id: str,
    ) -> AccountMutationResult:
        alias = self._validate_alias(alias)
        self._validate_identity(actor_id, field="actor identifier")
        operation = {
            "disable": "account.disabled",
            "recover": "account.recovered",
            "remove": "account.removed",
        }[request.action]
        binding = {
            "alias": alias,
            "action": request.action,
            "reason_fingerprint": _reason_fingerprint(
                request.reason,
                domain=_ACCOUNT_REASON_DOMAIN,
            ),
        }
        existing = self._journal(request.mutation_id, operation)
        self._require_binding(existing, binding)
        self._require_actor_binding(existing, actor_id)
        completed = self._completed_account(existing)
        if completed is not None:
            return completed
        account = self._require_account(alias)
        if request.action == "remove" and (
            any(
                self._active_work(str(row["credential_id"]))
                for row in self.connection.execute(
                    """
                    SELECT credential_id FROM credentials
                     WHERE quota_scope_id = ? AND credential_role = 'WORKLOAD'
                       AND state != 'RETIRED'
                    """,
                    (str(account["quota_scope_id"]),),
                )
            )
        ):
            raise AccountLifecycleConflict("account still owns active work")
        if existing is None or str(existing["state"]) in {"ROLLED_BACK", "FAILED"}:
            audit_event_id = self._event_id_factory()
            state_event_id = self._event_id_factory()
            self._prepare_account_mutation(
                mutation_id=request.mutation_id,
                operation=operation,
                actor_id=actor_id,
                state="ACCOUNT_STATE_PREPARED",
                credential_id=None,
                metadata={
                    **binding,
                    "audit_event_id": audit_event_id,
                    "state_event_id": state_event_id,
                },
            )
        else:
            metadata = _metadata(existing["metadata_json"])
            audit_event_id = str(metadata.get("audit_event_id", ""))
            state_event_id = str(metadata.get("state_event_id", ""))
            self._validate_identity(audit_event_id, field="audit event identifier")
            self._validate_identity(state_event_id, field="state event identifier")
        if request.action == "remove":
            return await self._finish_remove(
                account=account,
                mutation_id=request.mutation_id,
                operation=operation,
                actor_id=actor_id,
                audit_event_id=audit_event_id,
                state_event_id=state_event_id,
            )
        return self._finish_state_change(
            account=account,
            mutation_id=request.mutation_id,
            operation=operation,
            action=request.action,
            actor_id=actor_id,
            audit_event_id=audit_event_id,
            state_event_id=state_event_id,
        )

    def _finish_state_change(
        self,
        *,
        account: sqlite3.Row,
        mutation_id: str,
        operation: str,
        action: _AccountStateAction,
        actor_id: str,
        audit_event_id: str,
        state_event_id: str,
    ) -> AccountMutationResult:
        now = self._safe_now()
        quota_scope_id = str(account["quota_scope_id"])
        if action == "disable":
            transition = self._quota_state.operator_disable(
                quota_scope_id=quota_scope_id,
                actor_id=actor_id,
                now_ms=now,
                event_id=state_event_id,
            )
        else:
            transition = self._quota_state.operator_recover(
                quota_scope_id=quota_scope_id,
                actor_id=actor_id,
                now_ms=now,
                event_id=state_event_id,
            )
        if transition.status in {
            QuotaTransitionStatus.NOT_FOUND,
            QuotaTransitionStatus.INELIGIBLE,
            QuotaTransitionStatus.GENERATION_CONFLICT,
        }:
            raise AccountLifecycleConflict("account state transition is unavailable")
        with transaction(self.connection, "IMMEDIATE"):
            if action == "disable":
                self.connection.execute(
                    "UPDATE pool_members SET enabled = 0 WHERE quota_scope_id = ?",
                    (quota_scope_id,),
                )
                self.connection.execute(
                    """
                    UPDATE quota_observation_schedules
                       SET state = 'DISABLED', next_due_at_ms = NULL,
                           generation = generation + 1, updated_at_ms = ?
                     WHERE quota_scope_id = ?
                    """,
                    (now, quota_scope_id),
                )
            else:
                self.connection.execute(
                    "UPDATE pool_members SET enabled = 1 WHERE quota_scope_id = ?",
                    (quota_scope_id,),
                )
            refreshed = self._require_account(str(account["alias"]))
            state = self._status_for_row(refreshed, now_ms=now).state
            result = AccountMutationResult(
                alias=str(account["alias"]),
                action=action,
                state=state,
                pool_alias=str(account["pool_alias"]),
                priority=int(account["priority"]),
                generation=self._account_generation(quota_scope_id),
                acted_at_ms=now,
                audit_event_id=audit_event_id,
            )
            self._commit_result_locked(
                mutation_id=mutation_id,
                operation=operation,
                expected_state="ACCOUNT_STATE_PREPARED",
                result=result,
                actor_id=actor_id,
                alias=str(account["alias"]),
                audit_event_id=audit_event_id,
                now_ms=now,
                audit_extra={"action": action, "state": state, "reason_supplied": True},
            )
        return result

    async def _finish_remove(
        self,
        *,
        account: sqlite3.Row,
        mutation_id: str,
        operation: str,
        actor_id: str,
        audit_event_id: str,
        state_event_id: str,
    ) -> AccountMutationResult:
        quota_scope_id = str(account["quota_scope_id"])
        credentials = self.connection.execute(
            """
            SELECT credential_id, state FROM credentials
             WHERE quota_scope_id = ? AND credential_role = 'WORKLOAD'
             ORDER BY generation, credential_id
            """,
            (quota_scope_id,),
        ).fetchall()
        for credential in credentials:
            if str(credential["state"]) != "RETIRED" and self._active_work(
                str(credential["credential_id"])
            ):
                raise AccountLifecycleConflict("account still owns active work")
        now = self._safe_now()
        transition = self._quota_state.operator_disable(
            quota_scope_id=quota_scope_id,
            actor_id=actor_id,
            now_ms=now,
            event_id=state_event_id,
        )
        if transition.status in {
            QuotaTransitionStatus.NOT_FOUND,
            QuotaTransitionStatus.INELIGIBLE,
            QuotaTransitionStatus.GENERATION_CONFLICT,
        }:
            raise AccountLifecycleConflict("account removal state transition is unavailable")
        with transaction(self.connection, "IMMEDIATE"):
            self.connection.execute(
                "UPDATE pool_members SET enabled = 0 WHERE quota_scope_id = ?",
                (quota_scope_id,),
            )
            self.connection.execute(
                """
                UPDATE quota_observation_schedules
                   SET state = 'DISABLED', next_due_at_ms = NULL,
                       generation = generation + 1, updated_at_ms = ?
                 WHERE quota_scope_id = ?
                """,
                (now, quota_scope_id),
            )
        for credential in credentials:
            credential_id = str(credential["credential_id"])
            current = self.connection.execute(
                "SELECT state FROM credentials WHERE credential_id = ?",
                (credential_id,),
            ).fetchone()
            if current is None or str(current["state"]) == "RETIRED":
                continue
            await super().change_credential_state(
                credential_id,
                CredentialStateChangeRequest(
                    mutation_id=_retirement_mutation_id(mutation_id, credential_id),
                    action="retire",
                    reason=_CREDENTIAL_RETIRE_REASON,
                ),
                actor_id,
            )
        try:
            stored_ids = {item.credential_id for item in await self._key_store.list_metadata()}
        except Exception as error:
            _scrub_exception(error)
            raise AccountLifecycleFailure("account custody inventory is unavailable") from None
        for credential in credentials:
            credential_id = str(credential["credential_id"])
            if credential_id in stored_ids and not await self._cleanup_new_custody(credential_id):
                raise AccountLifecycleFailure("account custody cleanup is incomplete")
        with transaction(self.connection, "IMMEDIATE"):
            blocking = self.connection.execute(
                """
                SELECT 1 FROM credentials
                 WHERE quota_scope_id = ? AND credential_role = 'WORKLOAD'
                   AND state != 'RETIRED' LIMIT 1
                """,
                (quota_scope_id,),
            ).fetchone()
            if blocking is not None:
                raise AccountLifecycleConflict("account credential retirement is incomplete")
            principal = self.connection.execute(
                "SELECT metadata_json FROM principals WHERE principal_id = ?",
                (str(account["principal_id"]),),
            ).fetchone()
            scope = self.connection.execute(
                "SELECT metadata_json FROM quota_scopes WHERE quota_scope_id = ?",
                (quota_scope_id,),
            ).fetchone()
            principal_metadata = _metadata(
                None if principal is None else principal["metadata_json"]
            )
            scope_metadata = _metadata(None if scope is None else scope["metadata_json"])
            principal_metadata.update({"tombstoned": True, "tombstoned_at_ms": now})
            scope_metadata.update({"tombstoned": True, "tombstoned_at_ms": now})
            self.connection.execute(
                """
                UPDATE principals SET enabled = 0, metadata_json = ?, updated_at_ms = ?
                 WHERE principal_id = ? AND enabled = 1
                """,
                (_json(principal_metadata), now, str(account["principal_id"])),
            )
            self.connection.execute(
                "UPDATE quota_scopes SET metadata_json = ? WHERE quota_scope_id = ?",
                (_json(scope_metadata), quota_scope_id),
            )
            result = AccountMutationResult(
                alias=str(account["alias"]),
                action="remove",
                state="DISABLED",
                pool_alias=str(account["pool_alias"]),
                priority=int(account["priority"]),
                generation=self._account_generation(quota_scope_id),
                acted_at_ms=now,
                audit_event_id=audit_event_id,
            )
            self._commit_result_locked(
                mutation_id=mutation_id,
                operation=operation,
                expected_state="ACCOUNT_STATE_PREPARED",
                result=result,
                actor_id=actor_id,
                alias=str(account["alias"]),
                audit_event_id=audit_event_id,
                now_ms=now,
                audit_extra={"action": "remove", "state": "DISABLED", "reason_supplied": True},
            )
        return result

    async def refresh_account(
        self,
        alias: str,
        request: AccountRefreshRequest,
        actor_id: str,
    ) -> AccountStatus:
        if not self._manual_refresh_enabled or self._observation_collector is None:
            raise AccountRefreshUnavailable("account refresh is disabled")
        alias = self._validate_alias(alias)
        operation = "account.refreshed"
        binding = {"alias": alias}
        existing = self._journal(request.mutation_id, operation)
        self._require_binding(existing, binding)
        self._require_actor_binding(existing, actor_id)
        completed = self._completed_status(existing)
        if completed is not None:
            return completed
        if existing is not None:
            raise AccountLifecycleConflict("account refresh outcome is already bound")
        account = self._require_account(alias)
        credential = self._current_credential(str(account["quota_scope_id"]))
        if str(credential["state"]) != "HEALTHY":
            raise AccountLifecycleConflict("account observer credential is unavailable")
        audit_event_id = self._event_id_factory()
        self._prepare_account_mutation(
            mutation_id=request.mutation_id,
            operation=operation,
            actor_id=actor_id,
            state="ACCOUNT_REFRESH_PREPARED",
            credential_id=str(credential["credential_id"]),
            metadata={
                **binding,
                "credential_generation": int(credential["generation"]),
                "audit_event_id": audit_event_id,
            },
        )
        try:
            observed = await self._observation_collector.observe_credential(
                str(credential["credential_id"]),
                expected_generation=int(credential["generation"]),
                actor_id=actor_id,
                source=_OPERATOR_OBSERVATION_SOURCE,
                freshness_ttl_ms=self._freshness_ttl_ms,
                request_id=request.mutation_id,
            )
        except BaseException as error:
            self._mark_account_refresh_unknown(request.mutation_id)
            if isinstance(error, Exception):
                _scrub_exception(error)
                raise AccountLifecycleFailure("account refresh outcome is unresolved") from None
            raise
        try:
            if (
                observed.credential_id != str(credential["credential_id"])
                or observed.generation != int(credential["generation"])
                or observed.quota_scope_id != str(account["quota_scope_id"])
            ):
                raise AccountLifecycleFailure("account refresh result is invalid")
            status = self._status_for_row(account, now_ms=self._safe_now())
            now = self._safe_now()
            with transaction(self.connection, "IMMEDIATE"):
                self._commit_result_locked(
                    mutation_id=request.mutation_id,
                    operation=operation,
                    expected_state="ACCOUNT_REFRESH_PREPARED",
                    result=status,
                    actor_id=actor_id,
                    alias=alias,
                    audit_event_id=audit_event_id,
                    now_ms=now,
                    audit_extra={"state": status.state, "stale": status.stale},
                )
        except BaseException as error:
            self._mark_account_refresh_unknown(request.mutation_id)
            if isinstance(error, Exception):
                _scrub_exception(error)
                raise AccountLifecycleFailure("account refresh outcome is unresolved") from None
            raise
        return status

    def _mark_account_refresh_unknown(self, mutation_id: str) -> None:
        """Retain ambiguous refresh authority; interruption never makes it replayable."""

        try:
            now = self._safe_now()
            with transaction(self.connection, "IMMEDIATE"):
                self.connection.execute(
                    "UPDATE credential_mutations SET state = 'ACCOUNT_REFRESH_UNKNOWN', "
                    "updated_at_ms = ?, completed_at_ms = ? WHERE mutation_id = ? "
                    "AND operation = 'account.refreshed' AND state = 'ACCOUNT_REFRESH_PREPARED'",
                    (now, now, mutation_id),
                )
        except Exception as error:
            _scrub_exception(error)

    async def change_account_observation(
        self,
        alias: str,
        request: AccountObservationChangeRequest,
        actor_id: str,
    ) -> AccountObservationMutationResult:
        alias = self._validate_alias(alias)
        operation = f"account.observation.{request.action}d"
        binding = {
            "alias": alias,
            "action": request.action,
            "reason_fingerprint": _reason_fingerprint(
                request.reason,
                domain=_OBSERVATION_REASON_DOMAIN,
            ),
        }
        with transaction(self.connection, "IMMEDIATE"):
            existing = self._journal(request.mutation_id, operation)
            self._require_binding(existing, binding)
            self._require_actor_binding(existing, actor_id)
            completed = self._completed_observation(existing)
            if completed is not None:
                return completed
            if existing is not None:
                raise AccountLifecycleConflict("account observation mutation is already active")
            account = self._require_account(alias)
            credential = self._current_credential(str(account["quota_scope_id"]))
            if request.action == "enable" and str(credential["state"]) != "HEALTHY":
                raise AccountLifecycleConflict("account observer credential is unavailable")
            now = self._safe_now()
            audit_event_id = self._event_id_factory()
            self.connection.execute(
                """
                INSERT INTO credential_mutations(
                    mutation_id, operation, credential_id, state, actor_id,
                    created_at_ms, updated_at_ms, metadata_json
                ) VALUES (?, ?, ?, 'ACCOUNT_STATE_PREPARED', ?, ?, ?, ?)
                """,
                (
                    request.mutation_id,
                    operation,
                    str(credential["credential_id"]),
                    actor_id,
                    now,
                    now,
                    _json(binding),
                ),
            )
            target = "ENABLED" if request.action == "enable" else "DISABLED"
            next_due = now if request.action == "enable" else None
            updated = self.connection.execute(
                """
                UPDATE quota_observation_schedules
                   SET observer_credential_id = ?, observer_credential_generation = ?,
                       state = ?, next_due_at_ms = ?, generation = generation + 1,
                       updated_at_ms = ?
                 WHERE quota_scope_id = ?
                """,
                (
                    str(credential["credential_id"]),
                    int(credential["generation"]),
                    target,
                    next_due,
                    now,
                    str(account["quota_scope_id"]),
                ),
            )
            if updated.rowcount != 1:
                raise AccountLifecycleFailure("account observation schedule is unavailable")
            result = AccountObservationMutationResult(
                alias=alias,
                action=request.action,
                enabled=request.action == "enable",
                acted_at_ms=now,
                audit_event_id=audit_event_id,
            )
            self._commit_result_locked(
                mutation_id=request.mutation_id,
                operation=operation,
                expected_state="ACCOUNT_STATE_PREPARED",
                result=result,
                actor_id=actor_id,
                alias=alias,
                audit_event_id=audit_event_id,
                now_ms=now,
                audit_extra={
                    "action": request.action,
                    "enabled": request.action == "enable",
                    "reason_supplied": True,
                },
            )
        return result

    async def recover_incomplete_account_mutations(self) -> int:
        """Clean orphan onboarding custody and resume non-network state mutations."""

        rows = self.connection.execute(
            f"""
            SELECT mutation_id, operation, credential_id, state, actor_id, metadata_json
              FROM credential_mutations
             WHERE state IN ({",".join("?" for _ in _ACCOUNT_JOURNAL_STATES)})
             ORDER BY created_at_ms, mutation_id
            """,  # noqa: S608
            _ACCOUNT_JOURNAL_STATES,
        ).fetchall()
        recovered = 0
        for row in rows:
            mutation_id = str(row["mutation_id"])
            operation = str(row["operation"])
            state = str(row["state"])
            metadata = _metadata(row["metadata_json"])
            if operation == "account.added":
                credential_id = row["credential_id"]
                cleaned = credential_id is None
                if credential_id is not None:
                    candidate = str(credential_id)
                    custody_alias = metadata.get("custody_intent_alias")
                    custody_created = metadata.get("custody_created") is True
                    if not custody_created and isinstance(custody_alias, str):
                        try:
                            cleaned = await self._discard_staged_custody(candidate, metadata)
                            if not cleaned and await self._matches_custody_intent(
                                candidate,
                                metadata,
                            ):
                                cleaned = await self._cleanup_new_custody(candidate)
                        except Exception:
                            cleaned = False
                    else:
                        cleaned = await self._cleanup_new_custody(candidate)
                if cleaned:
                    self._mark_account_rolled_back(mutation_id)
                    recovered += 1
                else:
                    self._mark_account_cleanup_required(mutation_id)
                continue
            if state == "ACCOUNT_REFRESH_PREPARED":
                self._mark_account_refresh_unknown(mutation_id)
                recovered += 1
                continue
            if state == "ACCOUNT_STATE_PREPARED" and operation in {
                "account.disabled",
                "account.recovered",
                "account.removed",
            }:
                alias = metadata.get("alias")
                audit_event_id = metadata.get("audit_event_id")
                state_event_id = metadata.get("state_event_id")
                identifiers = (alias, audit_event_id, state_event_id)
                if not all(isinstance(item, str) and item for item in identifiers):
                    self._mark_account_cleanup_required(mutation_id)
                    continue
                account = self._account(cast(str, alias))
                if account is None:
                    self._mark_account_cleanup_required(mutation_id)
                    continue
                action = {
                    "account.disabled": "disable",
                    "account.recovered": "recover",
                    "account.removed": "remove",
                }[operation]
                try:
                    if action == "remove":
                        await self._finish_remove(
                            account=account,
                            mutation_id=mutation_id,
                            operation=operation,
                            actor_id=str(row["actor_id"]),
                            audit_event_id=cast(str, audit_event_id),
                            state_event_id=cast(str, state_event_id),
                        )
                    else:
                        self._finish_state_change(
                            account=account,
                            mutation_id=mutation_id,
                            operation=operation,
                            action=cast(_AccountStateAction, action),
                            actor_id=str(row["actor_id"]),
                            audit_event_id=cast(str, audit_event_id),
                            state_event_id=cast(str, state_event_id),
                        )
                except AccountLifecycleConflict as error:
                    _scrub_exception(error)
                except Exception as error:
                    _scrub_exception(error)
                else:
                    recovered += 1
        return recovered + self.repair_account_schedule_bindings()

    def repair_account_schedule_bindings(self) -> int:
        """Rebind schedules to current workload generations without changing opt-in state."""

        now = self._safe_now()
        repaired = 0
        with transaction(self.connection, "IMMEDIATE"):
            rows = self.connection.execute(
                """
                SELECT schedule.schedule_id, schedule.generation AS schedule_generation,
                       schedule.observer_credential_id,
                       schedule.observer_credential_generation,
                       (
                           SELECT credential.credential_id
                             FROM credentials AS credential
                            WHERE credential.quota_scope_id = scope.quota_scope_id
                              AND credential.credential_role = 'WORKLOAD'
                              AND credential.state = 'HEALTHY'
                            ORDER BY credential.generation DESC,
                                     credential.created_at_ms DESC,
                                     credential.credential_id DESC
                            LIMIT 1
                       ) AS current_credential_id,
                       (
                           SELECT credential.generation
                             FROM credentials AS credential
                            WHERE credential.quota_scope_id = scope.quota_scope_id
                              AND credential.credential_role = 'WORKLOAD'
                              AND credential.state = 'HEALTHY'
                            ORDER BY credential.generation DESC,
                                     credential.created_at_ms DESC,
                                     credential.credential_id DESC
                            LIMIT 1
                       ) AS current_credential_generation
                  FROM quota_observation_schedules AS schedule
                  JOIN quota_scopes AS scope
                    ON scope.quota_scope_id = schedule.quota_scope_id
                  JOIN principals AS principal
                    ON principal.principal_id = scope.principal_id
                 WHERE principal.service_id = 'firecrawl'
                   AND principal.identity_kind = 'ACCOUNT'
                   AND principal.enabled = 1
                   AND scope.scope_kind = 'TEAM'
                 ORDER BY schedule.schedule_id
                """
            ).fetchall()
            for row in rows:
                current_id = row["current_credential_id"]
                current_generation = row["current_credential_generation"]
                if current_id is None or current_generation is None:
                    continue
                if (
                    row["observer_credential_id"] == current_id
                    and row["observer_credential_generation"] == current_generation
                ):
                    continue
                updated = self.connection.execute(
                    """
                    UPDATE quota_observation_schedules
                       SET observer_credential_id = ?,
                           observer_credential_generation = ?,
                           generation = generation + 1, updated_at_ms = ?
                     WHERE schedule_id = ? AND generation = ?
                    """,
                    (
                        str(current_id),
                        int(current_generation),
                        now,
                        str(row["schedule_id"]),
                        int(row["schedule_generation"]),
                    ),
                )
                repaired += updated.rowcount
        return repaired
