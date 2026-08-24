"""Single-dispatch administrative validation for one installed credential."""

from __future__ import annotations

import asyncio
import hashlib
import json
import math
import sqlite3
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal, Protocol

from gatehouse.credentials import CredentialMetadata, KeyStore, SecretScanner
from gatehouse.database import AuditEvent, GatehouseRepository, LeaseStatus
from gatehouse.database.quota_state import (
    QuotaObservationStatus,
    SqliteQuotaStateRepository,
)
from gatehouse.providers.base import (
    CredentialCustodyKind,
    CredentialRole,
    ProviderErrorClass,
    ProviderRequest,
    ProviderResponse,
)
from gatehouse.providers.firecrawl.adapter import FirecrawlAdapter, FirecrawlOutcome
from gatehouse.reconciliation import ReconciliationStore

from .models import CredentialValidationRequest, CredentialValidationResult

_OPERATION = "firecrawl.account.credit_status"
_SOURCE = "admin-credential-validation"
_SCHEDULED_SOURCE = "scheduled-firecrawl-credit-observation"
_ACCOUNT_REFRESH_SOURCE = "account-manual-refresh"
_ALLOWED_SOURCES = frozenset({_SOURCE, _SCHEDULED_SOURCE, _ACCOUNT_REFRESH_SOURCE})
_REQUEST_TIMEOUT_MS = 10_000
_MAXIMUM_RESPONSE_BYTES = 64 * 1_024
_METADATA_DEADLINE_SECONDS = 5.0
_MAXIMUM_DISPATCH_DEADLINE_SECONDS = 15.0
_MAXIMUM_DATABASE_WAIT_MS = 5_000
_LEASE_NONDISPATCH_MARGIN_MS = 20_000
_POST_HEARTBEAT_MARGIN_MS = 15_000
_DEFAULT_FRESHNESS_TTL_MS = 30 * 60 * 1_000
_MAXIMUM_FRESHNESS_TTL_MS = 7 * 24 * 60 * 60 * 1_000


class ProviderTransport(Protocol):
    async def send(self, request: ProviderRequest) -> ProviderResponse: ...


class CredentialValidationError(RuntimeError):
    """Base class for secret-free credential-validation failures."""


class CredentialValidationUnavailable(CredentialValidationError):
    """Validation is disabled or its exact authority is unavailable."""


class CredentialValidationBusy(CredentialValidationError):
    """The single process slot or exact durable credential lease is busy."""


class CredentialValidationProviderFailure(CredentialValidationError):
    """The one provider exchange completed without validated authentication."""

    def __init__(
        self,
        error_class: ProviderErrorClass,
        retry_after_seconds: float | None = None,
    ) -> None:
        self.error_class = error_class
        self.retry_after_seconds = _safe_retry_after(retry_after_seconds)
        super().__init__("provider credential validation did not authenticate")


class CredentialValidationPersistenceError(CredentialValidationError):
    """Durable sanitized credential-validation evidence could not be committed."""


@dataclass(frozen=True, slots=True)
class _CredentialAuthority:
    credential_id: str
    principal_id: str
    quota_scope_id: str
    alias: str
    generation: int
    credential_role: CredentialRole
    secret_reference: str
    expires_at_ms: int | None


class SqliteCredentialValidationService:
    """Validate exactly one persistent generation through one fixed provider read."""

    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        transport: ProviderTransport,
        persistent_key_store: KeyStore,
        provider_mode: Literal["disabled", "scripted", "live"],
        network_enabled: bool,
        now_ms: Callable[[], int] | None = None,
        adapter: FirecrawlAdapter | None = None,
        repository: GatehouseRepository | None = None,
        quota_state: SqliteQuotaStateRepository | None = None,
        audit_store: ReconciliationStore | None = None,
        scanner: SecretScanner | None = None,
        event_id_factory: Callable[[], str] | None = None,
        snapshot_id_factory: Callable[[], str] | None = None,
        lease_id_factory: Callable[[], str] | None = None,
        dispatch_deadline_seconds: float = _MAXIMUM_DISPATCH_DEADLINE_SECONDS,
        lease_ttl_ms: int = 45_000,
        freshness_ttl_ms: int = _DEFAULT_FRESHNESS_TTL_MS,
        maximum_concurrent_validations: int = 1,
    ) -> None:
        if provider_mode not in {"disabled", "scripted", "live"}:
            raise ValueError("provider mode is invalid")
        if not isinstance(network_enabled, bool):
            raise ValueError("provider network switch must be boolean")
        if (
            isinstance(dispatch_deadline_seconds, bool)
            or not isinstance(dispatch_deadline_seconds, (int, float))
            or not math.isfinite(dispatch_deadline_seconds)
            or not 0 < dispatch_deadline_seconds <= _MAXIMUM_DISPATCH_DEADLINE_SECONDS
        ):
            raise ValueError("credential validation dispatch deadline is invalid")
        minimum_lease_ttl_ms = (
            math.ceil((_METADATA_DEADLINE_SECONDS + dispatch_deadline_seconds) * 1_000)
            + _LEASE_NONDISPATCH_MARGIN_MS
        )
        if lease_ttl_ms <= minimum_lease_ttl_ms or lease_ttl_ms > 60_000:
            raise ValueError("credential validation lease TTL is invalid")
        if (
            isinstance(freshness_ttl_ms, bool)
            or not isinstance(freshness_ttl_ms, int)
            or not 60_000 <= freshness_ttl_ms <= _MAXIMUM_FRESHNESS_TTL_MS
        ):
            raise ValueError("credential validation freshness TTL is invalid")
        if (
            isinstance(maximum_concurrent_validations, bool)
            or not isinstance(maximum_concurrent_validations, int)
            or not 1 <= maximum_concurrent_validations <= 8
        ):
            raise ValueError("credential validation concurrency is invalid")
        self.connection = connection
        self._transport = transport
        self._key_store = persistent_key_store
        self._provider_mode = provider_mode
        self._network_enabled = network_enabled
        self._now_ms = now_ms or (lambda: int(time.time() * 1_000))
        self._adapter = adapter or FirecrawlAdapter()
        self._repository = repository or GatehouseRepository(connection)
        self._quota_state = quota_state or SqliteQuotaStateRepository(connection)
        self._audit_store = audit_store or ReconciliationStore(connection, scanner=scanner)
        self._scanner = scanner or SecretScanner()
        self._event_id_factory = event_id_factory or (lambda: _identifier("evt"))
        self._snapshot_id_factory = snapshot_id_factory or (lambda: _identifier("snapshot"))
        self._lease_id_factory = lease_id_factory or (lambda: _identifier("lease"))
        self._dispatch_deadline_seconds = float(dispatch_deadline_seconds)
        self._lease_ttl_ms = lease_ttl_ms
        self._freshness_ttl_ms = freshness_ttl_ms
        self._slot = threading.BoundedSemaphore(maximum_concurrent_validations)

    async def validate_credential(
        self,
        credential_id: str,
        request: CredentialValidationRequest,
        actor_id: str,
    ) -> CredentialValidationResult:
        return await self.observe_credential(
            credential_id,
            expected_generation=request.expected_generation,
            actor_id=actor_id,
            source=_SOURCE,
            freshness_ttl_ms=self._freshness_ttl_ms,
        )

    async def observe_credential(
        self,
        credential_id: str,
        *,
        expected_generation: int,
        actor_id: str,
        source: str,
        freshness_ttl_ms: int,
    ) -> CredentialValidationResult:
        if self._provider_mode != "live" or not self._network_enabled:
            raise CredentialValidationUnavailable(
                "credential validation requires explicit live provider networking"
            )
        self._require_bounded_database_wait()
        _validate_identifier(credential_id, name="credential identifier")
        _validate_identifier(actor_id, name="administrative actor identifier")
        if (
            isinstance(expected_generation, bool)
            or not isinstance(expected_generation, int)
            or expected_generation <= 0
        ):
            raise ValueError("expected credential generation must be positive")
        if source not in _ALLOWED_SOURCES:
            raise ValueError("credential observation source is unsupported")
        if (
            isinstance(freshness_ttl_ms, bool)
            or not isinstance(freshness_ttl_ms, int)
            or not 60_000 <= freshness_ttl_ms <= _MAXIMUM_FRESHNESS_TTL_MS
        ):
            raise ValueError("credential observation freshness TTL is invalid")
        self._assert_clean_identifier(credential_id)
        self._assert_clean_identifier(actor_id)
        if not self._slot.acquire(blocking=False):
            raise CredentialValidationBusy("credential validation is already in progress")

        try:
            return await self._validate_in_slot(
                credential_id,
                expected_generation,
                actor_id,
                source=source,
                freshness_ttl_ms=freshness_ttl_ms,
            )
        finally:
            self._slot.release()

    async def _validate_in_slot(
        self,
        credential_id: str,
        expected_generation: int,
        actor_id: str,
        *,
        source: str,
        freshness_ttl_ms: int,
    ) -> CredentialValidationResult:
        started_at_ms = self._safe_now()
        lease_id = self._bounded_factory_value(self._lease_id_factory, "validation lease")
        owner_id = _identifier("validation")
        lease_failed = False
        lease = None
        try:
            lease = self._repository.acquire_credential_validation_lease(
                credential_id=credential_id,
                expected_generation=expected_generation,
                owner_id=owner_id,
                now_ms=started_at_ms,
                expires_at_ms=started_at_ms + self._lease_ttl_ms,
                lease_id=lease_id,
            )
        except Exception as error:
            _scrub_exception(error)
            lease_failed = True
        if lease_failed:
            raise CredentialValidationUnavailable(
                "credential validation authority could not be established"
            ) from None
        if lease is None:
            raise CredentialValidationUnavailable(
                "credential validation authority could not be established"
            )
        if lease.status is LeaseStatus.BUSY:
            raise CredentialValidationBusy("credential validation authority is busy")
        if lease.status is LeaseStatus.INELIGIBLE:
            raise CredentialValidationUnavailable(
                "the exact persistent credential generation is unavailable"
            )
        if lease.status is not LeaseStatus.ACQUIRED or lease.lease_id != lease_id:
            raise CredentialValidationUnavailable(
                "credential validation authority could not be established"
            )

        cancellation: asyncio.CancelledError | None = None
        try:
            return await self._validate_with_lease(
                credential_id=credential_id,
                expected_generation=expected_generation,
                actor_id=actor_id,
                lease_id=lease_id,
                owner_id=owner_id,
                source=source,
                freshness_ttl_ms=freshness_ttl_ms,
            )
        except asyncio.CancelledError as error:
            cancellation = error
            raise
        finally:
            release_failed = False
            released = False
            try:
                released = self._repository.release_lease(
                    lease_id=lease_id,
                    owner_id=owner_id,
                    now_ms=self._safe_now(),
                )
            except Exception as error:
                _scrub_exception(error)
                release_failed = True
            if release_failed or not released:
                if cancellation is not None:
                    cancellation.add_note("credential validation lease release failed")
                else:
                    raise CredentialValidationUnavailable(
                        "credential validation authority could not be released"
                    ) from None

    async def _validate_with_lease(
        self,
        *,
        credential_id: str,
        expected_generation: int,
        actor_id: str,
        lease_id: str,
        owner_id: str,
        source: str,
        freshness_ttl_ms: int,
    ) -> CredentialValidationResult:
        authority = self._load_authority(credential_id, expected_generation)
        metadata_failed = False
        metadata_items: tuple[CredentialMetadata, ...] = ()
        try:
            metadata_items = await asyncio.wait_for(
                self._key_store.list_metadata(),
                timeout=_METADATA_DEADLINE_SECONDS,
            )
        except asyncio.CancelledError:
            raise
        except Exception as error:
            _scrub_exception(error)
            metadata_failed = True
        if metadata_failed:
            raise CredentialValidationUnavailable(
                "persistent credential custody metadata is unavailable"
            ) from None
        self._verify_custody(authority, metadata_items)
        heartbeat_at_ms = self._safe_now()
        heartbeat_expires_at_ms = heartbeat_at_ms + self._lease_ttl_ms
        heartbeat_failed = False
        heartbeat_succeeded = False
        try:
            heartbeat_succeeded = self._repository.heartbeat_lease(
                lease_id=lease_id,
                owner_id=owner_id,
                now_ms=heartbeat_at_ms,
                expires_at_ms=heartbeat_expires_at_ms,
            )
        except Exception as error:
            _scrub_exception(error)
            heartbeat_failed = True
        minimum_remaining_ms = (
            math.ceil(self._dispatch_deadline_seconds * 1_000) + _POST_HEARTBEAT_MARGIN_MS
        )
        if (
            heartbeat_failed
            or not heartbeat_succeeded
            or heartbeat_expires_at_ms - self._safe_now() <= minimum_remaining_ms
        ):
            raise CredentialValidationUnavailable(
                "credential validation authority could not be refreshed"
            ) from None

        request = self._adapter.build_request(
            _OPERATION,
            {},
            credential_id=credential_id,
            credential_generation=expected_generation,
            credential_role=authority.credential_role,
        )
        self._verify_fixed_request(
            request,
            credential_id=credential_id,
            expected_generation=expected_generation,
        )
        if self.connection.in_transaction:
            raise CredentialValidationUnavailable(
                "credential validation cannot dispatch inside a database transaction"
            )

        dispatch_failed = False
        dispatch_timed_out = False
        response: ProviderResponse | None = None
        try:
            response = await asyncio.wait_for(
                self._transport.send(request),
                timeout=self._dispatch_deadline_seconds,
            )
        except asyncio.CancelledError:
            raise
        except TimeoutError as error:
            _scrub_exception(error)
            dispatch_timed_out = True
        except Exception as error:
            _scrub_exception(error)
            dispatch_failed = True
        if dispatch_timed_out:
            self._record_failure_audit(
                credential_id=credential_id,
                expected_generation=expected_generation,
                actor_id=actor_id,
                error_class=ProviderErrorClass.TIMEOUT,
            )
            raise CredentialValidationProviderFailure(ProviderErrorClass.TIMEOUT) from None
        if dispatch_failed or response is None:
            self._record_failure_audit(
                credential_id=credential_id,
                expected_generation=expected_generation,
                actor_id=actor_id,
                error_class=ProviderErrorClass.UNKNOWN_OUTCOME,
            )
            raise CredentialValidationUnavailable("provider credential validation failed") from None

        classification_failed = False
        outcome: FirecrawlOutcome | None = None
        try:
            outcome = self._adapter.classify_response(_OPERATION, response)
        except Exception as error:
            _scrub_exception(error)
            classification_failed = True
        del response
        if classification_failed or outcome is None:
            self._record_failure_audit(
                credential_id=credential_id,
                expected_generation=expected_generation,
                actor_id=actor_id,
                error_class=ProviderErrorClass.MALFORMED_RESPONSE,
            )
            raise CredentialValidationProviderFailure(ProviderErrorClass.MALFORMED_RESPONSE)
        if not outcome.succeeded:
            error_class = _stable_failure_class(outcome.error_class)
            if error_class is ProviderErrorClass.QUOTA_EXHAUSTED:
                self._record_definitive_exhaustion(
                    authority=authority,
                    observed_at_ms=self._safe_now(),
                )
            self._record_failure_audit(
                credential_id=credential_id,
                expected_generation=expected_generation,
                actor_id=actor_id,
                error_class=error_class,
            )
            raise CredentialValidationProviderFailure(
                error_class,
                outcome.retry_after_seconds,
            )
        parse_failed = False
        try:
            credit_status = self._adapter.parse_credit_status(outcome)
        except Exception as error:
            _scrub_exception(error)
            parse_failed = True
        del outcome
        if parse_failed:
            self._record_failure_audit(
                credential_id=credential_id,
                expected_generation=expected_generation,
                actor_id=actor_id,
                error_class=ProviderErrorClass.MALFORMED_RESPONSE,
            )
            raise CredentialValidationProviderFailure(ProviderErrorClass.MALFORMED_RESPONSE)

        captured_at_ms = self._safe_now()
        snapshot_id = self._bounded_factory_value(
            self._snapshot_id_factory,
            "quota snapshot",
        )
        audit_event_id = self._bounded_factory_value(
            self._event_id_factory,
            "validation audit event",
        )
        stale_at_ms = captured_at_ms + freshness_ttl_ms
        if stale_at_ms > (1 << 63) - 1:
            raise CredentialValidationPersistenceError(
                "credential validation freshness boundary is invalid"
            )
        payload_json = json.dumps(
            {
                "actor_id": actor_id,
                "credential_generation": expected_generation,
                "credential_id": credential_id,
                "outcome": "authenticated",
                "principal_id": authority.principal_id,
                "quota_scope_id": authority.quota_scope_id,
                "snapshot_id": snapshot_id,
                "source": source,
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )
        self._scanner.assert_clean(payload_json, location="credential_validation.audit")
        audit_event = AuditEvent(
            event_id=audit_event_id,
            occurred_at_ms=captured_at_ms,
            event_type="credential.provider_validated",
            severity="INFO",
            payload_json=payload_json,
            service_id="firecrawl",
            operation=_OPERATION,
            preserve=True,
        )
        persistence_failed = False
        observation = None
        try:
            observation = self._quota_state.record_authenticated_observation(
                quota_scope_id=authority.quota_scope_id,
                credential_id=credential_id,
                credential_generation=expected_generation,
                unit="credits",
                exact_remaining=credit_status.observed_remaining_credits_decimal,
                exact_plan_total=credit_status.observed_plan_credits_decimal,
                period_start_ms=credit_status.billing_period_start_ms,
                period_end_ms=credit_status.billing_period_end_ms,
                captured_at_ms=captured_at_ms,
                stale_at_ms=stale_at_ms,
                source=source,
                now_ms=captured_at_ms,
                snapshot_id=snapshot_id,
                audit_event=audit_event,
            )
        except Exception as error:
            _scrub_exception(error)
            persistence_failed = True
        if persistence_failed:
            raise CredentialValidationPersistenceError(
                "credential validation evidence could not be committed"
            ) from None
        if (
            observation is None
            or observation.status
            not in {QuotaObservationStatus.RECORDED, QuotaObservationStatus.RECORDED_STALE}
            or observation.snapshot_id != snapshot_id
        ):
            raise CredentialValidationPersistenceError(
                "credential validation evidence identity is inconsistent"
            )
        return CredentialValidationResult(
            credential_id=credential_id,
            generation=expected_generation,
            service="firecrawl",
            principal_id=authority.principal_id,
            quota_scope_id=authority.quota_scope_id,
            state="authenticated",
            snapshot_id=snapshot_id,
            unit="credits",
            remaining_units=credit_status.remaining_credits,
            plan_total_units=credit_status.plan_credits,
            observed_remaining_units_decimal=(credit_status.observed_remaining_credits_decimal),
            observed_plan_total_units_decimal=credit_status.observed_plan_credits_decimal,
            captured_at_ms=captured_at_ms,
            audit_event_id=audit_event_id,
        )

    def _record_definitive_exhaustion(
        self,
        *,
        authority: _CredentialAuthority,
        observed_at_ms: int,
    ) -> None:
        failed = False
        try:
            self._quota_state.mark_definitive_exhaustion(
                quota_scope_id=authority.quota_scope_id,
                now_ms=observed_at_ms,
                reason_code="OBSERVATION_QUOTA_EXHAUSTED",
                credential_id=authority.credential_id,
                credential_generation=authority.generation,
            )
        except Exception as error:
            _scrub_exception(error)
            failed = True
        if failed:
            raise CredentialValidationPersistenceError(
                "credential validation exhaustion evidence could not be committed"
            ) from None

    def _record_failure_audit(
        self,
        *,
        credential_id: str,
        expected_generation: int,
        actor_id: str,
        error_class: ProviderErrorClass,
    ) -> None:
        persistence_failed = False
        recorded_event_id: str | None = None
        audit_event_id: str | None = None
        try:
            stable_error_class = _stable_failure_class(error_class)
            captured_at_ms = self._safe_now()
            audit_event_id = self._bounded_factory_value(
                self._event_id_factory,
                "validation failure audit event",
            )
            payload_json = json.dumps(
                {
                    "actor_id": actor_id,
                    "credential_generation": expected_generation,
                    "credential_id": credential_id,
                    "error_class": stable_error_class.value,
                    "outcome": "failed",
                },
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            )
            self._scanner.assert_clean(
                payload_json,
                location="credential_validation.failure_audit",
            )
            recorded_event_id = self._audit_store.record_audit_event(
                AuditEvent(
                    event_id=audit_event_id,
                    occurred_at_ms=captured_at_ms,
                    event_type="credential.provider_validation_failed",
                    severity="WARNING",
                    payload_json=payload_json,
                    service_id="firecrawl",
                    operation=_OPERATION,
                    preserve=True,
                )
            )
        except Exception as error:
            _scrub_exception(error)
            persistence_failed = True
        if persistence_failed or audit_event_id is None or recorded_event_id != audit_event_id:
            raise CredentialValidationPersistenceError(
                "credential validation failure evidence could not be committed"
            ) from None

    def _load_authority(
        self,
        credential_id: str,
        expected_generation: int,
    ) -> _CredentialAuthority:
        query_failed = False
        row: sqlite3.Row | None = None
        try:
            row = self.connection.execute(
                """
                SELECT c.credential_id, c.principal_id, c.quota_scope_id, c.alias,
                       c.state, c.generation, c.secret_backend, c.secret_reference,
                       c.expires_at_ms, c.credential_role,
                       pr.service_id, pr.enabled, qs.unit
                  FROM credentials AS c
                  JOIN quota_scopes AS qs
                    ON qs.quota_scope_id = c.quota_scope_id
                   AND qs.principal_id = c.principal_id
                  JOIN principals AS pr
                    ON pr.principal_id = c.principal_id
                 WHERE c.credential_id = ? AND c.generation = ?
                """,
                (credential_id, expected_generation),
            ).fetchone()
        except Exception as error:
            _scrub_exception(error)
            query_failed = True
        if query_failed or row is None:
            raise CredentialValidationUnavailable(
                "the exact persistent credential generation is unavailable"
            ) from None
        expires_at_ms = None if row["expires_at_ms"] is None else int(row["expires_at_ms"])
        try:
            credential_role = CredentialRole(str(row["credential_role"]))
        except ValueError:
            raise CredentialValidationUnavailable(
                "the exact persistent credential generation is unavailable"
            ) from None
        if (
            str(row["state"]) != "HEALTHY"
            or str(row["secret_backend"]) != "dpapi-current-user"
            or str(row["service_id"]) != "firecrawl"
            or int(row["enabled"]) != 1
            or str(row["unit"]) != "credits"
            or credential_role not in {CredentialRole.WORKLOAD, CredentialRole.OBSERVER}
            or (expires_at_ms is not None and expires_at_ms <= self._safe_now())
        ):
            raise CredentialValidationUnavailable(
                "the exact persistent credential generation is unavailable"
            )
        authority = _CredentialAuthority(
            credential_id=str(row["credential_id"]),
            principal_id=str(row["principal_id"]),
            quota_scope_id=str(row["quota_scope_id"]),
            alias=str(row["alias"]),
            generation=int(row["generation"]),
            credential_role=credential_role,
            secret_reference=str(row["secret_reference"]),
            expires_at_ms=expires_at_ms,
        )
        expected_reference = _dpapi_reference(authority.credential_id)
        if authority.secret_reference != expected_reference:
            raise CredentialValidationUnavailable(
                "persistent credential custody metadata is inconsistent"
            )
        return authority

    def _verify_custody(
        self,
        authority: _CredentialAuthority,
        items: tuple[CredentialMetadata, ...],
    ) -> None:
        if len(items) > 10_000:
            raise CredentialValidationUnavailable(
                "persistent credential custody metadata exceeds its bound"
            )
        matches = tuple(item for item in items if item.credential_id == authority.credential_id)
        if len(matches) != 1:
            raise CredentialValidationUnavailable(
                "persistent credential custody metadata is inconsistent"
            )
        item = matches[0]
        if (
            item.principal_id != authority.principal_id
            or item.quota_scope_id != authority.quota_scope_id
            or item.alias != authority.alias
            or item.state != "HEALTHY"
            or item.generation != authority.generation
            or item.secret_reference != authority.secret_reference
            or item.expires_at_ms != authority.expires_at_ms
        ):
            raise CredentialValidationUnavailable(
                "persistent credential custody metadata is inconsistent"
            )

    @staticmethod
    def _verify_fixed_request(
        request: ProviderRequest,
        *,
        credential_id: str,
        expected_generation: int,
    ) -> None:
        if (
            request.method != "GET"
            or request.path != "/v2/team/credit-usage"
            or request.json_body is not None
            or dict(request.query)
            or request.timeout_ms != _REQUEST_TIMEOUT_MS
            or request.maximum_response_bytes != _MAXIMUM_RESPONSE_BYTES
            or request.operation != _OPERATION
            or request.credential_id != credential_id
            or request.credential_generation != expected_generation
            or request.credential_custody is not CredentialCustodyKind.PERSISTENT
            or request.provider_id != "firecrawl"
            or request.credential_role not in {CredentialRole.WORKLOAD, CredentialRole.OBSERVER}
        ):
            raise CredentialValidationUnavailable(
                "credential validation provider request is not fixed"
            )

    def _assert_clean_identifier(self, value: str) -> None:
        failed = False
        try:
            self._scanner.assert_clean(value, location="credential_validation.identifier")
        except Exception as error:
            _scrub_exception(error)
            failed = True
        if failed:
            raise ValueError("credential validation identifier is invalid") from None

    def _bounded_factory_value(self, factory: Callable[[], str], name: str) -> str:
        failed = False
        value: object = None
        try:
            value = factory()
        except Exception as error:
            _scrub_exception(error)
            failed = True
        if failed or not isinstance(value, str) or not value or len(value) > 160:
            raise CredentialValidationUnavailable(f"{name} identity is unavailable") from None
        self._assert_clean_identifier(value)
        return value

    def _safe_now(self) -> int:
        failed = False
        value: object = None
        try:
            value = self._now_ms()
        except Exception as error:
            _scrub_exception(error)
            failed = True
        if failed or isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise CredentialValidationUnavailable("validation clock is unavailable") from None
        return value

    def _require_bounded_database_wait(self) -> None:
        failed = False
        row: sqlite3.Row | tuple[object, ...] | None = None
        try:
            row = self.connection.execute("PRAGMA busy_timeout").fetchone()
        except Exception as error:
            _scrub_exception(error)
            failed = True
        value = None if row is None else row[0]
        if (
            failed
            or isinstance(value, bool)
            or not isinstance(value, int)
            or not 0 < value <= _MAXIMUM_DATABASE_WAIT_MS
        ):
            raise CredentialValidationUnavailable(
                "credential validation requires a bounded database wait"
            ) from None


def _identifier(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex}"


def _validate_identifier(value: object, *, name: str) -> None:
    if not isinstance(value, str) or not value or len(value) > 160:
        raise ValueError(f"{name} is invalid")


def _dpapi_reference(credential_id: str) -> str:
    stem = hashlib.sha256(credential_id.encode("utf-8")).hexdigest()
    return f"dpapi-current-user://{stem}"


def _safe_retry_after(value: float | None) -> float | None:
    if value is None:
        return None
    try:
        normalized = float(value)
    except (TypeError, ValueError, OverflowError):
        return None
    if not math.isfinite(normalized) or not 0 <= normalized <= 3_600:
        return None
    return normalized


def _stable_failure_class(value: object) -> ProviderErrorClass:
    if isinstance(value, ProviderErrorClass) and value is not ProviderErrorClass.NONE:
        return value
    return ProviderErrorClass.MALFORMED_RESPONSE


def _scrub_exception(error: BaseException) -> None:
    """Detach hostile exception data before a stable error is raised later."""

    error.args = ()
    error.__traceback__ = None
    error.__cause__ = None
    error.__context__ = None
