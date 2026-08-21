"""Bounded, process-local emergency credential admission.

This module deliberately has no persistence or routing integration.  A caller
must explicitly project the one active unlock into an exact authority context
and reserve every request without waiting or automatic selection.
"""

from __future__ import annotations

import asyncio
import json
import secrets
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Final, cast

from gatehouse.core.ids import CredentialId, PoolId, PrincipalId, QuotaScopeId

from .base import CredentialMetadata, CredentialNotFoundError
from .memory import InMemoryKeyStore
from .validation import is_admissible_firecrawl_secret

_ASYNC_CREATION_OPERATION: Final = "firecrawl.crawl.start"
_MAXIMUM_IDENTIFIER_LENGTH: Final = 256
_MINIMUM_OPAQUE_ID_LENGTH: Final = 16


def _contains_active_secret(value: object, secret: bytes | bytearray) -> bool:
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
    if isinstance(value, (list, tuple)):
        return any(_contains_active_secret(item, secret) for item in value)
    return False


class EmergencyUnlockError(RuntimeError):
    """Base class for redacted emergency-unlock failures."""


class EmergencyUnlockState(StrEnum):
    """Non-secret manager state exposed through status."""

    LOCKED = "LOCKED"
    ACTIVE = "ACTIVE"
    CLOSED = "CLOSED"


@dataclass(frozen=True, slots=True, repr=False)
class EmergencyUnlockProjection:
    """A manual, exact-authority view of the active unlock."""

    unlock_id: str
    credential_id: str
    principal_id: str
    quota_scope_id: str
    alias: str
    service_id: str
    pool_id: str
    pool_name: str
    session_id: str
    root_run_id: str
    expires_at_ms: int
    maximum_requests: int
    remaining_requests: int
    maximum_credits: int
    remaining_credits: int
    maximum_concurrency: int
    available_concurrency: int
    automatic: bool = False

    def __repr__(self) -> str:
        return (
            "EmergencyUnlockProjection("
            "authority=<redacted>, ids=<redacted>, "
            f"remaining_requests={self.remaining_requests}, "
            f"remaining_credits={self.remaining_credits}, "
            f"available_concurrency={self.available_concurrency})"
        )


@dataclass(frozen=True, slots=True, repr=False)
class EmergencyUnlockStatus:
    """A secret-free snapshot of the in-memory manager."""

    state: EmergencyUnlockState
    unlock_id: str | None = None
    credential_id: str | None = None
    principal_id: str | None = None
    quota_scope_id: str | None = None
    alias: str | None = None
    service_id: str | None = None
    pool_id: str | None = None
    pool_name: str | None = None
    session_id: str | None = None
    root_run_id: str | None = None
    expires_at_ms: int | None = None
    maximum_requests: int = 0
    remaining_requests: int = 0
    maximum_credits: int = 0
    remaining_credits: int = 0
    maximum_concurrency: int = 1
    available_concurrency: int = 0

    @property
    def locked(self) -> bool:
        return self.state is not EmergencyUnlockState.ACTIVE

    def __repr__(self) -> str:
        return (
            "EmergencyUnlockStatus("
            f"state={self.state.value!r}, authority=<redacted>, ids=<redacted>, "
            f"remaining_requests={self.remaining_requests}, "
            f"remaining_credits={self.remaining_credits}, "
            f"available_concurrency={self.available_concurrency})"
        )


class EmergencyRequestPermit:
    """One non-transferable, nonwaiting reservation against an unlock."""

    __slots__ = (
        "_estimated_credits",
        "_manager_token",
        "_permit_id",
        "_settled",
        "_unlock_id",
    )

    def __init__(
        self,
        *,
        manager_token: object,
        unlock_id: str,
        permit_id: str,
        estimated_credits: int,
    ) -> None:
        self._manager_token = manager_token
        self._unlock_id = unlock_id
        self._permit_id = permit_id
        self._estimated_credits = estimated_credits
        self._settled = False

    @property
    def unlock_id(self) -> str:
        return self._unlock_id

    @property
    def permit_id(self) -> str:
        return self._permit_id

    @property
    def estimated_credits(self) -> int:
        return self._estimated_credits

    @property
    def settled(self) -> bool:
        return self._settled

    def _mark_settled(self) -> None:
        self._settled = True

    def __repr__(self) -> str:
        return (
            "EmergencyRequestPermit("
            "ids=<redacted>, "
            f"estimated_credits={self.estimated_credits}, settled={self.settled})"
        )


@dataclass(slots=True, repr=False)
class _ActiveUnlock:
    unlock_id: str
    credential_id: str
    principal_id: str
    quota_scope_id: str
    alias: str
    service_id: str
    pool_id: str
    pool_name: str
    session_id: str
    root_run_id: str
    expires_at_ms: int
    maximum_requests: int
    maximum_credits: int
    requests_used: int = 0
    credits_committed: int = 0
    credits_reserved: int = 0
    active_permit: EmergencyRequestPermit | None = None
    expiry_task: asyncio.Task[None] | None = None


def _new_opaque_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_hex(20)}"


def _is_positive_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _is_nonnegative_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _valid_identifier(value: object) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and len(value) <= _MAXIMUM_IDENTIFIER_LENGTH
        and value == value.strip()
        and all(character.isprintable() for character in value)
    )


def _valid_opaque_id(value: object) -> bool:
    return (
        isinstance(value, str)
        and _valid_identifier(value)
        and len(value) >= _MINIMUM_OPAQUE_ID_LENGTH
    )


class EmergencyUnlockManager:
    """Own one bounded emergency unlock and no persistent state."""

    __slots__ = (
        "_active",
        "_closed",
        "_closing",
        "_credential_id_factory",
        "_emergency_pool_name",
        "_hard_maximum_credits",
        "_hard_maximum_duration_ms",
        "_hard_maximum_requests",
        "_hard_maximum_secret_bytes",
        "_key_store",
        "_lock",
        "_manager_token",
        "_now_ms",
        "_permit_id_factory",
        "_principal_id_factory",
        "_quota_scope_id_factory",
        "_sleep",
        "_unlock_id_factory",
    )

    def __init__(
        self,
        *,
        key_store: InMemoryKeyStore,
        now_ms: Callable[[], int] | None = None,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        unlock_id_factory: Callable[[], str] | None = None,
        credential_id_factory: Callable[[], str] | None = None,
        principal_id_factory: Callable[[], str] | None = None,
        quota_scope_id_factory: Callable[[], str] | None = None,
        permit_id_factory: Callable[[], str] | None = None,
        emergency_pool_name: str = "emergency-locked",
        hard_maximum_duration_ms: int = 15 * 60 * 1_000,
        hard_maximum_requests: int = 25,
        hard_maximum_credits: int = 100,
        hard_maximum_secret_bytes: int = 4_096,
    ) -> None:
        if not isinstance(key_store, InMemoryKeyStore):
            raise TypeError("emergency manager requires an in-memory key store")
        if not _valid_identifier(emergency_pool_name):
            raise ValueError("emergency manager configuration is invalid")
        if not all(
            _is_positive_int(value)
            for value in (
                hard_maximum_duration_ms,
                hard_maximum_requests,
                hard_maximum_credits,
                hard_maximum_secret_bytes,
            )
        ):
            raise ValueError("emergency manager configuration is invalid")

        self._key_store = key_store
        self._now_ms = now_ms or (lambda: int(time.time() * 1_000))
        self._sleep = sleep
        self._unlock_id_factory = unlock_id_factory or (lambda: _new_opaque_id("unl"))
        self._credential_id_factory = credential_id_factory or CredentialId.new
        self._principal_id_factory = principal_id_factory or PrincipalId.new
        self._quota_scope_id_factory = quota_scope_id_factory or QuotaScopeId.new
        self._permit_id_factory = permit_id_factory or (lambda: _new_opaque_id("req"))
        self._emergency_pool_name = emergency_pool_name
        self._hard_maximum_duration_ms = hard_maximum_duration_ms
        self._hard_maximum_requests = hard_maximum_requests
        self._hard_maximum_credits = hard_maximum_credits
        self._hard_maximum_secret_bytes = hard_maximum_secret_bytes
        self._manager_token = object()
        self._lock = asyncio.Lock()
        self._active: _ActiveUnlock | None = None
        self._closing: _ActiveUnlock | None = None
        self._closed = False

    def __repr__(self) -> str:
        if self._closed:
            state = EmergencyUnlockState.CLOSED
        elif self._active is None:
            state = EmergencyUnlockState.LOCKED
        else:
            state = EmergencyUnlockState.ACTIVE
        return f"EmergencyUnlockManager(state={state.value!r}, details=<redacted>)"

    async def unlock(
        self,
        *,
        secret: bytes | bytearray,
        service_id: str,
        pool_id: str,
        pool_name: str,
        session_id: str,
        root_run_id: str,
        interactive: bool,
        duration_ms: int,
        maximum_requests: int,
        maximum_credits: int,
        maximum_concurrency: int = 1,
        credential_alias: str = "emergency-memory-only",
    ) -> EmergencyUnlockProjection:
        """Create the sole unlock after validating every hard ceiling."""

        if not self._valid_unlock_request(
            secret=secret,
            service_id=service_id,
            pool_id=pool_id,
            pool_name=pool_name,
            session_id=session_id,
            root_run_id=root_run_id,
            interactive=interactive,
            duration_ms=duration_ms,
            maximum_requests=maximum_requests,
            maximum_credits=maximum_credits,
            maximum_concurrency=maximum_concurrency,
            credential_alias=credential_alias,
        ):
            raise EmergencyUnlockError("emergency unlock request was denied")

        async with self._lock:
            if self._closed:
                raise EmergencyUnlockError("emergency manager is closed")
            await self._expire_if_due_locked()
            if self._active is not None or self._closing is not None:
                raise EmergencyUnlockError("emergency unlock is unavailable")

            unlock_id = ""
            credential_id = ""
            principal_id = ""
            quota_scope_id = ""
            identity_failed = False
            try:
                unlock_id = self._unlock_id_factory()
                credential_id = str(CredentialId(self._credential_id_factory()))
                principal_id = str(PrincipalId(self._principal_id_factory()))
                quota_scope_id = str(QuotaScopeId(self._quota_scope_id_factory()))
            except Exception:
                identity_failed = True
            if identity_failed:
                raise EmergencyUnlockError("emergency unlock request was denied") from None
            if not _valid_opaque_id(unlock_id):
                raise EmergencyUnlockError("emergency unlock request was denied")
            now_ms = self._read_clock()
            expires_at_ms = now_ms + duration_ms
            if _contains_active_secret(
                (
                    unlock_id,
                    credential_id,
                    principal_id,
                    quota_scope_id,
                    credential_alias,
                    service_id,
                    pool_id,
                    pool_name,
                    session_id,
                    root_run_id,
                    now_ms,
                    expires_at_ms,
                    duration_ms,
                    maximum_requests,
                    maximum_credits,
                    maximum_concurrency,
                    "HEALTHY",
                    "ACTIVE",
                    1,
                    False,
                    None,
                ),
                secret,
            ):
                raise EmergencyUnlockError("emergency unlock request was denied")

            metadata = CredentialMetadata(
                credential_id=credential_id,
                principal_id=principal_id,
                quota_scope_id=quota_scope_id,
                alias=credential_alias,
                expires_at_ms=expires_at_ms,
            )
            custody_failed = False
            reference = ""
            try:
                reference = await self._key_store.put(metadata, cast(bytes, secret))
            except asyncio.CancelledError:
                raise
            except Exception:
                custody_failed = True
            if custody_failed:
                raise EmergencyUnlockError("emergency credential custody failed") from None
            if _contains_active_secret(reference, secret):
                cleanup_failed = False
                try:
                    await self._key_store.delete(credential_id)
                except Exception:
                    cleanup_failed = True
                if cleanup_failed:
                    raise EmergencyUnlockError("emergency credential cleanup failed")
                raise EmergencyUnlockError("emergency credential custody failed")

            entry = _ActiveUnlock(
                unlock_id=unlock_id,
                credential_id=credential_id,
                principal_id=principal_id,
                quota_scope_id=quota_scope_id,
                alias=credential_alias,
                service_id=service_id,
                pool_id=pool_id,
                pool_name=pool_name,
                session_id=session_id,
                root_run_id=root_run_id,
                expires_at_ms=expires_at_ms,
                maximum_requests=maximum_requests,
                maximum_credits=maximum_credits,
            )
            self._active = entry
            expiry_task_failed = False
            try:
                entry.expiry_task = asyncio.create_task(
                    self._expire_after(unlock_id, duration_ms),
                    name="gatehouse-emergency-unlock-expiry",
                )
            except Exception:
                expiry_task_failed = True
            if expiry_task_failed:
                self._active = None
                await self._delete_if_present(credential_id)
                raise EmergencyUnlockError("emergency unlock request was denied")
            return self._projection(entry)

    async def project(
        self,
        *,
        service_id: str,
        pool_name: str,
        session_id: str,
        root_run_id: str,
        automatic: bool,
    ) -> EmergencyUnlockProjection:
        """Manually project the unlock only into its exact authority."""

        async with self._lock:
            entry = await self._require_exact_active_locked(
                service_id=service_id,
                pool_name=pool_name,
                session_id=session_id,
                root_run_id=root_run_id,
                automatic=automatic,
            )
            return self._projection(entry)

    async def reserve(
        self,
        *,
        service_id: str,
        pool_name: str,
        session_id: str,
        root_run_id: str,
        operation: str,
        estimated_credits: int,
        automatic: bool,
    ) -> EmergencyRequestPermit:
        """Reserve the sole concurrency slot immediately, without queuing."""

        if (
            not _valid_identifier(operation)
            or operation.casefold() == _ASYNC_CREATION_OPERATION
            or not _is_positive_int(estimated_credits)
            or automatic is not False
        ):
            raise EmergencyUnlockError("emergency request was denied")

        async with self._lock:
            entry = await self._require_exact_active_locked(
                service_id=service_id,
                pool_name=pool_name,
                session_id=session_id,
                root_run_id=root_run_id,
                automatic=automatic,
            )
            if entry.active_permit is not None:
                raise EmergencyUnlockError("emergency capacity is unavailable")
            if entry.requests_used >= entry.maximum_requests:
                raise EmergencyUnlockError("emergency capacity is unavailable")
            remaining_credits = (
                entry.maximum_credits - entry.credits_committed - entry.credits_reserved
            )
            if estimated_credits > remaining_credits:
                raise EmergencyUnlockError("emergency capacity is unavailable")

            permit_id = ""
            permit_identity_failed = False
            try:
                permit_id = self._permit_id_factory()
            except Exception:
                permit_identity_failed = True
            if permit_identity_failed:
                raise EmergencyUnlockError("emergency request was denied")
            if not _valid_opaque_id(permit_id):
                raise EmergencyUnlockError("emergency request was denied")

            permit = EmergencyRequestPermit(
                manager_token=self._manager_token,
                unlock_id=entry.unlock_id,
                permit_id=permit_id,
                estimated_credits=estimated_credits,
            )
            entry.requests_used += 1
            entry.credits_reserved += estimated_credits
            entry.active_permit = permit
            return permit

    async def settle(
        self,
        permit: EmergencyRequestPermit,
        *,
        actual_credits: int | None,
        outcome_known: bool,
    ) -> bool:
        """Release concurrency and conservatively account for the outcome."""

        if not isinstance(permit, EmergencyRequestPermit):
            raise EmergencyUnlockError("emergency settlement was denied")
        if outcome_known is True:
            if actual_credits is None or not _is_nonnegative_int(actual_credits):
                raise EmergencyUnlockError("emergency settlement was denied")
        elif outcome_known is False:
            if actual_credits is not None:
                raise EmergencyUnlockError("emergency settlement was denied")
        else:
            raise EmergencyUnlockError("emergency settlement was denied")

        async with self._lock:
            if permit.settled:
                return False
            await self._expire_if_due_locked()
            entry = self._active
            closing = False
            if entry is None:
                entry = self._closing
                closing = entry is not None
            if (
                entry is None
                or permit._manager_token is not self._manager_token
                or entry.unlock_id != permit.unlock_id
                or entry.active_permit is not permit
            ):
                raise EmergencyUnlockError("emergency settlement was denied")

            if closing:
                await self._delete_if_present(entry.credential_id)
            entry.credits_reserved -= permit.estimated_credits
            if outcome_known:
                assert actual_credits is not None
                entry.credits_committed += actual_credits
            else:
                entry.credits_committed += permit.estimated_credits
            entry.active_permit = None
            permit._mark_settled()
            if closing:
                self._closing = None
            return True

    async def cancel(self, unlock_id: str | None = None) -> bool:
        """Relock immediately and destroy custody material, idempotently."""

        async with self._lock:
            await self._expire_if_due_locked()
            entry = self._active
            if entry is None:
                closing = self._closing
                if closing is not None and (unlock_id is None or unlock_id == closing.unlock_id):
                    await self._delete_if_present(closing.credential_id)
                    if closing.active_permit is None:
                        self._closing = None
                return False
            if unlock_id is not None and unlock_id != entry.unlock_id:
                return False
            await self._relock_locked(entry)
            return True

    async def status(self) -> EmergencyUnlockStatus:
        """Return a safe snapshot without secret, reason, or lease material."""

        async with self._lock:
            await self._expire_if_due_locked()
            entry = self._active
            if entry is None:
                state = EmergencyUnlockState.CLOSED if self._closed else EmergencyUnlockState.LOCKED
                return EmergencyUnlockStatus(state=state)
            return EmergencyUnlockStatus(
                state=EmergencyUnlockState.ACTIVE,
                unlock_id=entry.unlock_id,
                credential_id=entry.credential_id,
                principal_id=entry.principal_id,
                quota_scope_id=entry.quota_scope_id,
                alias=entry.alias,
                service_id=entry.service_id,
                pool_id=entry.pool_id,
                pool_name=entry.pool_name,
                session_id=entry.session_id,
                root_run_id=entry.root_run_id,
                expires_at_ms=entry.expires_at_ms,
                maximum_requests=entry.maximum_requests,
                remaining_requests=max(0, entry.maximum_requests - entry.requests_used),
                maximum_credits=entry.maximum_credits,
                remaining_credits=self._remaining_credits(entry),
                maximum_concurrency=1,
                available_concurrency=int(entry.active_permit is None),
            )

    async def close(self) -> None:
        """Permanently close this instance and leave it empty and locked."""

        async with self._lock:
            if self._closed and self._active is None and self._closing is None:
                return
            self._closed = True
            entry = self._active
            if entry is not None:
                await self._relock_locked(entry)
            closing = self._closing
            if closing is not None:
                await self._delete_if_present(closing.credential_id)
                if closing.active_permit is None:
                    self._closing = None

    async def __aenter__(self) -> EmergencyUnlockManager:
        return self

    async def __aexit__(self, exc_type: object, exc: object, tb: object) -> None:
        await self.close()

    def _valid_unlock_request(
        self,
        *,
        secret: bytes | bytearray,
        service_id: str,
        pool_id: str,
        pool_name: str,
        session_id: str,
        root_run_id: str,
        interactive: bool,
        duration_ms: int,
        maximum_requests: int,
        maximum_credits: int,
        maximum_concurrency: int,
        credential_alias: str,
    ) -> bool:
        identifiers_valid = all(
            _valid_identifier(value)
            for value in (service_id, pool_id, pool_name, session_id, root_run_id)
        )
        try:
            PoolId(pool_id)
        except (TypeError, ValueError):
            identifiers_valid = False
        secret_valid = isinstance(secret, (bytes, bytearray)) and is_admissible_firecrawl_secret(
            secret,
            maximum_bytes=self._hard_maximum_secret_bytes,
        )
        return (
            identifiers_valid
            and _valid_identifier(credential_alias)
            and pool_name == self._emergency_pool_name
            and interactive is True
            and secret_valid
            and _is_positive_int(duration_ms)
            and duration_ms <= self._hard_maximum_duration_ms
            and _is_positive_int(maximum_requests)
            and maximum_requests <= self._hard_maximum_requests
            and _is_positive_int(maximum_credits)
            and maximum_credits <= self._hard_maximum_credits
            and maximum_concurrency == 1
            and not isinstance(maximum_concurrency, bool)
        )

    async def _require_exact_active_locked(
        self,
        *,
        service_id: str,
        pool_name: str,
        session_id: str,
        root_run_id: str,
        automatic: bool,
    ) -> _ActiveUnlock:
        if automatic is not False:
            raise EmergencyUnlockError("emergency unlock is unavailable")
        await self._expire_if_due_locked()
        entry = self._active
        if entry is None:
            raise EmergencyUnlockError("emergency unlock is unavailable")
        if (
            service_id != entry.service_id
            or pool_name != entry.pool_name
            or session_id != entry.session_id
            or root_run_id != entry.root_run_id
        ):
            raise EmergencyUnlockError("emergency unlock is unavailable")
        return entry

    async def _expire_after(self, unlock_id: str, duration_ms: int) -> None:
        try:
            await self._sleep(duration_ms / 1_000)
            async with self._lock:
                entry = self._active
                if entry is not None and entry.unlock_id == unlock_id:
                    await self._relock_locked(entry)
        except asyncio.CancelledError:
            return
        except Exception:
            # Admission is already fail-closed by _relock_locked before cleanup.
            return

    async def _expire_if_due_locked(self) -> None:
        entry = self._active
        if entry is not None and self._read_clock() >= entry.expires_at_ms:
            await self._relock_locked(entry)

    async def _relock_locked(self, entry: _ActiveUnlock) -> None:
        if self._active is not entry:
            return
        self._active = None
        self._closing = entry
        expiry_task = entry.expiry_task
        entry.expiry_task = None
        if expiry_task is not None and expiry_task is not asyncio.current_task():
            expiry_task.cancel()
        cleanup_failed = False
        try:
            await self._key_store.delete(entry.credential_id)
        except CredentialNotFoundError:
            pass
        except Exception:
            cleanup_failed = True
        if cleanup_failed:
            raise EmergencyUnlockError("emergency credential cleanup failed")
        if entry.active_permit is None:
            self._closing = None

    async def _delete_if_present(self, credential_id: str) -> None:
        cleanup_failed = False
        try:
            await self._key_store.delete(credential_id)
        except CredentialNotFoundError:
            return
        except Exception:
            cleanup_failed = True
        if cleanup_failed:
            raise EmergencyUnlockError("emergency credential cleanup failed")

    def _projection(self, entry: _ActiveUnlock) -> EmergencyUnlockProjection:
        return EmergencyUnlockProjection(
            unlock_id=entry.unlock_id,
            credential_id=entry.credential_id,
            principal_id=entry.principal_id,
            quota_scope_id=entry.quota_scope_id,
            alias=entry.alias,
            service_id=entry.service_id,
            pool_id=entry.pool_id,
            pool_name=entry.pool_name,
            session_id=entry.session_id,
            root_run_id=entry.root_run_id,
            expires_at_ms=entry.expires_at_ms,
            maximum_requests=entry.maximum_requests,
            remaining_requests=max(0, entry.maximum_requests - entry.requests_used),
            maximum_credits=entry.maximum_credits,
            remaining_credits=self._remaining_credits(entry),
            maximum_concurrency=1,
            available_concurrency=int(entry.active_permit is None),
            automatic=False,
        )

    @staticmethod
    def _remaining_credits(entry: _ActiveUnlock) -> int:
        return max(
            0,
            entry.maximum_credits - entry.credits_committed - entry.credits_reserved,
        )

    def _read_clock(self) -> int:
        now_ms = -1
        clock_failed = False
        try:
            now_ms = self._now_ms()
        except Exception:
            clock_failed = True
        if clock_failed:
            raise EmergencyUnlockError("emergency clock is unavailable")
        if not _is_nonnegative_int(now_ms):
            raise EmergencyUnlockError("emergency clock is unavailable")
        return now_ms
