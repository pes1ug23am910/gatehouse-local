"""Launch-minted session capabilities and memory-only access-token management."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import secrets
from collections import OrderedDict
from collections.abc import Callable, Mapping
from dataclasses import dataclass

from gatehouse.core.clock import FixedUtcClock
from gatehouse.core.ids import RootRunId, SessionId
from gatehouse.core.states import InvalidStateTransition, SessionState

from .models import (
    RootRunRecord,
    RootRunState,
    SessionRecord,
    SessionTransitionConditionError,
)
from .persistence import SessionPersistence, SessionRunCapacityExceeded


class SessionError(RuntimeError):
    """Base class for session authorization failures."""


class BootstrapCapabilityError(SessionError):
    pass


class InvalidAccessToken(SessionError):
    pass


class SessionUnavailable(SessionError):
    pass


class AccessTokenCapacityExceeded(SessionError):
    pass


class RootRunNotFound(SessionError):
    pass


class CrossSessionRootRun(SessionError):
    pass


@dataclass(frozen=True, slots=True)
class LaunchedSession:
    session: SessionRecord
    bootstrap_capability: str


@dataclass(frozen=True, slots=True)
class AccessPrincipal:
    session_id: str
    client_id: str
    workspace_id: str | None
    identity_assurance: str
    policy_version: str
    token_epoch: int
    absolute_expires_at_ms: int


@dataclass(frozen=True, slots=True)
class IssuedAccessToken:
    access_token: str
    expires_at_ms: int
    principal: AccessPrincipal


@dataclass(frozen=True, slots=True)
class _AccessTokenRecord:
    session_id: str
    token_epoch: int
    revocation_epoch: int
    issued_at_ms: int
    expires_at_ms: int


def _encode_opaque(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _decode_opaque(value: str, *, expected_bytes: int) -> bytes:
    if not value or any(character.isspace() for character in value):
        raise ValueError("opaque value is empty or contains whitespace")
    padding = "=" * (-len(value) % 4)
    try:
        decoded = base64.b64decode(
            value + padding,
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, binascii.Error) as exc:
        raise ValueError("opaque value is not valid Base64URL") from exc
    if len(decoded) != expected_bytes:
        raise ValueError("opaque value has the wrong entropy length")
    return decoded


class SessionManager:
    """Own session authentication without persisting plaintext capabilities.

    The process stores only keyed access-token verifiers.  Starting a new manager
    advances the durable daemon epoch, invalidating every token from an older daemon
    while leaving bootstrap capabilities usable for bounded re-adoption.
    """

    _BOOTSTRAP_DOMAIN = b"gatehouse/session-bootstrap/v1\x00"
    _ACCESS_DOMAIN = b"gatehouse/access-token/v1\x00"

    def __init__(
        self,
        *,
        persistence: SessionPersistence,
        verifier_key: bytes,
        token_epoch: int,
        now_ms: Callable[[], int],
        random_bytes: Callable[[int], bytes],
        access_token_ttl_ms: int,
        reconnect_grace_ms: int,
        stale_after_ms: int = 2 * 60 * 1_000,
        maximum_access_tokens: int,
        maximum_concurrent_runs_by_client_id: Mapping[str, int] | None = None,
    ) -> None:
        if len(verifier_key) < 32:
            raise ValueError("session verifier key must contain at least 256 bits")
        if access_token_ttl_ms <= 0 or reconnect_grace_ms <= 0 or stale_after_ms <= 0:
            raise ValueError("session durations must be positive")
        if maximum_access_tokens <= 0:
            raise ValueError("maximum_access_tokens must be positive")
        run_limits_required = maximum_concurrent_runs_by_client_id is not None
        run_limits = dict(maximum_concurrent_runs_by_client_id or {})
        if any(
            not client_id
            or isinstance(maximum, bool)
            or not isinstance(maximum, int)
            or maximum <= 0
            for client_id, maximum in run_limits.items()
        ):
            raise ValueError("client concurrent-run limits must be positive")
        self._persistence = persistence
        self._verifier_key = verifier_key
        self._token_epoch = token_epoch
        self._now_ms = now_ms
        self._random_bytes = random_bytes
        self._access_token_ttl_ms = access_token_ttl_ms
        self._reconnect_grace_ms = reconnect_grace_ms
        self._stale_after_ms = stale_after_ms
        self._maximum_access_tokens = maximum_access_tokens
        self._run_limits_required = run_limits_required
        self._maximum_concurrent_runs_by_client_id = run_limits
        self._access_tokens: OrderedDict[bytes, _AccessTokenRecord] = OrderedDict()

    @classmethod
    async def start(
        cls,
        *,
        persistence: SessionPersistence,
        verifier_key: bytes,
        now_ms: Callable[[], int],
        random_bytes: Callable[[int], bytes] = secrets.token_bytes,
        access_token_ttl_ms: int = 10 * 60 * 1_000,
        reconnect_grace_ms: int = 30 * 60 * 1_000,
        stale_after_ms: int = 2 * 60 * 1_000,
        maximum_access_tokens: int = 4_096,
        maximum_concurrent_runs_by_client_id: Mapping[str, int] | None = None,
    ) -> SessionManager:
        epoch = await persistence.begin_daemon_epoch(
            now_ms=now_ms(),
            reconnect_grace_ms=reconnect_grace_ms,
        )
        return cls(
            persistence=persistence,
            verifier_key=verifier_key,
            token_epoch=epoch,
            now_ms=now_ms,
            random_bytes=random_bytes,
            access_token_ttl_ms=access_token_ttl_ms,
            reconnect_grace_ms=reconnect_grace_ms,
            stale_after_ms=stale_after_ms,
            maximum_access_tokens=maximum_access_tokens,
            maximum_concurrent_runs_by_client_id=maximum_concurrent_runs_by_client_id,
        )

    @property
    def token_epoch(self) -> int:
        return self._token_epoch

    def _hmac(self, domain: bytes, *parts: bytes) -> bytes:
        message = domain + b"\x00".join(parts)
        return hmac.new(self._verifier_key, message, hashlib.sha256).digest()

    async def create_session(
        self,
        *,
        client_id: str,
        workspace_id: str | None,
        identity_assurance: str,
        policy_version: str,
        absolute_ttl_ms: int,
        budget: Mapping[str, int] | None = None,
        maximum_concurrent_runs: int | None = None,
        block_on_runaway_quarantine: bool = False,
    ) -> LaunchedSession:
        if absolute_ttl_ms <= 0:
            raise ValueError("absolute session TTL must be positive")
        if maximum_concurrent_runs is not None and maximum_concurrent_runs <= 0:
            raise ValueError("maximum concurrent runs must be positive")
        now = self._now_ms()
        session_id = SessionId.new(
            clock=FixedUtcClock(now),
            entropy=self._random_bytes,
        )
        raw_bootstrap = self._random_bytes(32)
        if len(raw_bootstrap) != 32:
            raise ValueError("random source did not return 32 bootstrap bytes")
        verifier = self._hmac(
            self._BOOTSTRAP_DOMAIN,
            session_id.encode("utf-8"),
            raw_bootstrap,
        )
        session = SessionRecord(
            session_id=session_id,
            client_id=client_id,
            workspace_id=workspace_id,
            bootstrap_verifier=verifier,
            bootstrap_version=1,
            token_epoch=self._token_epoch,
            revocation_epoch=0,
            state=SessionState.CREATED,
            identity_assurance=identity_assurance,
            policy_version=policy_version,
            created_at_ms=now,
            last_seen_at_ms=None,
            disconnected_at_ms=None,
            reconnect_until_ms=now + absolute_ttl_ms,
            absolute_expires_at_ms=now + absolute_ttl_ms,
            budget=budget or {},
        )
        await self._persistence.insert_session(
            session,
            maximum_concurrent_runs=maximum_concurrent_runs,
            stale_after_ms=self._stale_after_ms,
            reconnect_grace_ms=self._reconnect_grace_ms,
            block_on_runaway_quarantine=block_on_runaway_quarantine,
        )
        return LaunchedSession(session, _encode_opaque(raw_bootstrap))

    async def exchange_bootstrap(
        self,
        *,
        session_id: str,
        bootstrap_capability: str,
    ) -> IssuedAccessToken:
        try:
            raw = _decode_opaque(bootstrap_capability, expected_bytes=32)
        except ValueError as exc:
            raise BootstrapCapabilityError("invalid bootstrap capability") from exc

        for _ in range(8):
            current = await self._persistence.load_session(session_id)
            if current is None:
                raise BootstrapCapabilityError("invalid bootstrap capability")
            expected = self._hmac(
                self._BOOTSTRAP_DOMAIN,
                session_id.encode("utf-8"),
                raw,
            )
            if not hmac.compare_digest(expected, current.bootstrap_verifier):
                raise BootstrapCapabilityError("invalid bootstrap capability")

            now = self._now_ms()
            if now >= current.absolute_expires_at_ms:
                await self._expire_if_possible(current, now_ms=now)
                raise SessionUnavailable("session has expired")
            if current.state in {
                SessionState.EXPIRED,
                SessionState.REVOKED,
                SessionState.SUSPENDED,
            }:
                raise SessionUnavailable(f"session is {current.state.lower()}")

            if current.state is SessionState.ACTIVE:
                stale_at_ms = self._stale_at_ms(current)
                if now >= stale_at_ms:
                    disconnected = current.transition(
                        SessionState.DISCONNECTED,
                        now_ms=stale_at_ms,
                        reconnect_grace_ms=self._reconnect_grace_ms,
                    )
                    if not await self._persistence.replace_session(
                        expected=current,
                        replacement=disconnected,
                    ):
                        continue
                    self._drop_session_tokens(current.session_id)
                    current = disconnected

            try:
                if current.state is SessionState.ACTIVE:
                    replacement = current.touch(now_ms=now, token_epoch=self._token_epoch)
                else:
                    replacement = current.transition(
                        SessionState.ACTIVE,
                        now_ms=now,
                        token_epoch=self._token_epoch,
                    )
            except (InvalidStateTransition, SessionTransitionConditionError) as exc:
                raise SessionUnavailable(str(exc)) from exc
            if await self._persistence.replace_session(
                expected=current,
                replacement=replacement,
            ):
                return self._issue_access_token(replacement, now_ms=now)
        raise SessionUnavailable("session changed concurrently; retry exchange")

    def _issue_access_token(
        self,
        session: SessionRecord,
        *,
        now_ms: int,
    ) -> IssuedAccessToken:
        self._purge_access_tokens(now_ms=now_ms)
        if len(self._access_tokens) >= self._maximum_access_tokens:
            raise AccessTokenCapacityExceeded("access-token capacity is exhausted")
        raw_token = self._random_bytes(32)
        if len(raw_token) != 32:
            raise ValueError("random source did not return 32 access-token bytes")
        verifier = self._hmac(self._ACCESS_DOMAIN, raw_token)
        expires_at = min(
            session.absolute_expires_at_ms,
            now_ms + self._access_token_ttl_ms,
        )
        self._access_tokens[verifier] = _AccessTokenRecord(
            session_id=session.session_id,
            token_epoch=self._token_epoch,
            revocation_epoch=session.revocation_epoch,
            issued_at_ms=now_ms,
            expires_at_ms=expires_at,
        )
        principal = self._principal(session)
        return IssuedAccessToken(_encode_opaque(raw_token), expires_at, principal)

    async def authenticate(self, access_token: str) -> AccessPrincipal:
        try:
            raw = _decode_opaque(access_token, expected_bytes=32)
        except ValueError as exc:
            raise InvalidAccessToken("invalid access token") from exc
        verifier = self._hmac(self._ACCESS_DOMAIN, raw)
        token = self._access_tokens.get(verifier)
        if token is None:
            raise InvalidAccessToken("invalid access token")
        for _ in range(8):
            now = self._now_ms()
            if token.expires_at_ms <= now or token.token_epoch != self._token_epoch:
                self._access_tokens.pop(verifier, None)
                raise InvalidAccessToken("access token has expired")
            session = await self._persistence.load_session(token.session_id)
            if (
                session is None
                or session.state is not SessionState.ACTIVE
                or session.token_epoch != self._token_epoch
                or session.revocation_epoch != token.revocation_epoch
                or session.absolute_expires_at_ms <= now
            ):
                self._access_tokens.pop(verifier, None)
                raise InvalidAccessToken("access token is no longer authorized")

            stale_at_ms = self._stale_at_ms(session)
            if now < stale_at_ms:
                if self._access_tokens.get(verifier) is not token:
                    raise InvalidAccessToken("access token is no longer authorized")
                self._access_tokens.move_to_end(verifier)
                return self._principal(session)

            replacement = session.transition(
                SessionState.DISCONNECTED,
                now_ms=stale_at_ms,
                reconnect_grace_ms=self._reconnect_grace_ms,
            )
            if await self._persistence.replace_session(
                expected=session,
                replacement=replacement,
            ):
                self._drop_session_tokens(session.session_id)
                raise InvalidAccessToken("session heartbeat has expired")
        raise SessionUnavailable("session changed concurrently; retry authentication")

    def _stale_at_ms(self, session: SessionRecord) -> int:
        last_activity_ms = (
            session.created_at_ms if session.last_seen_at_ms is None else session.last_seen_at_ms
        )
        return last_activity_ms + self._stale_after_ms

    async def heartbeat(self, access_token: str) -> AccessPrincipal:
        principal = await self.authenticate(access_token)
        for _ in range(8):
            current = await self._persistence.load_session(principal.session_id)
            if current is None or current.state is not SessionState.ACTIVE:
                raise SessionUnavailable("session is not active")
            now = self._now_ms()
            try:
                replacement = current.touch(now_ms=now, token_epoch=self._token_epoch)
            except (InvalidStateTransition, SessionTransitionConditionError) as exc:
                raise SessionUnavailable(str(exc)) from exc
            if await self._persistence.replace_session(
                expected=current,
                replacement=replacement,
            ):
                return self._principal(replacement)
        raise SessionUnavailable("session changed concurrently; retry heartbeat")

    async def mark_disconnected(self, session_id: str) -> SessionRecord:
        return await self._transition(
            session_id,
            SessionState.DISCONNECTED,
            reconnect_grace_ms=self._reconnect_grace_ms,
        )

    async def suspend(self, session_id: str) -> SessionRecord:
        record = await self._transition(session_id, SessionState.SUSPENDED)
        self._drop_session_tokens(session_id)
        return record

    async def resume(self, session_id: str) -> SessionRecord:
        record = await self._transition(
            session_id,
            SessionState.ACTIVE,
            token_epoch=self._token_epoch,
        )
        self._drop_session_tokens(session_id)
        return record

    async def revoke(self, session_id: str) -> SessionRecord:
        record = await self._transition(session_id, SessionState.REVOKED)
        self._drop_session_tokens(session_id)
        return record

    async def _transition(
        self,
        session_id: str,
        target: SessionState,
        *,
        reconnect_grace_ms: int | None = None,
        token_epoch: int | None = None,
    ) -> SessionRecord:
        for _ in range(8):
            current = await self._persistence.load_session(session_id)
            if current is None:
                raise SessionUnavailable("session does not exist")
            try:
                replacement = current.transition(
                    target,
                    now_ms=self._now_ms(),
                    reconnect_grace_ms=reconnect_grace_ms,
                    token_epoch=token_epoch,
                )
            except (InvalidStateTransition, SessionTransitionConditionError) as exc:
                raise SessionUnavailable(str(exc)) from exc
            if await self._persistence.replace_session(
                expected=current,
                replacement=replacement,
            ):
                return replacement
        raise SessionUnavailable("session changed concurrently; retry transition")

    async def _expire_if_possible(self, current: SessionRecord, *, now_ms: int) -> None:
        if current.state in {SessionState.EXPIRED, SessionState.REVOKED}:
            return
        try:
            replacement = current.transition(SessionState.EXPIRED, now_ms=now_ms)
        except (InvalidStateTransition, SessionTransitionConditionError):
            return
        await self._persistence.replace_session(expected=current, replacement=replacement)
        self._drop_session_tokens(current.session_id)

    async def create_root_run(
        self,
        *,
        access_token: str,
        budget: Mapping[str, int] | None = None,
    ) -> RootRunRecord:
        principal = await self.authenticate(access_token)
        session = await self._persistence.load_session(principal.session_id)
        if session is None:
            raise SessionUnavailable("session does not exist")
        requested = dict(session.budget if budget is None else budget)
        for unit, maximum in requested.items():
            session_maximum = session.budget.get(unit)
            if session_maximum is None or maximum > session_maximum:
                raise ValueError(f"root-run {unit} budget exceeds the session ceiling")
        now = self._now_ms()
        root_run = RootRunRecord(
            root_run_id=RootRunId.new(
                clock=FixedUtcClock(now),
                entropy=self._random_bytes,
            ),
            session_id=principal.session_id,
            state=RootRunState.ACTIVE,
            started_at_ms=now,
            budget=requested,
        )
        if (
            self._run_limits_required
            and session.client_id not in self._maximum_concurrent_runs_by_client_id
        ):
            raise SessionRunCapacityExceeded("client profile run authority is unavailable")
        maximum_concurrent_runs = self._maximum_concurrent_runs_by_client_id.get(session.client_id)
        await self._persistence.insert_root_run(
            root_run,
            client_id=session.client_id,
            maximum_concurrent_runs=maximum_concurrent_runs,
            now_ms=now,
            stale_after_ms=self._stale_after_ms,
            reconnect_grace_ms=self._reconnect_grace_ms,
            block_on_runaway_quarantine=maximum_concurrent_runs is not None,
        )
        return root_run

    async def resolve_root_run(
        self,
        *,
        access_token: str,
        root_run_id: str,
    ) -> RootRunRecord:
        principal = await self.authenticate(access_token)
        root_run = await self._persistence.load_root_run(root_run_id)
        if root_run is None:
            raise RootRunNotFound("unknown root-run identifier")
        if root_run.session_id != principal.session_id:
            raise CrossSessionRootRun("root run belongs to another session")
        return root_run

    def _purge_access_tokens(self, *, now_ms: int) -> None:
        expired = [
            verifier
            for verifier, record in self._access_tokens.items()
            if record.expires_at_ms <= now_ms or record.token_epoch != self._token_epoch
        ]
        for verifier in expired:
            self._access_tokens.pop(verifier, None)

    def _drop_session_tokens(self, session_id: str) -> None:
        stale = [
            verifier
            for verifier, record in self._access_tokens.items()
            if record.session_id == session_id
        ]
        for verifier in stale:
            self._access_tokens.pop(verifier, None)

    @staticmethod
    def _principal(session: SessionRecord) -> AccessPrincipal:
        return AccessPrincipal(
            session_id=session.session_id,
            client_id=session.client_id,
            workspace_id=session.workspace_id,
            identity_assurance=session.identity_assurance,
            policy_version=session.policy_version,
            token_epoch=session.token_epoch,
            absolute_expires_at_ms=session.absolute_expires_at_ms,
        )
