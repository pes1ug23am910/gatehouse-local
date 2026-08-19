"""Memory-only, restart-revoked authentication for the local admin realm."""

from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import hmac
import secrets
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass, replace


class AdminAuthenticationError(RuntimeError):
    pass


class AdminAuthCapacityExceeded(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class MintedLoginCode:
    code: str
    expires_at_ms: int


@dataclass(frozen=True, slots=True)
class AdminLoginSession:
    admin_session_id: str
    cookie: str
    csrf_token: str
    idle_expires_at_ms: int
    absolute_expires_at_ms: int


@dataclass(frozen=True, slots=True)
class AdminPrincipal:
    admin_session_id: str
    idle_expires_at_ms: int
    absolute_expires_at_ms: int


@dataclass(frozen=True, slots=True)
class _LoginCodeRecord:
    expires_at_ms: int


@dataclass(frozen=True, slots=True)
class _AdminSessionRecord:
    admin_session_id: str
    csrf_verifier: bytes
    idle_expires_at_ms: int
    absolute_expires_at_ms: int


def _encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _decode(value: str) -> bytes:
    if not value or any(character.isspace() for character in value):
        raise AdminAuthenticationError("invalid administrative capability")
    try:
        raw = base64.b64decode(
            value + "=" * (-len(value) % 4),
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, binascii.Error) as exc:
        raise AdminAuthenticationError("invalid administrative capability") from exc
    if len(raw) != 32:
        raise AdminAuthenticationError("invalid administrative capability")
    return raw


class AdminAuthManager:
    _LOGIN_DOMAIN = b"gatehouse/admin-login/v1\x00"
    _COOKIE_DOMAIN = b"gatehouse/admin-cookie/v1\x00"
    _CSRF_DOMAIN = b"gatehouse/admin-csrf/v1\x00"

    def __init__(
        self,
        *,
        verifier_key: bytes,
        now_ms: Callable[[], int],
        random_bytes: Callable[[int], bytes] = secrets.token_bytes,
        login_code_ttl_ms: int = 60_000,
        idle_ttl_ms: int = 15 * 60_000,
        absolute_ttl_ms: int = 8 * 60 * 60_000,
        maximum_login_codes: int = 32,
        maximum_sessions: int = 16,
    ) -> None:
        if len(verifier_key) < 32:
            raise ValueError("admin verifier key must contain at least 256 bits")
        if min(login_code_ttl_ms, idle_ttl_ms, absolute_ttl_ms) <= 0:
            raise ValueError("admin authentication TTLs must be positive")
        if idle_ttl_ms > absolute_ttl_ms:
            raise ValueError("admin idle TTL cannot exceed absolute TTL")
        if min(maximum_login_codes, maximum_sessions) <= 0:
            raise ValueError("admin authentication capacities must be positive")
        self._key = verifier_key
        self._now_ms = now_ms
        self._random_bytes = random_bytes
        self._login_code_ttl_ms = login_code_ttl_ms
        self._idle_ttl_ms = idle_ttl_ms
        self._absolute_ttl_ms = absolute_ttl_ms
        self._maximum_login_codes = maximum_login_codes
        self._maximum_sessions = maximum_sessions
        self._login_codes: OrderedDict[bytes, _LoginCodeRecord] = OrderedDict()
        self._sessions: OrderedDict[bytes, _AdminSessionRecord] = OrderedDict()
        self._lock = asyncio.Lock()

    def _verifier(self, domain: bytes, raw: bytes, *, session_id: str = "") -> bytes:
        message = domain + session_id.encode("utf-8") + b"\x00" + raw
        return hmac.new(self._key, message, hashlib.sha256).digest()

    def _random_32(self) -> bytes:
        raw = self._random_bytes(32)
        if len(raw) != 32:
            raise ValueError("random source did not return 32 bytes")
        return raw

    def _purge(self, now_ms: int) -> None:
        for verifier, code_record in tuple(self._login_codes.items()):
            if code_record.expires_at_ms <= now_ms:
                self._login_codes.pop(verifier, None)
        for verifier, session_record in tuple(self._sessions.items()):
            if (
                min(
                    session_record.idle_expires_at_ms,
                    session_record.absolute_expires_at_ms,
                )
                <= now_ms
            ):
                self._sessions.pop(verifier, None)

    async def mint_login_code(self) -> MintedLoginCode:
        async with self._lock:
            now = self._now_ms()
            self._purge(now)
            if len(self._login_codes) >= self._maximum_login_codes:
                raise AdminAuthCapacityExceeded("admin login-code capacity is exhausted")
            raw = self._random_32()
            verifier = self._verifier(self._LOGIN_DOMAIN, raw)
            expires = now + self._login_code_ttl_ms
            self._login_codes[verifier] = _LoginCodeRecord(expires_at_ms=expires)
            return MintedLoginCode(code=_encode(raw), expires_at_ms=expires)

    async def exchange_login_code(self, code: str) -> AdminLoginSession:
        raw_code = _decode(code)
        verifier = self._verifier(self._LOGIN_DOMAIN, raw_code)
        async with self._lock:
            now = self._now_ms()
            self._purge(now)
            record = self._login_codes.get(verifier)
            if record is None or record.expires_at_ms <= now:
                raise AdminAuthenticationError("invalid or expired admin login code")
            if len(self._sessions) >= self._maximum_sessions:
                raise AdminAuthCapacityExceeded("admin session capacity is exhausted")
            self._login_codes.pop(verifier, None)

            cookie_raw = self._random_32()
            csrf_raw = self._random_32()
            admin_session_id = f"adm_{self._random_bytes(16).hex()}"
            cookie_verifier = self._verifier(self._COOKIE_DOMAIN, cookie_raw)
            absolute_expires = now + self._absolute_ttl_ms
            idle_expires = min(absolute_expires, now + self._idle_ttl_ms)
            self._sessions[cookie_verifier] = _AdminSessionRecord(
                admin_session_id=admin_session_id,
                csrf_verifier=self._verifier(
                    self._CSRF_DOMAIN,
                    csrf_raw,
                    session_id=admin_session_id,
                ),
                idle_expires_at_ms=idle_expires,
                absolute_expires_at_ms=absolute_expires,
            )
            return AdminLoginSession(
                admin_session_id=admin_session_id,
                cookie=_encode(cookie_raw),
                csrf_token=_encode(csrf_raw),
                idle_expires_at_ms=idle_expires,
                absolute_expires_at_ms=absolute_expires,
            )

    async def authenticate(
        self,
        cookie: str,
        *,
        csrf_token: str | None = None,
        require_csrf: bool = False,
    ) -> AdminPrincipal:
        raw_cookie = _decode(cookie)
        cookie_verifier = self._verifier(self._COOKIE_DOMAIN, raw_cookie)
        async with self._lock:
            now = self._now_ms()
            self._purge(now)
            record = self._sessions.get(cookie_verifier)
            if record is None:
                raise AdminAuthenticationError("invalid or expired admin session")
            if require_csrf:
                if csrf_token is None:
                    raise AdminAuthenticationError("CSRF token is required")
                raw_csrf = _decode(csrf_token)
                supplied = self._verifier(
                    self._CSRF_DOMAIN,
                    raw_csrf,
                    session_id=record.admin_session_id,
                )
                if not hmac.compare_digest(supplied, record.csrf_verifier):
                    raise AdminAuthenticationError("invalid CSRF token")
            replacement = replace(
                record,
                idle_expires_at_ms=min(
                    record.absolute_expires_at_ms,
                    now + self._idle_ttl_ms,
                ),
            )
            self._sessions[cookie_verifier] = replacement
            self._sessions.move_to_end(cookie_verifier)
            return AdminPrincipal(
                admin_session_id=replacement.admin_session_id,
                idle_expires_at_ms=replacement.idle_expires_at_ms,
                absolute_expires_at_ms=replacement.absolute_expires_at_ms,
            )

    async def revoke(self, cookie: str) -> bool:
        try:
            raw_cookie = _decode(cookie)
        except AdminAuthenticationError:
            return False
        verifier = self._verifier(self._COOKIE_DOMAIN, raw_cookie)
        async with self._lock:
            return self._sessions.pop(verifier, None) is not None
