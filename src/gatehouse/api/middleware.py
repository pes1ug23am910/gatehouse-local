"""ASGI-level local Host validation and complete request-body bounds."""

from __future__ import annotations

import asyncio
import base64
import hashlib
from collections.abc import Awaitable, Callable, Iterable

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from gatehouse.core.errors import ErrorCode, make_error

from .errors import error_response, schema_error


class _RequestBodyDeadlineExceeded(TimeoutError):
    pass


class _RequestBodyTooLarge(ValueError):
    pass


class LocalRequestBoundsMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        *,
        allowed_hosts: Iterable[str],
        maximum_body_bytes: int,
        defer_body_read: Callable[[Scope], bool] | None = None,
        require_bearer: Callable[[Scope], bool] | None = None,
        authenticate_bearer: Callable[[str], Awaitable[bool]] | None = None,
        total_body_timeout_ms: int = 10_000,
        inter_chunk_timeout_ms: int = 2_000,
    ) -> None:
        hosts = frozenset(host.casefold().rstrip(".") for host in allowed_hosts)
        if not hosts:
            raise ValueError("at least one local Host value is required")
        if type(maximum_body_bytes) is not int or not 1 <= maximum_body_bytes <= 16 * 1_024 * 1_024:
            raise ValueError("maximum_body_bytes must be positive")
        if (
            isinstance(total_body_timeout_ms, bool)
            or isinstance(inter_chunk_timeout_ms, bool)
            or not isinstance(total_body_timeout_ms, int)
            or not isinstance(inter_chunk_timeout_ms, int)
            or inter_chunk_timeout_ms <= 0
            or total_body_timeout_ms < inter_chunk_timeout_ms
            or total_body_timeout_ms > 60_000
            or inter_chunk_timeout_ms > 10_000
        ):
            raise ValueError("request-body deadlines are invalid")
        self._app = app
        self._allowed_hosts = hosts
        self._maximum_body_bytes = maximum_body_bytes
        self._defer_body_read = defer_body_read
        self._require_bearer = require_bearer
        self._authenticate_bearer = authenticate_bearer
        self._total_body_timeout_seconds = total_body_timeout_ms / 1_000
        self._inter_chunk_timeout_seconds = inter_chunk_timeout_ms / 1_000

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        headers = {
            key.decode("latin-1").casefold(): value.decode("latin-1")
            for key, value in scope.get("headers", ())
        }
        host_values = [
            value.decode("latin-1").casefold().rstrip(".")
            for key, value in scope.get("headers", ())
            if key.decode("latin-1").casefold() == "host"
        ]
        if len(host_values) != 1 or host_values[0] not in self._allowed_hosts:
            await error_response(
                make_error(ErrorCode.INVALID_TARGET, retryable=False),
                status_code=400,
            )(scope, receive, send)
            return

        if self._require_bearer is not None and self._require_bearer(scope):
            authorization_values = [
                value.decode("latin-1")
                for key, value in scope.get("headers", ())
                if key.decode("latin-1").casefold() == "authorization"
            ]
            valid_bearer = False
            if len(authorization_values) == 1:
                scheme, separator, token = authorization_values[0].partition(" ")
                valid_bearer = (
                    separator == " "
                    and scheme.casefold() == "bearer"
                    and len(token) == 43
                    and all(character.isalnum() or character in "-_" for character in token)
                )
            if not valid_bearer:
                await error_response(
                    make_error(ErrorCode.INVALID_SESSION, retryable=False),
                    status_code=401,
                )(scope, receive, send)
                return
            if self._authenticate_bearer is not None and not await self._authenticate_bearer(token):
                await error_response(
                    make_error(ErrorCode.INVALID_SESSION, retryable=False),
                    status_code=401,
                )(scope, receive, send)
                return

        content_length = headers.get("content-length")
        if content_length is not None:
            try:
                declared = int(content_length)
            except ValueError:
                await error_response(schema_error(), status_code=400)(scope, receive, send)
                return
            if declared < 0 or declared > self._maximum_body_bytes:
                await error_response(schema_error(), status_code=413)(scope, receive, send)
                return

        loop = asyncio.get_running_loop()
        deadline = loop.time() + self._total_body_timeout_seconds
        observed_body_bytes = 0

        async def bounded_receive() -> Message:
            nonlocal observed_body_bytes
            remaining = deadline - loop.time()
            if remaining <= 0:
                raise _RequestBodyDeadlineExceeded("request body exceeded its total deadline")
            try:
                message = await asyncio.wait_for(
                    receive(),
                    timeout=min(remaining, self._inter_chunk_timeout_seconds),
                )
            except TimeoutError as error:
                raise _RequestBodyDeadlineExceeded(
                    "request body exceeded its inter-chunk deadline"
                ) from error
            if message["type"] == "http.request":
                observed_body_bytes += len(message.get("body", b""))
                if observed_body_bytes > self._maximum_body_bytes:
                    raise _RequestBodyTooLarge("request body exceeded its byte bound")
            return message

        if self._defer_body_read is not None and self._defer_body_read(scope):
            # Private scope contract consumed by admin.control. Bind the actual
            # receiver without modifying the caller's scope or duplicating bounds.
            deferred_scope = dict(scope)
            deferred_scope["gatehouse.bounded_body_receive"] = bounded_receive
            response_started = False

            async def tracked_send(message: Message) -> None:
                nonlocal response_started
                if message["type"] == "http.response.start":
                    response_started = True
                await send(message)

            try:
                await self._app(deferred_scope, bounded_receive, tracked_send)
            except (_RequestBodyDeadlineExceeded, _RequestBodyTooLarge) as error:
                if response_started:
                    raise
                status_code = 408 if isinstance(error, _RequestBodyDeadlineExceeded) else 413
                await error_response(schema_error(), status_code=status_code)(scope, receive, send)
            return

        body = bytearray()
        disconnected = False
        while True:
            try:
                message = await bounded_receive()
            except _RequestBodyDeadlineExceeded:
                body[:] = b"\x00" * len(body)
                await error_response(schema_error(), status_code=408)(scope, receive, send)
                return
            except _RequestBodyTooLarge:
                body[:] = b"\x00" * len(body)
                await error_response(schema_error(), status_code=413)(scope, receive, send)
                return
            if message["type"] == "http.disconnect":
                disconnected = True
                break
            if message["type"] != "http.request":
                continue
            body.extend(message.get("body", b""))
            if len(body) > self._maximum_body_bytes:
                body[:] = b"\x00" * len(body)
                await error_response(schema_error(), status_code=413)(scope, receive, send)
                return
            if not message.get("more_body", False):
                break

        emitted = False

        async def replay() -> Message:
            nonlocal emitted
            if disconnected or emitted:
                return {"type": "http.disconnect"}
            emitted = True
            return {"type": "http.request", "body": bytes(body), "more_body": False}

        try:
            await self._app(scope, replay, send)
        finally:
            body[:] = b"\x00" * len(body)


class AdminSecurityHeadersMiddleware:
    """Apply browser hardening without enabling CORS or external assets."""

    _HEADERS = (
        (b"cache-control", b"no-store"),
        (
            b"content-security-policy",
            b"default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; "
            b"frame-ancestors 'none'; base-uri 'none'",
        ),
        (b"referrer-policy", b"no-referrer"),
        (b"x-content-type-options", b"nosniff"),
        (b"x-frame-options", b"DENY"),
    )

    def __init__(self, app: ASGIApp, *, login_script: str | None = None) -> None:
        self._app = app
        self._login_headers: tuple[tuple[bytes, bytes], ...] = self._HEADERS
        if login_script is not None:
            digest = base64.b64encode(hashlib.sha256(login_script.encode("utf-8")).digest())
            self._login_headers = tuple(
                (name, value + b"; script-src 'sha256-" + digest + b"'")
                if name == b"content-security-policy"
                else (name, value)
                for name, value in self._HEADERS
            )

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        async def secured_send(message: Message) -> None:
            if message["type"] == "http.response.start":
                message = dict(message)
                headers = (
                    self._login_headers
                    if scope.get("path") == "/login" and scope.get("method") == "GET"
                    else self._HEADERS
                )
                message["headers"] = [*message.get("headers", ()), *headers]
            await send(message)

        await self._app(scope, receive, secured_send)
