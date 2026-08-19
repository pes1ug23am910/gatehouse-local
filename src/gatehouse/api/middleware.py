"""ASGI-level local Host validation and complete request-body bounds."""

from __future__ import annotations

from collections.abc import Iterable

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from gatehouse.core.errors import ErrorCode, make_error

from .errors import error_response, schema_error


class LocalRequestBoundsMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        *,
        allowed_hosts: Iterable[str],
        maximum_body_bytes: int,
    ) -> None:
        hosts = frozenset(host.casefold().rstrip(".") for host in allowed_hosts)
        if not hosts:
            raise ValueError("at least one local Host value is required")
        if maximum_body_bytes <= 0:
            raise ValueError("maximum_body_bytes must be positive")
        self._app = app
        self._allowed_hosts = hosts
        self._maximum_body_bytes = maximum_body_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        headers = {
            key.decode("latin-1").casefold(): value.decode("latin-1")
            for key, value in scope.get("headers", ())
        }
        host = headers.get("host", "").casefold().rstrip(".")
        if host not in self._allowed_hosts:
            await error_response(
                make_error(ErrorCode.INVALID_TARGET, retryable=False),
                status_code=400,
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

        body = bytearray()
        disconnected = False
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                disconnected = True
                break
            if message["type"] != "http.request":
                continue
            body.extend(message.get("body", b""))
            if len(body) > self._maximum_body_bytes:
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

        await self._app(scope, replay, send)


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

    def __init__(self, app: ASGIApp) -> None:
        self._app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        async def secured_send(message: Message) -> None:
            if message["type"] == "http.response.start":
                message = dict(message)
                message["headers"] = [*message.get("headers", ()), *self._HEADERS]
            await send(message)

        await self._app(scope, receive, secured_send)
