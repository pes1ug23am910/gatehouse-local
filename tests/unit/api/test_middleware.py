from __future__ import annotations

import asyncio

import pytest

from gatehouse.api.middleware import LocalRequestBoundsMiddleware


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "host_headers",
    [
        (),
        ((b"host", b"testserver"), (b"host", b"testserver")),
        ((b"host", b"foreign.invalid"), (b"host", b"testserver")),
        ((b"host", b"testserver"), (b"host", b"foreign.invalid")),
        ((b"Host", b"testserver"), (b"hOSt", b"testserver")),
    ],
)
async def test_ambiguous_or_missing_host_is_rejected_before_body_authentication_or_app(
    host_headers: tuple[tuple[bytes, bytes], ...],
) -> None:
    calls: list[str] = []
    messages: list[dict[str, object]] = []

    async def receive() -> dict[str, object]:
        calls.append("receive")
        return {"type": "http.request", "body": b"synthetic", "more_body": False}

    async def app(scope: object, receive: object, send: object) -> None:
        calls.append("app")

    async def authenticate(token: str) -> bool:
        calls.append("authenticate")
        return True

    async def send(message: dict[str, object]) -> None:
        messages.append(message)

    scope = _scope()
    scope["headers"] = (*host_headers, (b"authorization", b"Bearer " + b"a" * 43))
    middleware = LocalRequestBoundsMiddleware(
        app,
        allowed_hosts=("testserver",),
        maximum_body_bytes=64,
        require_bearer=lambda _: True,
        authenticate_bearer=authenticate,
    )
    await middleware(scope, receive, send)  # type: ignore[arg-type]
    assert messages[0]["status"] == 400
    assert b"invalid_target" in messages[1]["body"]  # type: ignore[operator]
    assert calls == []


def _scope() -> dict[str, object]:
    return {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/bounded",
        "raw_path": b"/bounded",
        "query_string": b"",
        "headers": ((b"host", b"testserver"),),
        "client": ("127.0.0.1", 1),
        "server": ("127.0.0.1", 47_621),
    }


@pytest.mark.asyncio
@pytest.mark.parametrize("deferred", [False, True])
async def test_request_body_inter_chunk_deadline_returns_408(deferred: bool) -> None:
    release = asyncio.Event()
    receives = 0

    async def receive() -> dict[str, object]:
        nonlocal receives
        receives += 1
        if receives == 1:
            return {"type": "http.request", "body": b"partial", "more_body": True}
        await release.wait()
        return {"type": "http.request", "body": b"", "more_body": False}

    async def app(scope: object, bounded_receive: object, send: object) -> None:
        del scope, send
        receiver = bounded_receive
        while True:
            message = await receiver()  # type: ignore[operator]
            if not message.get("more_body", False):
                return

    messages: list[dict[str, object]] = []

    async def send(message: dict[str, object]) -> None:
        messages.append(message)

    middleware = LocalRequestBoundsMiddleware(
        app,
        allowed_hosts=("testserver",),
        maximum_body_bytes=64,
        defer_body_read=(lambda _: True) if deferred else None,
        total_body_timeout_ms=100,
        inter_chunk_timeout_ms=10,
    )

    await asyncio.wait_for(
        middleware(_scope(), receive, send),  # type: ignore[arg-type]
        timeout=1,
    )

    starts = [message for message in messages if message["type"] == "http.response.start"]
    assert starts and starts[0]["status"] == 408


@pytest.mark.asyncio
async def test_missing_bearer_is_rejected_without_reading_the_body() -> None:
    body_reads = 0
    app_called = False

    async def receive() -> dict[str, object]:
        nonlocal body_reads
        body_reads += 1
        return {"type": "http.request", "body": b"untrusted", "more_body": False}

    async def app(scope: object, bounded_receive: object, send: object) -> None:
        nonlocal app_called
        del scope, bounded_receive, send
        app_called = True

    messages: list[dict[str, object]] = []

    async def send(message: dict[str, object]) -> None:
        messages.append(message)

    middleware = LocalRequestBoundsMiddleware(
        app,
        allowed_hosts=("testserver",),
        maximum_body_bytes=64,
        require_bearer=lambda _: True,
    )

    await middleware(_scope(), receive, send)  # type: ignore[arg-type]

    starts = [message for message in messages if message["type"] == "http.response.start"]
    assert starts and starts[0]["status"] == 401
    assert body_reads == 0
    assert not app_called


@pytest.mark.asyncio
async def test_unknown_shaped_bearer_is_rejected_before_reading_the_body() -> None:
    body_reads = 0
    app_called = False
    authenticated: list[str] = []

    async def receive() -> dict[str, object]:
        nonlocal body_reads
        body_reads += 1
        return {"type": "http.request", "body": b"untrusted", "more_body": False}

    async def app(scope: object, bounded_receive: object, send: object) -> None:
        nonlocal app_called
        del scope, bounded_receive, send
        app_called = True

    async def authenticate(token: str) -> bool:
        authenticated.append(token)
        return False

    messages: list[dict[str, object]] = []

    async def send(message: dict[str, object]) -> None:
        messages.append(message)

    token = "A" * 43
    scope = _scope()
    scope["headers"] = (
        (b"host", b"testserver"),
        (b"authorization", f"Bearer {token}".encode("ascii")),
    )
    middleware = LocalRequestBoundsMiddleware(
        app,
        allowed_hosts=("testserver",),
        maximum_body_bytes=64,
        require_bearer=lambda _: True,
        authenticate_bearer=authenticate,
    )

    await middleware(scope, receive, send)  # type: ignore[arg-type]

    starts = [message for message in messages if message["type"] == "http.response.start"]
    assert starts and starts[0]["status"] == 401
    assert authenticated == [token]
    assert body_reads == 0
    assert not app_called
