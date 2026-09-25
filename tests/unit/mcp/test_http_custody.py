from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from typing import Any, cast

import httpx
import pytest

from gatehouse.mcp import client as mcp_client
from gatehouse.mcp.client import (
    SESSION_BOOTSTRAP_ENVIRONMENT,
    SESSION_ID_ENVIRONMENT,
    LoopbackMcpBackend,
    McpStartupError,
    _AgentClientError,
    _BoundedAgentClient,
)

CANARY = "synthetic-mcp-custody-canary-" + "x" * 43
CONTROL_ERRORS = (asyncio.CancelledError, KeyboardInterrupt, SystemExit)


class _ResponseStream(httpx.AsyncByteStream):
    def __init__(
        self,
        body: bytes,
        *,
        failure: BaseException | None = None,
        close_failure: BaseException | None = None,
    ) -> None:
        self.body = bytearray(body)
        self.failure = failure
        self.close_failure = close_failure
        self.closes = 0

    async def __aiter__(self) -> AsyncIterator[bytes]:
        if self.failure is not None:
            raise self.failure
        yield bytes(self.body)

    async def aclose(self) -> None:
        self.closes += 1
        if self.close_failure is not None:
            raise self.close_failure


def _client(transport: httpx.AsyncBaseTransport) -> _BoundedAgentClient:
    return _BoundedAgentClient(
        base_url="http://127.0.0.1:47621",
        timeout_seconds=1,
        maximum_request_bytes=1024,
        maximum_response_bytes=1024,
        transport_factory=lambda: transport,
    )


def _assert_error_scrubbed(error: BaseException) -> None:
    assert error.args == ()
    assert error.__cause__ is None
    assert error.__context__ is None
    assert error.__traceback__ is None
    assert not error.__dict__
    if isinstance(error, SystemExit):
        assert error.code is None
    if isinstance(error, OSError):
        assert error.filename is None
        assert error.filename2 is None
        assert error.strerror is None


def _assert_request_scrubbed(request: httpx.Request) -> None:
    assert not request.headers
    assert not request.extensions
    assert request.content == b""
    assert str(request.url) == ""
    assert request.method == ""


@pytest.mark.asyncio
async def test_success_returns_json_but_scrubs_actual_http_objects_and_mutable_buffers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stream = _ResponseStream(json.dumps({"result": CANARY}).encode())
    original_body = stream.body
    requests: list[httpx.Request] = []
    responses: list[httpx.Response] = []
    request_bodies: list[bytearray] = []
    clients: list[httpx.AsyncClient] = []
    original_init = mcp_client._OwnedJsonBody.__init__
    original_client = _BoundedAgentClient._client

    def capture_body(self: mcp_client._OwnedJsonBody, body: bytearray) -> None:
        request_bodies.append(body)
        original_init(self, body)

    def capture_client(self: _BoundedAgentClient) -> httpx.AsyncClient:
        client = original_client(self)
        clients.append(client)
        return client

    monkeypatch.setattr(mcp_client._OwnedJsonBody, "__init__", capture_body)
    monkeypatch.setattr(_BoundedAgentClient, "_client", capture_client)

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["authorization"] == f"Bearer {CANARY}"
        assert json.loads(request.content) == {"bootstrap_capability": CANARY}
        requests.append(request)
        response = httpx.Response(
            200,
            headers={"content-type": "application/json", "set-cookie": f"a={CANARY}"},
            stream=stream,
        )
        responses.append(response)
        return response

    status, result = await _client(httpx.MockTransport(handler)).request(
        "POST",
        "/v1/sessions/exchange",
        payload={"bootstrap_capability": CANARY},
        access_token=CANARY,
        query={"synthetic": CANARY},
    )

    assert status == 200 and result == {"result": CANARY}
    _assert_request_scrubbed(requests[0])
    assert not responses[0].headers and not responses[0].extensions
    assert responses[0].content == b""
    assert original_body and not any(original_body)
    assert request_bodies[0] and not any(request_bodies[0])
    assert clients[0].is_closed and not clients[0].cookies
    assert stream.closes == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [307, 308])
async def test_unfollowed_redirect_scrubs_the_actual_next_request(
    monkeypatch: pytest.MonkeyPatch,
    status: int,
) -> None:
    requests: list[httpx.Request] = []
    responses: list[httpx.Response] = []
    next_requests: list[httpx.Request] = []
    original_send = httpx.AsyncClient.send

    async def capture_send(
        self: httpx.AsyncClient,
        request: httpx.Request,
        **kwargs: object,
    ) -> httpx.Response:
        response = await original_send(self, request, **kwargs)  # type: ignore[arg-type]
        next_request = response.next_request
        assert next_request is not None
        assert next_request.headers["authorization"] == f"Bearer {CANARY}"
        assert CANARY in next_request.headers["cookie"]
        next_requests.append(next_request)
        return response

    monkeypatch.setattr(httpx.AsyncClient, "send", capture_send)

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        response = httpx.Response(
            status,
            headers={"location": "/v1/unfollowed", "set-cookie": f"a={CANARY}"},
            json={"redirect": True},
        )
        responses.append(response)
        return response

    returned_status, _ = await _client(httpx.MockTransport(handler)).request(
        "POST",
        "/v1/test",
        payload={"value": CANARY},
        access_token=CANARY,
    )

    assert returned_status == status
    assert len(requests) == len(next_requests) == 1
    _assert_request_scrubbed(requests[0])
    _assert_request_scrubbed(next_requests[0])
    assert responses[0].next_request is None
    assert not responses[0].headers and responses[0].content == b""


@pytest.mark.asyncio
async def test_finite_exception_chain_cannot_starve_owned_http_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    failures = [RuntimeError(CANARY) for _ in range(80)]
    for outer, inner in zip(failures, failures[1:], strict=False):
        outer.__cause__ = inner
    stream = _ResponseStream(CANARY.encode(), failure=failures[0])
    original_body = stream.body
    requests: list[httpx.Request] = []
    responses: list[httpx.Response] = []
    request_bodies: list[bytearray] = []
    original_init = mcp_client._OwnedJsonBody.__init__

    def capture_body(self: mcp_client._OwnedJsonBody, body: bytearray) -> None:
        request_bodies.append(body)
        original_init(self, body)

    monkeypatch.setattr(mcp_client._OwnedJsonBody, "__init__", capture_body)

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        response = httpx.Response(
            200,
            headers={"content-type": "application/json"},
            stream=stream,
        )
        responses.append(response)
        return response

    with pytest.raises(_AgentClientError) as caught:
        await _client(httpx.MockTransport(handler)).request(
            "POST",
            "/v1/test",
            payload={"value": CANARY},
            access_token=CANARY,
        )

    assert caught.value.__cause__ is None and caught.value.__context__ is None
    _assert_request_scrubbed(requests[0])
    assert not responses[0].headers and responses[0].content == b""
    assert original_body and not any(original_body)
    assert request_bodies[0] and not any(request_bodies[0])
    _assert_error_scrubbed(failures[0])


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["transport", "httpx", "json", "length", "media", "oversize"])
async def test_ordinary_failures_scrub_actual_handles_and_exception_graphs(kind: str) -> None:
    inner = ValueError(CANARY)
    failure = httpx.ReadError(CANARY) if kind == "httpx" else OSError(1, CANARY, CANARY, 1, CANARY)
    failure.__cause__ = inner
    failure.add_note(CANARY)
    cast(Any, failure).secret = CANARY
    requests: list[httpx.Request] = []
    responses: list[httpx.Response] = []
    body = ("{" + CANARY).encode() if kind == "json" else b'{"ok": true}'
    if kind == "oversize":
        body = CANARY.encode() * 20
    stream = _ResponseStream(body)
    original_body = stream.body

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if kind in {"transport", "httpx"}:
            cast(Any, failure).request = request
            raise failure
        headers = {"content-type": "text/plain" if kind == "media" else "application/json"}
        if kind == "length":
            headers["content-length"] = CANARY
        response = httpx.Response(200, headers=headers, stream=stream)
        responses.append(response)
        return response

    with pytest.raises(_AgentClientError) as caught:
        await _client(httpx.MockTransport(handler)).request(
            "POST",
            "/v1/test",
            payload={"value": CANARY},
            access_token=CANARY,
        )

    assert CANARY not in str(caught.value)
    assert caught.value.__cause__ is None and caught.value.__context__ is None
    _assert_request_scrubbed(requests[0])
    if kind in {"transport", "httpx"}:
        _assert_error_scrubbed(failure)
        _assert_error_scrubbed(inner)
    else:
        assert original_body and not any(original_body)
        assert responses[0].content == b"" and not responses[0].headers


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["decode", "encode"])
async def test_unicode_exception_slots_release_the_actual_failed_body(kind: str) -> None:
    failure = (
        UnicodeDecodeError(CANARY, CANARY.encode(), 0, 1, CANARY)
        if kind == "decode"
        else UnicodeEncodeError(CANARY, CANARY, 0, 1, CANARY)
    )
    stream = _ResponseStream(CANARY.encode(), failure=failure)
    original_body = stream.body

    with pytest.raises(_AgentClientError) as caught:
        await _client(
            httpx.MockTransport(
                lambda _: httpx.Response(
                    200,
                    headers={"content-type": "application/json"},
                    stream=stream,
                )
            )
        ).request("POST", "/v1/test", access_token=CANARY)

    assert caught.value.__cause__ is None and caught.value.__context__ is None
    _assert_error_scrubbed(failure)
    assert failure.object == (b"" if kind == "decode" else "")
    assert failure.encoding == failure.reason == ""
    assert failure.start == failure.end == 0
    assert original_body and not any(original_body)


@pytest.mark.asyncio
@pytest.mark.parametrize("primary_type", CONTROL_ERRORS, ids=["cancel", "keyboard", "exit"])
@pytest.mark.parametrize(
    "cleanup_type",
    (RuntimeError, *CONTROL_ERRORS),
    ids=["ordinary", "cancel", "keyboard", "exit"],
)
async def test_primary_control_intent_survives_response_cleanup_failure(
    primary_type: type[BaseException],
    cleanup_type: type[BaseException],
) -> None:
    primary = primary_type(CANARY)
    cleanup = cleanup_type(CANARY)
    stream = _ResponseStream(CANARY.encode(), failure=primary, close_failure=cleanup)
    original_body = stream.body
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, headers={"content-type": "application/json"}, stream=stream)

    with pytest.raises(primary_type) as caught:
        await _client(httpx.MockTransport(handler)).request("POST", "/v1/test", access_token=CANARY)

    assert caught.value is not primary and caught.value is not cleanup
    assert CANARY not in str(caught.value)
    assert caught.value.__context__ is None and caught.value.__cause__ is None
    _assert_error_scrubbed(primary)
    _assert_error_scrubbed(cleanup)
    _assert_request_scrubbed(requests[0])
    assert original_body and not any(original_body)
    assert stream.closes == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("cleanup_type", CONTROL_ERRORS, ids=["cancel", "keyboard", "exit"])
async def test_sole_client_cleanup_control_interruption_is_preserved(
    cleanup_type: type[BaseException],
) -> None:
    failure = cleanup_type(CANARY)

    class Transport(httpx.MockTransport):
        async def aclose(self) -> None:
            raise failure

    with pytest.raises(cleanup_type) as caught:
        await _client(Transport(lambda _: httpx.Response(200, json={"ok": True}))).request(
            "POST",
            "/v1/test",
            access_token=CANARY,
        )
    assert CANARY not in str(caught.value)
    assert caught.value.__context__ is None and caught.value.__cause__ is None
    _assert_error_scrubbed(failure)


@pytest.mark.asyncio
@pytest.mark.parametrize("primary_type", CONTROL_ERRORS, ids=["cancel", "keyboard", "exit"])
async def test_primary_control_intent_survives_client_close_failure(
    primary_type: type[BaseException],
) -> None:
    primary = primary_type(CANARY)
    cleanup = RuntimeError(CANARY)
    closes = 0

    class Transport(httpx.MockTransport):
        async def aclose(self) -> None:
            nonlocal closes
            closes += 1
            raise cleanup

    def handler(request: httpx.Request) -> httpx.Response:
        raise primary

    with pytest.raises(primary_type) as caught:
        await _client(Transport(handler)).request("POST", "/v1/test", access_token=CANARY)
    assert closes == 1
    assert caught.value is not primary and CANARY not in str(caught.value)
    assert caught.value.__context__ is None and caught.value.__cause__ is None
    _assert_error_scrubbed(primary)
    _assert_error_scrubbed(cleanup)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure_type",
    (RuntimeError, *CONTROL_ERRORS),
    ids=["ordinary", "cancel", "keyboard", "exit"],
)
async def test_startup_failure_scrubs_adoption_frames_and_preserves_control_intent(
    failure_type: type[BaseException],
) -> None:
    failure = failure_type(CANARY)
    environment = {SESSION_ID_ENVIRONMENT: "ses_synthetic", SESSION_BOOTSTRAP_ENVIRONMENT: CANARY}

    def handler(request: httpx.Request) -> httpx.Response:
        assert json.loads(request.content)["bootstrap_capability"] == CANARY
        raise failure

    expected = McpStartupError if failure_type is RuntimeError else failure_type
    with pytest.raises(expected) as caught:
        await LoopbackMcpBackend.from_environment(
            environment=environment,
            transport_factory=lambda: httpx.MockTransport(handler),
        )

    assert not environment
    assert CANARY not in str(caught.value)
    assert caught.value.__context__ is None and caught.value.__cause__ is None
    _assert_error_scrubbed(failure)
    traceback = caught.value.__traceback__
    while traceback is not None:
        if traceback.tb_frame.f_code.co_filename.replace("\\", "/").endswith("mcp/client.py"):
            retained = {
                key: value
                for key, value in traceback.tb_frame.f_locals.items()
                if key not in {"cls", "self"}
            }
            assert CANARY not in repr(retained)
        traceback = traceback.tb_next


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "url",
    [
        "http://[::1]:47621",
        "http://localhost:47621",
        "http://127.0.0.1:47621/\n",
    ],
)
async def test_startup_rejects_non_listener_urls_before_transport(url: str) -> None:
    calls = 0

    def factory() -> httpx.AsyncBaseTransport:
        nonlocal calls
        calls += 1
        raise AssertionError("transport must not be constructed")

    with pytest.raises(McpStartupError):
        await LoopbackMcpBackend.from_environment(
            environment={
                SESSION_ID_ENVIRONMENT: "ses_synthetic",
                SESSION_BOOTSTRAP_ENVIRONMENT: CANARY,
            },
            agent_url=url,
            transport_factory=factory,
        )
    assert calls == 0
