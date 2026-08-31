from __future__ import annotations

import asyncio
import json
from collections.abc import Callable, Mapping

import httpx
import pytest

from gatehouse.core.errors import JsonValue
from gatehouse.core.ids import RequestId
from gatehouse.mcp import LoopbackMcpBackend, McpStartupError, create_mcp_server
from gatehouse.mcp import client as mcp_client
from gatehouse.mcp import server as mcp_server
from gatehouse.mcp.client import (
    AGENT_URL_ENVIRONMENT,
    SESSION_BOOTSTRAP_ENVIRONMENT,
    SESSION_ID_ENVIRONMENT,
)

SESSION_ID = "ses_controlled"
BOOTSTRAP = "b" * 43
ACCESS_TOKEN = "a" * 43
READOPTED_ACCESS_TOKEN = "c" * 43
ROOT_RUN_ID = "run_server_minted"
HEARTBEAT_INTERVAL_MS = 30_000


def _json_body(request: httpx.Request) -> dict[str, object]:
    decoded = json.loads(request.content.decode("utf-8"))
    assert isinstance(decoded, dict)
    return decoded


def _error_code(result: Mapping[str, object]) -> object:
    error = result.get("error")
    assert isinstance(error, dict)
    return error.get("code")


def _adoption_response(
    request: httpx.Request,
    *,
    capabilities: list[str],
) -> httpx.Response | None:
    if request.url.path == "/v1/sessions/exchange":
        return httpx.Response(
            200,
            json={
                "access_token": ACCESS_TOKEN,
                "token_type": "Bearer",
                "expires_in_seconds": 600,
                "heartbeat_interval_ms": HEARTBEAT_INTERVAL_MS,
                "session": {"session_id": SESSION_ID, "state": "ACTIVE"},
                "capabilities": capabilities,
            },
        )
    if request.url.path == "/v1/root-runs":
        return httpx.Response(
            201,
            json={
                "root_run_id": ROOT_RUN_ID,
                "session_id": SESSION_ID,
                "state": "ACTIVE",
            },
        )
    return None


def _environment(*, agent_url: str | None = None) -> dict[str, str]:
    result = {
        SESSION_ID_ENVIRONMENT: SESSION_ID,
        SESSION_BOOTSTRAP_ENVIRONMENT: BOOTSTRAP,
    }
    if agent_url is not None:
        result[AGENT_URL_ENVIRONMENT] = agent_url
    return result


def _transport_factory(
    handler: Callable[[httpx.Request], httpx.Response],
) -> Callable[[], httpx.AsyncBaseTransport]:
    return lambda: httpx.MockTransport(handler)


@pytest.mark.asyncio
async def test_adoption_consumes_environment_once_and_registers_returned_public_tools() -> None:
    requests: list[httpx.Request] = []
    capabilities = [
        "docs.search",
        "firecrawl.search",
        "firecrawl.account.credit_status",
    ]

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        response = _adoption_response(request, capabilities=capabilities)
        assert response is not None
        return response

    environment = _environment()
    backend = await LoopbackMcpBackend.from_environment(
        environment=environment,
        client_nonce="nonce-mcp-client",
        transport_factory=_transport_factory(handler),
    )

    assert SESSION_ID_ENVIRONMENT not in environment
    assert SESSION_BOOTSTRAP_ENVIRONMENT not in environment
    assert backend.capabilities == frozenset({"docs.search", "firecrawl.search"})
    assert backend.session_heartbeat_interval_seconds == 30.0
    assert [request.url.path for request in requests] == [
        "/v1/sessions/exchange",
        "/v1/root-runs",
    ]
    assert all(request.url.port == 47_621 for request in requests)
    assert _json_body(requests[0]) == {
        "session_id": SESSION_ID,
        "bootstrap_capability": BOOTSTRAP,
        "client_nonce": "nonce-mcp-client",
    }
    assert "authorization" not in requests[0].headers
    assert requests[1].headers["authorization"] == f"Bearer {ACCESS_TOKEN}"
    assert ACCESS_TOKEN not in repr(backend)

    tools = await create_mcp_server(
        backend=backend,
        capabilities=backend.capabilities,
    ).list_tools()
    assert {tool.name for tool in tools} == {
        "gatehouse_status",
        "gatehouse_capabilities",
        "gatehouse_docs_search",
        "firecrawl_search",
    }


@pytest.mark.parametrize(
    "heartbeat_interval_ms",
    [None, True, 999, 300_001, 30.5],
)
@pytest.mark.asyncio
async def test_initial_adoption_rejects_invalid_heartbeat_cadence(
    heartbeat_interval_ms: object,
) -> None:
    environment = _environment()

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/v1/sessions/exchange"
        return httpx.Response(
            200,
            json={
                "access_token": ACCESS_TOKEN,
                "token_type": "Bearer",
                "heartbeat_interval_ms": heartbeat_interval_ms,
                "session": {"session_id": SESSION_ID, "state": "ACTIVE"},
                "capabilities": ["firecrawl.search"],
            },
        )

    with pytest.raises(McpStartupError, match="session adoption failed"):
        await LoopbackMcpBackend.from_environment(
            environment=environment,
            client_nonce="nonce-mcp-client",
            transport_factory=_transport_factory(handler),
        )

    assert SESSION_ID_ENVIRONMENT not in environment
    assert SESSION_BOOTSTRAP_ENVIRONMENT not in environment


@pytest.mark.asyncio
async def test_typed_routes_inject_the_exact_adopted_root_run() -> None:
    requests: list[httpx.Request] = []
    capabilities = [
        "firecrawl.search",
        "docs.search",
        "docs.get",
        "feedback.submit",
        "jobs.status",
        "jobs.await",
        "jobs.cancel",
    ]

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        adoption = _adoption_response(request, capabilities=capabilities)
        if adoption is not None:
            return adoption
        return httpx.Response(200, json={"route": request.url.path})

    backend = await LoopbackMcpBackend.from_environment(
        environment=_environment(agent_url="http://127.0.0.1:48111"),
        client_nonce="nonce-mcp-client",
        transport_factory=_transport_factory(handler),
    )
    await backend.call("firecrawl.search", {"query": "graduate roles"})
    await backend.call(
        "docs.search",
        {"service": "firecrawl", "query": "rate limit", "limit": 5},
    )
    await backend.call("docs.get", {"service": "firecrawl", "document": "guide"})
    await backend.call(
        "feedback.submit",
        {
            "category": "contract",
            "severity": "medium",
            "component": "mcp",
            "summary": "Bounded feedback",
        },
    )
    await backend.call("jobs.status", {"job_id": "job_one"})
    await backend.call(
        "jobs.await",
        {"job_id": "job_one", "maximum_wait_ms": 12_345},
    )
    await backend.call("jobs.cancel", {"job_id": "job_one"})

    routed = requests[2:]
    assert all(request.url.port == 48_111 for request in routed)
    assert all(request.headers["authorization"] == f"Bearer {ACCESS_TOKEN}" for request in routed)

    invocation = _json_body(routed[0])
    assert invocation["context"] == {"root_run_id": ROOT_RUN_ID}
    assert invocation["service"] == "firecrawl"
    assert invocation["operation"] == "search"
    assert invocation["input"] == {"query": "graduate roles"}

    status_request = routed[4]
    assert status_request.url.path == "/v1/jobs/job_one"
    assert status_request.url.params["root_run_id"] == ROOT_RUN_ID
    assert _json_body(routed[5]) == {
        "root_run_id": ROOT_RUN_ID,
        "maximum_wait_ms": 12_345,
    }
    assert _json_body(routed[6]) == {"root_run_id": ROOT_RUN_ID}


@pytest.mark.asyncio
async def test_watcher_routes_inject_root_and_strip_targets_and_fence_internals() -> None:
    requests: list[httpx.Request] = []
    capabilities = [
        "watcher.scan_feed_set",
        "watcher.get_cursor",
        "watcher.commit_cursor",
        "watcher.get_previous_summary",
    ]

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        adoption = _adoption_response(request, capabilities=capabilities)
        if adoption is not None:
            return adoption
        return httpx.Response(200, json={"state": "accepted"})

    backend = await LoopbackMcpBackend.from_environment(
        environment=_environment(),
        client_nonce="nonce-mcp-client",
        transport_factory=_transport_factory(handler),
    )
    forged_root = "run_caller_supplied"
    await backend.call(
        "watcher.scan_feed_set",
        {
            "feed_set_id": "placements",
            "cursor": "cursor-7",
            "root_run_id": forged_root,
            "url": "https://outside.example/jobs",
            "targets": ["https://outside.example/jobs"],
        },
    )
    await backend.call("watcher.get_cursor", {"feed_set_id": "placements"})
    await backend.call("watcher.get_previous_summary", {"feed_set_id": "placements"})
    await backend.call(
        "watcher.commit_cursor",
        {
            "feed_set_id": "placements",
            "watcher_run_id": "watch_one",
            "expected_version": 0,
            "cursor_value": "cursor-8",
            "cursor_sequence": 8,
            "root_run_id": forged_root,
            "lease_id": "lease_forged",
            "generation": 99,
            "previous_summary": {"changed": 999},
        },
    )

    scan, cursor, previous, commit = requests[2:]
    assert scan.method == "POST"
    assert scan.url.path == "/v1/watcher/feed-sets/placements/scan"
    assert _json_body(scan) == {"root_run_id": ROOT_RUN_ID, "cursor": "cursor-7"}
    assert cursor.method == previous.method == "GET"
    assert cursor.url.path == "/v1/watcher/feed-sets/placements/cursor"
    assert previous.url.path == "/v1/watcher/feed-sets/placements/previous-summary"
    assert dict(cursor.url.params) == dict(previous.url.params) == {"root_run_id": ROOT_RUN_ID}
    assert commit.method == "POST"
    assert commit.url.path == "/v1/watcher/feed-sets/placements/cursor/commit"
    assert _json_body(commit) == {
        "root_run_id": ROOT_RUN_ID,
        "watcher_run_id": "watch_one",
        "expected_version": 0,
        "cursor_value": "cursor-8",
        "cursor_sequence": 8,
    }


@pytest.mark.asyncio
async def test_exact_mcp_retry_transparently_consumes_pending_approval() -> None:
    requests: list[httpx.Request] = []
    invocation_count = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal invocation_count
        requests.append(request)
        adoption = _adoption_response(request, capabilities=["firecrawl.search"])
        if adoption is not None:
            return adoption
        assert request.url.path == "/v1/invocations"
        invocation_count += 1
        invocation = _json_body(request)
        if invocation_count == 1:
            assert "approval_id" not in invocation
            return httpx.Response(
                202,
                json={
                    "request_id": f"req_{'0' * 25}1",
                    "state": "WAITING_APPROVAL",
                    "approval_id": "apr_pending",
                    "error": {
                        "code": "approval_pending",
                        "message": "Approval is pending in the local dashboard.",
                        "retryable": True,
                        "retry_after_seconds": 1,
                    },
                },
            )
        assert invocation["approval_id"] == "apr_pending"
        return httpx.Response(
            200,
            json={
                "request_id": f"req_{'0' * 25}2",
                "state": "SUCCEEDED",
                "service": "firecrawl",
                "operation": "search",
            },
        )

    backend = await LoopbackMcpBackend.from_environment(
        environment=_environment(),
        client_nonce="nonce-mcp-client",
        transport_factory=_transport_factory(handler),
    )
    payload = {"query": "graduate roles"}

    pending = await backend.call("firecrawl.search", payload)
    completed = await backend.call("firecrawl.search", payload)

    assert _error_code(pending) == "approval_pending"
    assert completed["state"] == "SUCCEEDED"
    invocations = [_json_body(item) for item in requests if item.url.path == "/v1/invocations"]
    assert invocations[0]["context"] == invocations[1]["context"] == {"root_run_id": ROOT_RUN_ID}
    assert invocations[0]["input"] == invocations[1]["input"] == payload


@pytest.mark.asyncio
async def test_pending_approval_is_never_attached_to_a_different_mcp_request() -> None:
    invocations: list[dict[str, object]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        adoption = _adoption_response(request, capabilities=["firecrawl.search"])
        if adoption is not None:
            return adoption
        invocation = _json_body(request)
        invocations.append(invocation)
        return httpx.Response(
            202,
            json={
                "request_id": f"req_{'0' * 25}{len(invocations)}",
                "state": "WAITING_APPROVAL",
                "approval_id": f"apr_{len(invocations)}",
                "error": {
                    "code": "approval_pending",
                    "message": "pending",
                    "retryable": True,
                    "retry_after_seconds": 1,
                },
            },
        )

    backend = await LoopbackMcpBackend.from_environment(
        environment=_environment(),
        client_nonce="nonce-mcp-client",
        transport_factory=_transport_factory(handler),
    )

    await backend.call("firecrawl.search", {"query": "graduate roles"})
    await backend.call("firecrawl.search", {"query": "different exact request"})

    assert "approval_id" not in invocations[0]
    assert "approval_id" not in invocations[1]


@pytest.mark.asyncio
async def test_invalid_pending_approval_response_is_sanitized_and_never_cached() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        adoption = _adoption_response(request, capabilities=["firecrawl.search"])
        if adoption is not None:
            return adoption
        return httpx.Response(
            202,
            json={
                "request_id": "not-a-request-id",
                "state": "WAITING_APPROVAL",
                "approval_id": "apr_pending",
                "error": {
                    "code": "approval_pending",
                    "message": "untrusted daemon text",
                    "retryable": True,
                },
            },
        )

    backend = await LoopbackMcpBackend.from_environment(
        environment=_environment(),
        client_nonce="nonce-mcp-client",
        transport_factory=_transport_factory(handler),
    )

    result = await backend.call("firecrawl.search", {"query": "graduate roles"})

    assert _error_code(result) == "daemon_degraded"
    assert backend.pending_approval_count == 0
    assert "untrusted daemon text" not in repr(result)


@pytest.mark.asyncio
async def test_pending_approval_cache_is_bounded_and_retains_no_request_payload() -> None:
    invocation_count = 0
    canary = "fc-secret-canary-never-retained"

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal invocation_count
        adoption = _adoption_response(request, capabilities=["firecrawl.search"])
        if adoption is not None:
            return adoption
        invocation_count += 1
        return httpx.Response(
            202,
            json={
                "request_id": f"req_{invocation_count:026d}",
                "state": "WAITING_APPROVAL",
                "approval_id": f"apr_{invocation_count}",
                "error": {
                    "code": "approval_pending",
                    "message": "pending",
                    "retryable": True,
                    "retry_after_seconds": 1,
                },
            },
        )

    backend = await LoopbackMcpBackend.from_environment(
        environment=_environment(),
        client_nonce="nonce-mcp-client",
        transport_factory=_transport_factory(handler),
    )
    for index in range(80):
        await backend.call("firecrawl.search", {"query": f"{canary}-{index}"})

    assert backend.pending_approval_count == 64
    assert canary not in repr(backend)


@pytest.mark.asyncio
async def test_only_one_exact_approval_continuation_can_be_in_flight() -> None:
    invocation_count = 0
    continuation_started = asyncio.Event()
    release_continuation = asyncio.Event()

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal invocation_count
        adoption = _adoption_response(request, capabilities=["firecrawl.search"])
        if adoption is not None:
            return adoption
        invocation_count += 1
        invocation = _json_body(request)
        if invocation_count == 1:
            return httpx.Response(
                202,
                json={
                    "request_id": f"req_{'0' * 25}1",
                    "state": "WAITING_APPROVAL",
                    "approval_id": "apr_pending",
                    "error": {
                        "code": "approval_pending",
                        "message": "pending",
                        "retryable": True,
                        "retry_after_seconds": 1,
                    },
                },
            )
        assert invocation["approval_id"] == "apr_pending"
        continuation_started.set()
        await release_continuation.wait()
        return httpx.Response(
            200,
            json={
                "request_id": f"req_{'0' * 25}2",
                "state": "SUCCEEDED",
                "service": "firecrawl",
                "operation": "search",
            },
        )

    backend = await LoopbackMcpBackend.from_environment(
        environment=_environment(),
        client_nonce="nonce-mcp-client",
        transport_factory=lambda: httpx.MockTransport(handler),
    )
    payload = {"query": "graduate roles"}
    await backend.call("firecrawl.search", payload)

    first = asyncio.create_task(backend.call("firecrawl.search", payload))
    await asyncio.wait_for(continuation_started.wait(), timeout=1)
    second = await backend.call("firecrawl.search", payload)
    release_continuation.set()
    completed = await asyncio.wait_for(first, timeout=1)

    assert _error_code(second) == "approval_pending"
    assert completed["state"] == "SUCCEEDED"
    assert invocation_count == 2


@pytest.mark.asyncio
async def test_crawl_approval_continuation_reuses_its_recovery_handle_after_ambiguity() -> None:
    invocations: list[dict[str, object]] = []
    original_request_id = "req_00000000000000000000000001"

    def handler(request: httpx.Request) -> httpx.Response:
        adoption = _adoption_response(request, capabilities=["firecrawl.crawl.start"])
        if adoption is not None:
            return adoption
        invocation = _json_body(request)
        invocations.append(invocation)
        request_id = invocation["request_id"]
        if len(invocations) == 1:
            return httpx.Response(
                202,
                json={
                    "request_id": request_id,
                    "state": "WAITING_APPROVAL",
                    "approval_id": "apr_pending",
                    "error": {
                        "code": "approval_pending",
                        "message": "pending",
                        "retryable": True,
                        "retry_after_seconds": 1,
                    },
                },
            )
        if len(invocations) == 2:
            return httpx.Response(
                503,
                json={
                    "error": {
                        "code": "daemon_degraded",
                        "message": "ambiguous local response",
                        "retryable": True,
                        "retry_after_seconds": 1,
                        "request_id": request_id,
                    }
                },
            )
        return httpx.Response(
            200,
            json={
                "request_id": request_id,
                "state": "SUCCEEDED",
                "service": "firecrawl",
                "operation": "crawl.start",
                "job_id": "job_one",
            },
        )

    backend = await LoopbackMcpBackend.from_environment(
        environment=_environment(),
        client_nonce="nonce-mcp-client",
        transport_factory=_transport_factory(handler),
    )
    payload = {"url": "https://example.com/careers"}

    await backend.call(
        "firecrawl.crawl.start",
        payload,
        request_id=original_request_id,
    )
    ambiguous = await backend.call(
        "firecrawl.crawl.start",
        payload,
        request_id=original_request_id,
    )
    recovered = await backend.call(
        "firecrawl.crawl.start",
        payload,
        request_id=original_request_id,
    )

    continuation_request_id = invocations[1]["request_id"]
    assert continuation_request_id != original_request_id
    assert invocations[2]["request_id"] == continuation_request_id
    assert "approval_id" not in invocations[0]
    assert invocations[1]["approval_id"] == invocations[2]["approval_id"] == "apr_pending"
    assert _error_code(ambiguous) == "daemon_degraded"
    assert recovered["state"] == "SUCCEEDED"


@pytest.mark.asyncio
async def test_cancelling_claimed_crawl_continuation_releases_claim_and_preserves_recovery_id() -> (
    None
):
    invocations: list[dict[str, object]] = []
    continuation_started = asyncio.Event()
    original_request_id = "req_00000000000000000000000001"

    async def handler(request: httpx.Request) -> httpx.Response:
        adoption = _adoption_response(request, capabilities=["firecrawl.crawl.start"])
        if adoption is not None:
            return adoption
        invocation = _json_body(request)
        invocations.append(invocation)
        request_id = invocation["request_id"]
        if len(invocations) == 1:
            return httpx.Response(
                202,
                json={
                    "request_id": request_id,
                    "state": "WAITING_APPROVAL",
                    "approval_id": "apr_pending",
                    "approval_context": {"root_run_id": ROOT_RUN_ID},
                    "error": {
                        "code": "approval_pending",
                        "message": "pending",
                        "retryable": True,
                        "retry_after_seconds": 1,
                    },
                },
            )
        if len(invocations) == 2:
            continuation_started.set()
            await asyncio.Event().wait()
        return httpx.Response(
            200,
            json={
                "request_id": request_id,
                "state": "SUCCEEDED",
                "service": "firecrawl",
                "operation": "crawl.start",
                "job_id": "job_one",
            },
        )

    backend = await LoopbackMcpBackend.from_environment(
        environment=_environment(),
        client_nonce="nonce-mcp-client",
        transport_factory=lambda: httpx.MockTransport(handler),
    )
    payload = {"url": "https://example.com/careers"}
    await backend.call("firecrawl.crawl.start", payload, request_id=original_request_id)
    cancelled = asyncio.create_task(
        backend.call("firecrawl.crawl.start", payload, request_id=original_request_id)
    )
    await asyncio.wait_for(continuation_started.wait(), timeout=1)

    cancelled.cancel()
    with pytest.raises(asyncio.CancelledError):
        await cancelled
    recovered = await backend.call(
        "firecrawl.crawl.start",
        payload,
        request_id=original_request_id,
    )

    assert recovered["state"] == "SUCCEEDED"
    assert invocations[1]["request_id"] == invocations[2]["request_id"]
    assert invocations[1]["request_id"] != original_request_id


@pytest.mark.asyncio
async def test_expired_in_flight_claim_lease_cannot_wedge_exact_retry() -> None:
    now = [0.0]
    invocation_count = 0
    blocked_continuation = asyncio.Event()

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal invocation_count
        adoption = _adoption_response(request, capabilities=["firecrawl.search"])
        if adoption is not None:
            return adoption
        invocation_count += 1
        if invocation_count == 1:
            return httpx.Response(
                202,
                json={
                    "request_id": "req_00000000000000000000000001",
                    "state": "WAITING_APPROVAL",
                    "approval_id": "apr_pending",
                    "error": {
                        "code": "approval_pending",
                        "message": "pending",
                        "retryable": True,
                        "retry_after_seconds": 1,
                    },
                },
            )
        if invocation_count == 2:
            blocked_continuation.set()
            await asyncio.Event().wait()
        return httpx.Response(
            200,
            json={
                "request_id": "req_00000000000000000000000003",
                "state": "SUCCEEDED",
                "service": "firecrawl",
                "operation": "search",
            },
        )

    backend = await LoopbackMcpBackend.from_environment(
        environment=_environment(),
        client_nonce="nonce-mcp-client",
        approval_claim_lease_seconds=1,
        monotonic=lambda: now[0],
        transport_factory=lambda: httpx.MockTransport(handler),
    )
    payload = {"query": "graduate roles"}
    await backend.call("firecrawl.search", payload)
    stale = asyncio.create_task(backend.call("firecrawl.search", payload))
    await asyncio.wait_for(blocked_continuation.wait(), timeout=1)

    now[0] = 2.0
    completed = await backend.call("firecrawl.search", payload)
    stale.cancel()
    with pytest.raises(asyncio.CancelledError):
        await stale

    assert completed["state"] == "SUCCEEDED"
    assert invocation_count == 3


def test_approval_request_commitment_is_keyed_per_process() -> None:
    first = mcp_client._approval_request_key(  # noqa: SLF001
        cache_key=b"a" * 32,
        session_id=SESSION_ID,
        root_run_id=ROOT_RUN_ID,
        operation="firecrawl.search",
        payload={"query": "graduate roles"},
        caller_request_id=None,
    )
    second = mcp_client._approval_request_key(  # noqa: SLF001
        cache_key=b"b" * 32,
        session_id=SESSION_ID,
        root_run_id=ROOT_RUN_ID,
        operation="firecrawl.search",
        payload={"query": "graduate roles"},
        caller_request_id=None,
    )

    assert first != second
    assert "graduate roles" not in first


@pytest.mark.parametrize("initial_request_id", [None, "req_00000000000000000000000001"])
@pytest.mark.asyncio
async def test_restarted_mcp_recovers_pending_crawl_then_uses_original_bound_root(
    initial_request_id: str | None,
) -> None:
    old_root = "run_original_pending"
    new_root = "run_after_restart"
    approval_id = "apr_pending"
    original_request_id: str | None = None
    continuation_bodies: list[dict[str, object]] = []
    heartbeat_bodies: list[dict[str, object]] = []

    def first_handler(request: httpx.Request) -> httpx.Response:
        nonlocal original_request_id
        if request.url.path == "/v1/sessions/exchange":
            response = _adoption_response(request, capabilities=["firecrawl.crawl.start"])
            assert response is not None
            return response
        if request.url.path == "/v1/root-runs":
            return httpx.Response(
                201,
                json={"root_run_id": old_root, "session_id": SESSION_ID, "state": "ACTIVE"},
            )
        body = _json_body(request)
        original_request_id = str(body["request_id"])
        return httpx.Response(
            202,
            json={
                "request_id": original_request_id,
                "state": "WAITING_APPROVAL",
                "approval_id": approval_id,
                "approval_context": {
                    "root_run_id": old_root,
                    "dashboard_url": "http://127.0.0.1:47622/dashboard",
                    "required_action": "decide_locally_then_retry_exact_request",
                },
                "error": {
                    "code": "approval_pending",
                    "message": "pending",
                    "retryable": True,
                    "retry_after_seconds": 1,
                },
            },
        )

    first_backend = await LoopbackMcpBackend.from_environment(
        environment=_environment(),
        client_nonce="nonce-first-process",
        transport_factory=_transport_factory(first_handler),
    )
    payload = {"url": "https://example.com/careers"}
    first_pending = await first_backend.call(
        "firecrawl.crawl.start",
        payload,
        request_id=initial_request_id,
    )
    assert _error_code(first_pending) == "approval_pending"
    assert original_request_id is not None

    def restarted_handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/sessions/exchange":
            response = _adoption_response(request, capabilities=["firecrawl.crawl.start"])
            assert response is not None
            return response
        if request.url.path == "/v1/root-runs":
            return httpx.Response(
                201,
                json={"root_run_id": new_root, "session_id": SESSION_ID, "state": "ACTIVE"},
            )
        if request.url.path == "/v1/sessions/heartbeat":
            heartbeat_bodies.append(_json_body(request))
            return httpx.Response(
                200,
                json={
                    "status": "active",
                    "session_id": SESSION_ID,
                    "reported_agent_count": 1,
                },
            )
        body = _json_body(request)
        continuation_bodies.append(body)
        if len(continuation_bodies) == 1:
            assert body["request_id"] == original_request_id
            return httpx.Response(
                202,
                json={
                    "request_id": original_request_id,
                    "state": "WAITING_APPROVAL",
                    "approval_id": approval_id,
                    "approval_context": {
                        "root_run_id": old_root,
                        "dashboard_url": "http://127.0.0.1:47622/dashboard",
                        "required_action": "decide_locally_then_retry_exact_request",
                    },
                    "error": {
                        "code": "approval_pending",
                        "message": "pending",
                        "retryable": True,
                        "retry_after_seconds": 1,
                    },
                },
            )
        assert body["approval_id"] == approval_id
        assert body["context"] == {"root_run_id": old_root}
        assert body["request_id"] != original_request_id
        return httpx.Response(
            200,
            json={
                "request_id": body["request_id"],
                "state": "SUCCEEDED",
                "service": "firecrawl",
                "operation": "crawl.start",
                "job_id": "job_one",
            },
        )

    restarted = await LoopbackMcpBackend.from_environment(
        environment=_environment(),
        client_nonce="nonce-restarted-process",
        transport_factory=_transport_factory(restarted_handler),
    )
    recovered_pending = await restarted.call(
        "firecrawl.crawl.start",
        payload,
        request_id=original_request_id,
    )
    heartbeat = await restarted.maintain_session()
    completed = await restarted.call(
        "firecrawl.crawl.start",
        payload,
        request_id=original_request_id,
    )

    assert _error_code(recovered_pending) == "approval_pending"
    approval_context = recovered_pending["approval_context"]
    assert isinstance(approval_context, dict)
    assert approval_context["dashboard_url"] == "http://127.0.0.1:47622/dashboard"
    assert heartbeat["status"] == "active"
    assert heartbeat_bodies == [
        {"active_root_runs": [new_root, old_root], "reported_agent_count": 1}
    ]
    assert completed["state"] == "SUCCEEDED"


@pytest.mark.asyncio
async def test_unauthorized_request_readopts_once_and_preserves_root_authority() -> None:
    requests: list[httpx.Request] = []
    exchanges = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal exchanges
        requests.append(request)
        if request.url.path == "/v1/sessions/exchange":
            exchanges += 1
            token = ACCESS_TOKEN if exchanges == 1 else READOPTED_ACCESS_TOKEN
            return httpx.Response(
                200,
                json={
                    "access_token": token,
                    "token_type": "Bearer",
                    "heartbeat_interval_ms": HEARTBEAT_INTERVAL_MS,
                    "session": {"session_id": SESSION_ID, "state": "ACTIVE"},
                    "capabilities": ["firecrawl.search"],
                },
            )
        if request.url.path == "/v1/root-runs":
            return httpx.Response(
                201,
                json={
                    "root_run_id": ROOT_RUN_ID,
                    "session_id": SESSION_ID,
                    "state": "ACTIVE",
                },
            )
        if request.url.path == "/v1/invocations":
            if request.headers["authorization"] == f"Bearer {ACCESS_TOKEN}":
                return httpx.Response(401, json={"error": {"code": "invalid_session"}})
            assert request.headers["authorization"] == f"Bearer {READOPTED_ACCESS_TOKEN}"
            return httpx.Response(
                200,
                json={
                    "request_id": f"req_{'0' * 25}1",
                    "state": "SUCCEEDED",
                    "service": "firecrawl",
                    "operation": "search",
                },
            )
        raise AssertionError(f"unexpected request path: {request.url.path}")

    backend = await LoopbackMcpBackend.from_environment(
        environment=_environment(),
        client_nonce="nonce-mcp-client",
        transport_factory=_transport_factory(handler),
    )

    result = await backend.call("firecrawl.search", {"query": "graduate roles"})

    assert result["state"] == "SUCCEEDED"
    assert exchanges == 2
    assert [request.url.path for request in requests].count("/v1/root-runs") == 1
    exchange_bodies = [
        _json_body(request) for request in requests if request.url.path == "/v1/sessions/exchange"
    ]
    assert [body["session_id"] for body in exchange_bodies] == [SESSION_ID, SESSION_ID]
    assert [body["bootstrap_capability"] for body in exchange_bodies] == [
        BOOTSTRAP,
        BOOTSTRAP,
    ]
    invocation_bodies = [
        _json_body(request) for request in requests if request.url.path == "/v1/invocations"
    ]
    assert [body["context"] for body in invocation_bodies] == [
        {"root_run_id": ROOT_RUN_ID},
        {"root_run_id": ROOT_RUN_ID},
    ]


@pytest.mark.asyncio
async def test_maintenance_heartbeat_readopts_and_preserves_the_exact_root() -> None:
    requests: list[httpx.Request] = []
    exchanges = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal exchanges
        requests.append(request)
        if request.url.path == "/v1/sessions/exchange":
            exchanges += 1
            return httpx.Response(
                200,
                json={
                    "access_token": (ACCESS_TOKEN if exchanges == 1 else READOPTED_ACCESS_TOKEN),
                    "token_type": "Bearer",
                    "heartbeat_interval_ms": 30_000 if exchanges == 1 else 5_000,
                    "session": {"session_id": SESSION_ID, "state": "ACTIVE"},
                    "capabilities": ["firecrawl.search"],
                },
            )
        if request.url.path == "/v1/root-runs":
            return httpx.Response(
                201,
                json={
                    "root_run_id": ROOT_RUN_ID,
                    "session_id": SESSION_ID,
                    "state": "ACTIVE",
                },
            )
        if request.url.path == "/v1/sessions/heartbeat":
            if request.headers["authorization"] == f"Bearer {ACCESS_TOKEN}":
                return httpx.Response(401, json={"error": {"code": "invalid_session"}})
            assert request.headers["authorization"] == f"Bearer {READOPTED_ACCESS_TOKEN}"
            return httpx.Response(
                200,
                json={
                    "status": "active",
                    "session_id": SESSION_ID,
                    "reported_agent_count": 1,
                },
            )
        raise AssertionError(f"unexpected request path: {request.url.path}")

    backend = await LoopbackMcpBackend.from_environment(
        environment=_environment(),
        client_nonce="nonce-mcp-client",
        transport_factory=_transport_factory(handler),
    )

    result = await backend.maintain_session()

    assert result == {
        "status": "active",
        "session_id": SESSION_ID,
        "reported_agent_count": 1,
    }
    assert exchanges == 2
    assert backend.session_heartbeat_interval_seconds == 5.0
    assert [request.url.path for request in requests].count("/v1/root-runs") == 1
    heartbeats = [
        _json_body(request) for request in requests if request.url.path == "/v1/sessions/heartbeat"
    ]
    assert heartbeats == [
        {"active_root_runs": [ROOT_RUN_ID], "reported_agent_count": 1},
        {"active_root_runs": [ROOT_RUN_ID], "reported_agent_count": 1},
    ]


@pytest.mark.asyncio
async def test_transient_readoption_failure_remains_retryable() -> None:
    exchanges = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal exchanges
        if request.url.path == "/v1/sessions/exchange":
            exchanges += 1
            if exchanges == 2:
                raise httpx.ConnectError("restart race", request=request)
            return httpx.Response(
                200,
                json={
                    "access_token": ACCESS_TOKEN,
                    "token_type": "Bearer",
                    "heartbeat_interval_ms": HEARTBEAT_INTERVAL_MS,
                    "session": {"session_id": SESSION_ID, "state": "ACTIVE"},
                    "capabilities": ["firecrawl.search"],
                },
            )
        if request.url.path == "/v1/root-runs":
            return httpx.Response(
                201,
                json={
                    "root_run_id": ROOT_RUN_ID,
                    "session_id": SESSION_ID,
                    "state": "ACTIVE",
                },
            )
        return httpx.Response(401, json={"error": {"code": "invalid_session"}})

    backend = await LoopbackMcpBackend.from_environment(
        environment=_environment(),
        client_nonce="nonce-mcp-client",
        transport_factory=_transport_factory(handler),
    )

    result = await backend.call("firecrawl.search", {"query": "graduate roles"})

    assert _error_code(result) == "daemon_degraded"
    error = result["error"]
    assert isinstance(error, dict)
    assert error["retryable"] is True
    assert exchanges == 2


@pytest.mark.asyncio
async def test_readoption_rejects_invalid_cadence_without_replacing_session_state() -> None:
    exchanges = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal exchanges
        if request.url.path == "/v1/sessions/exchange":
            exchanges += 1
            return httpx.Response(
                200,
                json={
                    "access_token": (ACCESS_TOKEN if exchanges == 1 else READOPTED_ACCESS_TOKEN),
                    "token_type": "Bearer",
                    "heartbeat_interval_ms": (
                        999 if exchanges == 2 else (30_000 if exchanges == 1 else 2_000)
                    ),
                    "session": {"session_id": SESSION_ID, "state": "ACTIVE"},
                    "capabilities": ["firecrawl.search"],
                },
            )
        if request.url.path == "/v1/root-runs":
            return httpx.Response(
                201,
                json={
                    "root_run_id": ROOT_RUN_ID,
                    "session_id": SESSION_ID,
                    "state": "ACTIVE",
                },
            )
        if request.url.path == "/v1/invocations":
            if request.headers["authorization"] == f"Bearer {ACCESS_TOKEN}":
                return httpx.Response(401, json={"error": {"code": "invalid_session"}})
            return httpx.Response(200, json={"state": "SUCCEEDED"})
        raise AssertionError(f"unexpected request path: {request.url.path}")

    backend = await LoopbackMcpBackend.from_environment(
        environment=_environment(),
        client_nonce="nonce-mcp-client",
        transport_factory=_transport_factory(handler),
    )

    rejected = await backend.call("firecrawl.search", {"query": "graduate roles"})
    assert _error_code(rejected) == "daemon_degraded"
    assert backend.session_heartbeat_interval_seconds == 30.0
    assert exchanges == 2

    retried = await backend.call("firecrawl.search", {"query": "graduate roles"})
    assert retried["state"] == "SUCCEEDED"
    assert backend.session_heartbeat_interval_seconds == 2.0
    assert exchanges == 3


@pytest.mark.asyncio
async def test_rejected_readoption_is_a_nonretryable_invalid_session() -> None:
    exchanges = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal exchanges
        if request.url.path == "/v1/sessions/exchange":
            exchanges += 1
            if exchanges == 2:
                return httpx.Response(401, json={"error": {"code": "invalid_session"}})
            return httpx.Response(
                200,
                json={
                    "access_token": ACCESS_TOKEN,
                    "token_type": "Bearer",
                    "heartbeat_interval_ms": HEARTBEAT_INTERVAL_MS,
                    "session": {"session_id": SESSION_ID, "state": "ACTIVE"},
                    "capabilities": ["firecrawl.search"],
                },
            )
        if request.url.path == "/v1/root-runs":
            return httpx.Response(
                201,
                json={
                    "root_run_id": ROOT_RUN_ID,
                    "session_id": SESSION_ID,
                    "state": "ACTIVE",
                },
            )
        return httpx.Response(401, json={"error": {"code": "invalid_session"}})

    backend = await LoopbackMcpBackend.from_environment(
        environment=_environment(),
        client_nonce="nonce-mcp-client",
        transport_factory=_transport_factory(handler),
    )

    result = await backend.call("firecrawl.search", {"query": "graduate roles"})

    assert _error_code(result) == "invalid_session"
    error = result["error"]
    assert isinstance(error, dict)
    assert error["retryable"] is False
    assert exchanges == 2


@pytest.mark.parametrize("terminal_code", ["session_expired", "session_revoked"])
@pytest.mark.asyncio
async def test_rejected_readoption_preserves_terminal_session_code(
    terminal_code: str,
) -> None:
    exchanges = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal exchanges
        if request.url.path == "/v1/sessions/exchange":
            exchanges += 1
            if exchanges == 2:
                return httpx.Response(401, json={"error": {"code": terminal_code}})
            return httpx.Response(
                200,
                json={
                    "access_token": ACCESS_TOKEN,
                    "token_type": "Bearer",
                    "heartbeat_interval_ms": HEARTBEAT_INTERVAL_MS,
                    "session": {"session_id": SESSION_ID, "state": "ACTIVE"},
                    "capabilities": ["firecrawl.search"],
                },
            )
        if request.url.path == "/v1/root-runs":
            return httpx.Response(
                201,
                json={
                    "root_run_id": ROOT_RUN_ID,
                    "session_id": SESSION_ID,
                    "state": "ACTIVE",
                },
            )
        return httpx.Response(401, json={"error": {"code": "invalid_session"}})

    backend = await LoopbackMcpBackend.from_environment(
        environment=_environment(),
        client_nonce="nonce-mcp-client",
        transport_factory=_transport_factory(handler),
    )

    result = await backend.maintain_session()

    assert _error_code(result) == terminal_code
    error = result["error"]
    assert isinstance(error, dict)
    assert error["retryable"] is False
    assert exchanges == 2


@pytest.mark.asyncio
async def test_readoption_does_not_replay_a_capability_revoked_at_the_new_epoch() -> None:
    exchanges = 0
    invocation_tokens: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal exchanges
        if request.url.path == "/v1/sessions/exchange":
            exchanges += 1
            return httpx.Response(
                200,
                json={
                    "access_token": ACCESS_TOKEN if exchanges == 1 else READOPTED_ACCESS_TOKEN,
                    "token_type": "Bearer",
                    "heartbeat_interval_ms": HEARTBEAT_INTERVAL_MS,
                    "session": {"session_id": SESSION_ID, "state": "ACTIVE"},
                    "capabilities": ["firecrawl.search"] if exchanges == 1 else [],
                },
            )
        if request.url.path == "/v1/root-runs":
            return httpx.Response(
                201,
                json={
                    "root_run_id": ROOT_RUN_ID,
                    "session_id": SESSION_ID,
                    "state": "ACTIVE",
                },
            )
        if request.url.path == "/v1/invocations":
            invocation_tokens.append(request.headers["authorization"])
            return httpx.Response(401, json={"error": {"code": "invalid_session"}})
        raise AssertionError(f"unexpected request path: {request.url.path}")

    backend = await LoopbackMcpBackend.from_environment(
        environment=_environment(),
        client_nonce="nonce-mcp-client",
        transport_factory=_transport_factory(handler),
    )

    result = await backend.call("firecrawl.search", {"query": "graduate roles"})

    assert _error_code(result) == "policy_denied"
    assert invocation_tokens == [f"Bearer {ACCESS_TOKEN}"]
    assert await backend.call("gatehouse.capabilities", {}) == {"capabilities": []}


@pytest.mark.asyncio
async def test_concurrent_unauthorized_requests_share_one_readoption_exchange() -> None:
    exchanges = 0
    old_requests = 0
    new_requests = 0
    both_old_requests = asyncio.Event()

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal exchanges, new_requests, old_requests
        if request.url.path == "/v1/sessions/exchange":
            exchanges += 1
            return httpx.Response(
                200,
                json={
                    "access_token": ACCESS_TOKEN if exchanges == 1 else READOPTED_ACCESS_TOKEN,
                    "token_type": "Bearer",
                    "heartbeat_interval_ms": HEARTBEAT_INTERVAL_MS,
                    "session": {"session_id": SESSION_ID, "state": "ACTIVE"},
                    "capabilities": ["firecrawl.search"],
                },
            )
        if request.url.path == "/v1/root-runs":
            return httpx.Response(
                201,
                json={
                    "root_run_id": ROOT_RUN_ID,
                    "session_id": SESSION_ID,
                    "state": "ACTIVE",
                },
            )
        if request.url.path == "/v1/invocations":
            if request.headers["authorization"] == f"Bearer {ACCESS_TOKEN}":
                old_requests += 1
                if old_requests == 2:
                    both_old_requests.set()
                await asyncio.wait_for(both_old_requests.wait(), timeout=1)
                return httpx.Response(401, json={"error": {"code": "invalid_session"}})
            assert request.headers["authorization"] == f"Bearer {READOPTED_ACCESS_TOKEN}"
            new_requests += 1
            return httpx.Response(200, json={"state": "SUCCEEDED"})
        raise AssertionError(f"unexpected request path: {request.url.path}")

    backend = await LoopbackMcpBackend.from_environment(
        environment=_environment(),
        client_nonce="nonce-mcp-client",
        transport_factory=lambda: httpx.MockTransport(handler),
    )

    results = await asyncio.gather(
        backend.call("firecrawl.search", {"query": "graduate roles"}),
        backend.call("firecrawl.search", {"query": "software internships"}),
    )

    assert [result["state"] for result in results] == ["SUCCEEDED", "SUCCEEDED"]
    assert exchanges == 2
    assert old_requests == 2
    assert new_requests == 2


@pytest.mark.asyncio
async def test_concurrent_stale_callers_share_one_transient_readoption_then_retry() -> None:
    exchanges = 0
    old_requests = 0
    both_old_requests = asyncio.Event()

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal exchanges, old_requests
        if request.url.path == "/v1/sessions/exchange":
            exchanges += 1
            if exchanges == 2:
                raise httpx.ConnectError("restart race", request=request)
            return httpx.Response(
                200,
                json={
                    "access_token": (ACCESS_TOKEN if exchanges == 1 else READOPTED_ACCESS_TOKEN),
                    "token_type": "Bearer",
                    "heartbeat_interval_ms": HEARTBEAT_INTERVAL_MS,
                    "session": {"session_id": SESSION_ID, "state": "ACTIVE"},
                    "capabilities": ["firecrawl.search"],
                },
            )
        if request.url.path == "/v1/root-runs":
            return httpx.Response(
                201,
                json={
                    "root_run_id": ROOT_RUN_ID,
                    "session_id": SESSION_ID,
                    "state": "ACTIVE",
                },
            )
        if request.url.path == "/v1/invocations":
            if request.headers["authorization"] == f"Bearer {ACCESS_TOKEN}":
                old_requests += 1
                if old_requests == 2:
                    both_old_requests.set()
                await asyncio.wait_for(both_old_requests.wait(), timeout=1)
                return httpx.Response(401, json={"error": {"code": "invalid_session"}})
            return httpx.Response(200, json={"state": "SUCCEEDED"})
        raise AssertionError(f"unexpected request path: {request.url.path}")

    backend = await LoopbackMcpBackend.from_environment(
        environment=_environment(),
        client_nonce="nonce-mcp-client",
        transport_factory=lambda: httpx.MockTransport(handler),
    )

    first, second = await asyncio.gather(
        backend.call("firecrawl.search", {"query": "graduate roles"}),
        backend.call("firecrawl.search", {"query": "software internships"}),
    )

    assert _error_code(first) == "daemon_degraded"
    assert _error_code(second) == "daemon_degraded"
    assert exchanges == 2

    retried = await backend.call("firecrawl.search", {"query": "graduate roles"})
    assert retried["state"] == "SUCCEEDED"
    assert exchanges == 3


@pytest.mark.asyncio
async def test_cancelling_one_stale_caller_does_not_cancel_shared_readoption() -> None:
    exchanges = 0
    old_requests = 0
    exchange_started = asyncio.Event()
    second_old_request = asyncio.Event()
    release_exchange = asyncio.Event()

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal exchanges, old_requests
        if request.url.path == "/v1/sessions/exchange":
            exchanges += 1
            if exchanges > 1:
                exchange_started.set()
                await release_exchange.wait()
            return httpx.Response(
                200,
                json={
                    "access_token": (ACCESS_TOKEN if exchanges == 1 else READOPTED_ACCESS_TOKEN),
                    "token_type": "Bearer",
                    "heartbeat_interval_ms": HEARTBEAT_INTERVAL_MS,
                    "session": {"session_id": SESSION_ID, "state": "ACTIVE"},
                    "capabilities": ["firecrawl.search"],
                },
            )
        if request.url.path == "/v1/root-runs":
            return httpx.Response(
                201,
                json={
                    "root_run_id": ROOT_RUN_ID,
                    "session_id": SESSION_ID,
                    "state": "ACTIVE",
                },
            )
        if request.url.path == "/v1/invocations":
            if request.headers["authorization"] == f"Bearer {ACCESS_TOKEN}":
                old_requests += 1
                if old_requests == 2:
                    second_old_request.set()
                return httpx.Response(401, json={"error": {"code": "invalid_session"}})
            return httpx.Response(200, json={"state": "SUCCEEDED"})
        raise AssertionError(f"unexpected request path: {request.url.path}")

    backend = await LoopbackMcpBackend.from_environment(
        environment=_environment(),
        client_nonce="nonce-mcp-client",
        transport_factory=lambda: httpx.MockTransport(handler),
    )
    cancelled = asyncio.create_task(backend.call("firecrawl.search", {"query": "graduate roles"}))
    await asyncio.wait_for(exchange_started.wait(), timeout=1)
    survivor = asyncio.create_task(
        backend.call("firecrawl.search", {"query": "software internships"})
    )
    await asyncio.wait_for(second_old_request.wait(), timeout=1)
    await asyncio.sleep(0)

    cancelled.cancel()
    with pytest.raises(asyncio.CancelledError):
        await cancelled
    release_exchange.set()

    result = await asyncio.wait_for(survivor, timeout=1)
    assert result["state"] == "SUCCEEDED"
    assert exchanges == 2


@pytest.mark.asyncio
async def test_readoption_bounds_the_number_of_shared_exchange_waiters() -> None:
    exchanges = 0
    old_requests = 0
    all_old_requests = asyncio.Event()
    exchange_started = asyncio.Event()
    release_exchange = asyncio.Event()

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal exchanges, old_requests
        if request.url.path == "/v1/sessions/exchange":
            exchanges += 1
            if exchanges > 1:
                exchange_started.set()
                await release_exchange.wait()
            return httpx.Response(
                200,
                json={
                    "access_token": (ACCESS_TOKEN if exchanges == 1 else READOPTED_ACCESS_TOKEN),
                    "token_type": "Bearer",
                    "heartbeat_interval_ms": HEARTBEAT_INTERVAL_MS,
                    "session": {"session_id": SESSION_ID, "state": "ACTIVE"},
                    "capabilities": ["firecrawl.search"],
                },
            )
        if request.url.path == "/v1/root-runs":
            return httpx.Response(
                201,
                json={
                    "root_run_id": ROOT_RUN_ID,
                    "session_id": SESSION_ID,
                    "state": "ACTIVE",
                },
            )
        if request.url.path == "/v1/invocations":
            if request.headers["authorization"] == f"Bearer {ACCESS_TOKEN}":
                old_requests += 1
                if old_requests == 65:
                    all_old_requests.set()
                await asyncio.wait_for(all_old_requests.wait(), timeout=1)
                return httpx.Response(401, json={"error": {"code": "invalid_session"}})
            assert request.headers["authorization"] == f"Bearer {READOPTED_ACCESS_TOKEN}"
            return httpx.Response(200, json={"state": "SUCCEEDED"})
        raise AssertionError(f"unexpected request path: {request.url.path}")

    backend = await LoopbackMcpBackend.from_environment(
        environment=_environment(),
        client_nonce="nonce-mcp-client",
        transport_factory=lambda: httpx.MockTransport(handler),
    )
    tasks = [
        asyncio.create_task(backend.call("firecrawl.search", {"query": f"roles-{index}"}))
        for index in range(65)
    ]
    await asyncio.wait_for(exchange_started.wait(), timeout=1)
    done, _ = await asyncio.wait(tasks, timeout=1, return_when=asyncio.FIRST_COMPLETED)
    release_exchange.set()
    results = await asyncio.gather(*tasks)

    assert len(done) == 1
    assert sum(result.get("state") == "SUCCEEDED" for result in results) == 64
    errors = [result for result in results if isinstance(result.get("error"), dict)]
    assert len(errors) == 1
    assert _error_code(errors[0]) == "daemon_degraded"
    assert exchanges == 2


@pytest.mark.asyncio
async def test_crawl_start_returns_and_reuses_its_stable_request_handle() -> None:
    requests: list[httpx.Request] = []
    capabilities = ["firecrawl.crawl.start"]

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        adoption = _adoption_response(request, capabilities=capabilities)
        if adoption is not None:
            return adoption
        return httpx.Response(
            503,
            json={
                "error": {
                    "code": "daemon_degraded",
                    "message": "degraded",
                    "retryable": True,
                    "retry_after_seconds": 1,
                    "request_id": None,
                }
            },
        )

    backend = await LoopbackMcpBackend.from_environment(
        environment=_environment(),
        client_nonce="nonce-mcp-client",
        transport_factory=_transport_factory(handler),
    )
    payload = {"url": "https://example.com/careers"}

    first = await backend.call("firecrawl.crawl.start", payload)
    first_error = first.get("error")
    assert isinstance(first_error, dict)
    first_request_id = first_error.get("request_id")
    assert isinstance(first_request_id, str)
    assert RequestId(first_request_id) == first_request_id

    second = await backend.call("firecrawl.crawl.start", payload)
    second_error = second.get("error")
    assert isinstance(second_error, dict)
    second_request_id = second_error.get("request_id")
    assert isinstance(second_request_id, str)
    assert second_request_id != first_request_id

    retried = await backend.call(
        "firecrawl.crawl.start",
        payload,
        request_id=first_request_id,
    )
    retried_error = retried.get("error")
    assert isinstance(retried_error, dict)
    assert retried_error.get("request_id") == first_request_id
    invocation_bodies = [_json_body(item) for item in requests[2:]]
    assert [item["request_id"] for item in invocation_bodies] == [
        first_request_id,
        second_request_id,
        first_request_id,
    ]


@pytest.mark.asyncio
async def test_redirects_fail_without_a_followup_request() -> None:
    requests: list[httpx.Request] = []
    capabilities = ["firecrawl.search"]

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        adoption = _adoption_response(request, capabilities=capabilities)
        if adoption is not None:
            return adoption
        return httpx.Response(
            307,
            headers={"Location": "http://remote.example/escape"},
            json={"status": "redirect"},
        )

    backend = await LoopbackMcpBackend.from_environment(
        environment=_environment(),
        client_nonce="nonce-mcp-client",
        transport_factory=_transport_factory(handler),
    )
    result = await backend.call("firecrawl.search", {"query": "roles"})

    assert _error_code(result) == "daemon_degraded"
    assert len(requests) == 3
    assert all(request.url.host == "127.0.0.1" for request in requests)


@pytest.mark.asyncio
async def test_body_limits_are_applied_before_returning_daemon_data() -> None:
    capabilities = ["docs.search"]

    def handler(request: httpx.Request) -> httpx.Response:
        adoption = _adoption_response(request, capabilities=capabilities)
        if adoption is not None:
            return adoption
        return httpx.Response(200, json={"content": "x" * 2_000})

    backend = await LoopbackMcpBackend.from_environment(
        environment=_environment(),
        client_nonce="nonce-mcp-client",
        maximum_response_bytes=1_024,
        transport_factory=_transport_factory(handler),
    )
    result = await backend.call(
        "docs.search",
        {"service": "firecrawl", "query": "rate limit", "limit": 5},
    )

    assert _error_code(result) == "daemon_degraded"


@pytest.mark.asyncio
async def test_oversized_request_body_is_rejected_before_transport() -> None:
    requests: list[httpx.Request] = []
    capabilities = ["feedback.submit"]

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        adoption = _adoption_response(request, capabilities=capabilities)
        assert adoption is not None
        return adoption

    backend = await LoopbackMcpBackend.from_environment(
        environment=_environment(),
        client_nonce="nonce-mcp-client",
        maximum_request_bytes=256,
        transport_factory=_transport_factory(handler),
    )
    result = await backend.call(
        "feedback.submit",
        {
            "category": "contract",
            "severity": "medium",
            "component": "mcp",
            "summary": "x" * 1_000,
        },
    )

    assert _error_code(result) == "daemon_degraded"
    assert len(requests) == 2


@pytest.mark.asyncio
async def test_non_loopback_url_is_rejected_after_bootstrap_environment_is_scrubbed() -> None:
    environment = _environment(agent_url="http://remote.example:47621")

    with pytest.raises(McpStartupError) as captured:
        await LoopbackMcpBackend.from_environment(environment=environment)

    assert SESSION_ID_ENVIRONMENT not in environment
    assert SESSION_BOOTSTRAP_ENVIRONMENT not in environment
    assert BOOTSTRAP not in str(captured.value)


@pytest.mark.asyncio
async def test_adoption_timeout_is_bounded_and_reports_only_a_sanitized_failure() -> None:
    environment = _environment()

    async def handler(_: httpx.Request) -> httpx.Response:
        await asyncio.sleep(0.05)
        return httpx.Response(500, json={"unexpected": True})

    with pytest.raises(McpStartupError) as captured:
        await LoopbackMcpBackend.from_environment(
            environment=environment,
            timeout_seconds=0.001,
            transport_factory=lambda: httpx.MockTransport(handler),
        )

    assert SESSION_ID_ENVIRONMENT not in environment
    assert SESSION_BOOTSTRAP_ENVIRONMENT not in environment
    assert str(captured.value) == "Gatehouse MCP session adoption failed."


@pytest.mark.asyncio
async def test_session_maintenance_uses_dynamic_bounded_cadence_and_stops_terminally() -> None:
    intervals: list[float] = []
    results: list[dict[str, JsonValue]] = [
        {
            "error": {
                "code": "daemon_degraded",
                "message": "retry",
                "retryable": True,
            }
        },
        {"status": "active"},
        {
            "error": {
                "code": "session_revoked",
                "message": "terminal",
                "retryable": False,
            }
        },
    ]

    class Backend:
        def __init__(self) -> None:
            self.session_heartbeat_interval_seconds = 1.0

        async def call(
            self,
            operation: str,
            payload: Mapping[str, JsonValue],
            *,
            request_id: str | None = None,
        ) -> dict[str, JsonValue]:
            del operation, payload, request_id
            return {}

        async def maintain_session(self) -> dict[str, JsonValue]:
            result = results.pop(0)
            self.session_heartbeat_interval_seconds += 1.0
            return result

    async def record_sleep(seconds: float) -> None:
        intervals.append(seconds)

    await mcp_server._run_session_maintenance(Backend(), sleep=record_sleep)  # noqa: SLF001

    assert intervals == [1.0, 2.0, 3.0]
    assert results == []


@pytest.mark.asyncio
async def test_server_lifespan_starts_and_cancels_session_maintenance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    started = asyncio.Event()
    stopped = asyncio.Event()

    class Backend:
        session_heartbeat_interval_seconds = 30.0

        async def call(
            self,
            operation: str,
            payload: Mapping[str, JsonValue],
            *,
            request_id: str | None = None,
        ) -> dict[str, JsonValue]:
            del operation, payload, request_id
            return {}

        async def maintain_session(self) -> dict[str, JsonValue]:
            return {"status": "active"}

    async def run_until_cancelled(_: object) -> None:
        started.set()
        try:
            await asyncio.Event().wait()
        finally:
            stopped.set()

    monkeypatch.setattr(mcp_server, "_run_session_maintenance", run_until_cancelled)
    server = create_mcp_server(backend=Backend(), capabilities=frozenset())
    lifespan = server.settings.lifespan
    assert lifespan is not None

    async with lifespan(server):
        await asyncio.wait_for(started.wait(), timeout=1)

    assert stopped.is_set()


def test_stock_main_adopts_before_registering_and_running(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []

    class Backend:
        capabilities = frozenset({"docs.search"})

    class Server:
        def run(self, *, transport: str) -> None:
            assert transport == "stdio"
            events.append("run")

    async def initialize() -> Backend:
        events.append("adopt")
        return Backend()

    def create(*, backend: object, capabilities: frozenset[str]) -> Server:
        assert isinstance(backend, Backend)
        assert capabilities == backend.capabilities
        events.append("register")
        return Server()

    monkeypatch.setattr(mcp_server, "_initialize_backend", initialize)
    monkeypatch.setattr(mcp_server, "create_mcp_server", create)

    mcp_server.main()

    assert events == ["adopt", "register", "run"]


def test_stock_main_fails_cleanly_before_tool_registration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def initialize() -> LoopbackMcpBackend:
        raise McpStartupError("Gatehouse MCP session adoption failed.")

    def create(**_: object) -> None:
        pytest.fail("tools must not be registered after failed adoption")

    monkeypatch.setattr(mcp_server, "_initialize_backend", initialize)
    monkeypatch.setattr(mcp_server, "create_mcp_server", create)

    with pytest.raises(SystemExit, match="session adoption failed"):
        mcp_server.main()
