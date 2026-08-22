from __future__ import annotations

import asyncio
import inspect
import json
from collections.abc import AsyncIterator

import httpx
import pytest

from gatehouse.core.provider_numbers import ExactProviderNumber, parse_json_provider_number
from gatehouse.credentials.base import CredentialMetadata, SecretLeaseExpiredError
from gatehouse.credentials.composite import CompositeKeyStore
from gatehouse.credentials.memory import InMemoryKeyStore
from gatehouse.policy.targets import TargetValidationError, validate_resolved_addresses
from gatehouse.providers.base import CredentialCustodyKind, ProviderErrorClass, ProviderRequest
from gatehouse.providers.firecrawl.adapter import FirecrawlAdapter
from gatehouse.providers.transport import (
    HttpxProviderTransport,
    ProviderNetworkDisabledError,
    ProviderPreHandoffError,
    ProviderTransportError,
    _redact_active_credential,
)


async def public_resolver(_host: str) -> tuple[str, ...]:
    return ("93.184.216.34",)


def _object_graph_contains_bytes(root: object, needle: bytes) -> bool:
    pending = [root]
    seen: set[int] = set()
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        if isinstance(current, (bytes, bytearray, memoryview)):
            if needle in bytes(current):
                return True
            continue
        if isinstance(current, str):
            if needle in current.encode("utf-8", "surrogatepass"):
                return True
            continue
        if isinstance(current, dict):
            pending.extend(current.keys())
            pending.extend(current.values())
            continue
        if isinstance(current, (list, tuple, set, frozenset)):
            pending.extend(current)
            continue
        state = getattr(current, "__dict__", None)
        if isinstance(state, dict):
            pending.extend(state.values())
    return False


async def key_store(
    secret: bytes = b"unit-test-provider-secret-123456",
    *,
    generation: int = 1,
) -> InMemoryKeyStore:
    store = InMemoryKeyStore()
    await store.put(
        CredentialMetadata(
            credential_id="credential-1",
            principal_id="principal-1",
            quota_scope_id="quota-1",
            alias="test-account",
            generation=generation,
        ),
        secret,
    )
    return store


def request(
    *,
    maximum_response_bytes: int = 1_024,
    credential_generation: int = 1,
    credential_custody: CredentialCustodyKind = CredentialCustodyKind.PERSISTENT,
    timeout_ms: int = 30_000,
) -> ProviderRequest:
    return ProviderRequest(
        method="POST",
        path="/v2/search",
        credential_id="credential-1",
        credential_generation=credential_generation,
        credential_custody=credential_custody,
        json_body={"query": "graduate roles", "limit": 5},
        timeout_ms=timeout_ms,
        maximum_response_bytes=maximum_response_bytes,
        operation="firecrawl.search",
    )


def credit_status_request(*, maximum_response_bytes: int = 64 * 1_024) -> ProviderRequest:
    return ProviderRequest(
        method="GET",
        path="/v2/team/credit-usage",
        credential_id="credential-1",
        credential_generation=1,
        json_body=None,
        timeout_ms=10_000,
        maximum_response_bytes=maximum_response_bytes,
        operation="firecrawl.account.credit_status",
    )


@pytest.mark.parametrize("generation", [0, -1, True])
def test_request_rejects_non_positive_credential_generation(generation: int) -> None:
    with pytest.raises(ValueError, match="credential generation must be positive"):
        request(credential_generation=generation)


def test_request_rejects_invalid_credential_custody_kind() -> None:
    with pytest.raises(ValueError, match="credential custody kind is invalid"):
        ProviderRequest(
            method="POST",
            path="/v2/search",
            credential_id="credential-1",
            credential_generation=1,
            credential_custody="ambient",  # type: ignore[arg-type]
        )


@pytest.mark.asyncio
async def test_real_network_is_disabled_by_default() -> None:
    transport = HttpxProviderTransport(key_store=await key_store())

    with pytest.raises(ProviderNetworkDisabledError):
        await transport.send(request())

    await transport.aclose()


@pytest.mark.asyncio
async def test_injects_secret_only_at_transport_boundary() -> None:
    expected_secret = "unit-test-provider-secret-123456"
    retained: list[httpx.Request] = []

    async def handler(incoming: httpx.Request) -> httpx.Response:
        retained.append(incoming)
        assert incoming.url == "https://api.firecrawl.dev/v2/search"
        assert incoming.headers["authorization"] == f"Bearer {expected_secret}"
        assert json.loads(incoming.content) == {"query": "graduate roles", "limit": 5}
        return httpx.Response(
            200,
            json={"success": True, "data": []},
            headers={"x-request-id": "provider-request-1"},
        )

    client = httpx.AsyncClient(
        base_url="https://api.firecrawl.dev",
        transport=httpx.MockTransport(handler),
    )
    transport = HttpxProviderTransport(
        key_store=await key_store(expected_secret.encode()),
        network_enabled=True,
        client=client,
        resolver=public_resolver,
    )

    response = await transport.send(request())

    assert response.status_code == 200
    assert response.provider_request_id == "provider-request-1"
    assert expected_secret not in repr(response)
    assert "authorization" not in retained[0].headers
    assert retained[0].content == b""
    assert retained[0].method == ""
    assert str(retained[0].url) == ""
    await client.aclose()


@pytest.mark.asyncio
async def test_provider_reflection_cannot_return_the_active_credential() -> None:
    canary = "PROVIDER-REFLECTION-CREDENTIAL-CANARY-1234567890"

    async def handler(_incoming: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={canary: "reflected-key", "reflected": canary},
            headers={
                "x-request-id": f"request-{canary}",
                "content-type": f"application/json; credential={canary}",
            },
        )

    client = httpx.AsyncClient(
        base_url="https://api.firecrawl.dev",
        transport=httpx.MockTransport(handler),
    )
    transport = HttpxProviderTransport(
        key_store=await key_store(canary.encode()),
        network_enabled=True,
        client=client,
        resolver=public_resolver,
    )

    response = await transport.send(request())

    assert response.status_code == 200
    assert response.transport_error == "malformed_response"
    assert response.data is None
    assert canary not in repr(response)
    assert canary not in (response.provider_request_id or "")
    assert canary not in repr(dict(response.headers))
    assert canary not in repr(response.data)
    await client.aclose()


@pytest.mark.asyncio
async def test_provider_set_cookie_is_rejected_cleared_and_never_replayed() -> None:
    canary = "PROVIDER-COOKIE-CREDENTIAL-CANARY-1234567890"
    observed_cookies: list[str | None] = []
    retained_responses: list[httpx.Response] = []

    async def handler(incoming: httpx.Request) -> httpx.Response:
        observed_cookies.append(incoming.headers.get("cookie"))
        if len(observed_cookies) == 1:
            response = httpx.Response(
                200,
                json={"success": True},
                headers={"set-cookie": f"provider_session={canary}; Path=/; Secure; HttpOnly"},
            )
            retained_responses.append(response)
            return response
        return httpx.Response(200, json={"success": True})

    client = httpx.AsyncClient(
        base_url="https://api.firecrawl.dev",
        transport=httpx.MockTransport(handler),
    )
    transport = HttpxProviderTransport(
        key_store=await key_store(canary.encode()),
        network_enabled=True,
        client=client,
        resolver=public_resolver,
    )

    rejected = await transport.send(request())
    accepted = await transport.send(request())

    assert rejected.transport_error == "malformed_response"
    assert rejected.submission_may_have_occurred
    assert accepted.status_code == 200
    assert observed_cookies == [None, None]
    assert len(client.cookies) == 0
    assert dict(retained_responses[0].headers) == {}
    assert retained_responses[0].content == b""
    await client.aclose()


@pytest.mark.asyncio
async def test_active_credential_in_unallowlisted_header_is_rejected_and_scrubbed() -> None:
    canary = "PROVIDER-HEADER-CREDENTIAL-CANARY-1234567890"
    retained_responses: list[httpx.Response] = []

    async def handler(_incoming: httpx.Request) -> httpx.Response:
        response = httpx.Response(
            200,
            json={"success": True},
            headers={"x-provider-debug": canary},
        )
        retained_responses.append(response)
        return response

    client = httpx.AsyncClient(
        base_url="https://api.firecrawl.dev",
        transport=httpx.MockTransport(handler),
    )
    transport = HttpxProviderTransport(
        key_store=await key_store(canary.encode()),
        network_enabled=True,
        client=client,
        resolver=public_resolver,
    )

    response = await transport.send(request())

    assert response.transport_error == "malformed_response"
    assert canary not in repr(response)
    assert dict(retained_responses[0].headers) == {}
    assert retained_responses[0].content == b""
    assert len(client.cookies) == 0
    await client.aclose()


@pytest.mark.asyncio
async def test_active_credential_in_response_extensions_is_rejected_and_scrubbed(
    caplog: pytest.LogCaptureFixture,
) -> None:
    canary = "PROVIDER-EXTENSION-CREDENTIAL-CANARY-1234567890"
    retained_responses: list[httpx.Response] = []
    caplog.set_level("DEBUG")

    async def handler(_incoming: httpx.Request) -> httpx.Response:
        response = httpx.Response(
            200,
            json={"success": True},
            extensions={
                "reason_phrase": canary.encode("ascii"),
                "nested": {"debug": [bytearray(canary, "ascii")]},
            },
        )
        retained_responses.append(response)
        return response

    client = httpx.AsyncClient(
        base_url="https://api.firecrawl.dev",
        transport=httpx.MockTransport(handler),
    )
    transport = HttpxProviderTransport(
        key_store=await key_store(canary.encode("ascii")),
        network_enabled=True,
        client=client,
        resolver=public_resolver,
    )

    response = await transport.send(request())

    assert response.transport_error == "malformed_response"
    assert retained_responses
    retained = retained_responses[0]
    assert retained.extensions == {}
    assert retained.content == b""
    if canary in repr(retained):
        raise AssertionError("active credential remained in retained provider response")
    if canary in caplog.text:
        raise AssertionError("active credential reached HTTP client logs")
    await client.aclose()


@pytest.mark.asyncio
async def test_reflected_redirect_request_is_scrubbed_and_detached() -> None:
    canary = "PROVIDER-REDIRECT-CREDENTIAL-CANARY-1234567890"
    retained_responses: list[httpx.Response] = []
    retained_redirects: list[httpx.Request] = []

    class RetainingRedirectClient(httpx.AsyncClient):
        def _build_redirect_request(
            self,
            request: httpx.Request,
            response: httpx.Response,
        ) -> httpx.Request:
            redirect = super()._build_redirect_request(request, response)
            retained_redirects.append(redirect)
            return redirect

    async def handler(_incoming: httpx.Request) -> httpx.Response:
        response = httpx.Response(
            302,
            headers={"location": f"https://api.firecrawl.dev/{canary}"},
        )
        retained_responses.append(response)
        return response

    client = RetainingRedirectClient(
        base_url="https://api.firecrawl.dev",
        transport=httpx.MockTransport(handler),
        follow_redirects=False,
    )
    transport = HttpxProviderTransport(
        key_store=await key_store(canary.encode("ascii")),
        network_enabled=True,
        client=client,
        resolver=public_resolver,
    )

    response = await transport.send(request())

    assert response.transport_error == "malformed_response"
    assert retained_responses and retained_responses[0].next_request is None
    assert retained_redirects
    redirect = retained_redirects[0]
    assert dict(redirect.headers) == {}
    assert redirect.content == b""
    assert redirect.method == ""
    assert str(redirect.url) == ""
    assert redirect.extensions == {}
    if canary in repr(redirect):
        raise AssertionError("active credential remained in retained redirect request")
    await client.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("credential", "raw_response"),
    [
        (b"12345678901234567890", b"12345678901234567890"),
        (b"true", b"true"),
    ],
    ids=["numeric", "boolean"],
)
async def test_raw_non_string_credential_reflection_fails_closed(
    credential: bytes,
    raw_response: bytes,
) -> None:
    retained_responses: list[httpx.Response] = []

    class ReflectionStream(httpx.AsyncByteStream):
        def __init__(self) -> None:
            self.body = bytearray(raw_response)
            self.close_count = 0

        async def __aiter__(self) -> AsyncIterator[bytes]:
            yield bytes(self.body)

        async def aclose(self) -> None:
            self.close_count += 1

    stream = ReflectionStream()

    async def handler(incoming: httpx.Request) -> httpx.Response:
        response = httpx.Response(200, stream=stream, request=incoming)
        retained_responses.append(response)
        return response

    client = httpx.AsyncClient(
        base_url="https://api.firecrawl.dev",
        transport=httpx.MockTransport(handler),
    )
    transport = HttpxProviderTransport(
        key_store=await key_store(credential),
        network_enabled=True,
        client=client,
        resolver=public_resolver,
    )

    response = await transport.send(request())

    assert response.status_code == 200
    assert response.transport_error == "malformed_response"
    assert response.data is None
    assert credential.decode() not in repr(response)
    assert len(retained_responses) == 1
    assert retained_responses[0].content == b""
    assert not _object_graph_contains_bytes(retained_responses[0].stream, credential)
    assert stream.close_count == 1
    assert stream.body == bytearray()
    await client.aclose()


@pytest.mark.asyncio
async def test_generation_mismatch_fails_before_mock_transport_send() -> None:
    sent = False
    resolved = False

    async def handler(_incoming: httpx.Request) -> httpx.Response:
        nonlocal sent
        sent = True
        return httpx.Response(200, json={"success": True})

    async def resolver(_host: str) -> tuple[str, ...]:
        nonlocal resolved
        resolved = True
        return validate_resolved_addresses(["93.184.216.34"])

    client = httpx.AsyncClient(
        base_url="https://api.firecrawl.dev",
        transport=httpx.MockTransport(handler),
    )
    transport = HttpxProviderTransport(
        key_store=await key_store(generation=2),
        network_enabled=True,
        client=client,
        resolver=resolver,
    )

    with pytest.raises(ProviderPreHandoffError) as captured:
        await transport.send(request(credential_generation=1))

    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None
    assert not sent
    assert resolved
    await client.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("credential", "path", "query", "json_body", "operation"),
    [
        (
            b"graduate roles",
            "/v2/search",
            {},
            {"query": "graduate roles"},
            "firecrawl.search",
        ),
        (
            b"secret-key-marker",
            "/v2/search",
            {},
            {"secret-key-marker": "value"},
            "firecrawl.search",
        ),
        (b"12345", "/v2/search", {}, {"limit": 12345}, "firecrawl.search"),
        (
            b"query-marker",
            "/v2/search",
            {"query": "query-marker"},
            None,
            "firecrawl.search",
        ),
        (b"path-marker", "/v2/path-marker", {}, None, "firecrawl.search"),
        (b"firecrawl.search", "/v2/search", {}, None, "firecrawl.search"),
    ],
    ids=["json-string", "json-key", "json-number", "query", "path", "operation"],
)
async def test_active_credential_overlap_in_non_authorization_request_never_sends(
    credential: bytes,
    path: str,
    query: dict[str, str],
    json_body: dict[str, object] | None,
    operation: str,
) -> None:
    sent = False

    async def handler(_incoming: httpx.Request) -> httpx.Response:
        nonlocal sent
        sent = True
        return httpx.Response(200, json={"success": True})

    client = httpx.AsyncClient(
        base_url="https://api.firecrawl.dev",
        transport=httpx.MockTransport(handler),
    )
    transport = HttpxProviderTransport(
        key_store=await key_store(credential),
        network_enabled=True,
        client=client,
        resolver=public_resolver,
    )
    overlapping = ProviderRequest(
        method="POST",
        path=path,
        credential_id="credential-1",
        credential_generation=1,
        query=query,
        json_body=json_body,
        operation=operation,
    )

    with pytest.raises(ProviderPreHandoffError) as captured:
        await transport.send(overlapping)

    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None
    assert credential.decode() not in repr(captured.value)
    assert not sent
    assert len(client.cookies) == 0
    await client.aclose()


@pytest.mark.asyncio
async def test_cancelled_emergency_custody_never_falls_back_to_colliding_persistent() -> None:
    persistent_secret = b"persistent-collision-secret-never-authorized"
    emergency_secret = b"emergency-secret-destroyed-by-cancel"
    metadata = CredentialMetadata(
        credential_id="credential-1",
        principal_id="principal-1",
        quota_scope_id="quota-1",
        alias="colliding-authority",
        generation=1,
    )
    persistent = InMemoryKeyStore()
    emergency = InMemoryKeyStore()
    await persistent.put(metadata, persistent_secret)
    await emergency.put(metadata, emergency_secret)
    composite = CompositeKeyStore(persistent=persistent, emergency=emergency)
    sent = False

    async def handler(_incoming: httpx.Request) -> httpx.Response:
        nonlocal sent
        sent = True
        return httpx.Response(200, json={"success": True})

    async def cancel_before_custody(_host: str) -> tuple[str, ...]:
        await emergency.delete(metadata.credential_id)
        return validate_resolved_addresses(["93.184.216.34"])

    client = httpx.AsyncClient(
        base_url="https://api.firecrawl.dev",
        transport=httpx.MockTransport(handler),
    )
    transport = HttpxProviderTransport(
        key_store=composite,
        network_enabled=True,
        client=client,
        resolver=cancel_before_custody,
    )

    with pytest.raises(ProviderPreHandoffError) as captured:
        await transport.send(request(credential_custody=CredentialCustodyKind.EMERGENCY))

    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None
    assert not sent
    assert persistent_secret.decode() not in repr(captured.value)
    await client.aclose()


@pytest.mark.asyncio
async def test_resolver_failure_precedes_credential_custody() -> None:
    class ForbiddenKeyStore:
        async def open_lease(self, *args: object, **kwargs: object) -> object:
            del args, kwargs
            raise AssertionError("resolver failure opened credential custody")

    async def failing_resolver(_host: str) -> tuple[str, ...]:
        raise OSError("synthetic resolver failure")

    transport = HttpxProviderTransport(
        key_store=ForbiddenKeyStore(),  # type: ignore[arg-type]
        network_enabled=True,
        resolver=failing_resolver,
    )

    with pytest.raises(ProviderPreHandoffError) as captured:
        await transport.send(request())

    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None
    await transport.aclose()


@pytest.mark.asyncio
async def test_blocked_resolver_is_bounded_before_credential_custody() -> None:
    class ForbiddenKeyStore:
        async def open_lease(self, *args: object, **kwargs: object) -> object:
            del args, kwargs
            raise AssertionError("resolver timeout opened credential custody")

    never = asyncio.Event()

    async def blocked_resolver(_host: str) -> tuple[str, ...]:
        await never.wait()
        return ()

    transport = HttpxProviderTransport(
        key_store=ForbiddenKeyStore(),  # type: ignore[arg-type]
        network_enabled=True,
        resolver=blocked_resolver,
    )

    with pytest.raises(ProviderPreHandoffError, match="resolution failed"):
        await transport.send(request(timeout_ms=5))

    await transport.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("addresses", [(), ("127.0.0.1",)])
async def test_transport_validates_every_injected_resolver_answer(
    addresses: tuple[str, ...],
) -> None:
    class ForbiddenKeyStore:
        async def open_lease(self, *args: object, **kwargs: object) -> object:
            del args, kwargs
            raise AssertionError("invalid resolver answer opened credential custody")

    async def untrusted_resolver(_host: str) -> tuple[str, ...]:
        return addresses

    transport = HttpxProviderTransport(
        key_store=ForbiddenKeyStore(),  # type: ignore[arg-type]
        network_enabled=True,
        resolver=untrusted_resolver,
    )

    with pytest.raises(TargetValidationError):
        await transport.send(request())

    await transport.aclose()


@pytest.mark.asyncio
async def test_lease_closed_between_open_and_entry_is_sanitized_pre_handoff() -> None:
    canary = "LEASE-ENTRY-SECRET-CANARY-1234567890"
    sent = False

    class ClosedLease:
        credential_id = "credential-1"
        generation = 1
        purpose = "provider-transport:firecrawl.search"

        def __init__(self) -> None:
            self.close_calls = 0

        async def __aenter__(self) -> memoryview:
            raise SecretLeaseExpiredError(canary)

        async def __aexit__(self, *args: object) -> None:
            del args
            self.close()

        def close(self) -> None:
            self.close_calls += 1

    lease = ClosedLease()

    class ClosingKeyStore:
        async def open_lease(self, *args: object, **kwargs: object) -> ClosedLease:
            del args, kwargs
            return lease

    async def handler(_incoming: httpx.Request) -> httpx.Response:
        nonlocal sent
        sent = True
        return httpx.Response(200, json={"success": True})

    client = httpx.AsyncClient(
        base_url="https://api.firecrawl.dev",
        transport=httpx.MockTransport(handler),
    )
    transport = HttpxProviderTransport(
        key_store=ClosingKeyStore(),  # type: ignore[arg-type]
        network_enabled=True,
        client=client,
        resolver=public_resolver,
    )

    with pytest.raises(ProviderPreHandoffError) as captured:
        await transport.send(request())

    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None
    assert canary not in repr(captured.value)
    assert lease.close_calls == 1
    assert not sent
    await client.aclose()


@pytest.mark.asyncio
async def test_invalid_credential_encoding_has_no_secret_bearing_exception_context() -> None:
    canary = b"\xffFAKE-INVALID-ENCODING-CREDENTIAL-CANARY-1234567890"
    sent = False

    async def handler(_incoming: httpx.Request) -> httpx.Response:
        nonlocal sent
        sent = True
        return httpx.Response(200, json={"success": True})

    client = httpx.AsyncClient(
        base_url="https://api.firecrawl.dev",
        transport=httpx.MockTransport(handler),
    )
    transport = HttpxProviderTransport(
        key_store=await key_store(canary),
        network_enabled=True,
        client=client,
        resolver=public_resolver,
    )

    with pytest.raises(ProviderTransportError) as captured:
        await transport.send(request())

    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None
    assert canary.decode("utf-8", "ignore") not in repr(captured.value)
    assert not sent
    await client.aclose()


@pytest.mark.asyncio
async def test_response_byte_limit_is_enforced() -> None:
    retained: list[httpx.Request] = []

    class TrackedStream(httpx.AsyncByteStream):
        def __init__(self) -> None:
            self.body = bytearray(b"x" * 100)
            self.close_count = 0

        async def __aiter__(self) -> AsyncIterator[bytes]:
            yield bytes(self.body)

        async def aclose(self) -> None:
            self.close_count += 1

    stream = TrackedStream()

    async def handler(incoming: httpx.Request) -> httpx.Response:
        retained.append(incoming)
        return httpx.Response(200, stream=stream, request=incoming)

    client = httpx.AsyncClient(
        base_url="https://api.firecrawl.dev",
        transport=httpx.MockTransport(handler),
    )
    transport = HttpxProviderTransport(
        key_store=await key_store(),
        network_enabled=True,
        client=client,
        resolver=public_resolver,
    )

    response = await transport.send(request(maximum_response_bytes=20))

    assert response.transport_error == "response_too_large"
    assert response.data is None
    assert "authorization" not in retained[0].headers
    assert stream.close_count == 1
    assert stream.body == bytearray()
    await client.aclose()


@pytest.mark.asyncio
async def test_completed_response_closes_original_stream_exactly_once() -> None:
    class TrackedStream(httpx.AsyncByteStream):
        def __init__(self) -> None:
            self.body = bytearray(b'{"success":true,"data":[]}')
            self.close_count = 0

        async def __aiter__(self) -> AsyncIterator[bytes]:
            yield bytes(self.body)

        async def aclose(self) -> None:
            self.close_count += 1

    stream = TrackedStream()

    async def handler(incoming: httpx.Request) -> httpx.Response:
        return httpx.Response(200, stream=stream, request=incoming)

    client = httpx.AsyncClient(
        base_url="https://api.firecrawl.dev",
        transport=httpx.MockTransport(handler),
    )
    transport = HttpxProviderTransport(
        key_store=await key_store(),
        network_enabled=True,
        client=client,
        resolver=public_resolver,
    )

    response = await transport.send(request())

    assert response.status_code == 200
    assert stream.close_count == 1
    assert stream.body == bytearray()
    await client.aclose()


@pytest.mark.asyncio
async def test_partial_stream_base_exception_wipes_body_before_response_close() -> None:
    body_canary = b"PARTIAL-RESPONSE-BODY-CANARY-1234567890"
    credential_canary = "PARTIAL-STREAM-AUTH-CANARY-1234567890"
    retained: list[httpx.Request] = []

    class SyntheticStreamAbort(BaseException):
        pass

    class CanaryThenAbortStream(httpx.AsyncByteStream):
        def __init__(self) -> None:
            self.body = bytearray(body_canary)
            self.closed = False
            self.close_count = 0
            self.raw_at_close: list[bytearray] = []
            self.raw_snapshots_at_close: list[bytes] = []

        async def __aiter__(self) -> AsyncIterator[bytes]:
            chunk = bytes(self.body)
            self.body[:] = b"\x00" * len(self.body)
            yield chunk
            chunk = b""
            raise SyntheticStreamAbort("synthetic response stream failure")

        async def aclose(self) -> None:
            self.closed = True
            self.close_count += 1
            frame = inspect.currentframe()
            try:
                while frame is not None:
                    if frame.f_code.co_name == "_send_with_authorization":
                        candidate = frame.f_locals.get("raw")
                        if isinstance(candidate, bytearray):
                            self.raw_at_close.append(candidate)
                            self.raw_snapshots_at_close.append(bytes(candidate))
                            break
                    frame = frame.f_back
            finally:
                del frame

    stream = CanaryThenAbortStream()

    class PartialStreamTransport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, incoming: httpx.Request) -> httpx.Response:
            retained.append(incoming)
            return httpx.Response(200, stream=stream, request=incoming)

    client = httpx.AsyncClient(
        base_url="https://api.firecrawl.dev",
        transport=PartialStreamTransport(),
    )
    transport = HttpxProviderTransport(
        key_store=await key_store(credential_canary.encode()),
        network_enabled=True,
        client=client,
        resolver=public_resolver,
    )

    with pytest.raises(SyntheticStreamAbort) as captured:
        await transport.send(request())

    exception_frames = []
    transport_frame = None
    traceback = captured.value.__traceback__
    while traceback is not None:
        exception_frames.append(traceback.tb_frame)
        if traceback.tb_frame.f_code.co_name == "_send_with_authorization":
            transport_frame = traceback.tb_frame
        traceback = traceback.tb_next
    assert transport_frame is not None
    assert all(
        "site-packages/httpx" not in frame.f_code.co_filename.replace("\\", "/")
        for frame in exception_frames
    )
    captured_raw = transport_frame.f_locals.get("raw")
    assert isinstance(captured_raw, bytearray)
    assert bytes(captured_raw) == b"\x00" * len(body_canary)
    assert stream.closed
    assert stream.close_count == 1
    assert stream.raw_at_close
    assert all(item is captured_raw for item in stream.raw_at_close)
    assert all(snapshot == b"\x00" * len(body_canary) for snapshot in stream.raw_snapshots_at_close)
    for value in transport_frame.f_locals.values():
        if isinstance(value, (bytes, bytearray, memoryview)):
            assert body_canary not in bytes(value)
        elif isinstance(value, str):
            assert body_canary.decode() not in value
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None
    assert body_canary.decode() not in repr(captured.value)
    assert "authorization" not in retained[0].headers
    assert credential_canary not in repr(retained[0])
    await client.aclose()


@pytest.mark.asyncio
async def test_cancellation_closes_and_scrubs_original_response_stream_once() -> None:
    credential = b"CANCELLED-RESPONSE-STREAM-CREDENTIAL-1234567890"
    iteration_started = asyncio.Event()
    never_complete = asyncio.Event()
    retained_responses: list[httpx.Response] = []

    class BlockingStream(httpx.AsyncByteStream):
        def __init__(self) -> None:
            self.body = bytearray(credential)
            self.close_count = 0

        async def __aiter__(self) -> AsyncIterator[bytes]:
            iteration_started.set()
            await never_complete.wait()
            yield bytes(self.body)

        async def aclose(self) -> None:
            self.close_count += 1

    stream = BlockingStream()

    async def handler(incoming: httpx.Request) -> httpx.Response:
        response = httpx.Response(200, stream=stream, request=incoming)
        retained_responses.append(response)
        return response

    client = httpx.AsyncClient(
        base_url="https://api.firecrawl.dev",
        transport=httpx.MockTransport(handler),
    )
    transport = HttpxProviderTransport(
        key_store=await key_store(credential),
        network_enabled=True,
        client=client,
        resolver=public_resolver,
    )
    send_task = asyncio.create_task(transport.send(request()))
    await asyncio.wait_for(iteration_started.wait(), timeout=1.0)
    send_task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await send_task

    assert stream.close_count == 1
    assert stream.body == bytearray()
    assert len(retained_responses) == 1
    assert not _object_graph_contains_bytes(retained_responses[0].stream, credential)
    await client.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("error_type", "expected_error", "submission_may_have_occurred"),
    [
        (httpx.PoolTimeout, "pool_timeout", False),
        (httpx.RemoteProtocolError, "ambiguous_transport_failure", True),
    ],
)
async def test_httpx_failures_are_sanitized_without_retaining_authorization(
    error_type: type[httpx.RequestError],
    expected_error: str,
    submission_may_have_occurred: bool,
) -> None:
    canary = "HTTPX-ERROR-AUTHORIZATION-CANARY-1234567890"

    class RaisingTransport(httpx.AsyncBaseTransport):
        def __init__(self) -> None:
            self.error: httpx.RequestError | None = None

        async def handle_async_request(self, incoming: httpx.Request) -> httpx.Response:
            self.error = error_type("synthetic transport failure", request=incoming)
            raise self.error

    raising = RaisingTransport()
    client = httpx.AsyncClient(
        base_url="https://api.firecrawl.dev",
        transport=raising,
    )
    transport = HttpxProviderTransport(
        key_store=await key_store(canary.encode()),
        network_enabled=True,
        client=client,
        resolver=public_resolver,
    )

    response = await transport.send(request())

    assert response.transport_error == expected_error
    assert response.submission_may_have_occurred is submission_may_have_occurred
    assert raising.error is not None
    assert "authorization" not in raising.error.request.headers
    assert canary not in repr(raising.error)
    assert canary not in repr(raising.error.request)
    await client.aclose()


@pytest.mark.asyncio
async def test_cancellation_scrubs_transport_retained_request_authorization() -> None:
    canary = "HTTPX-CANCELLED-AUTHORIZATION-CANARY-1234567890"
    request_started = asyncio.Event()
    never_complete = asyncio.Event()
    retained: list[httpx.Request] = []

    class BlockingTransport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, incoming: httpx.Request) -> httpx.Response:
            retained.append(incoming)
            request_started.set()
            await never_complete.wait()
            return httpx.Response(200, json={"success": True})

    client = httpx.AsyncClient(
        base_url="https://api.firecrawl.dev",
        transport=BlockingTransport(),
    )
    transport = HttpxProviderTransport(
        key_store=await key_store(canary.encode()),
        network_enabled=True,
        client=client,
        resolver=public_resolver,
    )

    send_task = asyncio.create_task(transport.send(request()))
    await asyncio.wait_for(request_started.wait(), timeout=1.0)
    send_task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await send_task

    assert "authorization" not in retained[0].headers
    assert canary not in repr(retained[0])
    await client.aclose()


@pytest.mark.asyncio
async def test_malformed_success_is_classified_at_transport() -> None:
    async def handler(_incoming: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"not-json")

    client = httpx.AsyncClient(
        base_url="https://api.firecrawl.dev",
        transport=httpx.MockTransport(handler),
    )
    transport = HttpxProviderTransport(
        key_store=await key_store(),
        network_enabled=True,
        client=client,
        resolver=public_resolver,
    )

    response = await transport.send(request())

    assert response.status_code == 200
    assert response.transport_error == "malformed_response"
    await client.aclose()


@pytest.mark.asyncio
async def test_credit_status_200_uses_exact_numeric_hooks_for_every_numeric_token() -> None:
    raw = (
        b'{"success":true,"data":{"remainingCredits":'
        b"1.000000000000000000000000000001,"
        b'"planCredits":1e2,"extension":' + (b"9" * 200) + b"}}"
    )

    async def handler(_incoming: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=raw)

    client = httpx.AsyncClient(
        base_url="https://api.firecrawl.dev",
        transport=httpx.MockTransport(handler),
    )
    transport = HttpxProviderTransport(
        key_store=await key_store(),
        network_enabled=True,
        client=client,
        resolver=public_resolver,
    )

    response = await transport.send(credit_status_request())

    assert response.transport_error is None
    assert isinstance(response.data, dict)
    data = response.data["data"]
    assert isinstance(data, dict)
    assert isinstance(data["remainingCredits"], ExactProviderNumber)
    assert data["remainingCredits"].canonical == "1.000000000000000000000000000001"
    assert isinstance(data["planCredits"], ExactProviderNumber)
    assert data["planCredits"].canonical == "100"
    assert isinstance(data["extension"], ExactProviderNumber)
    assert data["extension"].significant_digits == 200
    outcome = FirecrawlAdapter().classify_response(
        "firecrawl.account.credit_status",
        response,
    )
    status = FirecrawlAdapter().parse_credit_status(outcome)
    assert status.observed_remaining_credits_decimal == "1.000000000000000000000000000001"
    assert status.observed_plan_credits_decimal == "100"
    await client.aclose()


def test_active_credential_redaction_preserves_only_valid_exact_wrappers() -> None:
    exact = parse_json_provider_number("1")
    forged = object.__new__(ExactProviderNumber)
    key = parse_json_provider_number("2")
    keyed = {key: "safe"}
    object.__delattr__(key, "_exponent")

    assert _redact_active_credential(exact, "credential") is exact
    assert _redact_active_credential(forged, "credential") == (
        "[REDACTED:invalid_exact_provider_number]"
    )
    assert _redact_active_credential(keyed, "credential") == {
        "[REDACTED:invalid_exact_provider_number]": "safe"
    }


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "raw",
    [
        b'{"success":true,"success":true,"data":{"remainingCredits":1}}',
        b'{"success":true,"data":{"remainingCredits":1,"remainingCredits":2}}',
        b'{"success":true,"data":{"remainingCredits":NaN}}',
        b'{"success":true,"data":{"remainingCredits":Infinity}}',
        b'{"success":true,"data":{"remainingCredits":-Infinity}}',
        b'{"success":true,"data":{"remainingCredits":1e257}}',
    ],
)
async def test_credit_status_200_rejects_duplicate_keys_constants_and_unbounded_numbers(
    raw: bytes,
) -> None:
    async def handler(_incoming: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=raw)

    client = httpx.AsyncClient(
        base_url="https://api.firecrawl.dev",
        transport=httpx.MockTransport(handler),
    )
    transport = HttpxProviderTransport(
        key_store=await key_store(),
        network_enabled=True,
        client=client,
        resolver=public_resolver,
    )

    response = await transport.send(credit_status_request())

    assert response.status_code == 200
    assert response.transport_error == "malformed_response"
    assert response.data is None
    assert raw.decode("ascii") not in repr(response)
    await client.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status_code", "expected"),
    [
        (401, ProviderErrorClass.UNAUTHORIZED),
        (429, ProviderErrorClass.RATE_LIMITED),
        (503, ProviderErrorClass.TRANSIENT),
    ],
)
@pytest.mark.parametrize(
    "raw",
    [
        b'{"error":',
        b'{"error":' + (b"9" * 10_000) + b"}",
        b'{"error":{"code":401,"ratio":1.5,"extension":-2e3}}',
    ],
    ids=["malformed-json", "python-int-digit-limit", "irrelevant-numeric-extensions"],
)
async def test_credit_status_error_body_is_discarded_without_replacing_status_classification(
    status_code: int,
    expected: ProviderErrorClass,
    raw: bytes,
) -> None:
    retained_responses: list[httpx.Response] = []

    async def handler(_incoming: httpx.Request) -> httpx.Response:
        headers = {"retry-after": "3"} if status_code == 429 else {}
        response = httpx.Response(status_code, content=raw, headers=headers)
        retained_responses.append(response)
        return response

    client = httpx.AsyncClient(
        base_url="https://api.firecrawl.dev",
        transport=httpx.MockTransport(handler),
    )
    transport = HttpxProviderTransport(
        key_store=await key_store(),
        network_enabled=True,
        client=client,
        resolver=public_resolver,
    )

    response = await transport.send(credit_status_request())
    outcome = FirecrawlAdapter().classify_response(
        "firecrawl.account.credit_status",
        response,
    )

    assert response.transport_error is None
    assert response.status_code == status_code
    assert response.data is None
    assert outcome.error_class is expected
    assert outcome.data is None
    assert outcome.retry_after_seconds == (3.0 if status_code == 429 else None)
    assert raw.decode("ascii") not in repr(response)
    assert retained_responses[0].content == b""
    await client.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("status_code", [201, 204])
@pytest.mark.parametrize(
    "raw",
    [
        b'{"success":true,"data":{"remainingCredits":1}}',
        b'{"success":true,"data":{"remainingCredits":1.5}}',
        b"",
    ],
    ids=["integer-body", "fractional-body", "empty-body"],
)
async def test_credit_status_non_200_success_is_always_malformed(
    status_code: int,
    raw: bytes,
) -> None:
    retained_responses: list[httpx.Response] = []

    async def handler(_incoming: httpx.Request) -> httpx.Response:
        response = httpx.Response(status_code, content=raw)
        retained_responses.append(response)
        return response

    client = httpx.AsyncClient(
        base_url="https://api.firecrawl.dev",
        transport=httpx.MockTransport(handler),
    )
    transport = HttpxProviderTransport(
        key_store=await key_store(),
        network_enabled=True,
        client=client,
        resolver=public_resolver,
    )

    response = await transport.send(credit_status_request())
    outcome = FirecrawlAdapter().classify_response(
        "firecrawl.account.credit_status",
        response,
    )

    assert response.status_code == status_code
    assert response.transport_error is None
    assert response.data is None
    assert outcome.error_class is ProviderErrorClass.MALFORMED_RESPONSE
    assert not outcome.retryable
    assert outcome.data is None
    if raw:
        assert raw.decode("ascii") not in repr(response)
    assert retained_responses[0].content == b""
    await client.aclose()


@pytest.mark.asyncio
async def test_credit_status_error_body_credential_overlap_remains_authoritative() -> None:
    canary = "CREDIT-STATUS-ERROR-CREDENTIAL-CANARY-1234567890"

    async def handler(_incoming: httpx.Request) -> httpx.Response:
        return httpx.Response(401, content=canary.encode("ascii"))

    client = httpx.AsyncClient(
        base_url="https://api.firecrawl.dev",
        transport=httpx.MockTransport(handler),
    )
    transport = HttpxProviderTransport(
        key_store=await key_store(canary.encode("ascii")),
        network_enabled=True,
        client=client,
        resolver=public_resolver,
    )

    response = await transport.send(credit_status_request())
    outcome = FirecrawlAdapter().classify_response(
        "firecrawl.account.credit_status",
        response,
    )

    assert response.status_code == 401
    assert response.transport_error == "malformed_response"
    assert response.data is None
    assert outcome.error_class is ProviderErrorClass.MALFORMED_RESPONSE
    assert canary not in repr(response)
    await client.aclose()


@pytest.mark.asyncio
async def test_credit_status_error_unsafe_header_remains_authoritative() -> None:
    async def handler(_incoming: httpx.Request) -> httpx.Response:
        return httpx.Response(
            401,
            content=b'{"error":"unauthorized"}',
            headers={"set-cookie": "provider_session=unsafe; Path=/"},
        )

    client = httpx.AsyncClient(
        base_url="https://api.firecrawl.dev",
        transport=httpx.MockTransport(handler),
    )
    transport = HttpxProviderTransport(
        key_store=await key_store(),
        network_enabled=True,
        client=client,
        resolver=public_resolver,
    )

    response = await transport.send(credit_status_request())
    outcome = FirecrawlAdapter().classify_response(
        "firecrawl.account.credit_status",
        response,
    )

    assert response.status_code == 401
    assert response.transport_error == "malformed_response"
    assert response.data is None
    assert response.submission_may_have_occurred
    assert outcome.error_class is ProviderErrorClass.MALFORMED_RESPONSE
    await client.aclose()


@pytest.mark.asyncio
async def test_credit_status_error_response_size_failure_remains_authoritative() -> None:
    async def handler(_incoming: httpx.Request) -> httpx.Response:
        return httpx.Response(401, content=b"{}")

    client = httpx.AsyncClient(
        base_url="https://api.firecrawl.dev",
        transport=httpx.MockTransport(handler),
    )
    transport = HttpxProviderTransport(
        key_store=await key_store(),
        network_enabled=True,
        client=client,
        resolver=public_resolver,
    )

    response = await transport.send(credit_status_request(maximum_response_bytes=1))
    outcome = FirecrawlAdapter().classify_response(
        "firecrawl.account.credit_status",
        response,
    )

    assert response.status_code == 401
    assert response.transport_error == "response_too_large"
    assert response.data is None
    assert response.submission_may_have_occurred
    assert outcome.error_class is ProviderErrorClass.MALFORMED_RESPONSE
    await client.aclose()


@pytest.mark.asyncio
async def test_other_successful_operations_retain_ordinary_json_numbers() -> None:
    async def handler(_incoming: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b'{"count":1,"ratio":1.5}')

    client = httpx.AsyncClient(
        base_url="https://api.firecrawl.dev",
        transport=httpx.MockTransport(handler),
    )
    transport = HttpxProviderTransport(
        key_store=await key_store(),
        network_enabled=True,
        client=client,
        resolver=public_resolver,
    )

    response = await transport.send(request())

    assert isinstance(response.data, dict)
    assert type(response.data["count"]) is int
    assert type(response.data["ratio"]) is float
    await client.aclose()


@pytest.mark.asyncio
async def test_url_bearing_operation_rechecks_target_dns_before_send() -> None:
    sent = False

    async def handler(_incoming: httpx.Request) -> httpx.Response:
        nonlocal sent
        sent = True
        return httpx.Response(200, json={"success": True})

    async def resolver(host: str) -> tuple[str, ...]:
        if host == "api.firecrawl.dev":
            return validate_resolved_addresses(["93.184.216.34"])
        return validate_resolved_addresses(["127.0.0.1"])

    client = httpx.AsyncClient(
        base_url="https://api.firecrawl.dev",
        transport=httpx.MockTransport(handler),
    )
    transport = HttpxProviderTransport(
        key_store=await key_store(),
        network_enabled=True,
        client=client,
        resolver=resolver,
    )
    scrape = ProviderRequest(
        method="POST",
        path="/v2/scrape",
        credential_id="credential-1",
        credential_generation=1,
        json_body={"url": "https://private-answer.example/jobs"},
        operation="firecrawl.scrape",
    )

    with pytest.raises(TargetValidationError):
        await transport.send(scrape)

    assert not sent
    await client.aclose()
