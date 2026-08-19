from __future__ import annotations

import json

import httpx
import pytest

from gatehouse.credentials.base import CredentialMetadata
from gatehouse.credentials.memory import InMemoryKeyStore
from gatehouse.policy.targets import TargetValidationError, validate_resolved_addresses
from gatehouse.providers.base import ProviderRequest
from gatehouse.providers.transport import (
    HttpxProviderTransport,
    ProviderNetworkDisabledError,
)


async def public_resolver(_host: str) -> tuple[str, ...]:
    return ("93.184.216.34",)


async def key_store(secret: bytes = b"unit-test-provider-secret-123456") -> InMemoryKeyStore:
    store = InMemoryKeyStore()
    await store.put(
        CredentialMetadata(
            credential_id="credential-1",
            principal_id="principal-1",
            quota_scope_id="quota-1",
            alias="test-account",
        ),
        secret,
    )
    return store


def request(*, maximum_response_bytes: int = 1_024) -> ProviderRequest:
    return ProviderRequest(
        method="POST",
        path="/v2/search",
        credential_id="credential-1",
        json_body={"query": "graduate roles", "limit": 5},
        maximum_response_bytes=maximum_response_bytes,
        operation="firecrawl.search",
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

    async def handler(incoming: httpx.Request) -> httpx.Response:
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
    await client.aclose()


@pytest.mark.asyncio
async def test_response_byte_limit_is_enforced() -> None:
    async def handler(_incoming: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"x" * 100)

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
        json_body={"url": "https://private-answer.example/jobs"},
        operation="firecrawl.scrape",
    )

    with pytest.raises(TargetValidationError):
        await transport.send(scrape)

    assert not sent
    await client.aclose()
