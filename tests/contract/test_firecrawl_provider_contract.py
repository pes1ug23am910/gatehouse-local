from __future__ import annotations

import time
from collections.abc import Mapping

import httpx
import pytest

from gatehouse.credentials import CredentialMetadata, InMemoryKeyStore
from gatehouse.providers import ProviderErrorClass
from gatehouse.providers.firecrawl import FirecrawlAdapter
from gatehouse.providers.transport import FIRECRAWL_ORIGIN, HttpxProviderTransport
from gatehouse.testing import ProviderScriptStep, ScriptedProviderASGI, ScriptMode

_SECRET = b"CONTRACT_ONLY_PROVIDER_SECRET_123456"


async def _public_resolver(_host: str) -> tuple[str, ...]:
    return ("93.184.216.34",)


async def _transport(
    app: ScriptedProviderASGI,
) -> tuple[HttpxProviderTransport, httpx.AsyncClient]:
    key_store = InMemoryKeyStore()
    await key_store.put(
        CredentialMetadata(
            credential_id="credential-1",
            principal_id="principal-1",
            quota_scope_id="quota-1",
            alias="contract",
        ),
        _SECRET,
    )
    client = httpx.AsyncClient(
        base_url=FIRECRAWL_ORIGIN,
        transport=httpx.ASGITransport(app=app),
    )
    return (
        HttpxProviderTransport(
            key_store=key_store,
            network_enabled=True,
            client=client,
            resolver=_public_resolver,
        ),
        client,
    )


def _operation_payloads() -> Mapping[str, dict[str, object]]:
    return {
        "firecrawl.search": {
            "query": "graduate roles",
            "limit": 5,
            "include_content": False,
            "purpose": "career_discovery",
            "data_classification": ["public_web_query"],
        },
        "firecrawl.scrape": {
            "url": "https://careers.example.com/jobs/1",
            "formats": ["markdown"],
            "only_main_content": True,
            "timeout_ms": 5_000,
            "purpose": "active_job_verification",
            "data_classification": ["public_job_data"],
        },
        "firecrawl.map": {
            "url": "https://careers.example.com/jobs",
            "limit": 10,
            "sitemap": "include",
            "purpose": "career_site_research",
            "data_classification": ["public_web"],
        },
        "firecrawl.crawl.start": {
            "url": "https://careers.example.com/jobs",
            "include_paths": [r"^/jobs(?:/.*)?$"],
            "maximum_pages": 5,
            "maximum_depth": 1,
            "maximum_concurrency": 2,
            "sitemap": "include",
            "ignore_query_parameters": True,
            "allow_subdomains": False,
            "allow_external_links": False,
            "purpose": "multi_page_job_extraction",
            "data_classification": ["public_job_data"],
        },
        "firecrawl.crawl.status": {"provider_job_id": "job-1"},
        "firecrawl.crawl.cancel": {"provider_job_id": "job-1"},
        "firecrawl.account.credit_status": {},
    }


@pytest.mark.asyncio
async def test_all_seven_operations_cross_real_adapter_and_secret_transport() -> None:
    adapter = FirecrawlAdapter()
    app = ScriptedProviderASGI()
    expected_routes: dict[tuple[str, str], dict[str, object]] = {}
    for operation, payload in _operation_payloads().items():
        request = adapter.build_request(operation, payload, credential_id="credential-1")
        response_data: dict[str, object] = {"success": True, "creditsUsed": 1}
        if operation == "firecrawl.crawl.start":
            response_data["id"] = "job-1"
        elif operation == "firecrawl.account.credit_status":
            response_data["data"] = {"remainingCredits": 100, "planCredits": 1_000}
        app.script(
            request.method,
            request.path,
            [
                ProviderScriptStep(
                    status_code=200,
                    json_data=response_data,
                    headers={"x-request-id": f"provider-{len(expected_routes) + 1}"},
                )
            ],
        )
        expected_routes[(request.method, request.path)] = payload

    transport, client = await _transport(app)
    try:
        for operation, payload in _operation_payloads().items():
            request = adapter.build_request(operation, payload, credential_id="credential-1")
            response = await transport.send(request)
            outcome = adapter.classify_response(operation, response)
            assert outcome.succeeded
            assert response.provider_request_id is not None
    finally:
        await client.aclose()

    observations = app.observations
    assert len(observations) == 7
    assert {(item.method, item.path) for item in observations} == set(expected_routes)
    assert all(item.authorization_present and item.accepted for item in observations)
    assert _SECRET.decode() not in repr(observations)


@pytest.mark.parametrize(
    ("status_code", "expected"),
    [
        (200, ProviderErrorClass.NONE),
        (400, ProviderErrorClass.INVALID_REQUEST),
        (401, ProviderErrorClass.UNAUTHORIZED),
        (402, ProviderErrorClass.QUOTA_EXHAUSTED),
        (403, ProviderErrorClass.PERMISSION_DENIED),
        (408, ProviderErrorClass.TIMEOUT),
        (409, ProviderErrorClass.CONFLICT),
        (422, ProviderErrorClass.INVALID_REQUEST),
        (429, ProviderErrorClass.RATE_LIMITED),
        (500, ProviderErrorClass.TRANSIENT),
        (503, ProviderErrorClass.TRANSIENT),
    ],
)
@pytest.mark.asyncio
async def test_scripted_status_matrix_and_retry_after(
    status_code: int,
    expected: ProviderErrorClass,
) -> None:
    app = ScriptedProviderASGI()
    app.script(
        "POST",
        "/v2/search",
        [
            ProviderScriptStep(
                status_code=status_code,
                json_data={"success": status_code == 200},
                headers={"retry-after": "7", "x-request-id": "matrix-request"},
            )
        ],
    )
    transport, client = await _transport(app)
    adapter = FirecrawlAdapter()
    request = adapter.build_request(
        "firecrawl.search",
        _operation_payloads()["firecrawl.search"],
        credential_id="credential-1",
    )
    try:
        response = await transport.send(request)
    finally:
        await client.aclose()
    outcome = adapter.classify_response("firecrawl.search", response)
    assert outcome.error_class is expected
    assert outcome.retry_after_seconds == 7


@pytest.mark.asyncio
async def test_malformed_delay_and_reset_semantics_are_distinct() -> None:
    app = ScriptedProviderASGI()
    app.script(
        "POST",
        "/v2/search",
        [
            ProviderScriptStep(mode=ScriptMode.MALFORMED, status_code=200),
            ProviderScriptStep(
                mode=ScriptMode.DELAY,
                status_code=200,
                delay_ms=15,
                json_data={"success": True},
            ),
            ProviderScriptStep(mode=ScriptMode.PRE_SEND_RESET),
            ProviderScriptStep(mode=ScriptMode.POST_SEND_RESET),
        ],
    )
    transport, client = await _transport(app)
    adapter = FirecrawlAdapter()
    request = adapter.build_request(
        "firecrawl.search",
        _operation_payloads()["firecrawl.search"],
        credential_id="credential-1",
    )
    try:
        malformed = await transport.send(request)
        started = time.perf_counter()
        delayed = await transport.send(request)
        delay_seconds = time.perf_counter() - started
        pre_send = await transport.send(request)
        post_send = await transport.send(request)
    finally:
        await client.aclose()

    assert malformed.transport_error == "malformed_response"
    assert (
        adapter.classify_response("firecrawl.search", malformed).error_class
        is ProviderErrorClass.MALFORMED_RESPONSE
    )
    assert delayed.succeeded and delay_seconds >= 0.01
    assert pre_send.status_code is None and not pre_send.submission_may_have_occurred
    assert post_send.status_code is None and post_send.submission_may_have_occurred
    assert (
        adapter.classify_response("firecrawl.search", pre_send).error_class
        is ProviderErrorClass.TIMEOUT
    )
    assert (
        adapter.classify_response("firecrawl.search", post_send).error_class
        is ProviderErrorClass.UNKNOWN_OUTCOME
    )
    # Malformed, delayed, and post-send-reset requests were accepted; pre-send was not.
    assert len(app.observations) == 3
