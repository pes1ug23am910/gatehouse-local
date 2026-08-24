from __future__ import annotations

from dataclasses import replace

import pytest

from gatehouse.providers import (
    DEFAULT_PROVIDER_REGISTRY,
    FIRECRAWL_DESCRIPTOR,
    FOUNDATION_PROVIDER_IDS,
    CredentialRole,
    ProviderContractError,
    ProviderImplementationState,
)
from gatehouse.providers.firecrawl.adapter import FirecrawlAdapter


def _payloads() -> dict[str, dict[str, object]]:
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


@pytest.mark.parametrize(("operation", "payload"), _payloads().items())
def test_every_firecrawl_adapter_request_matches_code_owned_registry(
    operation: str,
    payload: dict[str, object],
) -> None:
    request = FirecrawlAdapter().build_request(
        operation,
        payload,
        credential_id="credential-1",
    )

    policy = FIRECRAWL_DESCRIPTOR.validate_request(request)

    assert policy.name == operation
    assert request.provider_id == "firecrawl"


def test_registry_tracks_only_implemented_dispatch_provider() -> None:
    assert DEFAULT_PROVIDER_REGISTRY.provider_ids == ("firecrawl",)
    assert FIRECRAWL_DESCRIPTOR.implementation_state is ProviderImplementationState.ACTIVE
    assert FOUNDATION_PROVIDER_IDS == {
        "firecrawl",
        "github",
        "openrouter",
        "gemini",
        "xai",
        "jarvislabs",
    }


def test_firecrawl_credit_observer_role_is_isolated_from_workloads() -> None:
    adapter = FirecrawlAdapter()
    observation = adapter.build_request(
        "firecrawl.account.credit_status",
        {},
        credential_id="observer-1",
        credential_role=CredentialRole.OBSERVER,
    )
    workload = adapter.build_request(
        "firecrawl.search",
        _payloads()["firecrawl.search"],
        credential_id="observer-1",
        credential_role=CredentialRole.OBSERVER,
    )

    assert FIRECRAWL_DESCRIPTOR.validate_request(observation).exact_response_numbers is True
    with pytest.raises(ProviderContractError, match="credential role"):
        FIRECRAWL_DESCRIPTOR.validate_request(workload)


@pytest.mark.parametrize(
    "change",
    [
        "method",
        "path",
        "provider_id",
        "query",
        "json_body",
        "credential_role",
    ],
)
def test_registry_rejects_request_shape_or_authority_drift(change: str) -> None:
    request = FirecrawlAdapter().build_request(
        "firecrawl.search",
        _payloads()["firecrawl.search"],
        credential_id="credential-1",
    )
    if change == "method":
        drifted = replace(request, method="GET")
    elif change == "path":
        drifted = replace(request, path="/v2/map")
    elif change == "provider_id":
        drifted = replace(request, provider_id="github")
    elif change == "query":
        drifted = replace(request, query={"url": "https://attacker.invalid"})
    elif change == "json_body":
        drifted = replace(request, json_body=None)
    else:
        drifted = replace(request, credential_role=CredentialRole.MANAGEMENT)

    with pytest.raises(ProviderContractError):
        FIRECRAWL_DESCRIPTOR.validate_request(drifted)


def test_registry_rejects_dynamic_resource_path_outside_fixed_pattern() -> None:
    request = FirecrawlAdapter().build_request(
        "firecrawl.crawl.status",
        {"provider_job_id": "job-1"},
        credential_id="credential-1",
    )

    with pytest.raises(ProviderContractError, match="typed provider operation"):
        FIRECRAWL_DESCRIPTOR.validate_request(replace(request, path="/v2/crawl/job-1/extra"))
