from __future__ import annotations

import pytest
from pydantic import ValidationError

from gatehouse.providers.base import ProviderErrorClass, ProviderResponse
from gatehouse.providers.firecrawl.adapter import FirecrawlAdapter
from gatehouse.providers.firecrawl.models import CrawlStartInput, SearchInput


def test_json_enum_values_validate_without_scalar_coercion() -> None:
    model = FirecrawlAdapter().validate(
        "firecrawl.search",
        {
            "query": "graduate roles",
            "limit": 10,
            "purpose": "career_discovery",
            "data_classification": ["public_web_query"],
        },
    )

    assert isinstance(model, SearchInput)
    with pytest.raises(ValidationError):
        FirecrawlAdapter().validate(
            "firecrawl.search",
            {
                "query": "graduate roles",
                "limit": "10",
                "purpose": "career_discovery",
                "data_classification": ["public_web_query"],
            },
        )


def test_search_mapping_does_not_forward_policy_metadata() -> None:
    request = FirecrawlAdapter().build_request(
        "firecrawl.search",
        {
            "query": "graduate roles",
            "limit": 5,
            "include_content": False,
            "purpose": "career_discovery",
            "data_classification": ["public_web_query"],
        },
        credential_id="credential-1",
        credential_generation=7,
    )

    assert request.path == "/v2/search"
    assert request.credential_generation == 7
    assert request.json_body == {"query": "graduate roles", "limit": 5}
    assert "purpose" not in request.json_body


def test_crawl_always_maps_safety_bounds() -> None:
    adapter = FirecrawlAdapter()
    payload = {
        "url": "https://careers.example.com/jobs",
        "include_paths": ["^/jobs(/.*)?$"],
        "maximum_pages": 10,
        "maximum_depth": 1,
        "maximum_concurrency": 2,
        "purpose": "multi_page_job_extraction",
        "data_classification": ["public_job_data"],
    }
    model = adapter.validate("firecrawl.crawl.start", payload)
    request = adapter.build_request(
        "firecrawl.crawl.start",
        payload,
        credential_id="credential-1",
    )

    assert isinstance(model, CrawlStartInput)
    assert request.path == "/v2/crawl"
    assert request.json_body is not None
    assert request.json_body["limit"] == 10
    assert request.json_body["crawlEntireDomain"] is False
    assert request.json_body["allowExternalLinks"] is False
    assert request.json_body["ignoreRobotsTxt"] is False


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (400, ProviderErrorClass.INVALID_REQUEST),
        (401, ProviderErrorClass.UNAUTHORIZED),
        (402, ProviderErrorClass.QUOTA_EXHAUSTED),
        (403, ProviderErrorClass.PERMISSION_DENIED),
        (409, ProviderErrorClass.CONFLICT),
        (429, ProviderErrorClass.RATE_LIMITED),
        (503, ProviderErrorClass.TRANSIENT),
    ],
)
def test_status_classification(status: int, expected: ProviderErrorClass) -> None:
    outcome = FirecrawlAdapter().classify_response(
        "firecrawl.search",
        ProviderResponse(status_code=status, headers={"retry-after": "3"}),
    )

    assert outcome.error_class is expected
    assert outcome.retry_after_seconds == 3


def test_ambiguous_crawl_submission_is_not_retryable() -> None:
    outcome = FirecrawlAdapter().classify_response(
        "firecrawl.crawl.start",
        ProviderResponse(status_code=None, submission_may_have_occurred=True),
    )

    assert outcome.error_class is ProviderErrorClass.UNKNOWN_OUTCOME
    assert not outcome.retryable


@pytest.mark.parametrize("provider_job_id", ["x" * 129, "invalid/job"])
def test_crawl_start_rejects_non_routable_provider_job_identifier(
    provider_job_id: str,
) -> None:
    outcome = FirecrawlAdapter().classify_response(
        "firecrawl.crawl.start",
        ProviderResponse(status_code=200, data={"id": provider_job_id}),
    )

    assert outcome.error_class is ProviderErrorClass.MALFORMED_RESPONSE
    assert outcome.provider_job_id is None
    assert outcome.submission_may_have_occurred
    assert not outcome.retryable


def test_oversized_provider_usage_is_treated_as_unknown() -> None:
    outcome = FirecrawlAdapter().classify_response(
        "firecrawl.crawl.start",
        ProviderResponse(
            status_code=200,
            data={"id": "valid-job", "creditsUsed": 10**400},
        ),
    )

    assert outcome.succeeded
    assert outcome.provider_job_id == "valid-job"
    assert outcome.actual_credits is None


def test_credit_status_mapping_is_fixed_and_tightly_bounded() -> None:
    request = FirecrawlAdapter().build_request(
        "firecrawl.account.credit_status",
        {},
        credential_id="credential-exact",
        credential_generation=9,
    )

    assert request.method == "GET"
    assert request.path == "/v2/team/credit-usage"
    assert request.credential_id == "credential-exact"
    assert request.credential_generation == 9
    assert request.json_body is None
    assert dict(request.query) == {}
    assert request.timeout_ms == 10_000
    assert request.maximum_response_bytes == 64 * 1_024


def test_credit_status_parser_extracts_only_allowlisted_nested_counters() -> None:
    outcome = FirecrawlAdapter().classify_response(
        "firecrawl.account.credit_status",
        ProviderResponse(
            status_code=200,
            data={
                "success": True,
                "data": {
                    "remainingCredits": 41,
                    "planCredits": 100,
                    "team": "must-not-be-retained",
                },
                "account": {"name": "must-not-be-retained"},
            },
        ),
    )

    status = FirecrawlAdapter().parse_credit_status(outcome)

    assert status.remaining_credits == 41
    assert status.plan_credits == 100
    assert not hasattr(status, "team")
    assert not hasattr(status, "account")


def test_credit_status_parser_allows_absent_optional_plan_counter() -> None:
    outcome = FirecrawlAdapter().classify_response(
        "firecrawl.account.credit_status",
        ProviderResponse(
            status_code=200,
            data={"success": True, "data": {"remainingCredits": 0}},
        ),
    )

    status = FirecrawlAdapter().parse_credit_status(outcome)

    assert status.remaining_credits == 0
    assert status.plan_credits is None


@pytest.mark.parametrize(
    "data",
    [
        None,
        {},
        {"success": False, "data": {"remainingCredits": 1}},
        {"success": True},
        {"success": True, "data": None},
        {"success": True, "remainingCredits": 1},
        {"success": True, "data": {}},
        {"success": True, "data": {"remainingCredits": True}},
        {"success": True, "data": {"remainingCredits": -1}},
        {"success": True, "data": {"remainingCredits": 1.0}},
        {"success": True, "data": {"remainingCredits": 2**63}},
        {"success": True, "data": {"remainingCredits": 1, "planCredits": None}},
        {"success": True, "data": {"remainingCredits": 1, "planCredits": False}},
        {"success": True, "data": {"remainingCredits": 1, "planCredits": -1}},
    ],
)
def test_credit_status_parser_fails_closed_for_malformed_envelopes(data: object) -> None:
    outcome = FirecrawlAdapter().classify_response(
        "firecrawl.account.credit_status",
        ProviderResponse(status_code=200, data=data),
    )

    with pytest.raises(ValueError, match="^credit status response is malformed$"):
        FirecrawlAdapter().parse_credit_status(outcome)


def test_credit_status_parser_rejects_provider_error_outcomes() -> None:
    outcome = FirecrawlAdapter().classify_response(
        "firecrawl.account.credit_status",
        ProviderResponse(status_code=401),
    )

    with pytest.raises(ValueError, match="^credit status response is malformed$"):
        FirecrawlAdapter().parse_credit_status(outcome)
