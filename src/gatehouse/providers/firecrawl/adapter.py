"""Strict mapping between Gatehouse operations and fixed Firecrawl v2 endpoints."""

from __future__ import annotations

import math
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from gatehouse.policy.targets import CanonicalTarget, canonicalize_public_url
from gatehouse.providers.base import (
    OperationSpec,
    ProviderErrorClass,
    ProviderRequest,
    ProviderResponse,
    RetrySafety,
    SideEffectClass,
)
from gatehouse.providers.firecrawl.models import (
    CrawlResourceInput,
    CrawlStartInput,
    CreditStatusInput,
    MapInput,
    ScrapeInput,
    SearchInput,
    StrictInput,
    validate_operation_input,
)

OPERATION_SPECS: Mapping[str, OperationSpec] = {
    "firecrawl.search": OperationSpec(
        name="firecrawl.search",
        side_effect=SideEffectClass.METERED_READ,
        retry_safety=RetrySafety.SAFE,
        coalescible=True,
        asynchronous=False,
        default_estimated_cost=1,
        default_timeout_ms=30_000,
    ),
    "firecrawl.scrape": OperationSpec(
        name="firecrawl.scrape",
        side_effect=SideEffectClass.METERED_READ,
        retry_safety=RetrySafety.SAFE,
        coalescible=True,
        asynchronous=False,
        default_estimated_cost=1,
        default_timeout_ms=300_000,
    ),
    "firecrawl.map": OperationSpec(
        name="firecrawl.map",
        side_effect=SideEffectClass.METERED_READ,
        retry_safety=RetrySafety.SAFE,
        coalescible=True,
        asynchronous=False,
        default_estimated_cost=1,
        default_timeout_ms=60_000,
    ),
    "firecrawl.crawl.start": OperationSpec(
        name="firecrawl.crawl.start",
        side_effect=SideEffectClass.ASYNC_CREATE,
        retry_safety=RetrySafety.RECONCILE_FIRST,
        coalescible=False,
        asynchronous=True,
        default_estimated_cost=25,
        default_timeout_ms=60_000,
    ),
    "firecrawl.crawl.status": OperationSpec(
        name="firecrawl.crawl.status",
        side_effect=SideEffectClass.LOCAL_READ,
        retry_safety=RetrySafety.SAFE,
        coalescible=False,
        asynchronous=False,
        default_estimated_cost=0,
        default_timeout_ms=30_000,
    ),
    "firecrawl.crawl.cancel": OperationSpec(
        name="firecrawl.crawl.cancel",
        side_effect=SideEffectClass.MUTATION,
        retry_safety=RetrySafety.RECONCILE_FIRST,
        coalescible=False,
        asynchronous=False,
        default_estimated_cost=0,
        default_timeout_ms=30_000,
    ),
    "firecrawl.account.credit_status": OperationSpec(
        name="firecrawl.account.credit_status",
        side_effect=SideEffectClass.LOCAL_READ,
        retry_safety=RetrySafety.SAFE,
        coalescible=False,
        asynchronous=False,
        default_estimated_cost=0,
        default_timeout_ms=30_000,
    ),
}

_PROVIDER_JOB_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,128}$")


@dataclass(frozen=True, slots=True)
class FirecrawlOutcome:
    """A classified, credential-free provider result."""

    operation: str
    error_class: ProviderErrorClass
    retryable: bool
    retry_after_seconds: float | None
    data: Any = None
    provider_request_id: str | None = None
    actual_credits: float | None = None
    provider_job_id: str | None = None
    submission_may_have_occurred: bool = False

    @property
    def succeeded(self) -> bool:
        return self.error_class is ProviderErrorClass.NONE


class FirecrawlAdapter:
    """Validate inputs, create fixed requests, and classify sanitized responses."""

    @staticmethod
    def operation_spec(operation: str) -> OperationSpec:
        try:
            return OPERATION_SPECS[operation]
        except KeyError as exc:
            raise ValueError(f"unsupported operation: {operation}") from exc

    @staticmethod
    def validate(operation: str, payload: object) -> StrictInput:
        return validate_operation_input(operation, payload)

    def build_request(
        self,
        operation: str,
        payload: object,
        *,
        credential_id: str,
        credential_generation: int = 1,
    ) -> ProviderRequest:
        model = self.validate(operation, payload)
        spec = self.operation_spec(operation)
        method, path, body = self._map_request(operation, model)
        return ProviderRequest(
            method=method,
            path=path,
            credential_id=credential_id,
            credential_generation=credential_generation,
            json_body=body,
            timeout_ms=spec.default_timeout_ms,
            maximum_response_bytes=spec.maximum_response_bytes,
            operation=operation,
        )

    @staticmethod
    def canonical_target(model: StrictInput) -> CanonicalTarget | None:
        value = getattr(model, "url", None)
        return canonicalize_public_url(value) if isinstance(value, str) else None

    @staticmethod
    def _map_request(
        operation: str,
        model: StrictInput,
    ) -> tuple[str, str, Mapping[str, Any] | None]:
        if isinstance(model, SearchInput):
            body: dict[str, Any] = {"query": model.query, "limit": model.limit}
            if model.include_content:
                body["scrapeOptions"] = {
                    "formats": ["markdown"],
                    "onlyMainContent": True,
                }
            return "POST", "/v2/search", body
        if isinstance(model, ScrapeInput):
            target = canonicalize_public_url(model.url)
            return (
                "POST",
                "/v2/scrape",
                {
                    "url": target.url,
                    "formats": [item.value for item in model.formats],
                    "onlyMainContent": model.only_main_content,
                    "timeout": model.timeout_ms,
                },
            )
        if isinstance(model, MapInput):
            target = canonicalize_public_url(model.url)
            body = {
                "url": target.url,
                "limit": model.limit,
                "sitemap": model.sitemap.value,
            }
            if model.search is not None:
                body["search"] = model.search
            return "POST", "/v2/map", body
        if isinstance(model, CrawlStartInput):
            target = canonicalize_public_url(model.url)
            return (
                "POST",
                "/v2/crawl",
                {
                    "url": target.url,
                    "includePaths": model.include_paths,
                    "excludePaths": model.exclude_paths,
                    "limit": model.maximum_pages,
                    "maxDiscoveryDepth": model.maximum_depth,
                    "maxConcurrency": model.maximum_concurrency,
                    "sitemap": model.sitemap.value,
                    "ignoreQueryParameters": model.ignore_query_parameters,
                    "crawlEntireDomain": False,
                    "allowSubdomains": model.allow_subdomains,
                    "allowExternalLinks": model.allow_external_links,
                    "ignoreRobotsTxt": False,
                    "scrapeOptions": {"formats": ["markdown"], "onlyMainContent": True},
                },
            )
        if isinstance(model, CrawlResourceInput):
            return (
                "DELETE" if operation.endswith(".cancel") else "GET",
                f"/v2/crawl/{model.provider_job_id}",
                None,
            )
        if isinstance(model, CreditStatusInput):
            return "GET", "/v2/team/credit-usage", None
        raise TypeError("validated operation did not map to a provider request")

    def classify_response(self, operation: str, response: ProviderResponse) -> FirecrawlOutcome:
        """Map status and transport ambiguity without replaying requests."""

        spec = self.operation_spec(operation)
        error_class = self._classify_error(response)
        retryable = error_class in {ProviderErrorClass.RATE_LIMITED, ProviderErrorClass.TRANSIENT}
        if error_class is ProviderErrorClass.TIMEOUT:
            retryable = (
                spec.retry_safety is RetrySafety.SAFE and not response.submission_may_have_occurred
            )
        if error_class in {ProviderErrorClass.CONFLICT, ProviderErrorClass.UNKNOWN_OUTCOME}:
            retryable = False

        data = response.data if error_class is ProviderErrorClass.NONE else None
        provider_job_id: str | None = None
        submission_may_have_occurred = response.submission_may_have_occurred
        actual_credits: float | None = None
        if isinstance(data, Mapping):
            raw_credits = data.get("creditsUsed")
            if isinstance(raw_credits, (int, float)) and not isinstance(raw_credits, bool):
                try:
                    normalized_credits = float(raw_credits)
                except OverflowError:
                    normalized_credits = math.inf
                if math.isfinite(normalized_credits) and normalized_credits >= 0:
                    actual_credits = normalized_credits
        if operation == "firecrawl.crawl.start" and error_class is ProviderErrorClass.NONE:
            raw_job_id = data.get("id") if isinstance(data, Mapping) else None
            if (
                not isinstance(raw_job_id, str)
                or _PROVIDER_JOB_ID_PATTERN.fullmatch(raw_job_id) is None
            ):
                error_class = ProviderErrorClass.MALFORMED_RESPONSE
                retryable = False
                data = None
                submission_may_have_occurred = True
            else:
                provider_job_id = raw_job_id

        return FirecrawlOutcome(
            operation=operation,
            error_class=error_class,
            retryable=retryable,
            retry_after_seconds=response.retry_after_seconds,
            data=data,
            provider_request_id=response.provider_request_id,
            actual_credits=actual_credits,
            provider_job_id=provider_job_id,
            submission_may_have_occurred=submission_may_have_occurred,
        )

    @staticmethod
    def _classify_error(response: ProviderResponse) -> ProviderErrorClass:
        if response.transport_error in {"malformed_response", "response_too_large"}:
            return ProviderErrorClass.MALFORMED_RESPONSE
        if response.succeeded:
            return ProviderErrorClass.NONE
        if response.status_code is None:
            if response.submission_may_have_occurred:
                return ProviderErrorClass.UNKNOWN_OUTCOME
            return ProviderErrorClass.TIMEOUT
        return {
            400: ProviderErrorClass.INVALID_REQUEST,
            401: ProviderErrorClass.UNAUTHORIZED,
            402: ProviderErrorClass.QUOTA_EXHAUSTED,
            403: ProviderErrorClass.PERMISSION_DENIED,
            404: ProviderErrorClass.NOT_FOUND,
            408: ProviderErrorClass.TIMEOUT,
            409: ProviderErrorClass.CONFLICT,
            422: ProviderErrorClass.INVALID_REQUEST,
            429: ProviderErrorClass.RATE_LIMITED,
        }.get(
            response.status_code,
            ProviderErrorClass.TRANSIENT
            if response.status_code >= 500
            else ProviderErrorClass.INVALID_REQUEST,
        )
