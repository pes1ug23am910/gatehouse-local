"""Strict agent-facing schemas for the allowed Firecrawl v2 surface."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class Purpose(StrEnum):
    CAREER_DISCOVERY = "career_discovery"
    CAREER_SITE_RESEARCH = "career_site_research"
    ACTIVE_JOB_VERIFICATION = "active_job_verification"
    JS_HEAVY_EXTRACTION = "js_heavy_extraction"
    MULTI_PAGE_JOB_EXTRACTION = "multi_page_job_extraction"
    OPENING_MONITORING = "opening_monitoring"


class DataClassification(StrEnum):
    PUBLIC_WEB_QUERY = "public_web_query"
    PUBLIC_WEB = "public_web"
    PUBLIC_JOB_DATA = "public_job_data"
    CREDENTIAL = "credential"
    API_KEY = "api_key"
    PRIVATE_KEY = "private_key"
    RESUME = "resume"
    PRIVATE_DOCUMENT = "private_document"
    IDENTITY_DOCUMENT = "identity_document"
    SENSITIVE_PERSONAL_INFORMATION = "sensitive_personal_information"


class ScrapeFormat(StrEnum):
    MARKDOWN = "markdown"
    SUMMARY = "summary"
    LINKS = "links"


class SitemapMode(StrEnum):
    SKIP = "skip"
    INCLUDE = "include"
    ONLY = "only"


class StrictInput(BaseModel):
    """Base model that treats accidental contract drift as an error."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


Classifications = Annotated[list[DataClassification], Field(min_length=1, max_length=8)]


class SearchInput(StrictInput):
    query: Annotated[str, Field(min_length=1, max_length=500)]
    limit: Annotated[int, Field(ge=1, le=20)] = 10
    include_content: bool = False
    purpose: Purpose
    data_classification: Classifications

    @field_validator("query")
    @classmethod
    def normalize_query(cls, value: str) -> str:
        normalized = " ".join(value.split())
        if not normalized:
            raise ValueError("query cannot contain whitespace only")
        return normalized


class ScrapeInput(StrictInput):
    url: Annotated[str, Field(min_length=9, max_length=2_048)]
    formats: Annotated[list[ScrapeFormat], Field(min_length=1, max_length=3)] = Field(
        default_factory=lambda: [ScrapeFormat.MARKDOWN]
    )
    only_main_content: Literal[True] = True
    timeout_ms: Annotated[int, Field(ge=1_000, le=300_000)] = 30_000
    purpose: Purpose
    data_classification: Classifications

    @field_validator("formats")
    @classmethod
    def formats_are_unique(cls, value: list[ScrapeFormat]) -> list[ScrapeFormat]:
        if len(set(value)) != len(value):
            raise ValueError("formats must be unique")
        return sorted(value, key=str)


class MapInput(StrictInput):
    url: Annotated[str, Field(min_length=9, max_length=2_048)]
    search: Annotated[str | None, Field(min_length=1, max_length=200)] = None
    limit: Annotated[int, Field(ge=1, le=100)] = 100
    sitemap: SitemapMode = SitemapMode.INCLUDE
    purpose: Literal[Purpose.CAREER_SITE_RESEARCH]
    data_classification: Classifications


class CrawlStartInput(StrictInput):
    url: Annotated[str, Field(min_length=9, max_length=2_048)]
    include_paths: Annotated[list[str], Field(max_length=50)] = Field(default_factory=list)
    exclude_paths: Annotated[list[str], Field(max_length=50)] = Field(default_factory=list)
    maximum_pages: Annotated[int, Field(ge=1, le=25)] = 25
    maximum_depth: Annotated[int, Field(ge=0, le=2)] = 2
    maximum_concurrency: Annotated[int, Field(ge=1, le=4)] = 2
    sitemap: SitemapMode = SitemapMode.INCLUDE
    ignore_query_parameters: Literal[True] = True
    allow_subdomains: Literal[False] = False
    allow_external_links: Literal[False] = False
    purpose: Literal[Purpose.MULTI_PAGE_JOB_EXTRACTION]
    data_classification: Classifications

    @field_validator("include_paths", "exclude_paths")
    @classmethod
    def validate_path_patterns(cls, values: list[str]) -> list[str]:
        if len(set(values)) != len(values):
            raise ValueError("path patterns must be unique")
        for pattern in values:
            if not pattern or len(pattern) > 300:
                raise ValueError("path patterns must contain 1 to 300 characters")
            try:
                re.compile(pattern)
            except re.error as exc:
                raise ValueError("path pattern is not a valid regular expression") from exc
        return sorted(values)

    @model_validator(mode="after")
    def require_narrow_scope(self) -> CrawlStartInput:
        if not self.include_paths:
            raise ValueError("a crawl requires at least one explicit include path")
        return self


class CrawlResourceInput(StrictInput):
    provider_job_id: Annotated[
        str,
        Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_-]+$"),
    ]


class CreditStatusInput(StrictInput):
    """No caller-controlled fields are accepted for account credit status."""


OPERATION_INPUTS: dict[str, type[StrictInput]] = {
    "firecrawl.search": SearchInput,
    "firecrawl.scrape": ScrapeInput,
    "firecrawl.map": MapInput,
    "firecrawl.crawl.start": CrawlStartInput,
    "firecrawl.crawl.status": CrawlResourceInput,
    "firecrawl.crawl.cancel": CrawlResourceInput,
    "firecrawl.account.credit_status": CreditStatusInput,
}


def validate_operation_input(operation: str, payload: object) -> StrictInput:
    """Validate a payload without permitting a fallback generic operation."""

    model = OPERATION_INPUTS.get(operation)
    if model is None:
        raise ValueError(f"unsupported operation: {operation}")
    if not isinstance(payload, Mapping):
        raise TypeError("operation payload must be a JSON object")
    serialized = json.dumps(payload, allow_nan=False, separators=(",", ":"))
    return model.model_validate_json(serialized)
