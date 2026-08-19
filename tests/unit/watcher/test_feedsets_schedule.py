from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from gatehouse.config import FeedSetConfig
from gatehouse.core.clock import datetime_to_utc_ms
from gatehouse.watcher import (
    FeedSetRegistry,
    FeedSetResolutionError,
    TargetNotAllowedError,
    TargetRequest,
    authorize_target,
    evaluate_schedule,
)


def _config(*, allow_subdomains: bool = False) -> FeedSetConfig:
    return FeedSetConfig.model_validate(
        {
            "schema_version": 1,
            "feed_set": {"id": "placements", "display_name": "Placements"},
            "allowed_targets": [
                {
                    "host": "careers.example.com",
                    "path_regex": r"^/jobs(?:/[^/]+)?$",
                    "operations": ["scrape", "crawl"],
                }
            ],
            "crawl": {
                "maximum_pages": 5,
                "maximum_depth": 2,
                "allow_external_links": False,
                "allow_subdomains": allow_subdomains,
                "ignore_query_parameters": True,
            },
            "schedule": {
                "timezone": "Asia/Kolkata",
                "windows": [{"days": ["mon"], "start": "22:00", "end": "02:00"}],
                "early_start_grace": "5m",
                "late_start_grace": "30m",
            },
            "budgets": {
                "maximum_requests_per_run": 10,
                "maximum_credits_per_run": 2.5,
                "maximum_duration": "30m",
            },
        }
    )


def _utc_ms(value: str) -> int:
    return datetime_to_utc_ms(datetime.fromisoformat(value).replace(tzinfo=UTC))


def test_registry_is_server_side_and_key_bound() -> None:
    config = _config()
    registry = FeedSetRegistry([config])
    assert registry.resolve("placements") is config
    with pytest.raises(FeedSetResolutionError, match="not configured"):
        registry.resolve("caller-injected")
    with pytest.raises(ValueError, match="does not match"):
        FeedSetRegistry({"different": config})


def test_strict_target_authorization_normalizes_and_drops_query() -> None:
    result = authorize_target(
        _config(),
        TargetRequest("scrape", "https://CAREERS.EXAMPLE.COM:443/jobs/backend?q=secret#"),
    )
    assert result.normalized_url == "https://careers.example.com/jobs/backend"
    assert result.operation == "scrape"


@pytest.mark.parametrize(
    ("operation", "url"),
    [
        ("search", "https://careers.example.com/jobs"),
        ("scrape", "http://careers.example.com/jobs"),
        ("scrape", "https://user@careers.example.com/jobs"),
        ("scrape", "https://careers.example.com:8443/jobs"),
        ("scrape", "https://careers.example.com.evil.test/jobs"),
        ("scrape", "https://careers.example.com/jobs/%2fadmin"),
        ("scrape", "https://careers.example.com/jobs/%252fadmin"),
        ("scrape", "https://careers.example.com/jobs/%252e%252e/admin"),
        ("scrape", "https://careers.example.com/jobs/../admin"),
        ("scrape", "https://sub.careers.example.com/jobs"),
    ],
)
def test_target_authorization_fails_closed(operation: str, url: str) -> None:
    with pytest.raises(TargetNotAllowedError):
        authorize_target(_config(), TargetRequest(operation, url))


def test_subdomains_require_explicit_feed_level_opt_in() -> None:
    result = authorize_target(
        _config(allow_subdomains=True),
        TargetRequest("crawl", "https://eu.careers.example.com/jobs"),
    )
    assert result.matched_host == "careers.example.com"


def test_schedule_handles_timezone_overnight_and_both_grace_edges() -> None:
    schedule = _config().schedule
    kolkata = timezone(timedelta(hours=5, minutes=30), name="Asia/Kolkata")
    # Monday 21:56 in Kolkata: four minutes before the configured start.
    early = evaluate_schedule(
        schedule,
        now_ms=_utc_ms("2026-08-17T16:26:00"),
        timezone=kolkata,
    )
    assert early.allowed and early.in_grace
    # Tuesday 01:00 in Kolkata belongs to Monday's overnight window.
    overnight = evaluate_schedule(
        schedule,
        now_ms=_utc_ms("2026-08-17T19:30:00"),
        timezone=kolkata,
    )
    assert overnight.allowed and not overnight.in_grace
    # Tuesday 02:20 remains inside the late grace; 02:31 does not.
    late = evaluate_schedule(
        schedule,
        now_ms=_utc_ms("2026-08-17T20:50:00"),
        timezone=kolkata,
    )
    outside = evaluate_schedule(
        schedule,
        now_ms=_utc_ms("2026-08-17T21:01:00"),
        timezone=kolkata,
    )
    assert late.allowed and late.in_grace
    assert not outside.allowed


def test_config_itself_rejects_non_dns_allowlist_hosts() -> None:
    document = _config().model_dump(mode="python")
    document["allowed_targets"][0]["host"] = "127.0.0.1"
    with pytest.raises(ValidationError):
        FeedSetConfig.model_validate(document)
