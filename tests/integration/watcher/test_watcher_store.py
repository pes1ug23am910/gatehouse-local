from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from pathlib import Path

import pytest

from gatehouse.config import FeedSetConfig
from gatehouse.credentials import SecretDetectedError, SecretScanner
from gatehouse.database import open_migrated_database
from gatehouse.watcher import (
    RESERVED_LANE,
    BudgetStatus,
    CursorCommitStatus,
    ReservedRouteError,
    ScanFeedSetResult,
    ScanStatus,
    StaleRunFenceError,
    SummaryMetadataError,
    TargetRequest,
    WatcherService,
    WatcherStore,
)
from gatehouse.watcher.feedsets import FeedSetRegistry


def _config() -> FeedSetConfig:
    return FeedSetConfig.model_validate(
        {
            "schema_version": 1,
            "feed_set": {"id": "placements", "display_name": "Placements"},
            "allowed_targets": [
                {
                    "host": "careers.example.com",
                    "path_regex": r"^/jobs(?:/.*)?$",
                    "operations": ["scrape"],
                }
            ],
            "crawl": {
                "maximum_pages": 2,
                "maximum_depth": 1,
                "allow_external_links": False,
                "allow_subdomains": False,
                "ignore_query_parameters": True,
            },
            "schedule": {
                "timezone": "Etc/UTC",
                "windows": [
                    {
                        "days": ["mon", "tue", "wed", "thu", "fri", "sat", "sun"],
                        "start": "00:00",
                        "end": "23:59",
                    }
                ],
                "early_start_grace": "1m",
                "late_start_grace": "1m",
            },
            "budgets": {
                "maximum_requests_per_run": 3,
                "maximum_credits_per_run": 2.0,
                "maximum_duration": "30m",
            },
        }
    )


@pytest.fixture
def database(tmp_path: Path) -> Iterator[sqlite3.Connection]:
    connection = open_migrated_database(tmp_path / "gatehouse.db")
    connection.execute(
        """
        INSERT INTO clients(
            client_id, display_name, kind, policy_profile, created_at_ms, updated_at_ms
        ) VALUES ('watcher-client', 'Watcher', 'system', 'watcher', 0, 0)
        """
    )
    connection.execute(
        """
        INSERT INTO workspaces(
            workspace_id, display_name, canonical_root, created_at_ms, updated_at_ms
        ) VALUES ('workspace', 'Workspace', 'E:\\Workspace', 0, 0)
        """
    )
    connection.execute(
        """
        INSERT INTO sessions(
            session_id, client_id, workspace_id, bootstrap_verifier,
            bootstrap_version, token_epoch, state, identity_assurance,
            policy_version, created_at_ms, reconnect_until_ms, absolute_expires_at_ms
        ) VALUES ('watcher-session', 'watcher-client', 'workspace', X'01', 1, 0,
                  'ACTIVE', 'LOCAL_SYSTEM', 'v1', 0, 9000000000000, 9000000000000)
        """
    )
    connection.execute(
        """
        INSERT INTO pools(
            pool_id, service_id, alias, state, selection_strategy, automatic_use
        ) VALUES ('watcher-pool', 'firecrawl', 'watcher-reserved', 'ACTIVE', 'pinned', 0)
        """
    )
    connection.execute(
        """
        INSERT INTO feed_sets(
            feed_set_id, workspace_id, policy_version, state, config_json,
            created_at_ms, updated_at_ms
        ) VALUES ('placements', 'workspace', 'v1', 'ACTIVE', '{}', 0, 0)
        """
    )
    yield connection
    connection.close()


def _service(
    connection: sqlite3.Connection,
    *,
    scanner: SecretScanner | None = None,
) -> tuple[WatcherService, WatcherStore]:
    store = WatcherStore(connection, scanner=scanner)
    service = WatcherService(
        registry=FeedSetRegistry([_config()]),
        store=store,
        reserved_pool_id="watcher-pool",
    )
    return service, store


def _start(
    service: WatcherService,
    *,
    now_ms: int = 1_700_000_000_000,
) -> ScanFeedSetResult:
    return service.scan_feed_set(
        feed_set_id="placements",
        session_id="watcher-session",
        targets=[TargetRequest("scrape", "https://careers.example.com/jobs")],
        now_ms=now_ms,
    )


def test_one_active_run_is_an_immediate_noop_and_budget_updates_are_atomic(
    database: sqlite3.Connection,
) -> None:
    service, store = _service(database)
    first = _start(service)
    contender = _start(service, now_ms=1_700_000_000_001)
    assert first.status is ScanStatus.STARTED
    assert first.fence is not None
    assert contender.status is ScanStatus.ALREADY_RUNNING
    assert contender.active_run_id == first.fence.watcher_run_id
    assert database.execute("SELECT COUNT(*) FROM watcher_runs").fetchone()[0] == 1

    accepted = store.consume_budget(
        first.fence,
        now_ms=1_700_000_000_100,
        requests=3,
        credit_micros=2_000_000,
        pages=2,
    )
    rejected = store.consume_budget(
        first.fence,
        now_ms=1_700_000_000_200,
        requests=1,
    )
    assert accepted.status is BudgetStatus.ACCEPTED
    assert rejected.status is BudgetStatus.REQUEST_LIMIT
    assert rejected.usage == accepted.usage
    stored = database.execute(
        "SELECT request_count, consumed_cost_units FROM watcher_runs"
    ).fetchone()
    assert tuple(stored) == (3, 2_000_000)

    wrong_generation = first.fence.__class__(
        watcher_run_id=first.fence.watcher_run_id,
        lease_id=first.fence.lease_id,
        generation=first.fence.generation + 1,
        feed_set_id=first.fence.feed_set_id,
        owner_session_id=first.fence.owner_session_id,
        expires_at_ms=first.fence.expires_at_ms,
    )
    assert (
        store.consume_budget(wrong_generation, now_ms=1_700_000_000_300, pages=1).status
        is BudgetStatus.STALE_FENCE
    )


def test_cursor_commit_is_fenced_versioned_monotonic_and_summary_only(
    database: sqlite3.Connection,
) -> None:
    canary = "FAKE_CANARY_VALUE_123456"
    service, store = _service(database, scanner=SecretScanner(canaries=[canary]))
    started = _start(service)
    assert started.fence is not None

    committed = service.commit_cursor(
        fence=started.fence,
        expected_version=0,
        cursor_value="cursor-10",
        cursor_sequence=10,
        previous_summary={"changed": 3, "companies": ["Example"]},
        now_ms=1_700_000_000_100,
    )
    stale = service.commit_cursor(
        fence=started.fence,
        expected_version=0,
        cursor_value="cursor-11",
        cursor_sequence=11,
        previous_summary={"changed": 4},
        now_ms=1_700_000_000_200,
    )
    backwards = service.commit_cursor(
        fence=started.fence,
        expected_version=1,
        cursor_value="cursor-9",
        cursor_sequence=9,
        previous_summary={"changed": 1},
        now_ms=1_700_000_000_300,
    )
    assert committed.status is CursorCommitStatus.COMMITTED
    assert stale.status is CursorCommitStatus.STALE_VERSION
    assert backwards.status is CursorCommitStatus.NON_MONOTONIC
    assert service.get_cursor(feed_set_id="placements").sequence == 10
    assert service.get_previous_summary(feed_set_id="placements") == {
        "changed": 3,
        "companies": ["Example"],
    }
    with pytest.raises(SummaryMetadataError, match="prohibited"):
        service.commit_cursor(
            fence=started.fence,
            expected_version=1,
            cursor_value="cursor-12",
            cursor_sequence=12,
            previous_summary={"response_body": "not allowed"},
            now_ms=1_700_000_000_400,
        )
    with pytest.raises(SecretDetectedError):
        service.commit_cursor(
            fence=started.fence,
            expected_version=1,
            cursor_value="cursor-12",
            cursor_sequence=12,
            previous_summary={"note": canary},
            now_ms=1_700_000_000_400,
        )

    assert store.finish_run(started.fence, now_ms=1_700_000_000_500)
    with pytest.raises(StaleRunFenceError):
        service.commit_cursor(
            fence=started.fence,
            expected_version=1,
            cursor_value="cursor-12",
            cursor_sequence=12,
            previous_summary={"changed": 0},
            now_ms=1_700_000_000_600,
        )


def test_duration_expiry_releases_run_and_advances_fence_generation(
    database: sqlite3.Connection,
) -> None:
    service, store = _service(database)
    first = _start(service)
    assert first.fence is not None
    with pytest.raises(StaleRunFenceError):
        service.commit_cursor(
            fence=first.fence,
            expected_version=0,
            cursor_value="too-late",
            cursor_sequence=1,
            previous_summary={"changed": 0},
            now_ms=first.fence.expires_at_ms,
        )
    expired = store.consume_budget(
        first.fence,
        now_ms=first.fence.expires_at_ms,
        requests=1,
    )
    assert expired.status is BudgetStatus.DURATION_EXCEEDED
    second = _start(service, now_ms=first.fence.expires_at_ms + 1)
    assert second.status is ScanStatus.STARTED
    assert second.fence is not None
    assert second.fence.generation == first.fence.generation + 1


def test_reserved_route_assertions_fail_closed(database: sqlite3.Connection) -> None:
    store = WatcherStore(database)
    with pytest.raises(ReservedRouteError):
        WatcherService(
            registry=FeedSetRegistry([_config()]),
            store=store,
            reserved_pool_id="watcher-pool",
            reserved_lane="INTERACTIVE",
        )
    database.execute("UPDATE pools SET automatic_use = 1 WHERE pool_id = 'watcher-pool'")
    with pytest.raises(ReservedRouteError):
        WatcherService(
            registry=FeedSetRegistry([_config()]),
            store=store,
            reserved_pool_id="watcher-pool",
            reserved_lane=RESERVED_LANE,
        )
