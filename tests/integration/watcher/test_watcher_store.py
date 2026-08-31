from __future__ import annotations

import sqlite3
from collections.abc import Callable, Iterator
from dataclasses import replace
from pathlib import Path

import pytest

from gatehouse.config import FeedSetConfig
from gatehouse.credentials import SecretDetectedError, SecretScanner
from gatehouse.database import open_migrated_database, recover_startup
from gatehouse.watcher import (
    MAX_CURSOR_SEQUENCE_ADVANCE,
    RESERVED_LANE,
    BudgetStatus,
    CursorCommitStatus,
    FeedSetLookupError,
    ReservedRouteError,
    RunFence,
    ScanFeedSetResult,
    ScanStatus,
    StaleRunFenceError,
    SummaryMetadataError,
    WatcherService,
    WatcherStore,
)
from gatehouse.watcher.feedsets import FeedSetRegistry


def _config() -> FeedSetConfig:
    return FeedSetConfig.model_validate(
        {
            "schema_version": 1,
            "feed_set": {
                "id": "placements",
                "display_name": "Placements",
                "workspace": "placement-schedule",
            },
            "allowed_targets": [
                {
                    "host": "careers.example.com",
                    "path_regex": r"^/jobs(?:/.*)?$",
                    "operations": ["scrape"],
                }
            ],
            "targets": [{"operation": "scrape", "url": "https://careers.example.com/jobs"}],
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
    connection.execute("UPDATE clients SET unattended = 1 WHERE client_id = 'watcher-client'")
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
                  'ACTIVE', 'CONTROLLED_UNATTENDED_LAUNCH', 'v1',
                  0, 9000000000000, 9000000000000)
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


def test_run_deadline_is_clamped_to_the_session_expiry(database: sqlite3.Connection) -> None:
    service, _ = _service(database)
    now_ms = 1_700_000_000_000
    session_expiry_ms = now_ms + 5_000
    database.execute(
        "UPDATE sessions SET absolute_expires_at_ms = ? WHERE session_id = 'watcher-session'",
        (session_expiry_ms,),
    )

    started = _start(service, now_ms=now_ms)

    assert started.fence is not None
    assert started.fence.expires_at_ms == session_expiry_ms


def test_cursor_commit_is_fenced_versioned_monotonic_and_summary_only(
    database: sqlite3.Connection,
) -> None:
    canary = "FAKE_CANARY_VALUE_123456"
    service, store = _service(database, scanner=SecretScanner(canaries=[canary]))
    started = _start(service)
    assert started.fence is not None
    with pytest.raises(SummaryMetadataError, match="prohibited"):
        store.mark_ready_to_commit(
            started.fence,
            pending_summary={"response_body": "not allowed"},
            now_ms=1_700_000_000_050,
        )
    with pytest.raises(SecretDetectedError):
        store.mark_ready_to_commit(
            started.fence,
            pending_summary={"note": canary},
            now_ms=1_700_000_000_050,
        )
    assert store.mark_ready_to_commit(
        started.fence,
        pending_summary={"changed": 3, "companies": ["Example"]},
        now_ms=1_700_000_000_100,
    )
    committed = store.commit_cursor(
        started.fence,
        expected_version=0,
        cursor_value="cursor-10",
        cursor_sequence=10,
        now_ms=1_700_000_000_200,
    )
    assert committed.status is CursorCommitStatus.COMMITTED
    assert service.get_cursor(feed_set_id="placements", workspace_id="workspace").sequence == 10
    assert service.get_previous_summary(
        feed_set_id="placements",
        workspace_id="workspace",
    ) == {
        "changed": 3,
        "companies": ["Example"],
    }
    with pytest.raises(FeedSetLookupError):
        service.get_cursor(feed_set_id="placements", workspace_id="other-workspace")
    with pytest.raises(FeedSetLookupError):
        service.get_previous_summary(
            feed_set_id="placements",
            workspace_id="other-workspace",
        )

    second = _start(service, now_ms=1_700_000_000_300)
    assert second.fence is not None
    assert store.mark_ready_to_commit(
        second.fence,
        pending_summary={"changed": 4},
        now_ms=1_700_000_000_400,
    )
    stale = store.commit_cursor(
        second.fence,
        expected_version=0,
        cursor_value="cursor-11",
        cursor_sequence=11,
        now_ms=1_700_000_000_500,
    )
    backwards = store.commit_cursor(
        second.fence,
        expected_version=1,
        cursor_value="cursor-9",
        cursor_sequence=9,
        now_ms=1_700_000_000_600,
    )
    excessive_jump = store.commit_cursor(
        second.fence,
        expected_version=1,
        cursor_value="cursor-too-far",
        cursor_sequence=10 + MAX_CURSOR_SEQUENCE_ADVANCE + 1,
        now_ms=1_700_000_000_700,
    )
    with pytest.raises(SecretDetectedError):
        store.commit_cursor(
            second.fence,
            expected_version=1,
            cursor_value=canary,
            cursor_sequence=11,
            now_ms=1_700_000_000_800,
        )
    accepted = store.commit_cursor(
        second.fence,
        expected_version=1,
        cursor_value="cursor-11",
        cursor_sequence=11,
        now_ms=1_700_000_000_900,
    )
    assert stale.status is CursorCommitStatus.STALE_VERSION
    assert backwards.status is CursorCommitStatus.NON_MONOTONIC
    assert excessive_jump.status is CursorCommitStatus.NON_MONOTONIC
    assert accepted.status is CursorCommitStatus.COMMITTED
    assert service.get_previous_summary(
        feed_set_id="placements",
        workspace_id="workspace",
    ) == {"changed": 4}


def test_duration_expiry_releases_run_and_advances_fence_generation(
    database: sqlite3.Connection,
) -> None:
    service, store = _service(database)
    first = _start(service)
    assert first.fence is not None
    with pytest.raises(StaleRunFenceError):
        store.commit_cursor(
            first.fence,
            expected_version=0,
            cursor_value="too-late",
            cursor_sequence=1,
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


def test_recovered_run_blocks_overlap_until_expiry_then_terminalizes(
    database: sqlite3.Connection,
) -> None:
    service, store = _service(database)
    first = _start(service)
    assert first.fence is not None
    recovered_at_ms = 1_700_000_000_100

    report = recover_startup(database, now_ms=recovered_at_ms)
    assert report.watcher_runs_recovering == 1
    database.execute("UPDATE sessions SET state = 'ACTIVE' WHERE session_id = 'watcher-session'")

    overlap = _start(service, now_ms=recovered_at_ms + 1)
    assert overlap.status is ScanStatus.ALREADY_RUNNING
    assert overlap.active_run_id == first.fence.watcher_run_id

    restarted_at_ms = first.fence.expires_at_ms + 1
    second = _start(service, now_ms=restarted_at_ms)
    assert second.status is ScanStatus.STARTED
    assert second.fence is not None
    assert second.fence.generation == first.fence.generation + 1
    assert tuple(
        database.execute(
            """
            SELECT state, completed_at_ms FROM watcher_runs
             WHERE watcher_run_id = ?
            """,
            (first.fence.watcher_run_id,),
        ).fetchone()
    ) == ("TIMED_OUT", restarted_at_ms)
    assert (
        database.execute(
            "SELECT state FROM leases WHERE lease_id = ?",
            (first.fence.lease_id,),
        ).fetchone()[0]
        == "EXPIRED"
    )
    assert (
        store.consume_budget(first.fence, now_ms=restarted_at_ms, requests=1).status
        is BudgetStatus.NOT_RUNNING
    )


def test_start_after_global_recovery_expiry_does_not_wedge(
    database: sqlite3.Connection,
) -> None:
    service, _ = _service(database)
    first = _start(service)
    assert first.fence is not None
    restarted_at_ms = first.fence.expires_at_ms + 1

    recover_startup(database, now_ms=restarted_at_ms)
    database.execute("UPDATE sessions SET state = 'ACTIVE' WHERE session_id = 'watcher-session'")
    second = _start(service, now_ms=restarted_at_ms + 1)

    assert second.status is ScanStatus.STARTED
    assert second.fence is not None
    assert second.fence.generation == first.fence.generation + 1
    assert tuple(
        database.execute(
            """
            SELECT wr.state, l.state
              FROM watcher_runs AS wr JOIN leases AS l ON l.lease_id = wr.lease_id
             WHERE wr.watcher_run_id = ?
            """,
            (first.fence.watcher_run_id,),
        ).fetchone()
    ) == ("EXPIRED", "EXPIRED")


def _forge_cross_feed(fence: RunFence) -> RunFence:
    return replace(fence, feed_set_id="different-feed")


def _forge_cross_session(fence: RunFence) -> RunFence:
    return replace(fence, owner_session_id="different-session")


def _forge_expiry(fence: RunFence) -> RunFence:
    return replace(fence, expires_at_ms=1_700_000_000_001)


@pytest.mark.parametrize(
    "forge",
    (_forge_cross_feed, _forge_cross_session, _forge_expiry),
    ids=("cross-feed", "cross-session", "expiry"),
)
def test_forged_fence_cannot_commit_charge_or_finish(
    database: sqlite3.Connection,
    forge: Callable[[RunFence], RunFence],
) -> None:
    service, store = _service(database)
    started = _start(service)
    assert started.fence is not None
    database.execute(
        """
        INSERT INTO feed_sets(
            feed_set_id, workspace_id, policy_version, state, config_json,
            created_at_ms, updated_at_ms
        ) VALUES ('different-feed', 'workspace', 'v1', 'ACTIVE', '{}', 0, 0)
        """
    )
    forged = forge(started.fence)

    with pytest.raises(StaleRunFenceError):
        store.commit_cursor(
            forged,
            expected_version=0,
            cursor_value="forged-cursor",
            cursor_sequence=1,
            now_ms=1_700_000_000_100,
        )
    assert (
        store.consume_budget(forged, now_ms=1_700_000_000_100, requests=1).status
        is BudgetStatus.STALE_FENCE
    )
    assert not store.finish_run(forged, now_ms=1_700_000_000_100)
    assert tuple(
        database.execute(
            """
            SELECT wr.state, l.state, wr.request_count
              FROM watcher_runs AS wr JOIN leases AS l ON l.lease_id = wr.lease_id
             WHERE wr.watcher_run_id = ?
            """,
            (started.fence.watcher_run_id,),
        ).fetchone()
    ) == ("RUNNING", "ACTIVE", 0)


def test_stale_generation_finish_cannot_time_out_the_live_generation(
    database: sqlite3.Connection,
) -> None:
    service, store = _service(database)
    first = _start(service)
    assert first.fence is not None
    second = _start(service, now_ms=first.fence.expires_at_ms + 1)
    assert second.fence is not None
    stale = replace(second.fence, generation=first.fence.generation)

    assert not store.finish_run(stale, now_ms=first.fence.expires_at_ms + 2)
    assert tuple(
        database.execute(
            """
            SELECT wr.state, l.state
              FROM watcher_runs AS wr JOIN leases AS l ON l.lease_id = wr.lease_id
             WHERE wr.watcher_run_id = ?
            """,
            (second.fence.watcher_run_id,),
        ).fetchone()
    ) == ("RUNNING", "ACTIVE")
    assert (
        store.consume_budget(
            second.fence,
            now_ms=first.fence.expires_at_ms + 2,
            requests=1,
        ).status
        is BudgetStatus.ACCEPTED
    )


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
