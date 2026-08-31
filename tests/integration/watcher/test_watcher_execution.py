from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from gatehouse.config import FeedSetConfig
from gatehouse.core.clock import FixedUtcClock
from gatehouse.core.errors import ErrorCode, GatehouseError, make_error
from gatehouse.core.ids import ClientId, RootRunId, SessionId, WorkspaceId
from gatehouse.core.states import InvocationState
from gatehouse.database import open_migrated_database
from gatehouse.invocations import InvocationRequest, InvocationResult, InvocationSession
from gatehouse.policy import ClientClass
from gatehouse.scheduler import PriorityClass
from gatehouse.watcher import (
    CursorCommitStatus,
    FeedSetRegistry,
    SynchronousWatcherExecutor,
    WatcherService,
    WatcherStore,
)

_NOW_MS = 1_700_000_000_000


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
                },
                {
                    "host": "jobs.example-ats.com",
                    "path_regex": r"^/company/.*$",
                    "operations": ["map"],
                },
            ],
            "targets": [
                {"operation": "scrape", "url": "https://careers.example.com/jobs"},
                {
                    "operation": "map",
                    "url": "https://jobs.example-ats.com/company/openings",
                    "limit": 1,
                },
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
                "maximum_requests_per_run": 2,
                "maximum_credits_per_run": 2,
                "maximum_duration": "30m",
            },
        }
    )


class RecordingCoordinator:
    def __init__(self, *, fail: bool = False, oversized_result: bool = False) -> None:
        self.fail = fail
        self.oversized_result = oversized_result
        self.calls: list[tuple[InvocationRequest, InvocationSession]] = []

    async def invoke_authenticated(
        self,
        request: InvocationRequest,
        session: InvocationSession,
    ) -> InvocationResult:
        self.calls.append((request, session))
        if self.fail:
            return InvocationResult(
                request_id=request.request_id,
                state=InvocationState.FAILED,
                attempts=1,
                error=make_error(ErrorCode.PROVIDER_UNAVAILABLE, retry_after_seconds=1).detail,
            )
        return InvocationResult(
            request_id=request.request_id,
            state=InvocationState.SUCCEEDED,
            attempts=1,
            data=(
                {"markdown": "x" * 128}
                if self.oversized_result
                else {"operation": request.operation}
            ),
        )


def _runtime(
    tmp_path: Path,
    *,
    fail: bool = False,
    oversized_result: bool = False,
    maximum_result_bytes: int = 2 * 1_024 * 1_024,
) -> tuple[
    sqlite3.Connection,
    SynchronousWatcherExecutor,
    RecordingCoordinator,
    InvocationSession,
]:
    clock = FixedUtcClock(_NOW_MS)
    connection = open_migrated_database(tmp_path / "gatehouse.db")
    client_id = ClientId.new(clock=clock)
    workspace_id = WorkspaceId.new(clock=clock)
    session_id = SessionId.new(clock=clock)
    root_run_id = RootRunId.new(clock=clock)
    connection.execute(
        """
        INSERT INTO clients(
            client_id, display_name, kind, unattended, policy_profile,
            enabled, created_at_ms, updated_at_ms
        ) VALUES (?, 'Watcher', 'system', 1, 'watcher', 1, ?, ?)
        """,
        (str(client_id), _NOW_MS, _NOW_MS),
    )
    connection.execute(
        """
        INSERT INTO workspaces(
            workspace_id, display_name, canonical_root, created_at_ms, updated_at_ms
        ) VALUES (?, 'Workspace', 'E:\\Workspace', ?, ?)
        """,
        (str(workspace_id), _NOW_MS, _NOW_MS),
    )
    connection.execute(
        """
        INSERT INTO sessions(
            session_id, client_id, workspace_id, bootstrap_verifier,
            bootstrap_version, token_epoch, state, identity_assurance,
            policy_version, created_at_ms, reconnect_until_ms, absolute_expires_at_ms
        ) VALUES (?, ?, ?, X'01', 1, 0, 'ACTIVE',
                  'CONTROLLED_UNATTENDED_LAUNCH', 'v1', ?, ?, ?)
        """,
        (
            str(session_id),
            str(client_id),
            str(workspace_id),
            _NOW_MS,
            _NOW_MS + 3_600_000,
            _NOW_MS + 3_600_000,
        ),
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
        ) VALUES ('placements', ?, 'v1', 'ACTIVE', '{}', ?, ?)
        """,
        (str(workspace_id), _NOW_MS, _NOW_MS),
    )
    store = WatcherStore(connection)
    service = WatcherService(
        registry=FeedSetRegistry([_config()]),
        store=store,
        reserved_pool_id="watcher-pool",
    )
    coordinator = RecordingCoordinator(fail=fail, oversized_result=oversized_result)
    executor = SynchronousWatcherExecutor(
        service=service,
        store=store,
        coordinator=coordinator,
        clock=clock,
        maximum_result_bytes=maximum_result_bytes,
    )
    session = InvocationSession(
        session_id=session_id,
        client_id=client_id,
        root_run_id=root_run_id,
        workspace_id=workspace_id,
        client_class=ClientClass.UNATTENDED,
        allowed_capabilities=frozenset({"firecrawl.scrape", "firecrawl.map"}),
        pool_bindings={"firecrawl": "watcher-reserved"},
        request_count_remaining=2,
        credit_budget_remaining_units=2,
        approval_mode="deny_on_ask",
        priority=PriorityClass.SYSTEM_RESERVED,
        feed_set_authorized=True,
        schedule_open=True,
        automatic_pool_selection=False,
    )
    return connection, executor, coordinator, session


@pytest.mark.asyncio
async def test_ordered_scan_persists_pending_summary_and_commit_terminalizes(
    tmp_path: Path,
) -> None:
    connection, executor, coordinator, session = _runtime(tmp_path)

    scanned = await executor.scan(
        feed_set_id="placements",
        expected_cursor=None,
        session=session,
    )

    assert scanned.status == "READY_TO_COMMIT"
    assert [request.operation for request, _ in coordinator.calls] == [
        "firecrawl.scrape",
        "firecrawl.map",
    ]
    assert [request.input_payload["url"] for request, _ in coordinator.calls] == [
        "https://careers.example.com/jobs",
        "https://jobs.example-ats.com/company/openings",
    ]
    assert coordinator.calls[1][0].input_payload["limit"] == 1
    assert all(
        call_session.automatic_pool_selection is False for _, call_session in coordinator.calls
    )
    assert all(call_session.feed_set_authorized for _, call_session in coordinator.calls)
    assert connection.execute("SELECT state FROM watcher_runs").fetchone()[0] == "READY_TO_COMMIT"
    assert connection.execute("SELECT state FROM leases").fetchone()[0] == "ACTIVE"
    assert scanned.watcher_run_id is not None

    committed = executor.commit_cursor(
        feed_set_id="placements",
        watcher_run_id=scanned.watcher_run_id,
        session_id=str(session.session_id),
        expected_version=0,
        cursor_value="cursor-1",
        cursor_sequence=1,
    )

    assert committed.status is CursorCommitStatus.COMMITTED
    assert connection.execute("SELECT state FROM watcher_runs").fetchone()[0] == "COMPLETED"
    assert connection.execute("SELECT state FROM leases").fetchone()[0] == "RELEASED"
    assert executor.get_previous_summary(
        feed_set_id="placements",
        workspace_id=str(session.workspace_id),
    ) == {
        "completed_targets": 2,
        "operations": ["scrape", "map"],
    }
    connection.close()


@pytest.mark.asyncio
async def test_failed_step_releases_run_without_advancing_cursor(tmp_path: Path) -> None:
    connection, executor, coordinator, session = _runtime(tmp_path, fail=True)

    with pytest.raises(GatehouseError) as caught:
        await executor.scan(feed_set_id="placements", expected_cursor=None, session=session)

    assert caught.value.detail.code is ErrorCode.PROVIDER_UNAVAILABLE
    assert len(coordinator.calls) == 1
    assert connection.execute("SELECT state FROM watcher_runs").fetchone()[0] == "FAILED"
    assert connection.execute("SELECT state FROM leases").fetchone()[0] == "RELEASED"
    assert (
        executor.get_cursor(
            feed_set_id="placements",
            workspace_id=str(session.workspace_id),
        ).version
        == 0
    )
    connection.close()


@pytest.mark.asyncio
async def test_cursor_mismatch_dispatches_nothing(tmp_path: Path) -> None:
    connection, executor, coordinator, session = _runtime(tmp_path)

    result = await executor.scan(
        feed_set_id="placements",
        expected_cursor="not-current",
        session=session,
    )

    assert result.status == "CURSOR_MISMATCH"
    assert coordinator.calls == []
    assert connection.execute("SELECT COUNT(*) FROM watcher_runs").fetchone()[0] == 0
    connection.close()


@pytest.mark.asyncio
async def test_oversized_aggregate_result_fails_and_releases_run(tmp_path: Path) -> None:
    connection, executor, coordinator, session = _runtime(
        tmp_path,
        oversized_result=True,
        maximum_result_bytes=64,
    )

    with pytest.raises(GatehouseError) as caught:
        await executor.scan(feed_set_id="placements", expected_cursor=None, session=session)

    assert caught.value.detail.code is ErrorCode.CAPACITY_EXCEEDED
    assert len(coordinator.calls) == 1
    assert connection.execute("SELECT state FROM watcher_runs").fetchone()[0] == "FAILED"
    assert connection.execute("SELECT state FROM leases").fetchone()[0] == "RELEASED"
    connection.close()
