"""Synchronous, server-owned watcher execution through the invocation coordinator."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

from gatehouse.config import FeedSetConfig
from gatehouse.core.clock import SYSTEM_UTC_CLOCK, UtcMsClock, require_utc_ms
from gatehouse.core.errors import ErrorCode, GatehouseError, JsonValue, make_error
from gatehouse.core.ids import RequestId
from gatehouse.core.states import InvocationState
from gatehouse.invocations import InvocationRequest, InvocationResult, InvocationSession

from .models import BudgetStatus, CursorCommitResult, CursorState, RunFence, ScanStatus
from .models import JsonValue as WatcherJsonValue
from .service import WatcherService
from .store import CREDIT_MICROS_PER_CREDIT, WatcherStore

_MAXIMUM_RESULT_BYTES = 2 * 1_024 * 1_024


class _Coordinator(Protocol):
    async def invoke_authenticated(
        self,
        request: InvocationRequest,
        session: InvocationSession,
    ) -> InvocationResult: ...


@dataclass(frozen=True, slots=True)
class WatcherStepResult:
    ordinal: int
    request_id: str
    operation: str
    url: str
    data: object


@dataclass(frozen=True, slots=True)
class WatcherExecutionResult:
    status: str
    feed_set_id: str
    cursor: CursorState
    schedule_window_end_ms: int | None
    watcher_run_id: str | None = None
    active_run_id: str | None = None
    results: tuple[WatcherStepResult, ...] = ()


class SynchronousWatcherExecutor:
    """Execute one configured scrape/map sequence without granting caller provider tools."""

    def __init__(
        self,
        *,
        service: WatcherService,
        store: WatcherStore,
        coordinator: _Coordinator,
        clock: UtcMsClock = SYSTEM_UTC_CLOCK,
        request_id_factory: Callable[[], RequestId] | None = None,
        queue_wait_ms: int = 15_000,
        maximum_execution_seconds: float = 30.0,
        maximum_result_bytes: int = _MAXIMUM_RESULT_BYTES,
    ) -> None:
        if not 1 <= queue_wait_ms <= 60_000:
            raise ValueError("watcher queue wait is outside its bound")
        if not 1 <= maximum_execution_seconds <= 30:
            raise ValueError("watcher execution timeout is outside its bound")
        if not 1 <= maximum_result_bytes <= _MAXIMUM_RESULT_BYTES:
            raise ValueError("watcher result capacity is outside its bound")
        self._service = service
        self._store = store
        self._coordinator = coordinator
        self._clock = clock
        self._request_id_factory = request_id_factory or (lambda: RequestId.new(clock=clock))
        self._queue_wait_ms = queue_wait_ms
        self._maximum_execution_seconds = maximum_execution_seconds
        self._maximum_result_bytes = maximum_result_bytes

    async def scan(
        self,
        *,
        feed_set_id: str,
        expected_cursor: str | None,
        session: InvocationSession,
    ) -> WatcherExecutionResult:
        current_cursor = self._service.get_cursor(
            feed_set_id=feed_set_id,
            workspace_id=str(session.workspace_id),
        )
        if expected_cursor is not None and expected_cursor != current_cursor.cursor_value:
            return WatcherExecutionResult(
                status="CURSOR_MISMATCH",
                feed_set_id=feed_set_id,
                cursor=current_cursor,
                schedule_window_end_ms=None,
            )

        started = self._service.scan_feed_set(
            feed_set_id=feed_set_id,
            session_id=str(session.session_id),
            now_ms=self._clock.now_ms(),
        )
        if started.status is not ScanStatus.STARTED:
            return WatcherExecutionResult(
                status=started.status.value,
                feed_set_id=feed_set_id,
                cursor=current_cursor,
                schedule_window_end_ms=started.schedule.window_end_ms,
                active_run_id=started.active_run_id,
            )
        fence = started.fence
        if fence is None:  # pragma: no cover - ScanFeedSetResult enforces this contract
            raise RuntimeError("started watcher run omitted its fence")

        results: list[WatcherStepResult] = []
        result_bytes = 0
        execution_deadline = asyncio.get_running_loop().time() + self._maximum_execution_seconds
        try:
            for ordinal, target in enumerate(started.targets, start=1):
                remaining_seconds = execution_deadline - asyncio.get_running_loop().time()
                if remaining_seconds <= 0:
                    raise TimeoutError
                now_ms = self._clock.now_ms()
                charged = self._store.consume_budget(
                    fence,
                    now_ms=now_ms,
                    requests=1,
                    credit_micros=CREDIT_MICROS_PER_CREDIT,
                    pages=1,
                )
                if charged.status is not BudgetStatus.ACCEPTED:
                    if charged.status is BudgetStatus.DURATION_EXCEEDED:
                        raise make_error(ErrorCode.PROVIDER_TIMEOUT, retryable=False)
                    if charged.status in {BudgetStatus.NOT_RUNNING, BudgetStatus.STALE_FENCE}:
                        raise make_error(ErrorCode.DAEMON_DEGRADED, retry_after_seconds=1)
                    self._store.finish_run(
                        fence,
                        now_ms=self._clock.now_ms(),
                        state="BUDGET_EXHAUSTED",
                    )
                    raise make_error(ErrorCode.BUDGET_EXHAUSTED, retryable=False)

                request_id = self._request_id_factory()
                queue_deadline_ms = require_utc_ms(
                    min(fence.expires_at_ms, self._clock.now_ms() + self._queue_wait_ms)
                )
                async with asyncio.timeout(remaining_seconds):
                    result = await self._coordinator.invoke_authenticated(
                        InvocationRequest(
                            request_id=request_id,
                            access_token=None,
                            root_run_id=session.root_run_id,
                            service_id="firecrawl",
                            operation=f"firecrawl.{target.operation}",
                            input_payload=self._provider_payload(
                                started.feed_set,
                                target.operation,
                                target.normalized_url,
                                ordinal,
                            ),
                            purpose="opening_monitoring",
                            data_classifications=frozenset({"public_job_data"}),
                            queue_deadline_ms=queue_deadline_ms,
                        ),
                        session,
                    )
                if result.request_id != request_id:
                    self._store.finish_run(
                        fence,
                        now_ms=self._clock.now_ms(),
                        state="FAILED",
                    )
                    raise make_error(ErrorCode.DAEMON_DEGRADED, retry_after_seconds=1)
                if result.error is not None or result.state is not InvocationState.SUCCEEDED:
                    terminal_state = (
                        "UNKNOWN"
                        if result.state is InvocationState.UNKNOWN
                        or (
                            result.error is not None
                            and result.error.code is ErrorCode.UNCERTAIN_OUTCOME
                        )
                        else "FAILED"
                    )
                    self._store.finish_run(
                        fence,
                        now_ms=self._clock.now_ms(),
                        state=terminal_state,
                    )
                    if result.error is not None:
                        raise GatehouseError(result.error)
                    raise make_error(ErrorCode.DAEMON_DEGRADED, retry_after_seconds=1)
                try:
                    encoded_result = json.dumps(
                        result.data,
                        allow_nan=False,
                        ensure_ascii=True,
                        separators=(",", ":"),
                    ).encode("utf-8")
                except (TypeError, ValueError):
                    raise make_error(ErrorCode.DAEMON_DEGRADED, retryable=False) from None
                result_bytes += len(encoded_result)
                if result_bytes > self._maximum_result_bytes:
                    raise make_error(ErrorCode.CAPACITY_EXCEEDED, retryable=False)
                safe_result: object = json.loads(encoded_result)
                results.append(
                    WatcherStepResult(
                        ordinal=ordinal,
                        request_id=str(request_id),
                        operation=target.operation,
                        url=target.normalized_url,
                        data=safe_result,
                    )
                )
            pending_summary: dict[str, object] = {
                "completed_targets": len(results),
                "operations": [item.operation for item in results],
            }
            if not self._store.mark_ready_to_commit(
                fence,
                pending_summary=pending_summary,
                now_ms=self._clock.now_ms(),
            ):
                raise make_error(ErrorCode.DAEMON_DEGRADED, retry_after_seconds=1)
        except asyncio.CancelledError:
            self._finish_if_current(fence, state="CANCELLED")
            raise
        except TimeoutError:
            self._finish_if_current(fence, state="FAILED")
            raise make_error(ErrorCode.PROVIDER_TIMEOUT, retryable=False) from None
        except GatehouseError:
            self._finish_if_current(fence, state="FAILED")
            raise
        except Exception as error:
            self._finish_if_current(fence, state="FAILED")
            error.args = ()
            raise make_error(ErrorCode.DAEMON_DEGRADED, retry_after_seconds=1) from None

        return WatcherExecutionResult(
            status="READY_TO_COMMIT",
            feed_set_id=feed_set_id,
            cursor=current_cursor,
            schedule_window_end_ms=started.schedule.window_end_ms,
            watcher_run_id=fence.watcher_run_id,
            results=tuple(results),
        )

    def _finish_if_current(self, fence: RunFence, *, state: str) -> None:
        try:
            self._store.finish_run(fence, now_ms=self._clock.now_ms(), state=state)
        except Exception:
            return

    def get_cursor(self, *, feed_set_id: str, workspace_id: str) -> CursorState:
        return self._service.get_cursor(feed_set_id=feed_set_id, workspace_id=workspace_id)

    def feed_workspace(self, *, feed_set_id: str) -> str:
        return self._service.feed_workspace(feed_set_id=feed_set_id)

    def supports_workspace(self, workspace_name: str) -> bool:
        return self._service.supports_workspace(workspace_name)

    def provider_capabilities(self, *, feed_set_id: str) -> frozenset[str]:
        return self._service.provider_capabilities(feed_set_id=feed_set_id)

    def get_previous_summary(
        self,
        *,
        feed_set_id: str,
        workspace_id: str,
    ) -> dict[str, WatcherJsonValue] | None:
        return self._service.get_previous_summary(
            feed_set_id=feed_set_id,
            workspace_id=workspace_id,
        )

    def commit_cursor(
        self,
        *,
        feed_set_id: str,
        watcher_run_id: str,
        session_id: str,
        expected_version: int,
        cursor_value: str,
        cursor_sequence: int,
    ) -> CursorCommitResult:
        now_ms = self._clock.now_ms()
        fence = self._store.resolve_active_fence(
            feed_set_id=feed_set_id,
            watcher_run_id=watcher_run_id,
            session_id=session_id,
            now_ms=now_ms,
            require_ready=True,
        )
        return self._store.commit_cursor(
            fence,
            expected_version=expected_version,
            cursor_value=cursor_value,
            cursor_sequence=cursor_sequence,
            now_ms=now_ms,
        )

    @staticmethod
    def _provider_payload(
        feed: FeedSetConfig,
        operation: str,
        url: str,
        ordinal: int,
    ) -> dict[str, JsonValue]:
        if operation == "scrape":
            return {
                "url": url,
                "formats": ["markdown"],
                "only_main_content": True,
                "timeout_ms": 30_000,
                "purpose": "opening_monitoring",
                "data_classification": ["public_job_data"],
            }
        if operation == "map":
            maximum_pages = getattr(getattr(feed, "crawl", None), "maximum_pages", None)
            if isinstance(maximum_pages, bool) or not isinstance(maximum_pages, int):
                raise TypeError("watcher map result bound is unavailable")
            targets = getattr(feed, "targets", ())
            configured_target = targets[ordinal - 1]
            configured_limit = getattr(configured_target, "limit", None)
            limit = min(100, maximum_pages) if configured_limit is None else configured_limit
            return {
                "url": url,
                "search": None,
                "limit": limit,
                "sitemap": "include",
                "purpose": "opening_monitoring",
                "data_classification": ["public_job_data"],
            }
        raise ValueError("watcher execution supports only scrape and map")
