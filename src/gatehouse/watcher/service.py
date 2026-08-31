"""Minimal public watcher facade; provider execution lives outside this package."""

from __future__ import annotations

from .feedsets import FeedSetRegistry, authorize_target
from .models import (
    CursorState,
    JsonValue,
    ScanFeedSetResult,
    ScanStatus,
    TargetRequest,
)
from .schedule import evaluate_schedule
from .store import RESERVED_LANE, WatcherStore, credits_to_micros


class WatcherService:
    """Resolve configured feeds and delegate their durable state transitions."""

    def __init__(
        self,
        *,
        registry: FeedSetRegistry,
        store: WatcherStore,
        reserved_pool_id: str,
        reserved_lane: str = RESERVED_LANE,
    ) -> None:
        store.assert_reserved_route(pool_id=reserved_pool_id, lane=reserved_lane)
        self._registry = registry
        self._store = store
        self._reserved_pool_id = reserved_pool_id
        self._reserved_lane = reserved_lane

    def scan_feed_set(
        self,
        *,
        feed_set_id: str,
        session_id: str,
        now_ms: int,
    ) -> ScanFeedSetResult:
        """Start one run using only the ordered targets owned by configuration."""

        config = self._registry.resolve(feed_set_id)
        schedule = evaluate_schedule(config.schedule, now_ms=now_ms)
        if not schedule.allowed:
            return ScanFeedSetResult(
                status=ScanStatus.OUTSIDE_SCHEDULE,
                feed_set=config,
                schedule=schedule,
                targets=(),
            )
        authorized = tuple(
            authorize_target(config, TargetRequest(target.operation, target.url))
            for target in config.targets
        )
        started = self._store.start_run(
            feed_set_id=feed_set_id,
            session_id=session_id,
            now_ms=now_ms,
            maximum_duration_ms=int(config.budgets.maximum_duration),
            maximum_requests=config.budgets.maximum_requests_per_run,
            maximum_credit_micros=credits_to_micros(config.budgets.maximum_credits_per_run),
            maximum_pages=config.crawl.maximum_pages,
            pool_id=self._reserved_pool_id,
            lane=self._reserved_lane,
        )
        return ScanFeedSetResult(
            status=started.status,
            feed_set=config,
            schedule=schedule,
            targets=authorized,
            fence=started.fence,
            active_run_id=started.active_run_id,
        )

    def get_cursor(self, *, feed_set_id: str, workspace_id: str) -> CursorState:
        self._registry.resolve(feed_set_id)
        return self._store.get_cursor(feed_set_id, workspace_id=workspace_id)

    def feed_workspace(self, *, feed_set_id: str) -> str:
        return str(self._registry.resolve(feed_set_id).feed_set.workspace)

    def supports_workspace(self, workspace_name: str) -> bool:
        return self._registry.supports_workspace(workspace_name)

    def provider_capabilities(self, *, feed_set_id: str) -> frozenset[str]:
        config = self._registry.resolve(feed_set_id)
        return frozenset(f"firecrawl.{target.operation}" for target in config.targets)

    def get_previous_summary(
        self,
        *,
        feed_set_id: str,
        workspace_id: str,
    ) -> dict[str, JsonValue] | None:
        self._registry.resolve(feed_set_id)
        return self._store.get_previous_summary(feed_set_id, workspace_id=workspace_id)
