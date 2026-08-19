"""Transactional persistence for watcher leases, budgets, and cursors."""

from __future__ import annotations

import json
import math
import sqlite3
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from decimal import ROUND_FLOOR, Decimal

from gatehouse.credentials import SecretScanner
from gatehouse.database import transaction

from .models import (
    BudgetChargeResult,
    BudgetStatus,
    BudgetUsage,
    CursorCommitResult,
    CursorCommitStatus,
    CursorState,
    JsonValue,
    RunFence,
    ScanStatus,
)

CREDIT_MICROS_PER_CREDIT = 1_000_000
RESERVED_LANE = "SYSTEM_RESERVED"
RESERVED_POOL_ALIAS = "watcher-reserved"
_LEASE_TYPE = "WATCHER_FEED_SET"
_MAX_CURSOR_BYTES = 4_096
_MAX_SUMMARY_BYTES = 16_384
_MAX_SUMMARY_DEPTH = 6
_MAX_SUMMARY_ITEMS = 256
_SENSITIVE_SUMMARY_KEYS = frozenset(
    {
        "authorization",
        "body",
        "content",
        "credential",
        "document",
        "documents",
        "headers",
        "html",
        "page_content",
        "payload",
        "raw",
        "raw_content",
        "request",
        "request_body",
        "response",
        "response_body",
        "secret",
        "token",
    }
)


class WatcherPersistenceError(RuntimeError):
    """Base class for watcher persistence invariant failures."""


class ReservedRouteError(WatcherPersistenceError):
    """Raised when a watcher is not pinned to its isolated pool and lane."""


class SummaryMetadataError(ValueError):
    """Raised when previous-summary metadata is unsafe or unbounded."""


class StaleRunFenceError(WatcherPersistenceError):
    """Raised when an expired or superseded watcher attempts a durable commit."""


@dataclass(frozen=True, slots=True)
class StartRunResult:
    status: ScanStatus
    fence: RunFence | None
    active_run_id: str | None


def credits_to_micros(credits: int | float | Decimal) -> int:
    """Convert a configured/provider credit quantity to conservative fixed units."""

    if isinstance(credits, bool):
        raise TypeError("credits must be numeric")
    value = Decimal(str(credits))
    if not value.is_finite() or value < 0:
        raise ValueError("credits must be finite and non-negative")
    micros = int((value * CREDIT_MICROS_PER_CREDIT).to_integral_value(ROUND_FLOOR))
    if value > 0 and micros == 0:
        raise ValueError("credit quantity is below the supported precision")
    return micros


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex}"


def _json(value: Mapping[str, JsonValue]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _mapping_from_json(raw: str) -> dict[str, JsonValue]:
    parsed: object = json.loads(raw)
    if not isinstance(parsed, dict) or any(not isinstance(key, str) for key in parsed):
        raise WatcherPersistenceError("watcher metadata is not a JSON object")
    source: dict[str, object] = {str(key): item for key, item in parsed.items()}
    return _normalize_json_mapping(source, enforce_summary_keys=False)


def _normalize_json_value(
    value: object,
    *,
    depth: int,
    item_budget: list[int],
    enforce_summary_keys: bool,
) -> JsonValue:
    if depth > _MAX_SUMMARY_DEPTH:
        raise SummaryMetadataError("summary metadata nesting is too deep")
    item_budget[0] += 1
    if item_budget[0] > _MAX_SUMMARY_ITEMS:
        raise SummaryMetadataError("summary metadata contains too many items")
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise SummaryMetadataError("summary metadata contains a non-finite number")
        return value
    if isinstance(value, Mapping):
        normalized: dict[str, JsonValue] = {}
        for raw_key, item in value.items():
            if not isinstance(raw_key, str):
                raise SummaryMetadataError("summary metadata keys must be strings")
            if enforce_summary_keys and raw_key.casefold() in _SENSITIVE_SUMMARY_KEYS:
                raise SummaryMetadataError("summary metadata contains a prohibited field")
            normalized[raw_key] = _normalize_json_value(
                item,
                depth=depth + 1,
                item_budget=item_budget,
                enforce_summary_keys=enforce_summary_keys,
            )
        return normalized
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [
            _normalize_json_value(
                item,
                depth=depth + 1,
                item_budget=item_budget,
                enforce_summary_keys=enforce_summary_keys,
            )
            for item in value
        ]
    raise SummaryMetadataError("summary metadata must be JSON-compatible")


def _normalize_json_mapping(
    value: Mapping[str, object],
    *,
    enforce_summary_keys: bool,
) -> dict[str, JsonValue]:
    normalized = _normalize_json_value(
        value,
        depth=0,
        item_budget=[0],
        enforce_summary_keys=enforce_summary_keys,
    )
    if not isinstance(normalized, dict):  # pragma: no cover - mapping input guarantees this
        raise SummaryMetadataError("summary metadata must be an object")
    return normalized


def _metadata_int(
    value: Mapping[str, JsonValue],
    key: str,
    *,
    default: int | None = None,
) -> int:
    raw = value.get(key, default)
    if isinstance(raw, bool) or not isinstance(raw, int):
        raise WatcherPersistenceError("watcher integer metadata is malformed")
    return raw


def normalize_summary(
    value: Mapping[str, object],
    *,
    scanner: SecretScanner,
) -> dict[str, JsonValue]:
    normalized = _normalize_json_mapping(value, enforce_summary_keys=True)
    encoded = _json(normalized)
    if len(encoded.encode("utf-8")) > _MAX_SUMMARY_BYTES:
        raise SummaryMetadataError("summary metadata exceeds the size limit")
    scanner.assert_clean(encoded, location="watcher.previous_summary")
    return normalized


class WatcherStore:
    """Own watcher state transitions that require a short SQLite transaction."""

    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        scanner: SecretScanner | None = None,
    ) -> None:
        self.connection = connection
        self._scanner = scanner or SecretScanner()

    def assert_reserved_route(
        self,
        *,
        pool_id: str,
        lane: str,
        expected_pool_alias: str = RESERVED_POOL_ALIAS,
    ) -> None:
        if lane != RESERVED_LANE:
            raise ReservedRouteError("watcher must use the reserved system lane")
        row = self.connection.execute(
            "SELECT alias, state, automatic_use FROM pools WHERE pool_id = ?",
            (pool_id,),
        ).fetchone()
        if (
            row is None
            or str(row["alias"]) != expected_pool_alias
            or str(row["state"]) != "ACTIVE"
            or int(row["automatic_use"]) != 0
        ):
            raise ReservedRouteError("watcher pool is missing, inactive, or not isolated")

    def start_run(
        self,
        *,
        feed_set_id: str,
        session_id: str,
        now_ms: int,
        maximum_duration_ms: int,
        maximum_requests: int,
        maximum_credit_micros: int,
        maximum_pages: int,
        pool_id: str,
        lane: str,
    ) -> StartRunResult:
        if min(maximum_duration_ms, maximum_requests, maximum_credit_micros, maximum_pages) <= 0:
            raise ValueError("watcher limits must be positive")
        maximum_runtime_at_ms = now_ms + maximum_duration_ms
        watcher_run_id = _new_id("watch")
        lease_id = _new_id("lease")
        with transaction(self.connection, "IMMEDIATE"):
            feed = self.connection.execute(
                "SELECT state FROM feed_sets WHERE feed_set_id = ?",
                (feed_set_id,),
            ).fetchone()
            if feed is None or str(feed["state"]) != "ACTIVE":
                raise WatcherPersistenceError("feed set is not active")
            session = self.connection.execute(
                "SELECT state, absolute_expires_at_ms FROM sessions WHERE session_id = ?",
                (session_id,),
            ).fetchone()
            if (
                session is None
                or str(session["state"]) != "ACTIVE"
                or int(session["absolute_expires_at_ms"]) <= now_ms
            ):
                raise WatcherPersistenceError("watcher session is not active")

            expired = self.connection.execute(
                """
                SELECT lease_id FROM leases
                 WHERE lease_type = ? AND lease_key = ? AND state = 'ACTIVE'
                   AND expires_at_ms <= ?
                """,
                (_LEASE_TYPE, feed_set_id, now_ms),
            ).fetchall()
            for row in expired:
                expired_lease_id = str(row["lease_id"])
                self.connection.execute(
                    """
                    UPDATE leases SET state = 'EXPIRED', released_at_ms = ?, heartbeat_at_ms = ?
                     WHERE lease_id = ? AND state = 'ACTIVE'
                    """,
                    (now_ms, now_ms, expired_lease_id),
                )
                self.connection.execute(
                    """
                    UPDATE watcher_runs SET state = 'TIMED_OUT', completed_at_ms = ?
                     WHERE lease_id = ? AND state = 'RUNNING'
                    """,
                    (now_ms, expired_lease_id),
                )

            active = self.connection.execute(
                """
                SELECT owner_id FROM leases
                 WHERE lease_type = ? AND lease_key = ? AND state = 'ACTIVE'
                """,
                (_LEASE_TYPE, feed_set_id),
            ).fetchone()
            if active is not None:
                return StartRunResult(
                    status=ScanStatus.ALREADY_RUNNING,
                    fence=None,
                    active_run_id=str(active["owner_id"]),
                )

            generation = int(
                self.connection.execute(
                    """
                    SELECT COALESCE(MAX(generation), 0) + 1 FROM leases
                     WHERE lease_type = ? AND lease_key = ?
                    """,
                    (_LEASE_TYPE, feed_set_id),
                ).fetchone()[0]
            )
            lease_metadata: dict[str, JsonValue] = {
                "watcher_run_id": watcher_run_id,
                "pool_id": pool_id,
                "lane": lane,
            }
            self.connection.execute(
                """
                INSERT INTO leases(
                    lease_id, lease_type, lease_key, owner_id, state, generation,
                    acquired_at_ms, heartbeat_at_ms, expires_at_ms, metadata_json
                ) VALUES (?, ?, ?, ?, 'ACTIVE', ?, ?, ?, ?, ?)
                """,
                (
                    lease_id,
                    _LEASE_TYPE,
                    feed_set_id,
                    watcher_run_id,
                    generation,
                    now_ms,
                    now_ms,
                    maximum_runtime_at_ms,
                    _json(lease_metadata),
                ),
            )
            run_metadata: dict[str, JsonValue] = {
                "budget": {
                    "maximum_requests": maximum_requests,
                    "maximum_credit_micros": maximum_credit_micros,
                    "maximum_pages": maximum_pages,
                },
                "usage": {"pages": 0},
                "route": {"pool_id": pool_id, "lane": lane},
            }
            self.connection.execute(
                """
                INSERT INTO watcher_runs(
                    watcher_run_id, session_id, feed_set_id, lease_id, state,
                    started_at_ms, heartbeat_at_ms, maximum_runtime_at_ms,
                    request_count, consumed_cost_units, cost_unit, metadata_json
                ) VALUES (?, ?, ?, ?, 'RUNNING', ?, ?, ?, 0, 0, 'credit_micro', ?)
                """,
                (
                    watcher_run_id,
                    session_id,
                    feed_set_id,
                    lease_id,
                    now_ms,
                    now_ms,
                    maximum_runtime_at_ms,
                    _json(run_metadata),
                ),
            )
        return StartRunResult(
            status=ScanStatus.STARTED,
            fence=RunFence(
                watcher_run_id=watcher_run_id,
                lease_id=lease_id,
                generation=generation,
                feed_set_id=feed_set_id,
                owner_session_id=session_id,
                expires_at_ms=maximum_runtime_at_ms,
            ),
            active_run_id=None,
        )

    def consume_budget(
        self,
        fence: RunFence,
        *,
        now_ms: int,
        requests: int = 0,
        credit_micros: int = 0,
        pages: int = 0,
    ) -> BudgetChargeResult:
        if min(requests, credit_micros, pages) < 0:
            raise ValueError("budget charges must be non-negative")
        if requests == credit_micros == pages == 0:
            raise ValueError("at least one budget dimension must be charged")
        with transaction(self.connection, "IMMEDIATE"):
            row = self.connection.execute(
                """
                SELECT wr.state, wr.maximum_runtime_at_ms, wr.request_count,
                       wr.consumed_cost_units, wr.metadata_json,
                       l.state AS lease_state, l.generation, l.owner_id, l.expires_at_ms
                  FROM watcher_runs AS wr
                  JOIN leases AS l ON l.lease_id = wr.lease_id
                 WHERE wr.watcher_run_id = ? AND wr.lease_id = ?
                """,
                (fence.watcher_run_id, fence.lease_id),
            ).fetchone()
            if row is None or str(row["state"]) != "RUNNING":
                return BudgetChargeResult(BudgetStatus.NOT_RUNNING, BudgetUsage(0, 0, 0))
            metadata = _mapping_from_json(str(row["metadata_json"]))
            usage_value = metadata.get("usage")
            budget_value = metadata.get("budget")
            if not isinstance(usage_value, dict) or not isinstance(budget_value, dict):
                raise WatcherPersistenceError("watcher budget metadata is malformed")
            current_usage = BudgetUsage(
                requests=int(row["request_count"]),
                credit_micros=int(row["consumed_cost_units"]),
                pages=_metadata_int(usage_value, "pages", default=0),
            )
            fenced = (
                str(row["lease_state"]) == "ACTIVE"
                and int(row["generation"]) == fence.generation
                and str(row["owner_id"]) == fence.watcher_run_id
            )
            if not fenced:
                return BudgetChargeResult(BudgetStatus.STALE_FENCE, current_usage)
            if now_ms >= int(row["maximum_runtime_at_ms"]) or now_ms >= int(row["expires_at_ms"]):
                self._expire_run_locked(fence, now_ms=now_ms)
                return BudgetChargeResult(BudgetStatus.DURATION_EXCEEDED, current_usage)

            proposed = BudgetUsage(
                requests=current_usage.requests + requests,
                credit_micros=current_usage.credit_micros + credit_micros,
                pages=current_usage.pages + pages,
            )
            maximum_requests = _metadata_int(budget_value, "maximum_requests")
            maximum_credit_micros = _metadata_int(budget_value, "maximum_credit_micros")
            maximum_pages = _metadata_int(budget_value, "maximum_pages")
            if proposed.requests > maximum_requests:
                return BudgetChargeResult(BudgetStatus.REQUEST_LIMIT, current_usage)
            if proposed.credit_micros > maximum_credit_micros:
                return BudgetChargeResult(BudgetStatus.CREDIT_LIMIT, current_usage)
            if proposed.pages > maximum_pages:
                return BudgetChargeResult(BudgetStatus.PAGE_LIMIT, current_usage)
            usage_value["pages"] = proposed.pages
            self.connection.execute(
                """
                UPDATE watcher_runs
                   SET request_count = ?, consumed_cost_units = ?, heartbeat_at_ms = ?,
                       metadata_json = ?
                 WHERE watcher_run_id = ? AND state = 'RUNNING'
                """,
                (
                    proposed.requests,
                    proposed.credit_micros,
                    now_ms,
                    _json(metadata),
                    fence.watcher_run_id,
                ),
            )
            self.connection.execute(
                "UPDATE leases SET heartbeat_at_ms = ? WHERE lease_id = ? AND state = 'ACTIVE'",
                (now_ms, fence.lease_id),
            )
            return BudgetChargeResult(BudgetStatus.ACCEPTED, proposed)

    def finish_run(self, fence: RunFence, *, now_ms: int, state: str = "COMPLETED") -> bool:
        if state not in {"COMPLETED", "FAILED", "BUDGET_EXHAUSTED"}:
            raise ValueError("invalid terminal watcher state")
        with transaction(self.connection, "IMMEDIATE"):
            if not self._is_current_fence_locked(fence, now_ms=now_ms):
                self._expire_run_locked(fence, now_ms=now_ms)
                return False
            updated = self.connection.execute(
                """
                UPDATE watcher_runs SET state = ?, completed_at_ms = ?, heartbeat_at_ms = ?
                 WHERE watcher_run_id = ? AND state = 'RUNNING'
                """,
                (state, now_ms, now_ms, fence.watcher_run_id),
            )
            self.connection.execute(
                """
                UPDATE leases SET state = 'RELEASED', released_at_ms = ?, heartbeat_at_ms = ?
                 WHERE lease_id = ? AND state = 'ACTIVE' AND generation = ?
                """,
                (now_ms, now_ms, fence.lease_id, fence.generation),
            )
            return updated.rowcount == 1

    def _is_current_fence_locked(self, fence: RunFence, *, now_ms: int) -> bool:
        row = self.connection.execute(
            """
            SELECT l.state, l.generation, l.owner_id, l.expires_at_ms,
                   wr.state AS run_state, wr.maximum_runtime_at_ms
              FROM leases AS l JOIN watcher_runs AS wr ON wr.lease_id = l.lease_id
             WHERE l.lease_id = ? AND wr.watcher_run_id = ?
            """,
            (fence.lease_id, fence.watcher_run_id),
        ).fetchone()
        return bool(
            row is not None
            and str(row["state"]) == "ACTIVE"
            and str(row["run_state"]) == "RUNNING"
            and int(row["generation"]) == fence.generation
            and str(row["owner_id"]) == fence.watcher_run_id
            and int(row["expires_at_ms"]) > now_ms
            and int(row["maximum_runtime_at_ms"]) > now_ms
        )

    def _expire_run_locked(self, fence: RunFence, *, now_ms: int) -> None:
        self.connection.execute(
            """
            UPDATE watcher_runs SET state = 'TIMED_OUT', completed_at_ms = ?, heartbeat_at_ms = ?
             WHERE watcher_run_id = ? AND state = 'RUNNING'
            """,
            (now_ms, now_ms, fence.watcher_run_id),
        )
        self.connection.execute(
            """
            UPDATE leases SET state = 'EXPIRED', released_at_ms = ?, heartbeat_at_ms = ?
             WHERE lease_id = ? AND state = 'ACTIVE' AND generation = ?
            """,
            (now_ms, now_ms, fence.lease_id, fence.generation),
        )

    def get_cursor(self, feed_set_id: str) -> CursorState:
        row = self.connection.execute(
            """
            SELECT fs.feed_set_id, fc.cursor_value, fc.cursor_version,
                   fc.committed_at_ms, fc.metadata_json
              FROM feed_sets AS fs
              LEFT JOIN feed_cursors AS fc ON fc.feed_set_id = fs.feed_set_id
             WHERE fs.feed_set_id = ?
            """,
            (feed_set_id,),
        ).fetchone()
        if row is None:
            raise FeedSetLookupError("feed set is not persisted")
        if row["cursor_version"] is None:
            return CursorState(feed_set_id, None, 0, -1, None)
        metadata = _mapping_from_json(str(row["metadata_json"]))
        return CursorState(
            feed_set_id=feed_set_id,
            cursor_value=None if row["cursor_value"] is None else str(row["cursor_value"]),
            version=int(row["cursor_version"]),
            sequence=_metadata_int(metadata, "cursor_sequence", default=-1),
            committed_at_ms=(
                None if row["committed_at_ms"] is None else int(row["committed_at_ms"])
            ),
        )

    def commit_cursor(
        self,
        fence: RunFence,
        *,
        expected_version: int,
        cursor_value: str,
        cursor_sequence: int,
        previous_summary: Mapping[str, object],
        now_ms: int,
    ) -> CursorCommitResult:
        if expected_version < 0 or cursor_sequence < 0:
            raise ValueError("cursor version and sequence must be non-negative")
        if not cursor_value or len(cursor_value.encode("utf-8")) > _MAX_CURSOR_BYTES:
            raise ValueError("cursor value is empty or exceeds the size limit")
        self._scanner.assert_clean(cursor_value, location="watcher.cursor")
        summary = normalize_summary(previous_summary, scanner=self._scanner)
        with transaction(self.connection, "IMMEDIATE"):
            feed_exists = self.connection.execute(
                "SELECT 1 FROM feed_sets WHERE feed_set_id = ?",
                (fence.feed_set_id,),
            ).fetchone()
            if feed_exists is None:
                return CursorCommitResult(CursorCommitStatus.UNKNOWN_FEED_SET, None)
            if not self._is_current_fence_locked(fence, now_ms=now_ms):
                raise StaleRunFenceError("watcher cursor commit has a stale fence")
            row = self.connection.execute(
                "SELECT cursor_version, metadata_json FROM feed_cursors WHERE feed_set_id = ?",
                (fence.feed_set_id,),
            ).fetchone()
            current_version = 0 if row is None else int(row["cursor_version"])
            current_sequence = -1
            if row is not None:
                current_metadata = _mapping_from_json(str(row["metadata_json"]))
                current_sequence = _metadata_int(
                    current_metadata,
                    "cursor_sequence",
                    default=-1,
                )
            if current_version != expected_version:
                return CursorCommitResult(
                    CursorCommitStatus.STALE_VERSION,
                    self._cursor_locked(fence.feed_set_id),
                )
            if cursor_sequence <= current_sequence:
                return CursorCommitResult(
                    CursorCommitStatus.NON_MONOTONIC,
                    self._cursor_locked(fence.feed_set_id),
                )
            metadata: dict[str, JsonValue] = {
                "cursor_sequence": cursor_sequence,
                "previous_summary": summary,
            }
            next_version = current_version + 1
            if row is None:
                self.connection.execute(
                    """
                    INSERT INTO feed_cursors(
                        feed_set_id, cursor_value, cursor_version, last_run_id,
                        committed_at_ms, metadata_json
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        fence.feed_set_id,
                        cursor_value,
                        next_version,
                        fence.watcher_run_id,
                        now_ms,
                        _json(metadata),
                    ),
                )
            else:
                updated = self.connection.execute(
                    """
                    UPDATE feed_cursors
                       SET cursor_value = ?, cursor_version = ?, last_run_id = ?,
                           committed_at_ms = ?, metadata_json = ?
                     WHERE feed_set_id = ? AND cursor_version = ?
                    """,
                    (
                        cursor_value,
                        next_version,
                        fence.watcher_run_id,
                        now_ms,
                        _json(metadata),
                        fence.feed_set_id,
                        expected_version,
                    ),
                )
                if updated.rowcount != 1:  # pragma: no cover - transaction serializes writers
                    return CursorCommitResult(CursorCommitStatus.STALE_VERSION, None)
            return CursorCommitResult(
                CursorCommitStatus.COMMITTED,
                CursorState(
                    feed_set_id=fence.feed_set_id,
                    cursor_value=cursor_value,
                    version=next_version,
                    sequence=cursor_sequence,
                    committed_at_ms=now_ms,
                ),
            )

    def _cursor_locked(self, feed_set_id: str) -> CursorState:
        row = self.connection.execute(
            """
            SELECT cursor_value, cursor_version, committed_at_ms, metadata_json
              FROM feed_cursors WHERE feed_set_id = ?
            """,
            (feed_set_id,),
        ).fetchone()
        if row is None:
            return CursorState(feed_set_id, None, 0, -1, None)
        metadata = _mapping_from_json(str(row["metadata_json"]))
        return CursorState(
            feed_set_id,
            None if row["cursor_value"] is None else str(row["cursor_value"]),
            int(row["cursor_version"]),
            _metadata_int(metadata, "cursor_sequence", default=-1),
            None if row["committed_at_ms"] is None else int(row["committed_at_ms"]),
        )

    def get_previous_summary(self, feed_set_id: str) -> dict[str, JsonValue] | None:
        row = self.connection.execute(
            "SELECT metadata_json FROM feed_cursors WHERE feed_set_id = ?",
            (feed_set_id,),
        ).fetchone()
        if row is None:
            return None
        metadata = _mapping_from_json(str(row["metadata_json"]))
        summary = metadata.get("previous_summary")
        if summary is None:
            return None
        if not isinstance(summary, dict):
            raise WatcherPersistenceError("previous-summary metadata is malformed")
        return dict(summary)


class FeedSetLookupError(LookupError):
    """Raised when durable state does not contain a requested feed set."""
