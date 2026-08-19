"""Bounded retry decisions and multi-scope circuit breakers."""

from __future__ import annotations

from collections import deque
from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import StrEnum
from threading import Lock

from gatehouse.core.clock import require_utc_ms
from gatehouse.core.states import CircuitBreakerState
from gatehouse.providers import OperationSpec, ProviderErrorClass, RetrySafety


class BreakerScopeType(StrEnum):
    CREDENTIAL = "credential"
    QUOTA_SCOPE = "quota_scope"
    PROVIDER_OPERATION = "provider_operation"
    SERVICE = "service"
    SESSION_RUNAWAY = "session_runaway"


@dataclass(frozen=True, slots=True)
class BreakerKey:
    scope_type: BreakerScopeType
    scope_id: str

    def __post_init__(self) -> None:
        if not self.scope_id:
            raise ValueError("breaker scope identifier is required")


@dataclass(frozen=True, slots=True)
class CircuitBreakerPolicy:
    failures_to_open: int = 5
    observation_window_ms: int = 60_000
    default_open_duration_ms: int = 120_000
    half_open_probe_count: int = 1

    def __post_init__(self) -> None:
        if (
            min(
                self.failures_to_open,
                self.observation_window_ms,
                self.default_open_duration_ms,
                self.half_open_probe_count,
            )
            <= 0
        ):
            raise ValueError("circuit-breaker bounds must be positive")


@dataclass(frozen=True, slots=True)
class CircuitBreakerSnapshot:
    key: BreakerKey
    state: CircuitBreakerState
    failure_count: int
    opened_at_ms: int | None
    retry_after_ms: int | None
    half_open_in_flight: int
    last_failure_class: ProviderErrorClass | None


@dataclass(frozen=True, slots=True)
class CircuitBreakerPermit:
    permit_id: int
    keys: tuple[BreakerKey, ...]
    probes: tuple[tuple[BreakerKey, int], ...]

    def __post_init__(self) -> None:
        if self.permit_id <= 0 or not self.keys:
            raise ValueError("circuit-breaker permit identity is invalid")


@dataclass(slots=True)
class _CircuitRecord:
    state: CircuitBreakerState = CircuitBreakerState.CLOSED
    failures: deque[int] = field(default_factory=deque)
    opened_at_ms: int | None = None
    retry_after_ms: int | None = None
    half_open_in_flight: int = 0
    half_open_generation: int = 0
    last_failure_class: ProviderErrorClass | None = None


class CircuitBreakerRegistry:
    """Thread-safe registry with explicit half-open probe admission."""

    def __init__(self, policy: CircuitBreakerPolicy | None = None) -> None:
        self.policy = policy or CircuitBreakerPolicy()
        self._records: dict[BreakerKey, _CircuitRecord] = {}
        self._active_permits: dict[int, CircuitBreakerPermit] = {}
        self._next_permit_id = 1
        self._lock = Lock()

    def is_available(self, key: BreakerKey, *, now_ms: int) -> bool:
        require_utc_ms(now_ms)
        with self._lock:
            record = self._records.get(key)
            if record is None or record.state is CircuitBreakerState.CLOSED:
                return True
            if record.state is CircuitBreakerState.OPEN:
                return record.retry_after_ms is not None and now_ms >= record.retry_after_ms
            return record.half_open_in_flight < self.policy.half_open_probe_count

    def try_acquire(
        self,
        key: BreakerKey,
        *,
        now_ms: int,
    ) -> CircuitBreakerPermit | None:
        """Admit one attempt and consume a half-open probe when applicable."""

        return self.try_acquire_many((key,), now_ms=now_ms)

    def try_acquire_many(
        self,
        keys: Iterable[BreakerKey],
        *,
        now_ms: int,
    ) -> CircuitBreakerPermit | None:
        """Atomically admit a dispatch across every applicable breaker scope."""

        require_utc_ms(now_ms)
        unique_keys = tuple(dict.fromkeys(keys))
        if not unique_keys:
            raise ValueError("at least one circuit-breaker key is required")
        with self._lock:
            records = [
                (key, self._records.setdefault(key, _CircuitRecord())) for key in unique_keys
            ]
            for _key, record in records:
                if record.state is CircuitBreakerState.CLOSED:
                    continue
                if record.state is CircuitBreakerState.OPEN and (
                    record.retry_after_ms is None or now_ms < record.retry_after_ms
                ):
                    return None
                if (
                    record.state is CircuitBreakerState.HALF_OPEN
                    and record.half_open_in_flight >= self.policy.half_open_probe_count
                ):
                    return None
            for _key, record in records:
                if record.state is CircuitBreakerState.OPEN:
                    record.state = CircuitBreakerState.HALF_OPEN
                    record.half_open_in_flight = 0
                    record.half_open_generation += 1
                if record.state is CircuitBreakerState.HALF_OPEN:
                    record.half_open_in_flight += 1
            permit_id = self._next_permit_id
            self._next_permit_id += 1
            permit = CircuitBreakerPermit(
                permit_id=permit_id,
                keys=unique_keys,
                probes=tuple(
                    (key, record.half_open_generation)
                    for key, record in records
                    if record.state is CircuitBreakerState.HALF_OPEN
                ),
            )
            self._active_permits[permit_id] = permit
            return permit

    def release(self, permit: CircuitBreakerPermit) -> bool:
        """Neutrally return every half-open probe owned by one dispatch."""

        with self._lock:
            stored = self._active_permits.pop(permit.permit_id, None)
            if stored != permit:
                return False
            for key, generation in permit.probes:
                record = self._records.get(key)
                if (
                    record is not None
                    and record.state is CircuitBreakerState.HALF_OPEN
                    and record.half_open_generation == generation
                    and record.half_open_in_flight > 0
                ):
                    record.half_open_in_flight -= 1
            return True

    def record_success(self, key: BreakerKey) -> CircuitBreakerSnapshot:
        with self._lock:
            record = self._records.setdefault(key, _CircuitRecord())
            record.state = CircuitBreakerState.CLOSED
            record.failures.clear()
            record.opened_at_ms = None
            record.retry_after_ms = None
            record.half_open_in_flight = 0
            record.last_failure_class = None
            return self._snapshot(key, record)

    def record_failure(
        self,
        key: BreakerKey,
        *,
        now_ms: int,
        error_class: ProviderErrorClass,
        open_until_ms: int | None = None,
        force_open: bool = False,
    ) -> CircuitBreakerSnapshot:
        require_utc_ms(now_ms)
        if open_until_ms is not None:
            require_utc_ms(open_until_ms)
            if open_until_ms <= now_ms:
                raise ValueError("breaker retry time must be in the future")
        with self._lock:
            record = self._records.setdefault(key, _CircuitRecord())
            threshold = now_ms - self.policy.observation_window_ms
            while record.failures and record.failures[0] < threshold:
                record.failures.popleft()
            record.failures.append(now_ms)
            record.last_failure_class = error_class
            was_probe = record.state is CircuitBreakerState.HALF_OPEN
            if was_probe and record.half_open_in_flight:
                record.half_open_in_flight -= 1
            if force_open or was_probe or len(record.failures) >= self.policy.failures_to_open:
                self._open(record, now_ms=now_ms, open_until_ms=open_until_ms)
            return self._snapshot(key, record)

    def snapshot(self, key: BreakerKey, *, now_ms: int) -> CircuitBreakerSnapshot:
        require_utc_ms(now_ms)
        with self._lock:
            record = self._records.setdefault(key, _CircuitRecord())
            return self._snapshot(key, record)

    def _open(
        self,
        record: _CircuitRecord,
        *,
        now_ms: int,
        open_until_ms: int | None,
    ) -> None:
        record.state = CircuitBreakerState.OPEN
        record.opened_at_ms = now_ms
        record.retry_after_ms = open_until_ms or now_ms + self.policy.default_open_duration_ms
        record.half_open_in_flight = 0

    @staticmethod
    def _snapshot(key: BreakerKey, record: _CircuitRecord) -> CircuitBreakerSnapshot:
        return CircuitBreakerSnapshot(
            key=key,
            state=record.state,
            failure_count=len(record.failures),
            opened_at_ms=record.opened_at_ms,
            retry_after_ms=record.retry_after_ms,
            half_open_in_flight=record.half_open_in_flight,
            last_failure_class=record.last_failure_class,
        )


class RetryAction(StrEnum):
    FAIL = "FAIL"
    RETRY_SAME_CREDENTIAL = "RETRY_SAME_CREDENTIAL"
    FAILOVER_WITHIN_POOL = "FAILOVER_WITHIN_POOL"
    RECONCILE = "RECONCILE"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True, slots=True)
class RetryDecision:
    action: RetryAction
    delay_ms: int = 0

    def __post_init__(self) -> None:
        if self.delay_ms < 0:
            raise ValueError("retry delay cannot be negative")
        if (
            self.action
            not in {
                RetryAction.RETRY_SAME_CREDENTIAL,
                RetryAction.RECONCILE,
            }
            and self.delay_ms
        ):
            raise ValueError("only delayed retry or reconciliation may carry a delay")


@dataclass(frozen=True, slots=True)
class RetryPolicy:
    maximum_attempts: int = 3
    initial_backoff_ms: int = 1_000
    maximum_backoff_ms: int = 30_000
    jitter: bool = True

    def __post_init__(self) -> None:
        if min(self.maximum_attempts, self.initial_backoff_ms, self.maximum_backoff_ms) <= 0:
            raise ValueError("retry bounds must be positive")
        if self.initial_backoff_ms > self.maximum_backoff_ms:
            raise ValueError("initial backoff cannot exceed maximum backoff")

    def decide(
        self,
        *,
        operation: OperationSpec,
        error_class: ProviderErrorClass,
        attempt_number: int,
        submission_may_have_occurred: bool,
        retry_after_seconds: float | None = None,
        has_pool_failover: bool = False,
    ) -> RetryDecision:
        if attempt_number <= 0:
            raise ValueError("attempt number must be positive")
        if retry_after_seconds is not None and retry_after_seconds < 0:
            raise ValueError("retry-after cannot be negative")
        if submission_may_have_occurred or error_class is ProviderErrorClass.UNKNOWN_OUTCOME:
            return RetryDecision(RetryAction.UNKNOWN)
        if error_class is ProviderErrorClass.CONFLICT:
            return RetryDecision(RetryAction.RECONCILE)
        if error_class is ProviderErrorClass.PERMISSION_DENIED:
            return RetryDecision(RetryAction.FAIL)
        if error_class in {
            ProviderErrorClass.INVALID_REQUEST,
            ProviderErrorClass.NOT_FOUND,
            ProviderErrorClass.MALFORMED_RESPONSE,
        }:
            return RetryDecision(RetryAction.FAIL)
        if error_class in {
            ProviderErrorClass.UNAUTHORIZED,
            ProviderErrorClass.QUOTA_EXHAUSTED,
        }:
            if has_pool_failover and attempt_number < self.maximum_attempts:
                return RetryDecision(RetryAction.FAILOVER_WITHIN_POOL)
            return RetryDecision(RetryAction.FAIL)

        retry_safe = operation.retry_safety is RetrySafety.SAFE
        if not retry_safe or attempt_number >= self.maximum_attempts:
            return RetryDecision(RetryAction.FAIL)
        if error_class is ProviderErrorClass.RATE_LIMITED and retry_after_seconds is not None:
            delay = min(round(retry_after_seconds * 1_000), self.maximum_backoff_ms)
        else:
            delay = self.backoff_ms(attempt_number=attempt_number)
        return RetryDecision(RetryAction.RETRY_SAME_CREDENTIAL, delay_ms=max(1, delay))

    def backoff_ms(self, *, attempt_number: int, jitter_unit: float = 0.5) -> int:
        """Return bounded backoff; injected jitter keeps tests and replay deterministic."""

        if attempt_number <= 0:
            raise ValueError("attempt number must be positive")
        if not 0 <= jitter_unit <= 1:
            raise ValueError("jitter_unit must be between zero and one")
        multiplier = 1 << (attempt_number - 1)
        raw: int = min(
            self.maximum_backoff_ms,
            self.initial_backoff_ms * multiplier,
        )
        if not self.jitter:
            return raw
        return max(1, round(raw * (0.5 + jitter_unit / 2)))
