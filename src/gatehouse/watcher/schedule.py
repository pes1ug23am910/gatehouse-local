"""Timezone-aware schedule-window evaluation for feed scans."""

from __future__ import annotations

from datetime import UTC, date, datetime, time, timedelta, tzinfo
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from gatehouse.config.models import ScheduleConfig, ScheduleWindowConfig
from gatehouse.core.clock import datetime_from_utc_ms, datetime_to_utc_ms, require_utc_ms

from .models import ScheduleDecision

_DAY_NAMES = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")


def _window_bounds(
    local_date: date,
    window: ScheduleWindowConfig,
    timezone: tzinfo,
) -> tuple[datetime, datetime]:
    start = datetime.combine(local_date, time.fromisoformat(str(window.start)), timezone)
    end_date = local_date if window.end > window.start else local_date + timedelta(days=1)
    end = datetime.combine(end_date, time.fromisoformat(str(window.end)), timezone)
    return start, end


class ScheduleTimezoneError(ValueError):
    """Raised when the configured IANA timezone data is unavailable."""


def _load_timezone(name: str) -> tzinfo:
    if name in {"Etc/UTC", "Etc/GMT"}:
        return UTC
    try:
        return ZoneInfo(name)
    except ZoneInfoNotFoundError as error:
        raise ScheduleTimezoneError("configured IANA timezone data is unavailable") from error


def evaluate_schedule(
    schedule: ScheduleConfig,
    *,
    now_ms: int,
    timezone: tzinfo | None = None,
) -> ScheduleDecision:
    """Return whether an instant is within a configured window or its grace."""

    require_utc_ms(now_ms)
    resolved_timezone = timezone or _load_timezone(str(schedule.timezone))
    local_now = datetime_from_utc_ms(now_ms).astimezone(resolved_timezone)
    candidates: list[tuple[datetime, datetime, bool]] = []
    for offset in (-1, 0):
        candidate_date = local_now.date() + timedelta(days=offset)
        day_name = _DAY_NAMES[candidate_date.weekday()]
        for window in schedule.windows:
            if day_name not in window.days:
                continue
            start, end = _window_bounds(candidate_date, window, resolved_timezone)
            allowed_start = start - timedelta(milliseconds=int(schedule.early_start_grace))
            allowed_end = end + timedelta(milliseconds=int(schedule.late_start_grace))
            if allowed_start <= local_now <= allowed_end:
                candidates.append((start, end, not (start <= local_now <= end)))

    if not candidates:
        return ScheduleDecision(
            allowed=False,
            evaluated_at_ms=now_ms,
            timezone=str(schedule.timezone),
        )
    start, end, in_grace = max(candidates, key=lambda item: item[0])
    return ScheduleDecision(
        allowed=True,
        evaluated_at_ms=now_ms,
        timezone=str(schedule.timezone),
        window_start_ms=datetime_to_utc_ms(start),
        window_end_ms=datetime_to_utc_ms(end),
        in_grace=in_grace,
    )
