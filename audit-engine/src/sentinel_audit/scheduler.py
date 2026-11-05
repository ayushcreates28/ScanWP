"""Calendar scheduling with explicit IANA time zones and aware clocks."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from zoneinfo import ZoneInfo

from .config import Schedule


def monthly_due(schedule: Schedule, now: datetime) -> datetime:
    if now.tzinfo is None:
        raise ValueError("An aware clock is required")
    local = now.astimezone(ZoneInfo(schedule.timezone))
    return local.replace(
        day=schedule.day, hour=schedule.hour, minute=schedule.minute, second=0, microsecond=0
    )


def due_period(schedule: Schedule, now: datetime) -> str | None:
    due = monthly_due(schedule, now)
    return due.strftime("%Y-%m") if now >= due.astimezone(UTC) else None


def next_due(schedule: Schedule, now: datetime) -> datetime:
    due = monthly_due(schedule, now)
    if due <= now:
        next_month = (due.replace(day=28) + timedelta(days=4)).replace(day=1)
        due = next_month.replace(day=schedule.day)
    return due.astimezone(UTC)


def is_missed(
    schedule: Schedule,
    now: datetime,
    last_period: str | None,
    grace: timedelta = timedelta(hours=24),
) -> bool:
    period = due_period(schedule, now)
    return bool(
        period
        and period != last_period
        and now - monthly_due(schedule, now).astimezone(UTC) > grace
    )
