from datetime import UTC, datetime

import pytest

from sentinel_audit.config import Schedule
from sentinel_audit.scheduler import due_period, is_missed, next_due


@pytest.mark.parametrize(
    "value,expected",
    [
        ("2026-11-01T03:46:59+00:00", None),
        ("2026-11-01T03:47:00+00:00", "2026-11"),
        ("2026-11-05T00:00:00+00:00", "2026-11"),
        ("2027-01-01T03:47:00+00:00", "2027-01"),
    ],
)
def test_ist_monthly_boundary(value, expected):
    assert due_period(Schedule(), datetime.fromisoformat(value)) == expected


def test_next_due_and_missed_detection():
    now = datetime(2026, 12, 31, 20, tzinfo=UTC)
    assert next_due(Schedule(), now) == datetime(2027, 1, 1, 3, 47, tzinfo=UTC)
    assert is_missed(Schedule(), datetime(2026, 11, 3, tzinfo=UTC), None)
    assert not is_missed(Schedule(), datetime(2026, 11, 1, 3, 48, tzinfo=UTC), None)
    assert not is_missed(Schedule(), datetime(2026, 11, 3, tzinfo=UTC), "2026-11")


def test_timezone_dst_and_aware_clock():
    schedule = Schedule(timezone="America/New_York", hour=9, minute=17)
    assert next_due(schedule, datetime(2026, 11, 1, tzinfo=UTC)) == datetime(
        2026, 11, 1, 14, 17, tzinfo=UTC
    )
    with pytest.raises(ValueError):
        due_period(schedule, datetime(2026, 1, 1))
