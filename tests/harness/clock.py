"""A clock the test moves by hand."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta


class FakeClock:
    """Satisfies ``sp_rtk_portal.clock.Clock``. Starts at a fixed instant."""

    def __init__(self, start: datetime | None = None) -> None:
        self._now = start or datetime(2026, 1, 1, 12, 0, tzinfo=UTC)

    def now(self) -> datetime:
        return self._now

    def advance(self, delta: timedelta | None = None, **kwargs: float) -> None:
        """``clock.advance(days=29)`` or ``clock.advance(timedelta(...))``."""
        self._now += delta if delta is not None else timedelta(**kwargs)
