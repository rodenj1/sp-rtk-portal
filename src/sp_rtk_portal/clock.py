"""The Portal's only source of "now".

Every timestamp the Portal writes or compares comes from a ``Clock``, never
from ``datetime.now()`` or SQL ``now()``, so tests can fake time.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Protocol


class Clock(Protocol):
    def now(self) -> datetime: ...


class SystemClock:
    def now(self) -> datetime:
        return datetime.now(UTC)
