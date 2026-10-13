"""Rate limiting (ticket #98): one bad actor can't flood the Portal.

:class:`Limiter` holds every counter, in memory: the Portal is one process
(``replicas: 1``), so a restart forgets them, which only ever lets a little
more through. Callers pass the limit with each call, read from ``Settings``
at that moment, so a changed setting applies at once.

Two shapes:

- a window (:meth:`Limiter.over` / :meth:`Limiter.hit` / :meth:`Limiter.take`):
  at most ``limit`` events per ``period`` per key (Claim starts per IP, wrong
  approve codes per account and overall, Shares per Operator);
- a bucket (:meth:`Limiter.spaced`): requests no closer than ``spacing``
  seconds on average, with a small ``burst`` (polls and Check-ins per base).

Each refusal is the number of seconds until the next one would pass, for
``Retry-After``.
"""

from __future__ import annotations

import math
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timedelta

from sp_rtk_portal.clock import Clock

_SWEEP_EVERY = 1000
"""Forget idle keys after this many calls, so memory stays bounded."""


@dataclass
class _Bucket:
    tokens: float
    at: datetime
    full_after: float


class Limiter:
    def __init__(self, clock: Clock) -> None:
        self._clock = clock
        self._windows: dict[tuple[str, str], tuple[deque[datetime], timedelta]] = {}
        self._buckets: dict[tuple[str, str], _Bucket] = {}
        self._calls = 0

    # --- windows ---------------------------------------------------------------

    def over(self, kind: str, key: str, *, limit: int, period: timedelta) -> int | None:
        """Seconds until ``key`` may have another ``kind`` event, or ``None``:
        it is under ``limit`` events in the last ``period``."""
        now = self._tick()
        events = self._events(kind, key, period, now)
        if len(events) < limit:
            return None
        if limit <= 0 or not events:
            return _ceil(period.total_seconds())
        oldest = events[len(events) - limit]
        return _ceil((oldest + period - now).total_seconds())

    def hit(self, kind: str, key: str, *, period: timedelta) -> None:
        """Count one ``kind`` event for ``key``."""
        now = self._tick()
        self._events(kind, key, period, now).append(now)

    def take(self, kind: str, key: str, *, limit: int, period: timedelta) -> int | None:
        """:meth:`over`, and when it isn't, count the event."""
        wait = self.over(kind, key, limit=limit, period=period)
        if wait is None:
            self.hit(kind, key, period=period)
        return wait

    def _events(
        self, kind: str, key: str, period: timedelta, now: datetime
    ) -> deque[datetime]:
        events, _ = self._windows.get((kind, key), (deque(), period))
        while events and events[0] <= now - period:
            events.popleft()
        self._windows[kind, key] = (events, period)
        return events

    # --- buckets ---------------------------------------------------------------

    def spaced(self, kind: str, key: str, *, spacing: float, burst: int) -> int | None:
        """One request from ``key``: ``None`` if it may pass (and it's
        counted), else seconds until one may. A token comes back every
        ``spacing`` seconds, up to ``burst`` saved."""
        now = self._tick()
        burst = max(burst, 1)
        bucket = self._buckets.get((kind, key))
        if bucket is None:
            tokens = float(burst)
        else:
            elapsed = (now - bucket.at).total_seconds()
            refill = elapsed / spacing if spacing > 0 else math.inf
            tokens = min(float(burst), bucket.tokens + refill)
        full_after = spacing * burst
        if tokens < 1:
            self._buckets[kind, key] = _Bucket(tokens, now, full_after)
            return max(1, _ceil((1 - tokens) * spacing))
        self._buckets[kind, key] = _Bucket(tokens - 1, now, full_after)
        return None

    # --- housekeeping ----------------------------------------------------------

    def _tick(self) -> datetime:
        now = self._clock.now()
        self._calls += 1
        if self._calls % _SWEEP_EVERY == 0:
            self._sweep(now)
        return now

    def _sweep(self, now: datetime) -> None:
        for k, (events, period) in list(self._windows.items()):
            if not events or events[-1] <= now - period:
                del self._windows[k]
        for k, b in list(self._buckets.items()):
            if (now - b.at).total_seconds() >= b.full_after:
                del self._buckets[k]


def _ceil(seconds: float) -> int:
    # Rounded first: 1.0000000000000002 s of float noise is 1 s, not 2.
    return max(0, math.ceil(round(seconds, 6)))
