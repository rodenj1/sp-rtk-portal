"""Virtual time for the real agent: its sleeps wait on the Portal's fake
clock, and only the test moves that clock on.

``run(seconds=60)`` lets a minute pass, waking each sleep on the way (so the
agent polls exactly when it would have); ``step()`` jumps to the next sleep.
After waking a sleep it waits (in real time) until that task sleeps again or
ends, and until nothing the agent started is still in flight (its requests
and tunnel opens are marked with :meth:`AgentTime.working`), so the requests
it makes have landed before the test looks and nothing lags behind virtual
time. The agent runs more than one task (its beat, its tunnel's pings), and
one may still be talking to the Portal when another's sleep ends. A task
that wakes to open the held tunnel then serves it, maybe for hours, and
says so (:meth:`AgentTime.serving`) rather than sleep again.
"""

from __future__ import annotations

import asyncio
import contextlib
import itertools
from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from .clock import FakeClock


@dataclass
class _Sleeper:
    deadline: datetime
    seq: int
    future: asyncio.Future[None]
    task: asyncio.Task[Any] | None


class AgentTime:
    def __init__(self, clock: FakeClock) -> None:
        self.clock = clock
        self._sleepers: list[_Sleeper] = []
        self._seq = itertools.count()
        self._busy = 0
        self._serving: set[asyncio.Task[Any]] = set()

    @contextlib.asynccontextmanager
    async def working(self) -> AsyncIterator[None]:
        """The agent is talking to the Portal (a request, a tunnel open):
        time doesn't move on until it's done."""
        self._busy += 1
        try:
            yield
        finally:
            self._busy -= 1

    def begin(self) -> None:
        """Like :meth:`working`, for work that ends elsewhere (a ping, until
        its pong): call :meth:`end` once it's done."""
        self._busy += 1

    def end(self) -> None:
        self._busy -= 1

    async def done(self) -> None:
        """Wait (real time) until nothing the agent started is in flight."""
        loop = asyncio.get_running_loop()
        give_up = loop.time() + 10
        while self._busy and loop.time() < give_up:
            await asyncio.sleep(0.001)

    def serving(self) -> None:
        """The current task now serves a tunnel until it closes (the agent
        holding its tunnel): once woken, it isn't waited for to sleep
        again."""
        task = asyncio.current_task()
        if task is not None:
            self._serving.add(task)

    async def sleep(self, seconds: float) -> None:
        if (task := asyncio.current_task()) is not None:
            self._serving.discard(task)
        sleeper = _Sleeper(
            self.clock.now() + timedelta(seconds=seconds),
            next(self._seq),
            asyncio.get_running_loop().create_future(),
            asyncio.current_task(),
        )
        self._sleepers.append(sleeper)
        try:
            await sleeper.future
        finally:
            with contextlib.suppress(ValueError):
                self._sleepers.remove(sleeper)

    def _next(self) -> _Sleeper | None:
        waiting = [s for s in self._sleepers if not s.future.done()]
        return min(waiting, key=lambda s: (s.deadline, s.seq), default=None)

    async def _wake(self, sleeper: _Sleeper) -> None:
        if sleeper.deadline > self.clock.now():
            self.clock.advance(sleeper.deadline - self.clock.now())
        sleeper.future.set_result(None)
        await self.settle(sleeper.task, after=sleeper.seq)

    async def settle(self, task: asyncio.Task[Any] | None, after: int = -1) -> None:
        """Wait (real time) until ``task`` sleeps again or ends."""
        loop = asyncio.get_running_loop()
        give_up = loop.time() + 10
        while loop.time() < give_up:
            await asyncio.sleep(0.001)
            if self._busy:
                continue
            if task is None or task.done() or task in self._serving:
                return
            if any(s.task is task and s.seq > after for s in self._sleepers):
                return

    async def until_asleep(self) -> None:
        """Wait (real time) until some agent task is asleep: after a start or
        a Claim, the poll loop has made its first requests."""
        loop = asyncio.get_running_loop()
        give_up = loop.time() + 10
        quiet = 0
        while loop.time() < give_up:
            await asyncio.sleep(0.001)
            quiet = quiet + 1 if self._next() is not None and not self._busy else 0
            if quiet >= 3:  # and stays so: another task may be about to start
                return
        raise AssertionError("the agent never went to sleep")

    async def step(self) -> bool:
        """Jump to the next sleep's end and run it. ``False`` if none waits."""
        await asyncio.sleep(0.001)
        sleeper = self._next()
        if sleeper is None:
            return False
        await self._wake(sleeper)
        return True

    async def run(self, delta: timedelta | None = None, **kwargs: float) -> None:
        """Let ``delta`` (or ``timedelta(**kwargs)``) pass."""
        target = self.clock.now() + (
            delta if delta is not None else timedelta(**kwargs)
        )
        await asyncio.sleep(0.001)
        while (sleeper := self._next()) is not None and sleeper.deadline <= target:
            await self._wake(sleeper)
        if target > self.clock.now():
            self.clock.advance(target - self.clock.now())
