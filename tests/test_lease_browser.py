"""Seam 2: the Session bar renews its path token's lease in real browsers
(ticket #202, ADR 0005).

The Portal asks an open Session bar to renew every 60 s of its (fake) clock
and the bar answers over its status channel, so renewal needs no timer in
the page: a background tab whose timers are throttled to once a minute
keeps its session. A bar that slept past the lease finds its Remote session
ended as lease expired and reconnects once, with a new path token.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest
from playwright.async_api import Browser, Page, Request, WebSocket, expect

from .harness.clock import FakeClock
from .harness.fake_authentik import FakeAuthentik
from .test_session_bar_states_browser import World, browser_app, frame_text, world

__all__ = ["browser_app"]  # the fixture

THROTTLED_TIMERS = """
// A background tab: hidden, its timers run at most once a minute (the
// intensive throttling Chrome applies to hidden pages).
(() => {
  Object.defineProperty(document, "visibilityState", { get: () => "hidden" });
  Object.defineProperty(document, "hidden", { get: () => true });
  const later = (ms) => Math.max(ms, 60000 - (Date.now() % 60000));
  const setTimeout_ = window.setTimeout.bind(window);
  window.setTimeout = (fn, ms, ...args) => setTimeout_(fn, later(ms || 0), ...args);
  const setInterval_ = window.setInterval.bind(window);
  window.setInterval = (fn, ms, ...args) =>
    setInterval_(fn, Math.max(ms || 0, 60000), ...args);
})();
"""

SLEEP = """
// A laptop that sleeps: while asleep the page runs nothing, so its status
// channel's messages wait until it wakes (window.__wake()).
(() => {
  let asleep = false;
  const held = [];
  const Native = window.WebSocket;
  window.WebSocket = class extends Native {
    addEventListener(type, fn, options) {
      const held_ = (event) =>
        asleep ? held.push(() => fn.call(this, event)) : fn.call(this, event);
      return super.addEventListener(type, held_, options);
    }
  };
  window.__sleep = () => { asleep = true; };
  window.__wake = () => { asleep = false; held.splice(0).forEach((f) => f()); };
})();
"""


@pytest.fixture
async def w(
    database_url: str,
    clock: FakeClock,
    authentik: FakeAuthentik,
    browser_app: Browser,
) -> AsyncIterator[World]:
    async with world(database_url, clock, authentik, browser_app) as it:
        yield it


def renewals(page: Page) -> list[str]:
    """Every renewal the page's status channels send."""
    sent: list[str] = []

    def channel(ws: WebSocket) -> None:
        ws.on(
            "framesent",
            lambda payload: sent.append(str(payload)) if "renew" in str(payload) else None,
        )

    page.on("websocket", channel)
    return sent


def opens(page: Page, base_id: str) -> list[Request]:
    """Every Open remotely the page posts."""
    posted: list[Request] = []
    page.on(
        "request",
        lambda r: posted.append(r)
        if r.method == "POST" and r.url.endswith(f"/bases/{base_id}/remote")
        else None,
    )
    return posted


async def test_a_background_tab_with_throttled_timers_keeps_renewing(w: World):
    await w.page.add_init_script(THROTTLED_TIMERS)
    sent = renewals(w.page)
    await w.open_remotely()
    await w.connected()
    path = await w.locate("frame").get_attribute("data-path")
    assert path

    await w.agent.run(minutes=12)

    await expect(w.locate("status")).to_have_text("Connected")
    assert await w.locate("frame").get_attribute("data-path") == path
    assert len(sent) >= 10
    assert (await w.page.request.get(w.origin + path)).ok


async def test_after_sleeping_past_the_lease_the_bar_reconnects_once_with_a_new_token(
    w: World,
):
    await w.page.add_init_script(SLEEP)
    posted = opens(w.page, w.base_id)
    await w.open_remotely()
    await w.connected()
    old = await w.locate("frame").get_attribute("data-path")
    assert old and len(posted) == 1

    await w.page.evaluate("window.__sleep()")
    await w.agent.run(minutes=6)
    assert (await w.page.request.get(w.origin + old)).status == 403
    await w.page.evaluate("window.__wake()")

    # The session ended, and its tunnel closed with it: Woken once more.
    await w.connected()
    new = await w.locate("frame").get_attribute("data-path")
    assert new and new != old
    await frame_text(w)
    assert len(posted) == 2  # one automatic reconnect


async def test_if_the_reconnect_fails_the_bar_shows_the_session_ended(w: World):
    await w.page.add_init_script(SLEEP)
    posted = opens(w.page, w.base_id)
    await w.open_remotely()
    await w.connected()

    await w.page.evaluate("window.__sleep()")
    w.agent.reachable = False  # the base went offline meanwhile
    await w.agent.run(minutes=6)
    await w.page.evaluate("window.__wake()")

    await expect(w.locate("status")).to_have_text("Session ended")
    await expect(w.locate("frame")).to_have_count(0)
    await expect(w.page.get_by_role("button", name="Open remotely")).to_be_visible()
    assert len(posted) == 2  # one automatic reconnect, then no more


async def test_a_paused_session_sends_no_renewals(w: World):
    sent = renewals(w.page)
    await w.open_remotely()
    await w.connected()
    await w.agent.run(minutes=60)  # the hard cap pauses it
    await expect(w.locate("status")).to_have_text("Session paused")
    assert sent
    before = len(sent)

    await w.agent.run(minutes=10)

    await expect(w.locate("status")).to_have_text("Session paused")
    assert len(sent) == before
