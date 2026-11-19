"""Seam 2: the Session bar's states in real browsers (ticket #90).

The Portal's clock is fake and the agent runs on virtual time, and the
Portal decides every state, so the browser only shows what the status
channel tells it: "after 35 s" means exactly 35 s of virtual time passed.

The base here polls (protocol version 1 agent) unless a test asks for one
holding its tunnel (fixture ``h``): the bar opens at once, says Didn't wake
after 15 s with no answer (its tunnel down, or its UI not answering down
it), and waits up to 75 s for a dropped tunnel (the
agent's first retry comes after a random 0-60 s).
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass

import pytest
from playwright.async_api import Browser, Locator, Page, async_playwright, expect
from sp_rtk_portal_protocol import HOLDING_VERSION

from .harness.agent import RunningAgent, running_agent
from .harness.base_ui import BaseUi, base_ui
from .harness.clock import FakeClock
from .harness.fake_authentik import FakeAuthentik
from .harness.portal import Portal, running_portal
from .harness.server import free_socket, serving
from .test_session_bar_browser import EMAIL, PASSWORD, claim, sign_in
from .test_tunnel import eventually

OTHER = "sam@example.com"


@pytest.fixture(params=["chromium", "firefox"])
async def browser_app(request: pytest.FixtureRequest) -> AsyncIterator[Browser]:
    async with async_playwright() as p:
        browser = await getattr(p, request.param).launch()
        try:
            yield browser
        finally:
            await browser.close()


@dataclass
class World:
    portal: Portal
    agent: RunningAgent
    origin: str
    page: Page
    base_id: str
    ui: BaseUi

    def locate(self, field: str, page: Page | None = None) -> Locator:
        return (page or self.page).locator(f"[data-field={field}]")

    async def open_remotely(self, page: Page | None = None) -> None:
        page = page or self.page
        await page.goto(f"{self.origin}/")
        await page.get_by_role("button", name="Open remotely").click()
        await page.wait_for_url(f"{self.origin}/bases/{self.base_id}")

    async def connected(self, page: Page | None = None) -> None:
        if self.agent.protocol_version < HOLDING_VERSION:
            status = self.locate("status", page)
            await expect(status).to_have_text("Waking North field…")
            await self.agent.run(seconds=20)  # the Wake's poll
        await expect(self.locate("status", page)).to_have_text("Connected")


@asynccontextmanager
async def world(
    database_url: str,
    clock: FakeClock,
    authentik: FakeAuthentik,
    app: Browser,
    *,
    protocol_version: int = 1,
) -> AsyncIterator[World]:
    sock = free_socket()
    origin = f"http://localhost:{sock.getsockname()[1]}"
    authentik.add_user(EMAIL, PASSWORD)
    async with (
        base_ui() as ui,
        running_portal(database_url, clock, authentik, origin=origin) as portal,
        serving(portal.app, sock) as port,
        running_agent(
            portal,
            server_port=port,
            app_port=ui.port,
            protocol_version=protocol_version,
        ) as agent,
    ):
        context = await app.new_context(viewport={"width": 1200, "height": 900})
        page = await context.new_page()
        await sign_in(page, portal)
        await claim(page, agent, origin)
        base_id = (await agent.status()).base_id
        assert base_id
        try:
            yield World(portal, agent, origin, page, base_id, ui)
        finally:
            await context.close()


@pytest.fixture
async def w(
    database_url: str,
    clock: FakeClock,
    authentik: FakeAuthentik,
    browser_app: Browser,
) -> AsyncIterator[World]:
    async with world(database_url, clock, authentik, browser_app) as it:
        yield it


@pytest.fixture
async def h(
    database_url: str,
    clock: FakeClock,
    authentik: FakeAuthentik,
    browser_app: Browser,
) -> AsyncIterator[World]:
    """A base holding its tunnel."""
    async with world(
        database_url, clock, authentik, browser_app, protocol_version=HOLDING_VERSION
    ) as it:
        await holding(it)
        yield it


async def holding(w: World) -> None:
    """Let the agent's reconnects run until it holds its tunnel again."""
    tunnels = w.portal.context.tunnels
    for _ in range(60):
        if tunnels.tunnel_up(w.base_id):
            return
        await w.agent.run(seconds=10)
        await asyncio.sleep(0.05)
    raise AssertionError("the base never held its tunnel")


async def dropped(w: World) -> None:
    """The network drops the held tunnel; the Portal notices."""
    w.agent.drop_tunnel()
    tunnels = w.portal.context.tunnels
    await eventually(lambda: not tunnels.tunnel_up(w.base_id), "the tunnel dropped")


async def record_states(page: Page) -> None:
    """From the next page load on, ``window.seenStates`` lists every state
    the bar showed, in order."""
    await page.add_init_script(
        """
        window.seenStates = [];
        document.addEventListener("DOMContentLoaded", () => {
          const bar = document.querySelector("[data-session-bar]");
          if (!bar) return;
          const note = () => window.seenStates.push(bar.dataset.state);
          note();
          new MutationObserver(note).observe(bar, { attributeFilter: ["data-state"] });
        });
        """
    )


async def seen_states(page: Page) -> list[str]:
    return await page.evaluate("window.seenStates")


async def frame_text(w: World, page: Page | None = None) -> None:
    base = (page or w.page).frame_locator("iframe[data-field=frame]")
    await expect(base.get_by_text("base page /")).to_be_visible()


# --- Didn't wake and Offline -------------------------------------------------------


async def test_didnt_wake_after_35_s_with_retry_and_offline_looks_different(w: World):
    page = w.page
    w.agent.reachable = False  # its polls stop arriving
    await w.open_remotely()
    await expect(w.locate("status")).to_have_text("Waking North field…")
    await expect(w.locate("hint-polling")).to_contain_text("every 20 s")
    await expect(w.locate("hint-holding")).to_be_hidden()
    await w.agent.run(seconds=34)
    await asyncio.sleep(0.2)
    await expect(w.locate("status")).to_have_text("Waking North field…")

    await w.agent.run(seconds=1)
    await expect(w.locate("status")).to_have_text("Didn't wake")
    didnt = w.locate("didnt-wake")
    await expect(didnt).to_be_visible()
    await expect(didnt).to_contain_text("North field didn't wake")
    await expect(w.locate("last-seen")).to_have_text("2026-01-01 12:00 UTC")
    await expect(w.locate("connection")).to_have_text("Polling every 20 s")
    await expect(didnt.locator("[data-field=open-locally]")).to_have_attribute(
        "href", "http://192.168.1.20:8080/"
    )
    await expect(w.locate("progress")).to_be_hidden()
    await expect(page.get_by_role("button", name="Try anyway")).to_be_hidden()
    didnt_color = await didnt.evaluate("e => getComputedStyle(e).borderLeftColor")

    # Retry Wakes it again, and this time it answers.
    w.agent.reachable = True
    await page.get_by_role("button", name="Retry").click()
    await w.connected()
    await frame_text(w)

    # Later the base goes offline; nobody is connected meanwhile.
    await page.goto(f"{w.origin}/")
    await w.agent.run(minutes=3)  # the session ended (2 min after leaving)
    w.agent.reachable = False
    await w.agent.run(seconds=61)
    await w.open_remotely()

    offline = w.locate("offline")
    await expect(w.locate("status")).to_have_text("Offline")
    await expect(offline).to_be_visible()
    await expect(offline).to_contain_text("is offline, last seen")
    await expect(page.get_by_role("button", name="Try anyway")).to_be_visible()
    await expect(offline.locator("[data-field=open-locally]")).to_have_text(
        "Open locally (192.168.1.20)"
    )
    await expect(page.get_by_role("button", name="Retry")).to_be_hidden()
    await expect(w.locate("didnt-wake")).to_be_hidden()
    await expect(w.locate("progress")).to_be_hidden()
    offline_color = await offline.evaluate("e => getComputedStyle(e).borderLeftColor")
    assert offline_color != didnt_color

    # Try anyway Wakes it after all.
    w.agent.reachable = True
    await page.get_by_role("button", name="Try anyway").click()
    await w.connected()


# --- A base holding its tunnel ---------------------------------------------------------


async def test_a_holding_base_opens_at_once_without_waking(h: World):
    await record_states(h.page)
    await h.open_remotely()

    await expect(h.locate("status")).to_have_text("Connected")  # no time passed
    await frame_text(h)
    assert "waking" not in await seen_states(h.page)


async def test_a_holding_base_that_doesnt_answer_shows_didnt_wake_after_15_s(h: World):
    page = h.page
    h.agent.reachable = False
    await dropped(h)  # still online for 2 min: it may come back any moment
    await record_states(page)
    await h.open_remotely()

    await expect(h.locate("status")).to_have_text("Connecting to North field…")
    await expect(h.locate("progress")).to_be_visible()
    await expect(h.locate("hint-holding")).to_be_visible()
    await expect(h.locate("hint-polling")).to_be_hidden()
    await h.agent.run(seconds=14)
    await asyncio.sleep(0.2)
    await expect(h.locate("status")).to_have_text("Connecting to North field…")

    await h.agent.run(seconds=1)
    await expect(h.locate("status")).to_have_text("Didn't wake")
    await expect(h.locate("didnt-wake")).to_contain_text("North field didn't wake")
    await expect(h.locate("connection")).to_have_text("Reconnecting its tunnel")
    assert "waking" not in await seen_states(page)

    # It comes back by itself, and the bar connects with no Retry.
    h.agent.reachable = True
    await holding(h)
    await expect(h.locate("status")).to_have_text("Connected")
    await frame_text(h)


async def test_a_holding_base_whose_ui_never_answers_shows_didnt_wake_after_15_s(
    h: World,
):
    h.ui.answering = False  # its tunnel is up, but nothing answers down it
    await record_states(h.page)
    await h.open_remotely()

    await expect(h.locate("status")).to_have_text("Connected")
    await h.agent.run(seconds=14)
    await asyncio.sleep(0.2)
    await expect(h.locate("status")).to_have_text("Connected")

    await h.agent.run(seconds=1)
    await expect(h.locate("status")).to_have_text("Didn't wake")
    await expect(h.locate("didnt-wake")).to_contain_text("North field didn't wake")
    await expect(h.locate("connection")).to_have_text("Holding its tunnel")
    assert "waking" not in await seen_states(h.page)

    # Its UI answers after all: the bar connects with no Retry.
    h.ui.answering = True
    await expect(h.locate("status")).to_have_text("Connected")
    await frame_text(h)


async def test_a_dropped_held_tunnel_shows_reconnecting_for_up_to_75_s(h: World):
    page = h.page
    await h.open_remotely()
    await h.connected()
    await frame_text(h)
    path = await h.locate("frame").get_attribute("data-path")

    # Back within the agent's random first retry (0-60 s): same session.
    await dropped(h)
    await expect(h.locate("status")).to_have_text("Reconnecting…")
    await expect(h.locate("progress")).to_be_visible()
    await expect(h.locate("hint-holding")).to_be_visible()
    await expect(h.locate("hint-polling")).to_be_hidden()
    await h.agent.run(seconds=60)
    await expect(h.locate("status")).to_have_text("Connected")
    await expect(h.locate("frame")).to_have_attribute("data-path", path or "")
    await frame_text(h)
    assert page.url == f"{h.origin}/bases/{h.base_id}"

    # Not back: Reconnecting for 75 s, then Didn't wake.
    h.agent.reachable = False
    await dropped(h)
    await expect(h.locate("status")).to_have_text("Reconnecting…")
    await h.agent.run(seconds=74)
    await asyncio.sleep(0.2)
    await expect(h.locate("status")).to_have_text("Reconnecting…")
    await h.agent.run(seconds=1)
    await expect(h.locate("status")).to_have_text("Didn't wake")
    await expect(h.locate("didnt-wake")).to_be_visible()


# --- Reconnecting -------------------------------------------------------------------


async def test_a_dropped_tunnel_reconnects_once_then_shows_didnt_wake(w: World):
    page = w.page
    await w.open_remotely()
    await w.connected()
    await frame_text(w)
    path = await w.locate("frame").get_attribute("data-path")

    w.agent.drop_tunnel()
    await expect(w.locate("status")).to_have_text("Reconnecting…")
    await expect(w.locate("progress")).to_be_visible()
    await expect(w.locate("hint-polling")).to_be_visible()
    await expect(w.locate("hint-holding")).to_be_hidden()
    await w.agent.run(seconds=20)  # the Portal's own re-Wake
    await expect(w.locate("status")).to_have_text("Connected")
    await expect(w.locate("frame")).to_have_attribute("data-path", path or "")
    await frame_text(w)
    assert page.url == f"{w.origin}/bases/{w.base_id}"  # no new login

    w.agent.reachable = False
    w.agent.drop_tunnel()
    await expect(w.locate("status")).to_have_text("Reconnecting…")
    await w.agent.run(seconds=35)
    await expect(w.locate("status")).to_have_text("Didn't wake")
    await expect(w.locate("didnt-wake")).to_be_visible()


# --- Still there? and Session paused -------------------------------------------------


async def test_keep_going_at_55_min_extends_the_session_otherwise_it_pauses_at_60(
    w: World,
):
    page = w.page
    await w.open_remotely()
    await w.connected()
    still = w.locate("still-there")
    await expect(still).to_be_hidden()

    await w.agent.run(minutes=55)
    await expect(still).to_be_visible()
    await expect(still).to_contain_text("Still there?")
    await page.get_by_role("button", name="Keep going").click()
    await expect(still).to_be_hidden()

    await w.agent.run(minutes=10)  # 65 min in: still going
    await asyncio.sleep(0.2)
    await expect(w.locate("status")).to_have_text("Connected")
    old = await w.locate("frame").get_attribute("data-path")
    assert old

    await w.agent.run(minutes=45)  # 55 min after Keep going
    await expect(still).to_be_visible()
    await w.agent.run(minutes=5)  # nobody kept going
    await expect(w.locate("status")).to_have_text("Session paused")
    await expect(w.locate("frame")).to_have_count(0)
    await expect(still).to_be_hidden()
    refused = await page.request.get(w.origin + old)
    assert refused.status == 403

    await page.get_by_role("button", name="Reconnect").click()
    await w.connected()
    new = await w.locate("frame").get_attribute("data-path")
    assert new and new != old
    await frame_text(w)


# --- Tabs, presence, full screen -------------------------------------------------------


async def test_two_tabs_share_one_session_and_closing_both_closes_the_tunnel_2_min_later(
    w: World,
):
    await w.open_remotely()
    await w.connected()
    second = await w.page.context.new_page()
    await second.goto(f"{w.origin}/")
    await second.get_by_role("button", name="Open remotely").click()
    await expect(w.locate("status", second)).to_have_text("Connected")
    first_path = await w.locate("frame").get_attribute("data-path")
    assert await w.locate("frame", second).get_attribute("data-path") == first_path

    # One clock: Still there? reaches both tabs; Keep going in one clears both.
    await w.agent.run(minutes=55)
    await expect(w.locate("still-there")).to_be_visible()
    await expect(w.locate("still-there", second)).to_be_visible()
    await second.get_by_role("button", name="Keep going").click()
    await expect(w.locate("still-there")).to_be_hidden()

    [operator] = await w.portal.query("SELECT id FROM account WHERE email = %s", EMAIL)
    session = w.portal.context.tunnels.session_for(operator["id"], w.base_id)
    assert session is not None
    await w.page.close()
    await second.close()
    await eventually(lambda: session.attendants == 0, "the Portal saw both go")
    await w.agent.run(seconds=110)
    await asyncio.sleep(0.2)
    assert (await w.agent.status()).tunnel == "open"
    await w.agent.run(seconds=10)

    async def closed() -> bool:
        return (await w.agent.status()).tunnel == "closed"

    await eventually(closed, "the tunnel closed 2 min after both tabs closed")
    assert not w.portal.context.tunnels.tunnel_up(w.base_id)


async def test_presence_shows_who_else_is_connected_and_updates_when_they_leave(
    w: World,
    authentik: FakeAuthentik,
    browser_app: Browser,
):
    await w.open_remotely()
    await w.connected()
    presence = w.locate("presence")
    await expect(presence).to_be_hidden()

    authentik.add_user(OTHER, PASSWORD)
    sams = await browser_app.new_context()
    try:
        sam = await sams.new_page()
        await sam.goto(f"{w.origin}/login")
        await sam.get_by_label("Email").fill(OTHER)
        await sam.get_by_label("Password").fill(PASSWORD)
        await sam.get_by_role("button", name="Sign in").click()
        await sam.wait_for_url(f"{w.origin}/")
        shared = await w.page.request.post(
            f"{w.origin}/bases/{w.base_id}/shares",
            data={"email": OTHER},
            headers={"X-Portal-Action": "1", "Origin": w.origin},
        )
        assert shared.ok, await shared.text()
        await w.open_remotely(sam)

        await expect(presence).to_have_text(f"Also connected: {OTHER} (Shared user)")
        await expect(w.locate("presence", sam)).to_have_text(
            f"Also connected: {EMAIL} (Operator)"
        )
        await sam.close()
        await expect(presence).to_be_hidden()
    finally:
        await sams.close()


async def test_full_screen_hides_the_bar_and_restores_it(w: World):
    page = w.page
    await w.open_remotely()
    await w.connected()
    await expect(w.locate("back")).to_be_visible()

    await page.get_by_role("button", name="Full screen").click()

    await expect(w.locate("back")).to_be_hidden()
    await expect(w.locate("status")).to_be_hidden()
    await expect(page.locator(".topbar")).to_be_hidden()
    await frame_text(w)
    box = await w.locate("frame").bounding_box()
    assert box is not None and box["height"] >= 880  # the whole window

    await page.get_by_role("button", name="Exit full screen").click()

    await expect(w.locate("back")).to_be_visible()
    await expect(w.locate("status")).to_have_text("Connected")
    await expect(page.get_by_role("button", name="Exit full screen")).to_be_hidden()
    await frame_text(w)

    # Anything the user must see ends full screen.
    await page.get_by_role("button", name="Full screen").click()
    await w.agent.run(minutes=55)
    await expect(w.locate("still-there")).to_be_visible()
    await expect(w.locate("back")).to_be_visible()
