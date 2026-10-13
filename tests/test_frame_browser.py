"""Seam 2: the real sp-rtk-base in the Session bar's sandboxed frame, through
the real Portal, in real browsers (spec #82 "Testing Decisions", ADR 0004).

Remote use isn't second-class: every base page renders as it does directly
on the base, its live parts stay live, and its links, ``ui.navigate.to`` and
``ui.download`` work. And base pages are isolated: nothing in the frame can
read or drive the Portal page or act as the signed-in user. That isolation
rests on two layers, the iframe's ``sandbox`` attribute and the proxy's
``Content-Security-Policy: sandbox`` header on every base answer, so the
suite checks each one on its own.

Runs in Chromium and Firefox, and in WebKit where the host can launch it
(otherwise skipped with the reason; ``PORTAL_TEST_REQUIRE_WEBKIT=1`` turns
that skip into a failure, as CI does). ``PORTAL_TEST_WEBKIT`` names a WebKit
executable to use instead of Playwright's (a wrapper that supplies WebKit's
system libraries on a host that lacks them). Safari itself is a manual
launch check (README).
"""

from __future__ import annotations

import asyncio
import json
import os
from collections.abc import AsyncIterator, Iterator

import pytest
from playwright.async_api import Browser, Frame, Page, async_playwright, expect
from playwright.async_api import Error as PlaywrightError

from .harness.clock import FakeClock
from .harness.fake_authentik import FakeAuthentik
from .harness.frame import SOCKET_CONNECTED, Remote, remote_frame
from .harness.real_base import RealBase, real_base

SANDBOX = "allow-scripts allow-forms allow-downloads"

# (the base's path, a heading that page shows)
PAGES = [
    ("/", "Dashboard"),
    ("/input", "Input"),
    ("/outputs", "Destinations"),
    ("/survey", "Survey-In"),
    ("/network", "Network"),
    ("/settings", "Settings"),
    ("/gps-config", "Advanced GPS"),
    ("/portal", "Portal"),
]

# Where a page's boxes are and how its body is styled: equal when the page
# lays out the same (its stylesheets, fonts and components all loaded).
LAYOUT = """() => {
  const boxes = [...document.querySelectorAll(
    'header, aside, .q-drawer, .q-card, .q-btn, .q-item, .q-tab, .q-table,'
    + ' .q-field, .q-toggle, .q-badge, label, h1, h2, h3, h4, h5, h6,'
    + ' .nicegui-content > *'
  )].map((e) => e.getBoundingClientRect())
    .filter((r) => r.width > 0 && r.height > 0)
    .map((r) => [r.x, r.y, r.width, r.height].map(Math.round));
  const body = getComputedStyle(document.body);
  return {body: [body.backgroundColor, body.color, body.fontFamily], boxes};
}"""


@pytest.fixture(params=["chromium", "firefox", "webkit"])
async def engine(request: pytest.FixtureRequest) -> AsyncIterator[Browser]:
    async with async_playwright() as p:
        if request.param == "webkit":
            browser = await _webkit(p)
        else:
            browser = await getattr(p, request.param).launch()
        try:
            yield browser
        finally:
            await browser.close()


async def _webkit(p: object) -> Browser:
    try:
        return await p.webkit.launch(  # type: ignore[attr-defined]
            executable_path=os.environ.get("PORTAL_TEST_WEBKIT") or None
        )
    except PlaywrightError as e:
        if os.environ.get("PORTAL_TEST_REQUIRE_WEBKIT") == "1":
            raise
        reason = " ".join(str(e).split())[:300]
        pytest.skip(f"WebKit can't launch on this host: {reason}")


@pytest.fixture(scope="module")
def sp_rtk_base() -> Iterator[RealBase]:
    with real_base(appliance=True) as base:  # every page, Network too
        yield base


@pytest.fixture
async def remote(
    database_url: str,
    clock: FakeClock,
    authentik: FakeAuthentik,
    engine: Browser,
    sp_rtk_base: RealBase,
) -> AsyncIterator[Remote]:
    async with remote_frame(database_url, clock, authentik, engine, sp_rtk_base) as r:
        yield r


async def test_every_base_page_renders_in_the_frame_as_it_does_directly(
    remote: Remote, engine: Browser, sp_rtk_base: RealBase
):
    frame = await remote.connected()
    width, height = await frame.evaluate("() => [innerWidth, innerHeight]")
    direct = await engine.new_page(viewport={"width": width, "height": height})

    for path, heading in PAGES:
        framed = await remote.go(path)  # socket.io up on this page
        await direct.goto(sp_rtk_base.url + path)

        await expect(remote.base.get_by_text(heading).first).to_be_visible()
        await _until_same_layout(framed, direct, path)
        assert await framed.evaluate("() => self.origin") == "null"


async def _until_same_layout(framed: Frame, direct: Page, path: str) -> None:
    """Both settle into the same layout (live values arrive over socket.io,
    so allow them a moment)."""
    for _ in range(50):
        ours = await framed.evaluate(LAYOUT)
        theirs = await direct.evaluate(LAYOUT)
        if ours == theirs and ours["boxes"]:
            return
        await asyncio.sleep(0.2)
    assert ours == theirs, f"{path} lays out differently in the frame"


async def test_the_base_stays_live_in_the_frame_for_30_s(
    remote: Remote, sp_rtk_base: RealBase
):
    frame = await remote.connected()
    await frame.evaluate(
        """() => {
            window.__drops = 0;
            window.__updates = 0;
            window.socket.on("disconnect", () => window.__drops++);
            window.socket.on("update", () => window.__updates++);
        }"""
    )

    await asyncio.sleep(30)

    assert await frame.evaluate(SOCKET_CONNECTED)
    assert await frame.evaluate("() => window.__drops") == 0
    assert await frame.evaluate("() => window.__updates") > 0
    # The live Event log came through the frame's prefix, and still streams.
    prefix = await remote.frame_path()
    assert [s.status for s in remote.requests.to(f"{prefix}api/events/ws")] == [101]
    text = await asyncio.to_thread(sp_rtk_base.start_relay)
    try:
        log = remote.base.get_by_test_id("event-log")
        await expect(log.get_by_text(text).first).to_be_visible(timeout=15_000)
    finally:
        await asyncio.to_thread(sp_rtk_base.stop_relay)


async def test_drawer_links_and_navigate_to_move_the_frame_not_the_page(
    remote: Remote, sp_rtk_base: RealBase
):
    await remote.connected()
    bar = remote.page.url
    prefix = (await remote.frame_path()).rstrip("/")

    await remote.base.locator("button:has(i:text('menu'))").first.click()
    await remote.base.locator(f'a[href="{prefix}/survey"]').first.click()

    await remote.until_at(await remote.url("/survey"))
    await expect(remote.base.get_by_text("Survey-In").first).to_be_visible()
    assert remote.page.url == bar

    with sp_rtk_base.connected_gps():
        await remote.go("/gps-config")
        card = remote.base.locator(".fixed-position-card")
        await expect(card).to_be_visible(timeout=15_000)

        await card.locator(".fixed-position-survey-link").click()  # ui.navigate.to

        await remote.until_at(await remote.url("/survey"))
    assert remote.page.url == bar


async def test_a_base_download_arrives_as_a_file(remote: Remote, sp_rtk_base: RealBase):
    name = "portal-frame-export"
    with sp_rtk_base.connected_gps(), sp_rtk_base.profile(name):
        await remote.go("/gps-config")
        base = remote.base
        await expect(base.locator(".rtcm-cell-1005-UART1")).to_have_text(
            "✓", timeout=15_000
        )
        await base.locator(".profile-picker").click()
        # Not a real click: WebKit's headless build never finishes the menu's
        # fade-in, so to Playwright the option is never clickable there.
        await base.locator(f".profile-option-{name}").dispatch_event("click")
        export = base.locator(".profile-export-icon")
        await expect(export).to_be_visible(timeout=10_000)

        async with remote.page.expect_download(timeout=15_000) as info:
            await export.click()  # ui.download

        download = await info.value
        assert download.suggested_filename == f"{name}.json"
        path = await download.path()
        assert json.loads(path.read_text())["name"] == name
