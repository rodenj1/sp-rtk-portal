"""Seam 2: the Session bar in real browsers (Chromium and Firefox, via
Playwright).

The Portal is served at ``http://localhost:<port>`` (its public origin for
this test, so the browser's ``Origin`` matches and its ``__Host-`` cookie is
kept: browsers treat localhost as secure). The real agent polls on virtual
time, so "within the poll interval" is checked by letting exactly one poll
interval pass.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Iterator

import pytest
from playwright.async_api import Browser, Page, async_playwright, expect

from .harness.agent import running_agent
from .harness.base_ui import BaseUi, base_ui
from .harness.clock import FakeClock
from .harness.fake_authentik import FakeAuthentik
from .harness.portal import Portal, running_portal
from .harness.real_base import RealBase, real_base
from .harness.server import free_socket, serving

EMAIL = "operator@example.com"
PASSWORD = "correct horse battery staple"


@pytest.fixture(params=["chromium", "firefox"])
async def browser_app(request: pytest.FixtureRequest) -> AsyncIterator[Browser]:
    async with async_playwright() as p:
        browser = await getattr(p, request.param).launch()
        try:
            yield browser
        finally:
            await browser.close()


@pytest.fixture
async def served() -> AsyncIterator[BaseUi]:
    async with base_ui() as ui:
        yield ui


async def test_open_remotely_shows_waking_with_the_hint_then_connected(
    database_url: str,
    clock: FakeClock,
    authentik: FakeAuthentik,
    browser_app: Browser,
    served: BaseUi,
):
    sock = free_socket()
    origin = f"http://localhost:{sock.getsockname()[1]}"
    authentik.add_user(EMAIL, PASSWORD)
    async with (
        running_portal(database_url, clock, authentik, origin=origin) as portal,
        serving(portal.app, sock) as port,
        running_agent(portal, server_port=port, app_port=served.port) as agent,
    ):
        page = await browser_app.new_page()
        await sign_in(page, portal)
        pairing = await agent.connect()
        await page.goto(f"{origin}/claim?code={pairing.user_code}")
        await page.get_by_label("Name").fill("North field")
        await page.get_by_role("button", name="Approve").click()
        await page.wait_for_url(f"{origin}/")
        await agent.until("connected")
        await page.reload()

        await page.get_by_role("button", name="Open remotely").click()

        status = page.locator("[data-field=status]")
        await expect(status).to_have_text("Waking North field…")
        await expect(page.locator("[data-field=hint]")).to_contain_text(
            "checks for requests every 20 s"
        )
        await expect(page.locator("[data-field=progress]")).to_be_visible()

        await agent.run(seconds=20)  # one poll interval: the Wake's poll

        await expect(status).to_have_text("Connected")
        await expect(page.locator("[data-field=progress]")).to_be_hidden()
        assert (await agent.status()).tunnel == "open"


@pytest.fixture(scope="module")
def sp_rtk_base() -> Iterator[RealBase]:
    with real_base() as base:
        yield base


async def test_the_base_ui_works_in_the_sandboxed_frame_with_its_live_event_log(
    database_url: str,
    clock: FakeClock,
    authentik: FakeAuthentik,
    browser_app: Browser,
    sp_rtk_base: RealBase,
):
    sock = free_socket()
    origin = f"http://localhost:{sock.getsockname()[1]}"
    authentik.add_user(EMAIL, PASSWORD)
    async with (
        running_portal(database_url, clock, authentik, origin=origin) as portal,
        serving(portal.app, sock) as port,
        running_agent(portal, server_port=port, app_port=sp_rtk_base.port) as agent,
    ):
        page = await browser_app.new_page(viewport={"width": 1400, "height": 1000})
        await sign_in(page, portal)
        await claim(page, agent, origin)
        await page.get_by_role("button", name="Open remotely").click()
        await expect(page.locator("[data-field=status]")).to_have_text(
            "Waking North field…"
        )

        async with page.expect_websocket(
            lambda ws: ws.url.endswith("/api/events/ws"), timeout=30_000
        ) as opened:
            await agent.run(seconds=20)  # the Wake's poll
            await expect(page.locator("[data-field=status]")).to_have_text("Connected")
        event_log = await opened.value
        await event_log.wait_for_event("framereceived", timeout=20_000)

        iframe = page.locator("iframe[data-field=frame]")
        assert await iframe.get_attribute("sandbox") == (
            "allow-scripts allow-forms allow-downloads"
        )
        await expect(page.locator("[data-field=frame-label]")).to_contain_text(
            "served by the base"
        )
        base = page.frame_locator("iframe[data-field=frame]")
        await expect(base.get_by_text("Dashboard").first).to_be_visible(timeout=15_000)
        handle = await iframe.element_handle()
        assert handle is not None
        frame = await handle.content_frame()
        assert frame is not None
        assert await frame.evaluate("() => self.origin") == "null"
        assert "/b/" in event_log.url

        text = await asyncio.to_thread(sp_rtk_base.start_relay)
        try:
            await expect(
                base.get_by_test_id("event-log").get_by_text(text).first
            ).to_be_visible(timeout=15_000)
        finally:
            await asyncio.to_thread(sp_rtk_base.stop_relay)
        assert page.url == f"{origin}/bases/{(await agent.status()).base_id}"


async def test_the_session_bar_ignores_message_events(
    database_url: str,
    clock: FakeClock,
    authentik: FakeAuthentik,
    browser_app: Browser,
    served: BaseUi,
):
    sock = free_socket()
    origin = f"http://localhost:{sock.getsockname()[1]}"
    authentik.add_user(EMAIL, PASSWORD)
    async with (
        running_portal(database_url, clock, authentik, origin=origin) as portal,
        serving(portal.app, sock) as port,
        running_agent(portal, server_port=port, app_port=served.port) as agent,
    ):
        page = await browser_app.new_page()
        await sign_in(page, portal)
        await claim(page, agent, origin)
        await page.get_by_role("button", name="Open remotely").click()
        status = page.locator("[data-field=status]")
        await expect(status).to_have_text("Waking North field…")
        await agent.run(seconds=20)
        await expect(status).to_have_text("Connected")

        heard = await page.evaluate(
            """() => new Promise((resolve) => {
                let heard = false;
                window.addEventListener("message", () => { heard = true; });
                window.postMessage({"state": "ended"}, "*");
                setTimeout(() => resolve(heard), 200);
            })"""
        )

        assert heard is False
        await expect(page.locator("[data-field=status]")).to_have_text("Connected")


async def claim(page: Page, agent: object, origin: str) -> None:
    pairing = await agent.connect()  # type: ignore[attr-defined]
    await page.goto(f"{origin}/claim?code={pairing.user_code}")
    await page.get_by_label("Name").fill("North field")
    await page.get_by_role("button", name="Approve").click()
    await page.wait_for_url(f"{origin}/")
    await agent.until("connected")  # type: ignore[attr-defined]
    await page.reload()


async def sign_in(page: Page, portal: Portal) -> None:
    await page.goto(f"{portal.origin}/login")
    await page.get_by_label("Email").fill(EMAIL)
    await page.get_by_label("Password").fill(PASSWORD)
    await page.get_by_role("button", name="Sign in").click()
    await page.wait_for_url(f"{portal.origin}/")
