"""Seam 2: a base with remote access paused, in real browsers (Chromium and
Firefox, via Playwright; ticket #92).

The base list shows "Remote access paused" with Open remotely disabled,
distinct from Offline; and a Session bar open when the base is paused says
so. Didn't wake is a Session bar state (#90), not a list state.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest
from playwright.async_api import Browser, Page, async_playwright, expect

from .harness.agent import RunningAgent, running_agent
from .harness.base_ui import BaseUi, base_ui
from .harness.clock import FakeClock
from .harness.fake_authentik import FakeAuthentik
from .harness.portal import Portal, running_portal
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


async def sign_in(page: Page, portal: Portal) -> None:
    await page.goto(f"{portal.origin}/login")
    await page.get_by_label("Email").fill(EMAIL)
    await page.get_by_label("Password").fill(PASSWORD)
    await page.get_by_role("button", name="Sign in").click()
    await page.wait_for_url(f"{portal.origin}/")


async def claim(page: Page, portal: Portal, agent: RunningAgent, name: str) -> str:
    pairing = await agent.connect()
    await page.goto(f"{portal.origin}/claim?code={pairing.user_code}")
    await page.get_by_label("Name").fill(name)
    await page.get_by_role("button", name="Approve").click()
    await page.wait_for_url(f"{portal.origin}/")
    status = await agent.until("connected")
    assert status.base_id
    return status.base_id


async def test_paused_offline_and_online_bases_look_different_in_the_list(
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
        running_agent(portal, server_port=port, app_port=served.port) as north,
        running_agent(
            portal, ip="198.51.100.31", server_port=port, app_port=served.port
        ) as south,
    ):
        page = await browser_app.new_page()
        await sign_in(page, portal)
        north_id = await claim(page, portal, north, "North field")
        south_id = await claim(page, portal, south, "South field")

        await north.pause()
        await south.stop()  # South goes quiet...
        await north.run(minutes=2)  # ...while North keeps polling, paused
        await page.reload()

        paused = page.locator(f"li[data-base='{north_id}']")
        offline = page.locator(f"li[data-base='{south_id}']")
        await expect(paused.locator("[data-field=state]")).to_have_text(
            "Remote access paused"
        )
        await expect(offline.locator("[data-field=state]")).to_have_text("Offline")
        await expect(
            paused.get_by_role("button", name="Open remotely")
        ).to_be_disabled()
        await expect(
            offline.get_by_role("button", name="Open remotely")
        ).to_be_enabled()

        await north.resume()
        await page.reload()

        await expect(paused.locator("[data-field=state]")).to_have_text("Online")
        await expect(paused.get_by_role("button", name="Open remotely")).to_be_enabled()


async def test_an_open_session_bar_says_when_the_base_is_paused(
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
        await claim(page, portal, agent, "North field")
        await page.reload()
        await page.get_by_role("button", name="Open remotely").click()
        status = page.locator("[data-field=status]")
        await expect(status).to_have_text("Waking North field…")
        await agent.run(seconds=20)
        await expect(status).to_have_text("Connected")

        await agent.pause()

        await expect(status).to_have_text("Remote access paused")
        await expect(page.locator("[data-field=remote-paused]")).to_be_visible()
        assert await page.locator("[data-field=frame]").count() == 0
