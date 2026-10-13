"""Seam 2: the Session bar in real browsers (Chromium and Firefox, via
Playwright).

The Portal is served at ``http://localhost:<port>`` (its public origin for
this test, so the browser's ``Origin`` matches and its ``__Host-`` cookie is
kept: browsers treat localhost as secure). The real agent polls on virtual
time, so "within the poll interval" is checked by letting exactly one poll
interval pass.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest
from playwright.async_api import Browser, Page, async_playwright, expect

from .harness.agent import running_agent
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


async def sign_in(page: Page, portal: Portal) -> None:
    await page.goto(f"{portal.origin}/login")
    await page.get_by_label("Email").fill(EMAIL)
    await page.get_by_label("Password").fill(PASSWORD)
    await page.get_by_role("button", name="Sign in").click()
    await page.wait_for_url(f"{portal.origin}/")
