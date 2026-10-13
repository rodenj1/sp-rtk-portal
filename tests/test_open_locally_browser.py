"""Seam 2: Local access detection on the base list, in real browsers
(ticket #97).

Chromium's Local Network Access only applies to a request from a less
private address to a more private one, and in a test everything is on
loopback. So Chromium is told (``--ip-address-space-overrides``) that the
Portal's address is public and each base's is local, which is what it sees in
production: the Portal behind Cloudflare, the base on the user's LAN. Each
base listens on its own loopback address (127.0.0.2, ...), standing in for
its LAN address, and the Portal links them on the test's port instead of
8080 (``Settings.base_ui_port``).

Headless Chromium denies a permission prompt at once, so "the click prompts"
is checked as "the click makes the request that prompts", and "no prompt"
as "no request to the base".
"""

from __future__ import annotations

import asyncio
import dataclasses
import socket
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass

import pytest
from playwright.async_api import (
    Browser,
    BrowserContext,
    Locator,
    Page,
    async_playwright,
    expect,
)
from playwright.async_api import (
    Request as PageRequest,
)
from sp_rtk_portal_protocol import LanAddress
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from .harness.agent import RunningAgent, running_agent
from .harness.base_ui import base_ui
from .harness.clock import FakeClock
from .harness.fake_authentik import FakeAuthentik
from .harness.portal import Portal, running_portal
from .harness.real_base import RealBase, real_base
from .harness.server import free_socket, serving
from .test_session_bar_browser import EMAIL, PASSWORD, claim, sign_in

BASE = "127.0.0.2"
"""The Claimed base's LAN address (the real sp-rtk-base listens here)."""
OTHER = "127.0.0.3"
"""Another base's address: it answers with another ``<id>``."""
NOBODY = "127.0.0.4"
"""Nothing listens here."""
PERMISSION = "local-network-access"
"""Playwright's name for Chromium's local-network permissions."""


def _port_on(*hosts: str) -> int:
    """A port free on every one of ``hosts``."""
    while True:
        with socket.socket() as s:
            s.bind((hosts[0], 0))
            port = int(s.getsockname()[1])
        try:
            for host in hosts[1:]:
                with socket.socket() as s:
                    s.bind((host, port))
            return port
        except OSError:
            continue


@dataclass
class Lan:
    portal: Portal
    origin: str
    agent: RunningAgent
    port: int
    """The base UI port on every LAN address."""
    browser: Browser
    base: RealBase | None = None

    def url(self, address: str) -> str:
        return f"http://{address}:{self.port}/"

    def identity(self, address: str) -> str:
        return self.url(address) + "api/portal/identity"

    async def base_id(self) -> str:
        base_id = (await self.agent.status()).base_id
        assert base_id
        return base_id

    async def move_to(self, address: str) -> None:
        """The base's next Check-in reports ``address`` as its primary LAN
        address."""
        self.agent.lan = [LanAddress(address=address, interface="eth0", primary=True)]
        await self.agent.run(minutes=5)

    async def signed_in(self, *, granted: bool) -> tuple[BrowserContext, Page]:
        context = await self.browser.new_context()
        if granted:
            await context.grant_permissions([PERMISSION])
        page = await context.new_page()
        await sign_in(page, self.portal)
        return context, page

    def card(self, page: Page, base_id: str) -> Locator:
        return page.locator(f"li[data-base='{base_id}']")


def _chromium_args(portal_port: int, ui_port: int, *public_ports: int) -> list[str]:
    spaces = [f"127.0.0.1:{p}=public" for p in (portal_port, *public_ports)]
    spaces += [f"{a}:{ui_port}=local" for a in (BASE, OTHER, NOBODY)]
    return [f"--ip-address-space-overrides={','.join(spaces)}"]


@asynccontextmanager
async def lan(
    database_url: str,
    clock: FakeClock,
    authentik: FakeAuthentik,
    browser_name: str = "chromium",
    *,
    with_real_base: bool = True,
    public_ports: tuple[int, ...] = (),
) -> AsyncIterator[Lan]:
    """A signed-up Operator, the Portal, and a base Claimed at ``BASE``."""
    sock = free_socket()
    portal_port = int(sock.getsockname()[1])
    origin = f"http://localhost:{portal_port}"
    ui_port = _port_on(BASE, OTHER, NOBODY)
    authentik.add_user(EMAIL, PASSWORD)
    async with (
        running_portal(database_url, clock, authentik, origin=origin) as portal,
        serving(portal.app, sock) as port,
        base_ui() as served,
        running_agent(portal, server_port=port, app_port=served.port) as agent,
        async_playwright() as p,
    ):
        portal.context.settings = dataclasses.replace(
            portal.context.settings, base_ui_port=ui_port
        )
        agent.lan = [LanAddress(address=BASE, interface="eth0", primary=True)]
        kind = getattr(p, browser_name)
        args = (
            _chromium_args(portal_port, ui_port, *public_ports)
            if browser_name == "chromium"
            else []
        )
        browser = await kind.launch(args=args)
        try:
            setup = Lan(portal, origin, agent, ui_port, browser)
            context = await browser.new_context()
            page = await context.new_page()
            await sign_in(page, portal)
            await claim(page, agent, origin)
            await context.close()
            if with_real_base:
                async with _real_base(agent, origin, ui_port) as base:
                    setup.base = base
                    yield setup
            else:
                yield setup
        finally:
            await browser.close()


@asynccontextmanager
async def _real_base(
    agent: RunningAgent, origin: str, port: int
) -> AsyncIterator[RealBase]:
    """The real sp-rtk-base at ``BASE``: its identity endpoint reads the
    agent's state dir and admits the Portal's origin."""
    cm = real_base(
        host=BASE,
        port=port,
        extra_env={
            "SP_RTK_BASE_PORTAL_AGENT_STATE": str(agent.state_dir),
            "SP_RTK_BASE_PORTAL_URL": origin,
        },
    )
    base = await asyncio.to_thread(cm.__enter__)
    try:
        yield base
    finally:
        await asyncio.to_thread(cm.__exit__, None, None, None)


@asynccontextmanager
async def identity_stub(
    address: str, port: int, base_id: str, origin: str
) -> AsyncIterator[None]:
    """Some other base on the LAN: its identity endpoint answers the Portal
    with ``base_id``."""

    async def identity(request: Request) -> Response:
        response = JSONResponse({"id": base_id})
        if request.headers.get("origin") == origin:
            response.headers["Access-Control-Allow-Origin"] = origin
        return response

    app = Starlette(routes=[Route("/api/portal/identity", identity)])
    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((address, port))
    async with serving(app, sock):
        yield


def _requests_to(page: Page, address: str) -> list[str]:
    seen: list[str] = []
    page.on("request", lambda r: seen.append(r.url) if address in r.url else None)
    return seen


async def _checked(page: Page, url: str) -> None:
    """Wait until the page's check of ``url`` is over, however it ended."""
    done = asyncio.get_running_loop().create_future()

    def finished(request: PageRequest) -> None:
        if request.url == url and not done.done():
            done.set_result(None)

    page.on("requestfinished", finished)
    page.on("requestfailed", finished)
    await page.reload()
    await asyncio.wait_for(done, 10)


# --- Chromium, permission already granted --------------------------------------------


async def test_with_the_permission_a_base_that_answers_its_id_is_opened_locally(
    database_url: str, clock: FakeClock, authentik: FakeAuthentik
):
    async with lan(database_url, clock, authentik) as setup:
        base_id = await setup.base_id()
        _, page = await setup.signed_in(granted=True)
        await page.goto(f"{setup.origin}/")
        card = setup.card(page, base_id)

        go = card.locator("[data-field=go-local]")
        await expect(go).to_be_visible()
        await expect(card.locator("[data-field=local-confirmed]")).to_have_text(
            "On this network"
        )
        await expect(card.locator("[data-field=open-remotely]")).to_be_hidden()
        await expect(page.locator("[data-field=detect]")).to_be_hidden()
        assert await go.get_attribute("href") == setup.url(BASE)

        await go.click()
        await page.wait_for_url(setup.url(BASE) + "**")
        await expect(page.get_by_text("Dashboard").first).to_be_visible(timeout=15_000)


async def test_with_the_permission_another_bases_id_or_no_answer_stays_unconfirmed(
    database_url: str, clock: FakeClock, authentik: FakeAuthentik
):
    async with lan(database_url, clock, authentik, with_real_base=False) as setup:
        base_id = await setup.base_id()
        _, page = await setup.signed_in(granted=True)
        card = setup.card(page, base_id)

        async with identity_stub(OTHER, setup.port, "SOMEONEELSE", setup.origin):
            await setup.move_to(OTHER)
            await _checked(page, setup.identity(OTHER))
            await expect(card.locator("[data-field=go-local]")).to_be_hidden()
            await expect(card.locator("[data-field=open-locally]")).to_have_text(
                f"Open locally ({OTHER})"
            )

        await setup.move_to(NOBODY)
        await _checked(page, setup.identity(NOBODY))
        await expect(card.locator("[data-field=go-local]")).to_be_hidden()
        await expect(card.locator("[data-field=open-locally]")).to_have_text(
            f"Open locally ({NOBODY})"
        )
        await expect(card.locator("[data-field=open-remotely]")).to_be_visible()


async def test_open_remotely_instead_starts_a_remote_session(
    database_url: str, clock: FakeClock, authentik: FakeAuthentik
):
    async with lan(database_url, clock, authentik, with_real_base=False) as setup:
        base_id = await setup.base_id()
        async with identity_stub(OTHER, setup.port, base_id, setup.origin):
            await setup.move_to(OTHER)
            _, page = await setup.signed_in(granted=True)
            card = setup.card(page, base_id)
            await expect(card.locator("[data-field=go-local]")).to_be_visible()

            await card.get_by_role("button", name="Open remotely instead").click()

            await page.wait_for_url(f"{setup.origin}/bases/{base_id}")
            await expect(page.locator("[data-field=status]")).to_have_text(
                "Waking North field…"
            )


# --- Chromium, permission not granted ----------------------------------------------


async def test_without_the_permission_nothing_is_checked_until_detect_is_clicked(
    database_url: str, clock: FakeClock, authentik: FakeAuthentik
):
    async with lan(database_url, clock, authentik, with_real_base=False) as setup:
        base_id = await setup.base_id()
        context = await setup.browser.new_context()
        page = await context.new_page()
        await sign_in(page, setup.portal)  # lands on the base list
        seen = _requests_to(page, BASE)
        await page.reload()

        detect = page.get_by_role("button", name="Detect bases on this network")
        await expect(detect).to_be_visible()
        await page.wait_for_load_state("networkidle")
        assert seen == []
        assert (
            await page.evaluate(
                "async () => (await navigator.permissions.query("
                "{name: 'local-network'})).state"
            )
            == "prompt"
        )

        async with page.expect_request(setup.identity(BASE)):
            await detect.click()

        card = setup.card(page, base_id)
        await expect(card.locator("[data-field=go-local]")).to_be_hidden()
        await expect(card.locator("[data-field=open-locally]")).to_be_visible()


# --- Firefox -------------------------------------------------------------------------


async def test_firefox_never_checks_and_open_locally_is_a_plain_link(
    database_url: str, clock: FakeClock, authentik: FakeAuthentik
):
    async with lan(
        database_url, clock, authentik, "firefox", with_real_base=False
    ) as setup:
        base_id = await setup.base_id()
        _, page = await setup.signed_in(granted=False)
        seen = _requests_to(page, BASE)
        await page.reload()
        await page.wait_for_load_state("networkidle")

        card = setup.card(page, base_id)
        link = card.get_by_role("link", name=f"Open locally ({BASE})")
        await expect(link).to_be_visible()
        assert await link.get_attribute("href") == setup.url(BASE)
        await expect(page.locator("[data-field=detect]")).to_be_hidden()
        await expect(card.locator("[data-field=go-local]")).to_be_hidden()
        assert seen == []


# --- The identity endpoint's CORS policy ------------------------------------------


@pytest.fixture
def other_site() -> int:
    """A port for a page on another origin than the Portal's."""
    with free_socket() as sock:
        return int(sock.getsockname()[1])


async def test_the_bases_identity_endpoint_answers_only_the_portal_origin(
    database_url: str, clock: FakeClock, authentik: FakeAuthentik, other_site: int
):
    async with lan(database_url, clock, authentik, public_ports=(other_site,)) as setup:
        base_id = await setup.base_id()
        context, page = await setup.signed_in(granted=True)
        fetch = (
            "async (url) => { try { const r = await fetch(url,"
            " {targetAddressSpace: 'local'}); return (await r.json()).id; }"
            " catch (e) { return 'refused: ' + e.name; } }"
        )
        assert await page.evaluate(fetch, setup.identity(BASE)) == base_id

        app = Starlette(routes=[Route("/", lambda r: Response("<!doctype html>"))])
        sock = socket.socket()
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", other_site))
        async with serving(app, sock):
            other = await context.new_page()
            errors: list[str] = []
            other.on("console", lambda m: errors.append(m.text))
            await other.goto(f"http://127.0.0.1:{other_site}/")

            answer = await other.evaluate(fetch, setup.identity(BASE))

        assert answer == "refused: TypeError"
        assert any("Access-Control-Allow-Origin" in e for e in errors), errors
