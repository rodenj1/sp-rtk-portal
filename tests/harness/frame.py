"""A real browser on a Remote session, with the real sp-rtk-base in the
Session bar's sandboxed frame (seam 2, ADR 0004).

``remote_frame(...)`` serves the Portal at ``https://localhost:<port>`` (its
public origin; a throwaway certificate the browser is told to accept, since
WebKit keeps the ``__Host-`` cookie only over HTTPS) plus a plain listener for
the agent's tunnel, runs the real agent pointed at a ``RealBase``, signs in, Claims the
base through the real pages, presses "Open remotely", lets the Wake's poll
happen and waits for Connected. Every request that reaches the Portal is
recorded (``Remote.requests``), so tests can see what a framed page sent and
what came back.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import AsyncIterator, Awaitable, Callable, MutableMapping
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any

from playwright.async_api import Browser, Frame, FrameLocator, Page, expect
from playwright.async_api import Error as PlaywrightError

from .agent import RunningAgent, running_agent
from .clock import FakeClock
from .fake_authentik import FakeAuthentik
from .portal import Portal, running_portal
from .real_base import RealBase
from .server import free_socket, localhost_tls, serving

EMAIL = "operator@example.com"
PASSWORD = "correct horse battery staple"
NAME = "North field"
FRAME = "iframe[data-field=frame]"
SOCKET_CONNECTED = "() => !!(window.socket && window.socket.connected)"

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]


@dataclass
class Seen:
    """One request as it reached the Portal, and what the Portal answered."""

    kind: str  # "http" | "websocket"
    method: str
    path: str
    headers: dict[str, str]
    status: int | None = None
    response_headers: dict[str, str] = field(default_factory=dict)


def _headers(raw: Any) -> dict[str, str]:
    out: dict[str, str] = {}
    for k, v in raw:
        name = k.decode("latin-1").lower()
        value = v.decode("latin-1")
        out[name] = f"{out[name]}, {value}" if name in out else value
    return out


class Recorder:
    """ASGI wrapper around the Portal app that keeps every request it gets."""

    def __init__(self, app: Any) -> None:
        self.app = app
        self.seen: list[Seen] = []

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return
        seen = Seen(
            scope["type"],
            scope.get("method", "GET"),
            scope["path"],
            _headers(scope["headers"]),
        )
        self.seen.append(seen)

        async def recording(message: Message) -> None:
            kind = message["type"]
            if kind in ("http.response.start", "websocket.http.response.start"):
                seen.status = message["status"]
                seen.response_headers = _headers(message.get("headers", []))
            elif kind == "websocket.accept":
                seen.status = 101
            elif kind == "websocket.close" and seen.status is None:
                seen.status = 403  # closed before accepting: the server says 403
            await send(message)

        await self.app(scope, receive, recording)

    def to(self, path: str) -> list[Seen]:
        return [s for s in self.seen if s.path == path]

    def mark(self) -> int:
        """Where the record is now: ``since(mark)`` is what came after."""
        return len(self.seen)

    def since(self, mark: int) -> list[Seen]:
        return self.seen[mark:]


@dataclass
class Remote:
    page: Page
    portal: Portal
    agent: RunningAgent
    origin: str
    base_id: str
    requests: Recorder

    @property
    def base(self) -> FrameLocator:
        """The base's UI, for locators inside the frame."""
        return self.page.frame_locator(FRAME)

    async def frame(self) -> Frame:
        handle = await self.page.locator(FRAME).element_handle()
        assert handle is not None
        frame = await handle.content_frame()
        assert frame is not None
        return frame

    async def frame_path(self) -> str:
        path = await self.page.locator(FRAME).get_attribute("data-path")
        assert path is not None
        return path

    async def connected(self, timeout: float = 15_000) -> Frame:
        """The frame, once its page's socket.io connection is up."""
        frame = await self.frame()
        await frame.wait_for_function(SOCKET_CONNECTED, timeout=timeout)
        return frame

    async def url(self, path: str) -> str:
        """The frame URL of the base's own ``path``."""
        return self.origin + await self.frame_path() + path.lstrip("/")

    async def go(self, path: str) -> Frame:
        """Move the frame to the base's ``path`` from inside it (what a base
        link does); returns it once that page's socket.io is up."""
        url = await self.url(path)
        frame = await self.frame()
        await frame.evaluate("url => location.assign(url)", url)
        return await self.until_at(url)

    async def until_at(self, url: str, timeout: float = 15) -> Frame:
        """Wait until the frame shows ``url`` with its socket.io connected.
        Asks the page itself: Playwright's ``Frame.url`` goes stale in
        Firefox after a sandboxed frame navigates itself."""
        frame = await self.frame()
        deadline = asyncio.get_running_loop().time() + timeout
        seen = None
        while asyncio.get_running_loop().time() < deadline:
            with contextlib.suppress(PlaywrightError):  # mid-navigation
                seen = await frame.evaluate("() => location.href")
                if seen == url and await frame.evaluate(SOCKET_CONNECTED):
                    return frame
            await asyncio.sleep(0.1)
        raise AssertionError(f"the frame is at {seen}, not {url}")


@asynccontextmanager
async def remote_frame(
    database_url: str,
    clock: FakeClock,
    authentik: FakeAuthentik,
    browser: Browser,
    base: RealBase,
    *,
    viewport: dict[str, int] | None = None,
) -> AsyncIterator[Remote]:
    sock = free_socket()
    origin = f"https://localhost:{sock.getsockname()[1]}"
    authentik.add_user(EMAIL, PASSWORD)
    async with running_portal(database_url, clock, authentik, origin=origin) as portal:
        recorder = Recorder(portal.app)
        with localhost_tls() as tls:
            async with (
                serving(recorder, sock, tls=tls),
                serving(portal.app) as tunnel_port,  # the agent's way in
                running_agent(
                    portal, server_port=tunnel_port, app_port=base.port
                ) as agent,
            ):
                context = await browser.new_context(
                    viewport=viewport or {"width": 1400, "height": 1000},
                    accept_downloads=True,
                    ignore_https_errors=True,
                )
                try:
                    page = await context.new_page()
                    await _sign_in(page, origin)
                    await _claim(page, agent, origin)
                    await page.get_by_role("button", name="Open remotely").click()
                    status = page.locator("[data-field=status]")
                    await expect(status).to_have_text(f"Waking {NAME}…")
                    await agent.run(seconds=20)  # one poll interval: the Wake's
                    await expect(status).to_have_text("Connected")
                    base_id = (await agent.status()).base_id
                    assert base_id is not None
                    yield Remote(page, portal, agent, origin, base_id, recorder)
                finally:
                    await context.close()


async def _sign_in(page: Page, origin: str) -> None:
    await page.goto(f"{origin}/login")
    await page.get_by_label("Email").fill(EMAIL)
    await page.get_by_label("Password").fill(PASSWORD)
    await page.get_by_role("button", name="Sign in").click()
    await page.wait_for_url(f"{origin}/")


async def _claim(page: Page, agent: RunningAgent, origin: str) -> None:
    pairing = await agent.connect()
    await page.goto(f"{origin}/claim?code={pairing.user_code}")
    await page.get_by_label("Name").fill(NAME)
    await page.get_by_role("button", name="Approve").click()
    await page.wait_for_url(f"{origin}/")
    await agent.until("connected")
    await page.reload()
