"""Seam 1: the base proxy, ``/b/<id>/s/<token>/…`` (ADR 0004, ticket #89).

A Remote session is Connected through the real agent and its tunnel; the
stub on ``:8080`` (``harness/base_ui.py``) plays the base's UI and records
what reaches it. The frame's URL comes from the Session bar's status
channel, as the page's script gets it.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Awaitable, Callable

import httpx
import pytest
from websockets.asyncio.client import ClientConnection, connect
from websockets.exceptions import ConnectionClosed, InvalidStatus

from sp_rtk_portal.accounts.sessions import COOKIE

from .harness.agent import RunningAgent, running_agent
from .harness.base_ui import BaseUi, base_ui
from .harness.fake_authentik import FakeAuthentik
from .harness.portal import ORIGIN, Browser, Portal
from .harness.server import serving
from .harness.session_bar import status_channel

EMAIL = "operator@example.com"
PASSWORD = "correct horse battery staple"

SANDBOX = "sandbox allow-scripts allow-forms allow-downloads"
FRAMED = {"Sec-Fetch-Dest": "iframe", "Sec-Fetch-Mode": "navigate"}
"""What a browser sends when the Session bar's frame loads a page."""


@pytest.fixture
async def operator(browser: Browser, authentik: FakeAuthentik) -> Browser:
    authentik.add_user(EMAIL, PASSWORD)
    assert (await browser.sign_in(EMAIL, PASSWORD)).json() == {"next": "/"}
    return browser


@pytest.fixture
async def server(portal: Portal) -> AsyncIterator[int]:
    async with serving(portal.app) as port:
        yield port


@pytest.fixture
async def ui() -> AsyncIterator[BaseUi]:
    async with base_ui() as stub:
        yield stub


@pytest.fixture
async def agent(
    portal: Portal, operator: Browser, server: int, ui: BaseUi
) -> AsyncIterator[RunningAgent]:
    async with running_agent(portal, server_port=server, app_port=ui.port) as a:
        await a.claim(operator)
        yield a


@pytest.fixture
async def frame(operator: Browser, agent: RunningAgent, server: int) -> str:
    """Open remotely until Connected; the frame's URL path (``/b/…/``)."""
    base_id = (await agent.status()).base_id
    assert base_id
    resp = await operator.action(f"/bases/{base_id}/remote")
    assert resp.json() == {"next": f"/bases/{base_id}"}, resp.text
    async with status_channel(server, operator, base_id) as bar:
        await agent.run(seconds=20)  # the poll that carries the Wake
        connected = await bar.until("connected")
    path = connected["frame"]
    assert path.startswith(f"/b/{base_id}/s/") and path.endswith("/")
    return str(path)


def prefix_of(frame: str) -> str:
    return frame.rstrip("/")


def assert_stamped(resp: httpx.Response | object) -> None:
    """The headers every base response carries, whatever its status."""
    headers = resp.headers  # type: ignore[attr-defined]
    every = getattr(headers, "get_list", None) or headers.get_all
    policies = every("content-security-policy")
    assert policies == [f"{SANDBOX}; frame-ancestors {ORIGIN}"], policies
    assert every("access-control-allow-origin") == ["*"]
    assert every("referrer-policy") == ["no-referrer"]
    assert "set-cookie" not in headers
    assert "x-frame-options" not in headers


async def ws_open(
    server: int, path: str, headers: dict[str, str] | None = None
) -> ClientConnection:
    return await connect(
        f"ws://127.0.0.1:{server}{path}", additional_headers=headers or {}
    )


async def eventually(check: Callable[[], Awaitable[bool] | bool], what: str) -> None:
    for _ in range(500):
        result = check()
        if isinstance(result, Awaitable):
            result = await result
        if result:
            return
        await asyncio.sleep(0.01)
    raise AssertionError(f"never: {what}")


# --- Proxying -----------------------------------------------------------------------


async def test_a_valid_token_reaches_the_base_ui_with_the_prefix_stripped(
    operator: Browser, frame: str, ui: BaseUi
):
    resp = await operator.get(frame + "survey?tab=2", headers=FRAMED)

    assert resp.status_code == 200
    assert resp.text == "base page /survey"
    [seen] = ui.seen
    assert (seen.method, seen.path) == ("GET", "/survey")
    assert seen.headers["x-forwarded-prefix"] == prefix_of(frame)
    assert_stamped(resp)


async def test_the_query_and_a_posted_body_go_through(
    operator: Browser, frame: str, ui: BaseUi
):
    resp = await operator.http.post(
        frame + "api/profiles?dry=1",
        content=b'{"name": "p1"}',
        headers={"Content-Type": "application/json", "Sec-Fetch-Dest": "empty"},
    )

    assert resp.status_code == 200
    [seen] = ui.seen
    assert (seen.method, seen.path, seen.body) == (
        "POST",
        "/api/profiles",
        b'{"name": "p1"}',
    )


async def test_client_supplied_forwarding_headers_are_overwritten(
    operator: Browser, frame: str, ui: BaseUi
):
    await operator.get(
        frame,
        headers={
            **FRAMED,
            "X-Forwarded-Prefix": "/elsewhere",
            "X-Forwarded-For": "10.0.0.1",
            "X-Forwarded-Host": "evil.example",
            "X-Forwarded-Proto": "gopher",
            "X-Real-IP": "10.0.0.1",
            "Forwarded": "for=10.0.0.1;host=evil.example",
        },
    )

    [seen] = ui.seen
    assert seen.path == "/"
    assert seen.headers["x-forwarded-prefix"] == prefix_of(frame)
    assert seen.headers["x-forwarded-proto"] == "https"
    assert seen.headers["x-forwarded-host"] == "sp-rtk-base.big-spray.com"
    for name in ("x-forwarded-for", "x-real-ip", "forwarded", "cf-connecting-ip"):
        assert name not in seen.headers, name


async def test_a_websocket_upgrade_is_passed_through(
    frame: str, server: int, ui: BaseUi
):
    ws = await ws_open(
        server,
        frame + "ws",
        {
            "Origin": "null",
            "X-Forwarded-Prefix": "/elsewhere",
            "Cookie": f"{COOKIE}=stolen",
        },
    )
    await ws.send("hello")
    assert await asyncio.wait_for(ws.recv(), 5) == "echo hello"
    await ws.close()

    [seen] = ui.seen
    assert (seen.method, seen.path) == ("WEBSOCKET", "/ws")
    assert seen.headers["x-forwarded-prefix"] == prefix_of(frame)
    assert "cookie" not in seen.headers


# --- Refusals -----------------------------------------------------------------------


async def test_a_missing_or_wrong_token_is_refused_with_the_sandbox_headers(
    operator: Browser, frame: str, ui: BaseUi, agent: RunningAgent
):
    base_id = (await agent.status()).base_id
    for path in (
        f"/b/{base_id}/s/{'A' * 43}/",  # wrong token
        f"/b/{base_id}/s/",  # missing token
        f"/b/{base_id}/",
        "/b/",
        f"/b/someone-elses/s/{frame.split('/')[4]}/",  # right token, wrong base
    ):
        resp = await operator.get(path, headers=FRAMED)
        assert resp.status_code in (403, 404), path
        assert_stamped(resp)
    assert ui.seen == []


async def test_a_revoked_token_stops_working_at_once(
    portal: Portal, operator: Browser, frame: str, server: int, ui: BaseUi
):
    ws = await ws_open(server, frame + "ws")
    await ws.send("before")
    assert await asyncio.wait_for(ws.recv(), 5) == "echo before"
    base_id = frame.split("/")[2]
    # e.g. an un-Share, Un-claim or log out everywhere
    await portal.context.tunnels.end_sessions("un_claim", base_id=base_id)

    with pytest.raises(ConnectionClosed):
        await asyncio.wait_for(ws.recv(), 5)
    resp = await operator.get(frame, headers=FRAMED)
    assert resp.status_code == 403
    assert_stamped(resp)
    with pytest.raises(InvalidStatus) as refused:
        await ws_open(server, frame + "ws")
    assert refused.value.response.status_code == 403
    assert_stamped(refused.value.response)


async def test_a_top_level_document_load_is_refused(
    operator: Browser, frame: str, ui: BaseUi
):
    for dest in ("document", "frame", "embed", "object"):
        resp = await operator.get(
            frame, headers={"Sec-Fetch-Dest": dest, "Sec-Fetch-Mode": "navigate"}
        )
        assert resp.status_code == 403, dest
        assert_stamped(resp)
    assert ui.seen == []


async def test_nothing_outside_b_reaches_the_base(
    operator: Browser, frame: str, ui: BaseUi
):
    tail = frame.removeprefix("/b")
    for path in (tail, "/bases" + tail, "/static" + tail + "x"):
        await operator.get(path, headers=FRAMED)
    assert ui.seen == []


# --- Cookies and credentials ---------------------------------------------------------


async def test_cookies_and_authorization_never_reach_the_base(
    operator: Browser, frame: str, ui: BaseUi
):
    assert operator.cookies.get(COOKIE)  # the Portal session cookie is sent...
    await operator.get(
        frame,
        headers={**FRAMED, "Authorization": "Bearer secret", "Cookie": "a=b"},
    )

    [seen] = ui.seen  # ...but never forwarded
    assert "cookie" not in seen.headers
    assert "authorization" not in seen.headers


async def test_a_set_cookie_from_the_base_never_reaches_the_browser(
    operator: Browser, frame: str
):
    resp = await operator.get(frame + "set-cookie", headers=FRAMED)

    assert resp.text == "base page /set-cookie"
    assert "set-cookie" not in resp.headers
    assert "base_cookie" not in operator.cookies


# --- Headers on every response class ------------------------------------------------


async def test_a_404_from_the_base_is_stamped(operator: Browser, frame: str):
    resp = await operator.get(frame + "missing", headers=FRAMED)
    assert resp.status_code == 404
    assert_stamped(resp)


async def test_a_redirect_is_stamped_and_stays_inside_the_frame(
    operator: Browser, frame: str
):
    resp = await operator.get(frame + "redirect", headers=FRAMED)

    assert resp.status_code == 302
    assert resp.headers["location"] == frame + "survey"
    assert_stamped(resp)


async def test_a_proxy_error_is_stamped(
    portal: Portal, operator: Browser, frame: str, agent: RunningAgent
):
    base_id = frame.split("/")[2]
    await portal.context.tunnels.close_tunnel(base_id)
    await eventually(
        lambda: not portal.context.tunnels.tunnel_up(base_id), "the tunnel is down"
    )

    resp = await operator.get(frame, headers=FRAMED)

    assert resp.status_code == 502
    assert_stamped(resp)


# --- The Session bar page -------------------------------------------------------------


async def test_the_session_bar_page_may_frame_only_its_own_origin(
    operator: Browser, frame: str
):
    """Its own origin is the base proxy; ``blob:`` is a framed page's own
    download (``ui.download``), which Firefox checks against this page's
    ``frame-src``."""
    base_id = frame.split("/")[2]
    resp = await operator.get(f"/bases/{base_id}")

    policy = dict(
        d.strip().split(" ", 1)
        for d in resp.headers["content-security-policy"].split(";")
    )
    assert policy["frame-ancestors"] == "'none'"
    assert policy["frame-src"] == "'self' blob:"
    assert (
        "frame-src" not in (await operator.get("/")).headers["content-security-policy"]
    )


async def test_the_session_bar_page_keeps_other_sites_windows_away_but_not_its_frame(
    operator: Browser, frame: str
):
    """``same-origin-allow-popups`` still cuts a cross-origin opener off;
    plain ``same-origin`` would make Firefox and WebKit refuse the framed
    base's ``window.open(url, "_self")`` (NiceGUI's ``ui.navigate.to``)."""
    base_id = frame.split("/")[2]
    resp = await operator.get(f"/bases/{base_id}")

    assert resp.headers["cross-origin-opener-policy"] == "same-origin-allow-popups"
    other = await operator.get("/")
    assert other.headers["cross-origin-opener-policy"] == "same-origin"
