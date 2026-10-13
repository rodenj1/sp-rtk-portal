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
    await expect(remote.page.locator("[data-field=frame-label]")).to_contain_text(
        "served by the base"
    )
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


# --- Isolation ------------------------------------------------------------------------

# What a framed page tries against the Portal page around it and the user.
REACH = r"""async (portal) => {
  const out = {};
  const probe = async (name, fn) => {
    try { out[name] = await fn(); } catch (e) { out[name] = "threw " + e.name; }
  };
  await probe("origin", () => self.origin);
  await probe("parent DOM", () => parent.document.title);
  await probe("top.location", () => top.location.href);
  await probe("document.cookie", () => document.cookie);
  await probe("IndexedDB", () => new Promise((opened, failed) => {
    const req = indexedDB.open("probe");
    req.onsuccess = () => opened("opened");
    req.onerror = () => failed(req.error);
  }));
  await probe("window.open", () =>
    window.open(portal + "/account") === null ? "blocked" : "opened");
  await probe("top navigation", () => {
    top.location.href = portal + "/account";
    return "navigated";
  });
  return out;
}"""

NOWHERE = {
    "origin": "null",
    "parent DOM": "threw SecurityError",
    "top.location": "threw SecurityError",
    "IndexedDB": "threw SecurityError",
    "top navigation": "threw SecurityError",
}


def _assert_shut_out(reached: dict[str, str], *, empty_jar: bool = False) -> None:
    """``empty_jar``: an empty ``document.cookie`` is as good as a throw."""
    # Chromium and WebKit answer window.open with null, Firefox throws.
    assert reached.pop("window.open") in ("blocked", "threw InvalidAccessError")
    cookie = reached.pop("document.cookie")
    assert cookie in (
        ("threw SecurityError", "") if empty_jar else ("threw SecurityError",)
    )
    assert reached == NOWHERE


async def test_a_framed_page_cannot_reach_the_portal_page_or_the_user(remote: Remote):
    frame = await remote.connected()
    bar = remote.page.url
    context = remote.page.context
    assert "__Host-portal_session" in {c["name"] for c in await context.cookies()}

    reached = await frame.evaluate(REACH, remote.origin)

    _assert_shut_out(reached)
    await asyncio.sleep(1)  # a navigation or popup would have begun by now
    assert remote.page.url == bar
    assert context.pages == [remote.page]


# Requests a framed page sends to the Portal's own paths, as the user if it
# could: a credentialed read, a simple POST (no preflight), a JSON action
# (preflighted), the Session bar's status channel, and a form POST.
SEND = r"""async ({portal, base}) => {
  const quietly = (p) => p.catch(() => null);
  await quietly(fetch(portal + "/account", {credentials: "include"}));
  await quietly(fetch(portal + "/bases/" + base + "/metered", {
    method: "POST", mode: "no-cors", credentials: "include",
    body: JSON.stringify({metered: "true"}),
  }));
  await quietly(fetch(portal + "/bases/" + base + "/remote", {
    method: "POST", credentials: "include",
    headers: {"Content-Type": "application/json", "X-Portal-Action": "1"},
    body: "{}",
  }));
  await new Promise((done) => {
    const ws = new WebSocket(portal.replace("https:", "wss:") + "/bases/" + base + "/session");
    ws.onclose = ws.onerror = () => done();
    setTimeout(done, 3000);
  });
  const form = document.createElement("form");
  form.method = "POST";
  form.action = portal + "/bases/" + base + "/metered";
  const field = document.createElement("input");
  field.name = "metered";
  field.value = "true";
  form.appendChild(field);
  document.body.appendChild(form);
  form.submit();
}"""


async def test_the_portal_refuses_every_request_a_framed_page_makes_as_the_user(
    remote: Remote, engine: Browser
):
    frame = await remote.connected()
    mark = remote.requests.mark()

    await frame.evaluate(SEND, {"portal": remote.origin, "base": remote.base_id})
    await asyncio.sleep(2)  # the form POST's navigation

    sent = [s for s in remote.requests.since(mark) if not s.path.startswith("/b/")]
    base = f"/bases/{remote.base_id}"
    assert sorted((s.method, s.path) for s in sent) == sorted(
        [
            ("GET", "/account"),
            ("POST", f"{base}/metered"),  # the no-cors fetch
            ("OPTIONS", f"{base}/remote"),  # the JSON action's preflight, refused,
            ("GET", f"{base}/session"),  # so the action itself is never sent
            ("POST", f"{base}/metered"),  # the form
        ]
    )
    for seen in sent:
        assert seen.headers.get("origin") == "null", seen
        assert seen.status == 403, seen
        if engine.browser_type.name != "webkit":
            assert "cookie" not in seen.headers, seen
        # WebKit sends the Portal's SameSite=Lax cookie with them (it treats
        # the sandboxed frame as same-site for cookies, while marking the
        # requests Sec-Fetch-Site: cross-site), which is why the Portal
        # refuses cross-site reads too. Safari: README launch checklist.
    await expect(remote.page.locator("[data-field=status]")).to_have_text("Connected")


async def test_each_isolation_layer_holds_on_its_own(remote: Remote):
    """The iframe's sandbox attribute and the proxy's ``CSP: sandbox`` header:
    either one alone keeps a base page in an opaque origin."""
    await remote.connected()
    path = await remote.frame_path()

    # Both are there.
    iframe = remote.page.locator("iframe[data-field=frame]")
    assert await iframe.get_attribute("sandbox") == SANDBOX
    answers = [  # (a request the browser gave up on has no answer)
        s
        for s in remote.requests.seen
        if s.path.startswith("/b/") and s.kind == "http" and s.status is not None
    ]
    assert len(answers) > 10  # the page, its scripts, styles, fonts ...
    for seen in answers:
        csp = seen.response_headers.get("content-security-policy", "")
        assert csp.startswith(f"sandbox {SANDBOX};"), seen

    # The header alone: a Session bar that forgot the attribute.
    bare = await _frame_without_sandbox(remote.page, path)
    _assert_shut_out(await bare.evaluate(REACH, remote.origin))

    # The attribute alone: the frame shows a document of its own making, which
    # never passed through the proxy (no header).
    frame = await remote.frame()
    await frame.evaluate(
        """() => location.assign(URL.createObjectURL(new Blob(
            ["<p>made here</p>"], {type: "text/html"})))"""
    )
    await expect(remote.base.get_by_text("made here")).to_be_visible()
    own = await remote.frame()
    # WebKit gives such a document an empty cookie jar instead of throwing.
    _assert_shut_out(await own.evaluate(REACH, remote.origin), empty_jar=True)

    # And a base page loaded on its own, outside any frame, is refused.
    elsewhere = await remote.page.context.new_page()
    resp = await elsewhere.goto(remote.origin + path)
    assert resp is not None
    assert resp.status == 403
    assert (await resp.all_headers())["content-security-policy"].startswith(
        f"sandbox {SANDBOX};"
    )


async def _frame_without_sandbox(page: Page, path: str) -> Frame:
    handle = await page.evaluate_handle(
        """(path) => new Promise((loaded) => {
            const iframe = document.createElement("iframe");
            iframe.onload = () => loaded(iframe);
            iframe.src = path;
            document.body.appendChild(iframe);
        })""",
        path,
    )
    element = handle.as_element()
    assert element is not None
    frame = await element.content_frame()
    assert frame is not None
    return frame
