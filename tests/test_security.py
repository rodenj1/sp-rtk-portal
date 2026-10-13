"""Portal-wide rules: strict CSP on every page, and the state-changing guard
(JSON body + custom header + same Origin)."""

import pytest

from .harness.fake_authentik import FakeAuthentik
from .harness.portal import ORIGIN, Browser

EMAIL = "operator@example.com"
PASSWORD = "correct horse battery staple"
GOOD_HEADERS = {"X-Portal-Action": "1", "Origin": ORIGIN}


@pytest.fixture
async def signed_in(browser: Browser, authentik: FakeAuthentik) -> Browser:
    authentik.add_user(EMAIL, PASSWORD)
    await browser.sign_in(EMAIL, PASSWORD)
    return browser


@pytest.mark.parametrize(
    ("why", "kwargs"),
    [
        (
            "no custom header",
            {"json": {}, "headers": {"Origin": ORIGIN}},
        ),
        (
            "form body",
            {"data": {"x": "1"}, "headers": GOOD_HEADERS},
        ),
        (
            "text body claiming nothing",
            {
                "content": b"{}",
                "headers": {**GOOD_HEADERS, "Content-Type": "text/plain"},
            },
        ),
        (
            "Origin: null (a sandboxed base frame)",
            {"json": {}, "headers": {"X-Portal-Action": "1", "Origin": "null"}},
        ),
        (
            "foreign origin",
            {
                "json": {},
                "headers": {"X-Portal-Action": "1", "Origin": "https://evil.example"},
            },
        ),
        (
            "no Origin",
            {"json": {}, "headers": {"X-Portal-Action": "1"}},
        ),
    ],
)
async def test_a_state_changing_request_that_breaks_a_rule_is_refused(
    signed_in: Browser, why: str, kwargs: dict
):
    resp = await signed_in.http.post("/logout", **kwargs)

    assert resp.status_code == 403, why
    # Still signed in: the refused sign-out did nothing.
    assert (await signed_in.get("/")).status_code == 200


async def test_a_refused_login_never_reaches_authentik(
    browser: Browser, authentik: FakeAuthentik
):
    authentik.add_user(EMAIL, PASSWORD)

    resp = await browser.http.post(
        "/login",
        json={"email": EMAIL, "password": PASSWORD},
        headers={"X-Portal-Action": "1", "Origin": "null"},
    )

    assert resp.status_code == 403
    assert authentik.executor_requests == []


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("GET", "/login"),
        ("GET", "/"),
        ("GET", "/healthz"),
        ("GET", "/static/portal.js"),
        ("GET", "/no-such-page"),
        ("POST", "/logout"),  # refused: no header
    ],
)
async def test_every_portal_response_carries_the_strict_csp(
    browser: Browser, method: str, path: str
):
    resp = await browser.http.request(method, path)

    csp = resp.headers["content-security-policy"]
    directives = {d.strip().split(" ")[0]: d.strip() for d in csp.split(";")}
    assert directives["frame-ancestors"] == "frame-ancestors 'none'"
    assert directives["default-src"] == "default-src 'none'"
    assert directives["script-src"] == "script-src 'self'"
    assert "unsafe-inline" not in csp and "unsafe-eval" not in csp


async def test_the_signed_in_base_list_carries_the_strict_csp(signed_in: Browser):
    resp = await signed_in.get("/")

    assert resp.status_code == 200
    assert "frame-ancestors 'none'" in resp.headers["content-security-policy"]


def fetch(site: str, mode: str, dest: str) -> dict[str, str]:
    """What a browser says about a request (Fetch Metadata)."""
    return {"Sec-Fetch-Site": site, "Sec-Fetch-Mode": mode, "Sec-Fetch-Dest": dest}


@pytest.mark.parametrize(
    ("why", "site", "mode", "dest"),
    [
        ("a sandboxed base frame's fetch", "cross-site", "cors", "empty"),
        ("another site's image or script tag", "cross-site", "no-cors", "image"),
        ("a base frame navigating itself", "cross-site", "navigate", "iframe"),
        ("a sibling subdomain's fetch", "same-site", "cors", "empty"),
    ],
)
async def test_a_cross_site_request_is_refused_even_a_read_unless_it_opens_a_page(
    signed_in: Browser, why: str, site: str, mode: str, dest: str
):
    """WebKit sends the ``SameSite=Lax`` cookie with a sandboxed frame's
    requests to the Portal, so the cookie alone can't tell the user from a
    base page acting as them."""
    resp = await signed_in.http.get("/account", headers=fetch(site, mode, dest))

    assert resp.status_code == 403, why
    assert resp.json() == {"error": "cross-site request"}


@pytest.mark.parametrize(
    ("why", "headers"),
    [
        ("a link from an email", fetch("none", "navigate", "document")),
        (
            "a link on another site",
            fetch("cross-site", "navigate", "document"),
        ),
        ("the Portal's own page", fetch("same-origin", "cors", "empty")),
        ("a client without Fetch Metadata", {}),
    ],
)
async def test_pages_opened_from_elsewhere_and_the_portals_own_requests_still_work(
    signed_in: Browser, why: str, headers: dict[str, str]
):
    resp = await signed_in.http.get("/account", headers=headers)

    assert resp.status_code == 200, why
