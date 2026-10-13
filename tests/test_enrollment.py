"""Sign-up on the Portal's own pages: Turnstile, a verification email whose
link lands back on the Portal, and the ``portal-users`` group (ADR 0003)."""

from urllib.parse import urlsplit

from .harness.fake_authentik import PORTAL_USERS, FakeAuthentik
from .harness.portal import ORIGIN, Browser

EMAIL = "new.operator@example.com"
PASSWORD = "correct horse battery staple"


def _sign_up_body(authentik: FakeAuthentik, **overrides) -> dict:
    body = {
        "email": EMAIL,
        "password": PASSWORD,
        "password_repeat": PASSWORD,
        "cf-turnstile-response": authentik.turnstile_token,
    }
    return body | overrides


def _link_path(link: str) -> str:
    parts = urlsplit(link)
    assert f"{parts.scheme}://{parts.netloc}" == ORIGIN
    return f"{parts.path}?{parts.query}"


async def test_sign_up_page_shows_the_form_and_turnstile(browser: Browser):
    page = await browser.get("/signup")

    assert page.status_code == 200
    for field in ('name="email"', 'name="password"', 'name="password_repeat"'):
        assert field in page.text
    assert 'class="cf-turnstile"' in page.text
    assert FakeAuthentik.turnstile_site_key in page.text
    assert "challenges.cloudflare.com" in page.headers["content-security-policy"]


async def test_sign_up_verify_then_sign_in(browser: Browser, authentik: FakeAuthentik):
    resp = await browser.action("/signup", _sign_up_body(authentik))

    assert resp.status_code == 200
    assert resp.json() == {"next": "/signup/sent"}
    assert "Check your email" in (await browser.get("/signup/sent")).text
    [email] = authentik.outbox
    assert email.to == EMAIL

    # The link lands on the Portal. Opening it only shows a button, so a mail
    # scanner that fetches links can't use up the token.
    path = _link_path(email.link)
    assert path.startswith("/verify?t=")
    page = await browser.get(path)
    assert page.status_code == 200
    token = path.split("t=", 1)[1]
    assert f'value="{token}"' in page.text

    done = await browser.action("/verify", {"t": token})
    assert done.json() == {"next": "/login?verified=1"}
    assert "Email confirmed" in (await browser.get("/login?verified=1")).text

    signed_in = await browser.sign_in(EMAIL, PASSWORD)
    assert signed_in.json() == {"next": "/"}
    assert EMAIL in (await browser.get("/")).text


async def test_sign_in_is_refused_until_the_email_is_verified(
    browser: Browser, authentik: FakeAuthentik
):
    await browser.action("/signup", _sign_up_body(authentik))

    resp = await browser.sign_in(EMAIL, PASSWORD)

    assert resp.status_code == 401
    assert (await browser.get("/")).status_code == 303


async def test_new_accounts_join_portal_users_through_the_enrollment_flow(
    browser: Browser, authentik: FakeAuthentik
):
    await browser.action("/signup", _sign_up_body(authentik))

    assert ("GET", authentik.enrollment_flow_slug) in authentik.executor_calls
    assert authentik.users[EMAIL].groups == [PORTAL_USERS]


async def test_a_verification_link_works_once(
    browser: Browser, authentik: FakeAuthentik
):
    await browser.action("/signup", _sign_up_body(authentik))
    token = authentik.outbox[0].link.split("t=", 1)[1]
    await browser.action("/verify", {"t": token})

    again = await browser.action("/verify", {"t": token})

    assert again.status_code == 400
    assert "expired" in again.json()["error"]


async def test_a_failed_turnstile_blocks_sign_up(
    browser: Browser, authentik: FakeAuthentik
):
    for answer in ("wrong-answer", ""):
        resp = await browser.action(
            "/signup", _sign_up_body(authentik, **{"cf-turnstile-response": answer})
        )

        assert resp.status_code == 400
        assert "captcha" in resp.json()["error"].lower()
    assert authentik.outbox == []
    assert EMAIL not in authentik.users


async def test_a_missing_turnstile_answer_blocks_sign_up(
    browser: Browser, authentik: FakeAuthentik
):
    body = _sign_up_body(authentik)
    del body["cf-turnstile-response"]

    resp = await browser.action("/signup", body)

    assert resp.status_code == 400
    assert EMAIL not in authentik.users


async def test_authentiks_complaint_about_the_form_is_shown(
    browser: Browser, authentik: FakeAuthentik
):
    resp = await browser.action(
        "/signup", _sign_up_body(authentik, password_repeat="something else")
    )

    assert resp.status_code == 400
    assert resp.json() == {"error": "Passwords don't match."}
    assert EMAIL not in authentik.users


async def test_an_unknown_stage_in_enrollment_fails_closed(
    browser: Browser, authentik: FakeAuthentik
):
    authentik.script_challenge({"component": "ak-stage-user-login", "x": 1})

    resp = await browser.action("/signup", _sign_up_body(authentik))

    assert resp.status_code == 502
    assert "location" not in resp.headers
    assert resp.json() == {"error": "Something went wrong. Please try again later."}


async def test_an_unknown_stage_after_the_verification_link_fails_closed(
    browser: Browser, authentik: FakeAuthentik
):
    await browser.action("/signup", _sign_up_body(authentik))
    token = authentik.outbox[0].link.split("t=", 1)[1]
    authentik.script_challenge({"component": "ak-stage-consent"})

    resp = await browser.action("/verify", {"t": token})

    assert resp.status_code == 502
    assert "location" not in resp.headers


async def test_only_the_turnstile_pages_allow_cloudflare_in_the_csp(browser: Browser):
    for path in ("/signup", "/recover"):
        csp = (await browser.get(path)).headers["content-security-policy"]
        assert "frame-src https://challenges.cloudflare.com" in csp
        assert "frame-ancestors 'none'" in csp
    for path in ("/login", "/verify?t=x", "/reset?t=x"):
        csp = (await browser.get(path)).headers["content-security-policy"]
        assert "cloudflare" not in csp
