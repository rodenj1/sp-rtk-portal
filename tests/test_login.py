"""Sign in and sign out on the Portal's own pages (ADR 0003)."""

from .harness.fake_authentik import FakeAuthentik
from .harness.portal import Browser

EMAIL = "operator@example.com"
PASSWORD = "correct horse battery staple"


async def test_signed_out_visitor_is_sent_to_the_login_page(browser: Browser):
    resp = await browser.get("/")

    assert resp.status_code == 303
    assert resp.headers["location"] == "/login"
    login = await browser.get("/login")
    assert login.status_code == 200
    assert 'name="email"' in login.text and 'name="password"' in login.text


async def test_sign_in_with_email_and_password_lands_on_an_empty_base_list(
    browser: Browser, authentik: FakeAuthentik
):
    authentik.add_user(EMAIL, PASSWORD)

    resp = await browser.sign_in(EMAIL, PASSWORD)

    assert resp.status_code == 200
    assert resp.json() == {"next": "/"}
    page = await browser.get("/")
    assert page.status_code == 200
    assert EMAIL in page.text
    assert "No bases yet" in page.text
