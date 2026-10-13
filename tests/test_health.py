from .harness.portal import Browser


async def test_healthz_is_ok_when_the_database_is_reachable(browser: Browser):
    resp = await browser.get("/healthz")

    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}
