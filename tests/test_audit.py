"""Audit entries. The audit page comes later, so these read the database."""

from .harness.fake_authentik import FakeAuthentik

EMAIL = "operator@example.com"
PASSWORD = "correct horse battery staple"


async def test_login_writes_an_audit_entry_with_who_when_and_ip(
    portal, authentik: FakeAuthentik, clock
):
    authentik.add_user(EMAIL, PASSWORD)
    async with portal.browser(ip="198.51.100.23") as browser:
        await browser.sign_in(EMAIL, PASSWORD)

    entries = await portal.query(
        "SELECT e.kind, a.email, e.at, host(e.ip) AS ip"
        " FROM audit_entry e JOIN account a ON a.id = e.account_id"
    )
    assert entries == [
        {"kind": "login", "email": EMAIL, "at": clock.now(), "ip": "198.51.100.23"}
    ]


async def test_a_failed_login_writes_no_login_entry(portal, authentik: FakeAuthentik):
    authentik.add_user(EMAIL, PASSWORD)
    async with portal.browser() as browser:
        await browser.sign_in(EMAIL, "wrong")

    assert await portal.query("SELECT * FROM audit_entry") == []
