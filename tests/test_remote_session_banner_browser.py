"""Seam 1: the base's own "Remote session active" banner (ticket #210,
spec #199).

The real agent runs with the real sp-rtk-base as the base's UI, reading the
agent's control socket as on a base. While anyone is on a Remote session,
every base page names them, in the Session bar's frame and on the base's
own page alike, and the banner clears once the last Remote session ends.

Runs in Chromium and Firefox, and in WebKit where the host can launch it
(as ``test_frame_browser``).
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest
from playwright.async_api import Browser, expect

from .harness.clock import FakeClock
from .harness.fake_authentik import FakeAuthentik
from .harness.frame import EMAIL, PASSWORD, Remote, remote_frame
from .test_frame_browser import engine  # noqa: F401  (the browser engines)

COLLEAGUE = "sam@example.com"
BANNER = "remote-session-banner"


@pytest.fixture
async def remote(
    database_url: str,
    clock: FakeClock,
    authentik: FakeAuthentik,
    engine: Browser,  # noqa: F811
) -> AsyncIterator[Remote]:
    async with remote_frame(database_url, clock, authentik, engine, None) as r:
        yield r


async def test_the_banner_names_the_remote_user_in_the_frame_and_on_the_base(
    remote: Remote,
    engine: Browser,  # noqa: F811
):
    await remote.connected()
    await expect(remote.base.get_by_test_id(BANNER)).to_have_text(
        f"Remote session active: {EMAIL} via the Portal"
    )
    direct = await engine.new_page()
    try:
        await direct.goto(f"{remote.ui.url}/settings")  # someone at the base
        await expect(direct.get_by_test_id(BANNER)).to_have_text(
            f"Remote session active: {EMAIL} via the Portal"
        )

        # Signing out ends the Operator's Remote session; the agent hears
        # of it on its next contact with the Portal.
        signed_out = await remote.page.request.post(
            f"{remote.origin}/logout",
            data={},
            headers={"X-Portal-Action": "1", "Origin": remote.origin},
        )
        assert signed_out.ok, await signed_out.text()
        await remote.agent.run(seconds=20)
        assert (await remote.agent.status()).sessions == []

        await expect(direct.get_by_test_id(BANNER)).to_have_count(0, timeout=5_000)
    finally:
        await direct.close()


async def test_the_banner_names_both_users_while_two_are_on_remote_sessions(
    remote: Remote,
    authentik: FakeAuthentik,
    engine: Browser,  # noqa: F811
):
    await remote.connected()
    authentik.add_user(COLLEAGUE, PASSWORD)
    shared = await remote.page.request.post(
        f"{remote.origin}/bases/{remote.base_id}/shares",
        data={"email": COLLEAGUE},
        headers={"X-Portal-Action": "1", "Origin": remote.origin},
    )
    assert shared.ok, await shared.text()
    sams = await engine.new_context(ignore_https_errors=True)
    try:
        sam = await sams.new_page()
        await sam.goto(f"{remote.origin}/login")
        await sam.get_by_label("Email").fill(COLLEAGUE)
        await sam.get_by_label("Password").fill(PASSWORD)
        await sam.get_by_role("button", name="Sign in").click()
        await sam.wait_for_url(f"{remote.origin}/")
        await sam.get_by_role("button", name="Open remotely").click()
        await sam.wait_for_url(f"{remote.origin}/bases/{remote.base_id}")
        await remote.agent.run(seconds=20)  # the next poll lists both

        await expect(remote.base.get_by_test_id(BANNER)).to_have_text(
            f"Remote session active: {EMAIL}, {COLLEAGUE} via the Portal"
        )
    finally:
        await sams.close()
