"""The Portal under test and a browser that talks to it.

``Portal`` wraps one real app instance (``create_app``) wired to the test's
database, fake Authentik and fake clock. ``Browser`` is what a user's browser
would do: it keeps cookies and sends state-changing requests the way the
Portal's own JavaScript does (JSON body, custom header, same Origin).
"""

from __future__ import annotations

import dataclasses
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import httpx
import psycopg
from asgi_lifespan import LifespanManager
from psycopg.rows import dict_row

from sp_rtk_portal.app import create_app
from sp_rtk_portal.config import Settings
from sp_rtk_portal.web.security import ACTION_HEADER

from .clock import FakeClock
from .doorbell_server import DOORBELL_TOKEN
from .fake_authentik import FakeAuthentik
from .fake_smtp import FakeSmtp

ORIGIN = "https://sp-rtk-base.big-spray.com"
CLIENT_IP = "203.0.113.7"
PORTAL_OWNER = "owner@example.com"
"""The Portal owner's email (``Settings.owner_emails``)."""


def test_settings(
    database_url: str, authentik: FakeAuthentik, smtp: FakeSmtp | None = None
) -> Settings:
    return Settings(
        database_url=database_url,
        public_origin=ORIGIN,
        authentik_url=authentik.base_url,
        login_flow_slug=authentik.login_flow_slug,
        enrollment_flow_slug=authentik.enrollment_flow_slug,
        recovery_flow_slug=authentik.recovery_flow_slug,
        totp_setup_flow_slug=authentik.totp_setup_flow_slug,
        password_change_flow_slug=authentik.password_change_flow_slug,
        authentik_api_token=authentik.api_token,
        turnstile_site_key=authentik.turnstile_site_key,
        oidc_app_slug=authentik.app_slug,
        oidc_client_id=authentik.client_id,
        oidc_client_secret=authentik.client_secret,
        owner_emails=(PORTAL_OWNER,),
        tunnel_sweep_interval=0.01,
        audit_purge_interval=0.05,
        smtp_host=smtp.host if smtp else "",
        smtp_port=smtp.port if smtp else 587,
        smtp_starttls=False,
        smtp_from="Portal <portal@example.com>",
        doorbell_token=DOORBELL_TOKEN,
    )


class Browser:
    """One browser profile: its own cookie jar, behind Cloudflare at ``ip``."""

    def __init__(self, client: httpx.AsyncClient) -> None:
        self.http = client

    @property
    def cookies(self) -> httpx.Cookies:
        return self.http.cookies

    async def get(self, path: str, **kwargs: Any) -> httpx.Response:
        return await self.http.get(path, **kwargs)

    async def action(
        self, path: str, body: dict[str, Any] | None = None
    ) -> httpx.Response:
        """A state-changing request as the Portal's own pages send it."""
        return await self.http.post(
            path,
            json=body or {},
            headers={ACTION_HEADER: "1", "Origin": ORIGIN},
        )

    async def sign_in(
        self, email: str, password: str, totp: str | None = None
    ) -> httpx.Response:
        """Run the login page's steps. Returns the last JSON response."""
        resp = await self.action("/login", {"email": email, "password": password})
        if totp is not None and resp.json().get("step") == "totp":
            resp = await self.action("/login/totp", {"code": totp})
        return resp


class Portal:
    def __init__(
        self,
        app: Any,
        settings: Settings,
        clock: FakeClock,
        authentik: FakeAuthentik,
        smtp: FakeSmtp | None = None,
    ) -> None:
        self.app = app
        self.smtp = smtp
        self.settings = settings
        self.clock = clock
        self.authentik = authentik
        self.origin = settings.public_origin

    @property
    def context(self) -> Any:
        """The app's ``PortalContext``, for wiring hooks (e.g. account events)."""
        return self.app.state.portal

    @asynccontextmanager
    async def browser(self, ip: str = CLIENT_IP) -> AsyncIterator[Browser]:
        transport = httpx.ASGITransport(app=self.app, client=(ip, 50000))
        async with httpx.AsyncClient(
            transport=transport,
            base_url=self.origin,
            headers={"CF-Connecting-IP": ip},
        ) as client:
            yield Browser(client)

    async def query(self, sql: str, *params: Any) -> list[dict[str, Any]]:
        """Read the database directly. Only for what the AC says is visible
        "in the database" (e.g. audit entries before the audit page exists),
        or to play a compromised Portal by writing to it."""
        async with await psycopg.AsyncConnection.connect(
            self.settings.database_url, row_factory=dict_row
        ) as conn:
            cur = await conn.execute(sql, params)  # type: ignore[arg-type]
            return await cur.fetchall() if cur.description else []


@asynccontextmanager
async def running_portal(
    database_url: str,
    clock: FakeClock,
    authentik: FakeAuthentik,
    origin: str = ORIGIN,
    smtp: FakeSmtp | None = None,
) -> AsyncIterator[Portal]:
    """The Portal, its lifespan running. ``origin``: its public origin (the
    browser tests serve it at ``http://localhost:<port>``). ``smtp``: where
    it sends email (none: it sends nothing)."""
    settings = dataclasses.replace(
        test_settings(database_url, authentik, smtp), public_origin=origin
    )
    app = create_app(settings, clock=clock, authentik_transport=authentik.transport())
    async with LifespanManager(app):
        yield Portal(app, settings, clock, authentik, smtp)
