"""The Portal app factory."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response
from sp_rtk_portal_protocol import ReplayCache

from sp_rtk_portal import health
from sp_rtk_portal.accounts import (
    account_page_routes,
    review,
    security,
    security_routes,
    signup_routes,
)
from sp_rtk_portal.accounts import routes as account_routes
from sp_rtk_portal.accounts.attempts import PendingAttempts
from sp_rtk_portal.accounts.authentik import Authentik
from sp_rtk_portal.accounts.deps import (
    SessionRenewalMiddleware,
    SignInRequired,
    login_url,
)
from sp_rtk_portal.accounts.events import AccountEvents
from sp_rtk_portal.agent_api import routes as agent_routes
from sp_rtk_portal.agent_api import settings_routes
from sp_rtk_portal.agent_api.auth import AgentRefused, agent_refused
from sp_rtk_portal.audit import routes as audit_routes
from sp_rtk_portal.audit.retention import Purger
from sp_rtk_portal.bases import routes as base_routes
from sp_rtk_portal.bases.events import BaseEvents
from sp_rtk_portal.clock import Clock, SystemClock
from sp_rtk_portal.config import Settings
from sp_rtk_portal.context import PortalContext
from sp_rtk_portal.db import Database
from sp_rtk_portal.doorbell import routes as doorbell_routes
from sp_rtk_portal.doorbell.bell import Doorbell
from sp_rtk_portal.mail import Mailer
from sp_rtk_portal.proxy.middleware import BaseProxy
from sp_rtk_portal.shares import routes as share_routes
from sp_rtk_portal.shares import sharing
from sp_rtk_portal.tunnel import routes as tunnel_routes
from sp_rtk_portal.tunnel.broker import TunnelBroker
from sp_rtk_portal.web.security import SAFE_METHODS, PortalSecurityMiddleware
from sp_rtk_portal.web.templates import static_files


def create_app(
    settings: Settings,
    *,
    clock: Clock | None = None,
    authentik_transport: httpx.AsyncBaseTransport | None = None,
) -> FastAPI:
    """Build the Portal.

    ``clock`` and ``authentik_transport`` exist for the test harness: a fake
    clock, and a transport that reaches a fake Authentik in-process.
    """
    clock = clock or SystemClock()
    db = Database(settings.database_url)
    tunnels = TunnelBroker(settings, clock, db)
    ctx = PortalContext(
        settings=settings,
        clock=clock,
        db=db,
        authentik=Authentik(settings, clock, authentik_transport),
        login_attempts=PendingAttempts(settings.login_attempt_lifetime),
        flow_attempts=PendingAttempts(settings.login_attempt_lifetime),
        account_events=AccountEvents(),
        base_events=BaseEvents(),
        agent_proofs=ReplayCache(),
        tunnels=tunnels,
        mailer=Mailer(settings),
        doorbell=Doorbell(clock, tunnels),
    )
    ctx.base_events.on_unclaimed(sharing.unclaimed)
    audit_purger = Purger(db, clock, settings.audit_purge_interval)
    ctx.account_events.on_password_changed(security.LogOutEverywhere(ctx))
    ctx.account_events.on_password_changed(review.review_due)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        await ctx.db.open()
        try:
            await ctx.tunnels.start()
            audit_purger.start()
            try:
                yield
            finally:
                await audit_purger.stop()
                await ctx.tunnels.stop()
        finally:
            await ctx.db.close()

    app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    app.state.portal = ctx
    # Added last runs first: the base proxy, then the security guard.
    app.add_middleware(SessionRenewalMiddleware)
    app.add_middleware(PortalSecurityMiddleware, origin=settings.public_origin)
    # Outermost: ``/b/`` is the base proxy, which nothing else may touch.
    app.add_middleware(BaseProxy, ctx=ctx)
    app.add_exception_handler(SignInRequired, _sign_in_required)
    app.add_exception_handler(AgentRefused, agent_refused)
    app.add_exception_handler(
        settings_routes.NotPortalOwner, settings_routes.not_portal_owner
    )
    app.mount("/static", static_files(), name="static")
    app.include_router(health.router)
    app.include_router(account_routes.router)
    app.include_router(signup_routes.router)
    app.include_router(account_page_routes.router)
    app.include_router(security_routes.router)
    app.include_router(base_routes.router)
    app.include_router(agent_routes.router)
    app.include_router(settings_routes.router)
    app.include_router(tunnel_routes.router)
    app.include_router(share_routes.router)
    app.include_router(doorbell_routes.router)
    app.include_router(audit_routes.router)
    return app


async def _sign_in_required(request: Request, exc: Exception) -> Response:
    if request.method in SAFE_METHODS:
        return RedirectResponse(login_url(request), status_code=303)
    return JSONResponse({"error": "Sign in first.", "next": "/login"}, status_code=401)
