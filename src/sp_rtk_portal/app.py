"""The Portal app factory."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI

from sp_rtk_portal import health
from sp_rtk_portal.clock import Clock, SystemClock
from sp_rtk_portal.config import Settings
from sp_rtk_portal.context import PortalContext
from sp_rtk_portal.db import Database
from sp_rtk_portal.web.security import PortalSecurityMiddleware


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
    ctx = PortalContext(
        settings=settings,
        clock=clock or SystemClock(),
        db=Database(settings.database_url),
        authentik_transport=authentik_transport,
    )

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        await ctx.db.open()
        try:
            yield
        finally:
            await ctx.db.close()

    app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    app.state.portal = ctx
    app.add_middleware(PortalSecurityMiddleware, origin=settings.public_origin)
    app.include_router(health.router)
    return app
