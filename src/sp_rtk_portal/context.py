"""What every route handler can reach: settings, clock, database, Authentik.

Handlers get it with ``ctx: PortalContext = Depends(portal_context)``.
"""

from __future__ import annotations

from dataclasses import dataclass

import httpx
from starlette.requests import HTTPConnection

from sp_rtk_portal.clock import Clock
from sp_rtk_portal.config import Settings
from sp_rtk_portal.db import Database


@dataclass
class PortalContext:
    settings: Settings
    clock: Clock
    db: Database
    authentik_transport: httpx.AsyncBaseTransport | None = None


def portal_context(conn: HTTPConnection) -> PortalContext:
    ctx: PortalContext = conn.app.state.portal
    return ctx
