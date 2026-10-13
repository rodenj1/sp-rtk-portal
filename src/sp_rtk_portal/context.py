"""What every route handler can reach: settings, clock, database, Authentik.

Handlers get it with ``ctx: PortalContext = Depends(portal_context)``. A new
module that needs process-wide state (the tunnel broker, rate limiters) adds
a field here and builds it in ``app.create_app``.
"""

from __future__ import annotations

from dataclasses import dataclass

from sp_rtk_portal_protocol import ReplayCache
from starlette.requests import HTTPConnection

from sp_rtk_portal.accounts.attempts import PendingAttempts
from sp_rtk_portal.accounts.authentik import Authentik
from sp_rtk_portal.accounts.events import AccountEvents
from sp_rtk_portal.bases.events import BaseEvents
from sp_rtk_portal.clock import Clock
from sp_rtk_portal.config import Settings
from sp_rtk_portal.db import Database
from sp_rtk_portal.doorbell.bell import Doorbell
from sp_rtk_portal.mail import Mailer
from sp_rtk_portal.tunnel.broker import TunnelBroker


@dataclass
class PortalContext:
    settings: Settings
    clock: Clock
    db: Database
    authentik: Authentik
    login_attempts: PendingAttempts
    # Flows other than login waiting for their next step (TOTP setup, a
    # TOTP code during recovery or a password change).
    flow_attempts: PendingAttempts
    account_events: AccountEvents
    # Hooks on a base going away (Un-claim); Shares (#94) hook in here.
    base_events: BaseEvents
    # Every agent request proof seen in the last minute (refuses replays).
    agent_proofs: ReplayCache
    # Wakes, tunnels and Remote sessions (process-local: one instance).
    tunnels: TunnelBroker
    # Email the Portal sends itself (Shares; possible copy, #98).
    mailer: Mailer
    # Doorbell return paths and rings (process-local too).
    doorbell: Doorbell


def portal_context(conn: HTTPConnection) -> PortalContext:
    ctx: PortalContext = conn.app.state.portal
    return ctx
