"""Flow attempts waiting for their next step (a TOTP code, or the code that
confirms a new TOTP device).

Held in memory: the Portal runs as a single instance (spec), and losing them
on restart only means typing the password again. The browser holds a random
key in a short-lived ``__Host-`` cookie.
"""

from __future__ import annotations

import secrets
from datetime import datetime, timedelta
from typing import TYPE_CHECKING

from starlette.responses import Response

from sp_rtk_portal.accounts.authentik import FlowAttempt

if TYPE_CHECKING:
    from sp_rtk_portal.context import PortalContext

COOKIE = "__Host-portal_login"
# Every other flow's pending step: recovery, TOTP setup, password change.
FLOW_COOKIE = "__Host-portal_flow"


class PendingAttempts:
    def __init__(self, lifetime: timedelta) -> None:
        self.lifetime = lifetime
        self._items: dict[str, tuple[datetime, FlowAttempt]] = {}

    def put(self, attempt: FlowAttempt, now: datetime) -> str:
        self._expire(now)
        key = secrets.token_urlsafe(32)
        self._items[key] = (now + self.lifetime, attempt)
        return key

    def get(self, key: str | None, now: datetime) -> FlowAttempt | None:
        self._expire(now)
        item = self._items.get(key or "")
        return item[1] if item else None

    def drop(self, key: str | None) -> None:
        self._items.pop(key or "", None)

    def _expire(self, now: datetime) -> None:
        for key in [k for k, (exp, _) in self._items.items() if exp <= now]:
            del self._items[key]


def keep(
    store: PendingAttempts,
    cookie: str,
    attempt: FlowAttempt,
    ctx: PortalContext,
    response: Response,
) -> None:
    """Hold ``attempt`` for its next step; the browser gets its key."""
    key = store.put(attempt, ctx.clock.now())
    response.set_cookie(
        cookie,
        key,
        max_age=int(store.lifetime.total_seconds()),
        path="/",
        secure=True,
        httponly=True,
        samesite="strict",
    )


def forget(
    store: PendingAttempts, cookie: str, key: str | None, response: Response
) -> None:
    store.drop(key)
    response.delete_cookie(cookie, path="/", secure=True, httponly=True)
