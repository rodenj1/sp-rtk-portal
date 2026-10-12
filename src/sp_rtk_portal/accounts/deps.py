"""``current_account``: the dependency every signed-in Portal page uses.

A live session is renewed on every use: ``SessionRenewalMiddleware`` re-sends
the cookie with a fresh 30-day ``Max-Age`` on the way out.
"""

from __future__ import annotations

from fastapi import Depends, Request
from starlette.datastructures import MutableHeaders
from starlette.responses import Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from sp_rtk_portal.accounts import sessions
from sp_rtk_portal.accounts.store import Account
from sp_rtk_portal.context import PortalContext, portal_context

_RENEW = "portal.renew_session"


class SignInRequired(Exception):
    """No live Portal session. Pages redirect to /login; actions get 401."""


async def current_account(
    request: Request, ctx: PortalContext = Depends(portal_context)
) -> Account:
    token = request.cookies.get(sessions.COOKIE)
    if not token:
        raise SignInRequired
    lifetime = ctx.settings.session_lifetime
    async with ctx.db.connection() as conn:
        account = await sessions.resume(conn, token, ctx.clock.now(), lifetime)
    if account is None:
        raise SignInRequired
    request.scope[_RENEW] = (token, lifetime)
    return account


class SessionRenewalMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_renewed(message: Message) -> None:
            renew = scope.get(_RENEW)
            if message["type"] == "http.response.start" and renew:
                headers = MutableHeaders(scope=message)
                already = any(
                    v.startswith(sessions.COOKIE + "=")
                    for v in headers.getlist("set-cookie")
                )
                if not already:
                    cookie = Response()
                    sessions.set_cookie(cookie, *renew)
                    headers.append("set-cookie", cookie.headers["set-cookie"])
            await send(message)

        await self.app(scope, receive, send_renewed)
