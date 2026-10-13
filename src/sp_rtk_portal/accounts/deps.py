"""``current_account``: the dependency every signed-in Portal page uses.

A live session is renewed on every use: ``SessionRenewalMiddleware`` re-sends
the cookie with a fresh 30-day ``Max-Age`` on the way out.
"""

from __future__ import annotations

from urllib.parse import quote, urlsplit

from fastapi import Depends, Request, WebSocket
from starlette.datastructures import MutableHeaders
from starlette.responses import Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from sp_rtk_portal.accounts import sessions
from sp_rtk_portal.accounts.store import Account
from sp_rtk_portal.context import PortalContext, portal_context

_RENEW = "portal.renew_session"


RETURN_AFTER_SIGN_IN = ("/claim",)
"""Pages that send a signed-out visitor back to themselves after login (a
link the base's local Portal page opened, carrying the pairing code)."""


def login_url(request: Request) -> str:
    """Where a signed-out GET goes: ``/login``, with ``next`` for the pages
    in :data:`RETURN_AFTER_SIGN_IN`."""
    path = request.url.path
    if path not in RETURN_AFTER_SIGN_IN:
        return "/login"
    target = path + (f"?{request.url.query}" if request.url.query else "")
    return "/login?next=" + quote(target, safe="/?=")


def safe_next(target: str) -> str:
    """``target`` if it's a path on this Portal, else ``/``."""
    if (
        target.startswith("/")
        and not target.startswith(("//", "/\\"))
        and "\\" not in target
        and urlsplit(target).netloc == ""
    ):
        return target
    return "/"


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


async def websocket_account(websocket: WebSocket, ctx: PortalContext) -> Account | None:
    """The signed-in account of a websocket from one of the Portal's own
    pages, or ``None``. Refuses any ``Origin`` but the Portal's (a page on
    another site, or a sandboxed base frame's ``null``)."""
    if websocket.headers.get("origin") != ctx.settings.public_origin:
        return None
    token = websocket.cookies.get(sessions.COOKIE)
    if not token:
        return None
    async with ctx.db.connection() as conn:
        return await sessions.resume(
            conn, token, ctx.clock.now(), ctx.settings.session_lifetime
        )


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
