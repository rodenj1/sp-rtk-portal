"""The login page, its JSON steps, and sign-out.

The page's JavaScript posts each step as JSON (see ``web.security``) and gets
back one of: ``{"next": url}``, ``{"step": "totp"}`` or ``{"error": message}``.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from sp_rtk_portal import audit
from sp_rtk_portal.accounts import attempts, events, review, security, sessions
from sp_rtk_portal.accounts.authentik import (
    AuthentikFailedClosed,
    FlowAttempt,
    Identity,
    NeedsTotp,
    Outcome,
)
from sp_rtk_portal.accounts.deps import safe_next
from sp_rtk_portal.accounts.events import PasswordChanged
from sp_rtk_portal.accounts.store import upsert_on_login
from sp_rtk_portal.context import PortalContext, portal_context
from sp_rtk_portal.shares import sharing
from sp_rtk_portal.web.client_ip import client_ip
from sp_rtk_portal.web.templates import render

log = logging.getLogger(__name__)

router = APIRouter()

WRONG_CREDENTIALS = "Wrong email or password."
WRONG_CODE = "Wrong code. Try again."
UNAVAILABLE = "Sign-in failed. Please try again later."
TIMED_OUT = "Sign-in timed out. Please start again."


class PasswordStep(BaseModel):
    email: str
    password: str
    next: str = ""


class TotpStep(BaseModel):
    code: str
    next: str = ""


@router.get("/login", response_class=HTMLResponse)
async def login_page(
    request: Request, verified: str = "", next: str = ""
) -> HTMLResponse:
    return render(
        request,
        "login.html",
        title="Sign in",
        verified=verified == "1",
        next_url=safe_next(next) if next else "",
    )


@router.post("/login")
async def login(
    step: PasswordStep, request: Request, ctx: PortalContext = Depends(portal_context)
) -> JSONResponse:
    ip = client_ip(request)
    try:
        attempt, outcome = await ctx.authentik.sign_in(step.email, step.password, ip)
    except AuthentikFailedClosed as e:
        return failed_closed(e)
    return await _respond(request, ctx, attempt, outcome, WRONG_CREDENTIALS, step.next)


@router.post("/login/totp")
async def login_totp(
    step: TotpStep, request: Request, ctx: PortalContext = Depends(portal_context)
) -> JSONResponse:
    key = request.cookies.get(attempts.COOKIE)
    attempt = ctx.login_attempts.get(key, ctx.clock.now())
    if attempt is None:
        return JSONResponse({"error": TIMED_OUT, "step": "password"}, status_code=400)
    try:
        outcome = await ctx.authentik.submit_totp(attempt, step.code)
    except AuthentikFailedClosed as e:
        ctx.login_attempts.drop(key)
        return failed_closed(e)
    return await _respond(request, ctx, attempt, outcome, WRONG_CODE, step.next)


@router.post("/logout")
async def logout(
    request: Request, ctx: PortalContext = Depends(portal_context)
) -> JSONResponse:
    if token := request.cookies.get(sessions.COOKIE):
        await security.log_out(ctx, token=token, ip=client_ip(request))
    response = JSONResponse({"next": "/login"})
    sessions.clear_cookie(response)
    return response


async def _respond(
    request: Request,
    ctx: PortalContext,
    attempt: FlowAttempt,
    outcome: Outcome,
    wrong: str,
    next_url: str = "",
) -> JSONResponse:
    if isinstance(outcome, Identity):
        response = await signed_in(
            request, ctx, outcome, next_url=safe_next(next_url or "/")
        )
        ctx.login_attempts.drop(request.cookies.get(attempts.COOKIE))
        response.delete_cookie(attempts.COOKIE, path="/", secure=True, httponly=True)
        return response
    if isinstance(outcome, NeedsTotp):
        response = JSONResponse({"step": "totp"})
        attempts.keep(ctx.login_attempts, attempts.COOKIE, attempt, ctx, response)
        return response
    return JSONResponse({"error": wrong}, status_code=401)


async def signed_in(
    request: Request,
    ctx: PortalContext,
    identity: Identity,
    *,
    recovered: bool = False,
    next_url: str = "/",
) -> JSONResponse:
    """Start a Portal session for whoever Authentik says signed in.

    After a recovery, the ``PasswordChanged`` hooks run first (in the same
    transaction), so they can end every session that existed before it.
    While the review of recent Shares is due, it's where the user lands.
    """
    now = ctx.clock.now()
    ip = client_ip(request)
    lifetime = ctx.settings.session_lifetime
    async with ctx.db.connection() as conn:
        account = await upsert_on_login(conn, identity, now)
        if recovered:
            await audit.record(
                conn, at=now, kind=audit.PASSWORD_RECOVERY, account_id=account.id, ip=ip
            )
            await ctx.account_events.password_changed(
                conn, PasswordChanged(account.id, now, events.RECOVERY, None, ip)
            )
        if await review.is_due(conn, account.id):
            next_url = review.PATH
        token = await sessions.start(conn, account.id, now, lifetime)
        await audit.record(conn, at=now, kind=audit.LOGIN, account_id=account.id, ip=ip)
        await sharing.convert_pending(conn, ctx, account, ip)
    log.info("account %s signed in", account.id)
    response = JSONResponse({"next": next_url})
    sessions.set_cookie(response, token, lifetime)
    return response


def failed_closed(
    error: AuthentikFailedClosed, message: str = UNAVAILABLE
) -> JSONResponse:
    """Authentik did something unexpected: an error, never a redirect."""
    log.warning("Authentik flow failed closed: %s", error)
    return JSONResponse({"error": message}, status_code=502)
