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
from sp_rtk_portal.accounts import attempts, sessions
from sp_rtk_portal.accounts.authentik import (
    AuthentikFailedClosed,
    Identity,
    LoginAttempt,
    NeedsTotp,
    Outcome,
)
from sp_rtk_portal.accounts.store import upsert_on_login
from sp_rtk_portal.context import PortalContext, portal_context
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


class TotpStep(BaseModel):
    code: str


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request) -> HTMLResponse:
    return render(request, "login.html", title="Sign in")


@router.post("/login")
async def login(
    step: PasswordStep, request: Request, ctx: PortalContext = Depends(portal_context)
) -> JSONResponse:
    ip = client_ip(request)
    try:
        attempt, outcome = await ctx.authentik.sign_in(step.email, step.password, ip)
    except AuthentikFailedClosed as e:
        return _failed_closed(e)
    return await _respond(request, ctx, attempt, outcome, WRONG_CREDENTIALS)


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
        return _failed_closed(e)
    return await _respond(request, ctx, attempt, outcome, WRONG_CODE)


@router.post("/logout")
async def logout(
    request: Request, ctx: PortalContext = Depends(portal_context)
) -> JSONResponse:
    if token := request.cookies.get(sessions.COOKIE):
        async with ctx.db.connection() as conn:
            await sessions.end(conn, token)
    response = JSONResponse({"next": "/login"})
    sessions.clear_cookie(response)
    return response


async def _respond(
    request: Request,
    ctx: PortalContext,
    attempt: LoginAttempt,
    outcome: Outcome,
    wrong: str,
) -> JSONResponse:
    if isinstance(outcome, Identity):
        return await _signed_in(request, ctx, outcome)
    if isinstance(outcome, NeedsTotp):
        key = ctx.login_attempts.put(attempt, ctx.clock.now())
        response = JSONResponse({"step": "totp"})
        response.set_cookie(
            attempts.COOKIE,
            key,
            max_age=int(ctx.login_attempts.lifetime.total_seconds()),
            path="/",
            secure=True,
            httponly=True,
            samesite="strict",
        )
        return response
    return JSONResponse({"error": wrong}, status_code=401)


async def _signed_in(
    request: Request, ctx: PortalContext, identity: Identity
) -> JSONResponse:
    now = ctx.clock.now()
    lifetime = ctx.settings.session_lifetime
    async with ctx.db.connection() as conn:
        account = await upsert_on_login(conn, identity, now)
        token = await sessions.start(conn, account.id, now, lifetime)
        await audit.record(
            conn, at=now, kind=audit.LOGIN, account_id=account.id, ip=client_ip(request)
        )
    ctx.login_attempts.drop(request.cookies.get(attempts.COOKIE))
    log.info("account %s signed in", account.id)
    response = JSONResponse({"next": "/"})
    sessions.set_cookie(response, token, lifetime)
    response.delete_cookie(attempts.COOKIE, path="/", secure=True, httponly=True)
    return response


def _failed_closed(error: AuthentikFailedClosed) -> JSONResponse:
    log.warning("sign-in failed closed: %s", error)
    return JSONResponse({"error": UNAVAILABLE}, status_code=502)
