"""The account page: two-step sign-in (TOTP) on and off, and password change.

The Portal keeps no Authentik session, so each change re-checks the password
by running a flow as the user:

- Turning TOTP on runs the TOTP setup flow (password, then a new secret shown
  here as a QR code, then a confirmation code).
- Turning it off signs in through the login flow with the password and a
  current code, then removes the device through the admin API (Authentik has
  no flow stage that removes one).
- Changing the password runs the password change flow (current password, TOTP
  code if on, new password) and fires ``PasswordChanged``.
"""

from __future__ import annotations

import segno
from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from pydantic import BaseModel

from sp_rtk_portal import audit
from sp_rtk_portal.accounts import attempts, events, review, sessions
from sp_rtk_portal.accounts.authentik import (
    AUTHENTICATOR_VALIDATE,
    IDENTIFICATION,
    PASSWORD,
    AuthentikFailedClosed,
    Done,
    FlowAttempt,
    Identity,
    NeedsTotp,
    Outcome,
    Rejected,
    TotpSetup,
)
from sp_rtk_portal.accounts.deps import current_account
from sp_rtk_portal.accounts.events import PasswordChanged
from sp_rtk_portal.accounts.routes import failed_closed
from sp_rtk_portal.accounts.store import Account, authentik_sub
from sp_rtk_portal.context import PortalContext, portal_context
from sp_rtk_portal.web.client_ip import client_ip
from sp_rtk_portal.web.templates import render

router = APIRouter()

FAILED = "Something went wrong. Please try again later."
WRONG_PASSWORD = "Wrong password."
WRONG_CODE = "Wrong code. Try again."
TIMED_OUT = "This took too long. Please start again."


class PasswordOnly(BaseModel):
    password: str


class Code(BaseModel):
    code: str


class PasswordAndCode(BaseModel):
    password: str
    code: str


class NewPassword(BaseModel):
    current_password: str
    password: str
    password_repeat: str


@router.get("/account", response_class=HTMLResponse)
async def account_page(
    request: Request,
    account: Account = Depends(current_account),
    ctx: PortalContext = Depends(portal_context),
) -> HTMLResponse:
    totp: bool | None
    try:
        totp = await ctx.authentik.has_totp(await _sub(ctx, account))
    except AuthentikFailedClosed:
        totp = None  # shown as unknown
    return render(request, "account.html", title="Account", account=account, totp=totp)


# --- TOTP on -------------------------------------------------------------------


@router.post("/account/totp")
async def totp_start(
    form: PasswordOnly,
    request: Request,
    account: Account = Depends(current_account),
    ctx: PortalContext = Depends(portal_context),
) -> JSONResponse:
    try:
        attempt, outcome = await ctx.authentik.start_totp_setup(
            account.email, form.password, client_ip(request), account.id
        )
    except AuthentikFailedClosed as e:
        return failed_closed(e, FAILED)
    if isinstance(outcome, TotpSetup):
        response = JSONResponse({"next": "/account/totp/setup"})
        attempts.keep(ctx.flow_attempts, attempts.FLOW_COOKIE, attempt, ctx, response)
        return response
    return _refused(outcome)


@router.get("/account/totp/setup", response_class=HTMLResponse)
async def totp_setup_page(
    request: Request,
    account: Account = Depends(current_account),
    ctx: PortalContext = Depends(portal_context),
) -> Response:
    attempt = _pending(request, ctx, account, ctx.settings.totp_setup_flow_slug)
    if attempt is None or attempt.totp_setup is None:
        return RedirectResponse("/account", status_code=303)
    setup = attempt.totp_setup
    qr = segno.make(setup.config_url, error="m").svg_inline(scale=4, omitsize=True)
    return render(
        request,
        "totp_setup.html",
        title="Turn on two-step sign-in",
        account=account,
        qr_svg=qr,
        secret=setup.secret,
    )


@router.post("/account/totp/confirm")
async def totp_confirm(
    step: Code,
    request: Request,
    account: Account = Depends(current_account),
    ctx: PortalContext = Depends(portal_context),
) -> JSONResponse:
    attempt = _pending(request, ctx, account, ctx.settings.totp_setup_flow_slug)
    if attempt is None:
        return JSONResponse({"error": TIMED_OUT, "next": "/account"}, status_code=400)
    try:
        outcome = await ctx.authentik.submit_code(attempt, step.code)
    except AuthentikFailedClosed as e:
        ctx.flow_attempts.drop(request.cookies.get(attempts.FLOW_COOKIE))
        return failed_closed(e, FAILED)
    if isinstance(outcome, Rejected):
        return JSONResponse({"error": WRONG_CODE}, status_code=401)
    if not isinstance(outcome, Done):
        return failed_closed(AuthentikFailedClosed(f"TOTP setup gave {outcome!r}"))
    await _audit(request, ctx, account, audit.TOTP_ENABLED)
    response = JSONResponse({"next": "/account"})
    attempts.forget(
        ctx.flow_attempts,
        attempts.FLOW_COOKIE,
        request.cookies.get(attempts.FLOW_COOKIE),
        response,
    )
    return response


# --- TOTP off ------------------------------------------------------------------


@router.post("/account/totp/disable")
async def totp_disable(
    form: PasswordAndCode,
    request: Request,
    account: Account = Depends(current_account),
    ctx: PortalContext = Depends(portal_context),
) -> JSONResponse:
    try:
        attempt, outcome = await ctx.authentik.sign_in(
            account.email, form.password, client_ip(request)
        )
        if isinstance(outcome, Rejected):
            return JSONResponse({"error": WRONG_PASSWORD}, status_code=401)
        if not isinstance(outcome, NeedsTotp):
            # Signed straight in: there's no TOTP to turn off.
            return JSONResponse({"next": "/account"})
        outcome = await ctx.authentik.submit_code(attempt, form.code)
        if isinstance(outcome, Rejected):
            return JSONResponse({"error": WRONG_CODE}, status_code=401)
        sub = await _sub(ctx, account)
        if not isinstance(outcome, Identity) or outcome.sub != sub:
            raise AuthentikFailedClosed("re-check signed in someone else")
        await ctx.authentik.remove_totp(sub)
    except AuthentikFailedClosed as e:
        return failed_closed(e, FAILED)
    await _audit(request, ctx, account, audit.TOTP_DISABLED)
    return JSONResponse({"next": "/account"})


# --- password change -----------------------------------------------------------


@router.post("/account/password")
async def change_password(
    form: NewPassword,
    request: Request,
    account: Account = Depends(current_account),
    ctx: PortalContext = Depends(portal_context),
) -> JSONResponse:
    try:
        attempt, outcome = await ctx.authentik.change_password(
            account.email,
            form.current_password,
            form.password,
            form.password_repeat,
            client_ip(request),
            account.id,
        )
    except AuthentikFailedClosed as e:
        return failed_closed(e, FAILED)
    return await _password_outcome(request, ctx, account, attempt, outcome)


@router.post("/account/password/totp")
async def change_password_totp(
    step: Code,
    request: Request,
    account: Account = Depends(current_account),
    ctx: PortalContext = Depends(portal_context),
) -> JSONResponse:
    slug = ctx.settings.password_change_flow_slug
    attempt = _pending(request, ctx, account, slug)
    if attempt is None:
        return JSONResponse({"error": TIMED_OUT, "step": "password"}, status_code=400)
    try:
        outcome = await ctx.authentik.submit_code(attempt, step.code)
    except AuthentikFailedClosed as e:
        ctx.flow_attempts.drop(request.cookies.get(attempts.FLOW_COOKIE))
        return failed_closed(e, FAILED)
    return await _password_outcome(request, ctx, account, attempt, outcome)


async def _password_outcome(
    request: Request,
    ctx: PortalContext,
    account: Account,
    attempt: FlowAttempt,
    outcome: Outcome,
) -> JSONResponse:
    key = request.cookies.get(attempts.FLOW_COOKIE)
    if isinstance(outcome, NeedsTotp):
        response = JSONResponse({"step": "totp"})
        attempts.keep(ctx.flow_attempts, attempts.FLOW_COOKIE, attempt, ctx, response)
        return response
    if isinstance(outcome, Rejected) and outcome.stage == AUTHENTICATOR_VALIDATE:
        return JSONResponse({"error": WRONG_CODE}, status_code=401)
    if isinstance(outcome, Done):
        now = ctx.clock.now()
        async with ctx.db.connection() as conn:
            await audit.record(
                conn,
                at=now,
                kind=audit.PASSWORD_CHANGE,
                account_id=account.id,
                ip=client_ip(request),
            )
            await ctx.account_events.password_changed(
                conn,
                PasswordChanged(
                    account.id,
                    now,
                    events.CHANGE,
                    request.cookies.get(sessions.COOKIE),
                    client_ip(request),
                ),
            )
        response = JSONResponse({"next": review.PATH})
    else:
        response = _refused(outcome)
    attempts.forget(ctx.flow_attempts, attempts.FLOW_COOKIE, key, response)
    return response


# --- helpers -------------------------------------------------------------------


def _pending(
    request: Request, ctx: PortalContext, account: Account, slug: str
) -> FlowAttempt | None:
    """This account's pending step of ``slug``, if any."""
    key = request.cookies.get(attempts.FLOW_COOKIE)
    attempt = ctx.flow_attempts.get(key, ctx.clock.now())
    if attempt is None or attempt.slug != slug or attempt.account_id != account.id:
        return None
    return attempt


def _refused(outcome: Outcome) -> JSONResponse:
    if isinstance(outcome, Rejected):
        if outcome.stage in (IDENTIFICATION, PASSWORD):
            return JSONResponse({"error": WRONG_PASSWORD}, status_code=401)
        return JSONResponse({"error": outcome.message}, status_code=400)
    return failed_closed(AuthentikFailedClosed(f"flow ended with {outcome!r}"), FAILED)


async def _sub(ctx: PortalContext, account: Account) -> str:
    async with ctx.db.connection() as conn:
        return await authentik_sub(conn, account.id)


async def _audit(
    request: Request, ctx: PortalContext, account: Account, kind: str
) -> None:
    async with ctx.db.connection() as conn:
        await audit.record(
            conn,
            at=ctx.clock.now(),
            kind=kind,
            account_id=account.id,
            ip=client_ip(request),
        )
