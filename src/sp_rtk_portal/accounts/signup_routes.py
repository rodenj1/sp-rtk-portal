"""Sign-up, email verification and password recovery, on the Portal's pages.

- ``/signup``: email + password + Turnstile. Authentik emails a link to
  ``/verify?t=…``; the account can't sign in until it's opened.
- ``/recover``: email + Turnstile. Authentik emails a link to ``/reset?t=…``,
  where the user sets a new password (and gives their TOTP code if they have
  one) and is signed in. That fires ``PasswordChanged``.

Opening an emailed link only shows a page with a button: the token is spent
when the user posts it, so a mail scanner that fetches links can't use it up.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from sp_rtk_portal.accounts import attempts
from sp_rtk_portal.accounts.authentik import (
    AUTHENTICATOR_VALIDATE,
    PROMPT,
    AuthentikFailedClosed,
    Done,
    EmailSent,
    FlowAttempt,
    Identity,
    LinkExpired,
    NeedsTotp,
    Outcome,
    Rejected,
)
from sp_rtk_portal.accounts.routes import failed_closed, signed_in
from sp_rtk_portal.context import PortalContext, portal_context
from sp_rtk_portal.web.client_ip import client_ip
from sp_rtk_portal.web.templates import render

router = APIRouter()

FAILED = "Something went wrong. Please try again later."
LINK_EXPIRED = "This link has expired or was already used. Please start again."
TIMED_OUT = "This took too long. Please open the link from your email again."
WRONG_CODE = "Wrong code. Try again."


class _Turnstile(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    # The hidden field Turnstile adds to the form.
    turnstile: str = Field("", alias="cf-turnstile-response")


class SignUp(_Turnstile):
    email: str
    password: str
    password_repeat: str


class Recover(_Turnstile):
    email: str


class Link(BaseModel):
    t: str


class Reset(Link):
    password: str
    password_repeat: str


class Code(BaseModel):
    code: str


# --- sign-up -------------------------------------------------------------------


@router.get("/signup", response_class=HTMLResponse)
async def signup_page(
    request: Request, ctx: PortalContext = Depends(portal_context)
) -> HTMLResponse:
    return render(
        request,
        "signup.html",
        title="Create an account",
        site_key=ctx.settings.turnstile_site_key,
    )


@router.post("/signup")
async def signup(
    form: SignUp, request: Request, ctx: PortalContext = Depends(portal_context)
) -> JSONResponse:
    try:
        outcome = await ctx.authentik.enroll(
            form.email,
            form.password,
            form.password_repeat,
            form.turnstile,
            client_ip(request),
        )
    except AuthentikFailedClosed as e:
        return failed_closed(e, FAILED)
    if isinstance(outcome, EmailSent):
        return JSONResponse({"next": "/signup/sent"})
    return _rejected(outcome)


@router.get("/signup/sent", response_class=HTMLResponse)
async def signup_sent(request: Request) -> HTMLResponse:
    return render(
        request, "email_sent.html", title="Check your email", purpose="signup"
    )


@router.get("/verify", response_class=HTMLResponse)
async def verify_page(request: Request, t: str = "") -> HTMLResponse:
    return render(request, "verify.html", title="Confirm your email", token=t)


@router.post("/verify")
async def verify(
    link: Link, request: Request, ctx: PortalContext = Depends(portal_context)
) -> JSONResponse:
    try:
        outcome = await ctx.authentik.verify_email(link.t, client_ip(request))
    except AuthentikFailedClosed as e:
        return failed_closed(e, FAILED)
    if isinstance(outcome, Done):
        return JSONResponse({"next": "/login?verified=1"})
    return _rejected(outcome)


# --- recovery ------------------------------------------------------------------


@router.get("/recover", response_class=HTMLResponse)
async def recover_page(
    request: Request, ctx: PortalContext = Depends(portal_context)
) -> HTMLResponse:
    return render(
        request,
        "recover.html",
        title="Reset your password",
        site_key=ctx.settings.turnstile_site_key,
    )


@router.post("/recover")
async def recover(
    form: Recover, request: Request, ctx: PortalContext = Depends(portal_context)
) -> JSONResponse:
    try:
        outcome = await ctx.authentik.request_recovery(
            form.email, form.turnstile, client_ip(request)
        )
    except AuthentikFailedClosed as e:
        return failed_closed(e, FAILED)
    if isinstance(outcome, EmailSent):
        return JSONResponse({"next": "/recover/sent"})
    return _rejected(outcome)


@router.get("/recover/sent", response_class=HTMLResponse)
async def recover_sent(request: Request) -> HTMLResponse:
    return render(
        request, "email_sent.html", title="Check your email", purpose="recover"
    )


@router.get("/reset", response_class=HTMLResponse)
async def reset_page(request: Request, t: str = "") -> HTMLResponse:
    return render(request, "reset.html", title="Choose a new password", token=t)


@router.post("/reset")
async def reset(
    form: Reset, request: Request, ctx: PortalContext = Depends(portal_context)
) -> JSONResponse:
    ip = client_ip(request)
    pending = _pending_reset(request, ctx)
    try:
        if pending is not None and pending.stage == PROMPT:
            # The link was spent on a password Authentik refused: try again
            # in the same flow session.
            attempt = pending
            outcome = await ctx.authentik.retry(
                attempt,
                PROMPT,
                {"password": form.password, "password_repeat": form.password_repeat},
            )
        else:
            attempt, outcome = await ctx.authentik.reset_password(
                form.t, form.password, form.password_repeat, ip
            )
    except AuthentikFailedClosed as e:
        return failed_closed(e, FAILED)
    return await _reset_outcome(request, ctx, attempt, outcome)


@router.post("/reset/totp")
async def reset_totp(
    step: Code, request: Request, ctx: PortalContext = Depends(portal_context)
) -> JSONResponse:
    attempt = _pending_reset(request, ctx)
    if attempt is None or attempt.stage != AUTHENTICATOR_VALIDATE:
        return JSONResponse({"error": TIMED_OUT}, status_code=400)
    try:
        outcome = await ctx.authentik.submit_code(attempt, step.code)
    except AuthentikFailedClosed as e:
        ctx.flow_attempts.drop(request.cookies.get(attempts.FLOW_COOKIE))
        return failed_closed(e, FAILED)
    return await _reset_outcome(request, ctx, attempt, outcome)


def _pending_reset(request: Request, ctx: PortalContext) -> FlowAttempt | None:
    key = request.cookies.get(attempts.FLOW_COOKIE)
    attempt = ctx.flow_attempts.get(key, ctx.clock.now())
    if attempt is None or attempt.slug != ctx.settings.recovery_flow_slug:
        return None
    return attempt


async def _reset_outcome(
    request: Request, ctx: PortalContext, attempt: FlowAttempt, outcome: Outcome
) -> JSONResponse:
    pending = request.cookies.get(attempts.FLOW_COOKIE)
    if isinstance(outcome, NeedsTotp):
        response = JSONResponse({"step": "totp"})
        attempts.forget(ctx.flow_attempts, attempts.FLOW_COOKIE, pending, response)
        attempts.keep(ctx.flow_attempts, attempts.FLOW_COOKIE, attempt, ctx, response)
        return response
    if isinstance(outcome, Rejected) and outcome.stage == AUTHENTICATOR_VALIDATE:
        return JSONResponse({"error": WRONG_CODE}, status_code=401)
    if isinstance(outcome, Rejected) and outcome.stage == PROMPT:
        # Keep the flow so the user can choose another password.
        response = JSONResponse({"error": outcome.message}, status_code=400)
        if (
            pending is None
            or ctx.flow_attempts.get(pending, ctx.clock.now()) is not attempt
        ):
            attempts.keep(
                ctx.flow_attempts, attempts.FLOW_COOKIE, attempt, ctx, response
            )
        return response
    if isinstance(outcome, Identity):
        response = await signed_in(request, ctx, outcome, recovered=True)
    else:
        response = _rejected(outcome)
    attempts.forget(ctx.flow_attempts, attempts.FLOW_COOKIE, pending, response)
    return response


def _rejected(outcome: Outcome) -> JSONResponse:
    if isinstance(outcome, LinkExpired):
        return JSONResponse({"error": LINK_EXPIRED}, status_code=400)
    if isinstance(outcome, Rejected):
        return JSONResponse({"error": outcome.message}, status_code=400)
    return failed_closed(AuthentikFailedClosed(f"flow ended with {outcome!r}"), FAILED)
