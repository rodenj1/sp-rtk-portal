"""Account security pages and actions: log out everywhere, the review of
recent Shares after a password change or recovery, and account deletion."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from sp_rtk_portal.accounts import attempts, deletion, review, security, sessions
from sp_rtk_portal.accounts.authentik import (
    ACCESS_DENIED,
    AUTHENTICATOR_VALIDATE,
    IDENTIFICATION,
    PASSWORD,
    AuthentikFailedClosed,
    FlowAttempt,
    NeedsTotp,
    Outcome,
    ReadyToDelete,
    Rejected,
)
from sp_rtk_portal.accounts.deps import current_account
from sp_rtk_portal.accounts.routes import failed_closed
from sp_rtk_portal.accounts.store import Account
from sp_rtk_portal.context import PortalContext, portal_context
from sp_rtk_portal.shares import sharing
from sp_rtk_portal.web.client_ip import client_ip
from sp_rtk_portal.web.templates import render

log = logging.getLogger(__name__)

router = APIRouter()


@router.post("/account/logout-everywhere")
async def logout_everywhere(
    request: Request,
    account: Account = Depends(current_account),
    ctx: PortalContext = Depends(portal_context),
) -> JSONResponse:
    await security.log_out_everywhere(ctx, account_id=account.id, ip=client_ip(request))
    response = JSONResponse({"next": "/login"})
    sessions.clear_cookie(response)
    return response


# --- review of recent Shares -------------------------------------------------------


@router.get(review.PATH, response_class=HTMLResponse)
async def review_page(
    request: Request,
    account: Account = Depends(current_account),
    ctx: PortalContext = Depends(portal_context),
) -> HTMLResponse:
    now = ctx.clock.now()
    async with ctx.db.connection() as conn:
        shares = await review.recent_shares(conn, account.id, now)
        pending = await review.recent_pending_shares(conn, account.id, now)
    return render(
        request,
        "review.html",
        title="Review recent Shares",
        account=account,
        shares=shares,
        pending=pending,
        days=review.WINDOW.days,
    )


@router.post(review.PATH + "/shares/{base_id}/{account_id}/remove")
async def review_remove_share(
    base_id: str,
    account_id: int,
    request: Request,
    account: Account = Depends(current_account),
    ctx: PortalContext = Depends(portal_context),
) -> JSONResponse:
    done = await sharing.remove(
        ctx,
        base_id=base_id,
        operator_id=account.id,
        account_id=account_id,
        ip=client_ip(request),
    )
    if not done:
        return JSONResponse({"error": "No such Share."}, status_code=404)
    return JSONResponse({"next": review.PATH})


@router.post(review.PATH + "/pending-shares/{base_id}/{pending_id}/remove")
async def review_remove_pending_share(
    base_id: str,
    pending_id: int,
    request: Request,
    account: Account = Depends(current_account),
    ctx: PortalContext = Depends(portal_context),
) -> JSONResponse:
    done = await sharing.remove_pending(
        ctx,
        base_id=base_id,
        operator_id=account.id,
        pending_id=pending_id,
        ip=client_ip(request),
    )
    if not done:
        return JSONResponse({"error": "No such Pending share."}, status_code=404)
    return JSONResponse({"next": review.PATH})


@router.post(review.PATH + "/done")
async def review_done(
    account: Account = Depends(current_account),
    ctx: PortalContext = Depends(portal_context),
) -> JSONResponse:
    async with ctx.db.connection() as conn:
        await review.seen(conn, account.id)
    return JSONResponse({"next": "/"})


# --- account deletion -----------------------------------------------------------------

DELETE_FAILED = "Your account couldn't be deleted right now. Nothing was changed."
DELETE_UNFINISHED = (
    "Your account couldn't be deleted right now. Your bases and Shares are"
    " unchanged. Try again."
)
WRONG_PASSWORD = "Wrong password."
WRONG_CODE = "Wrong code."
TIMED_OUT = "This took too long. Please start again."
UNFINISHED_PATH = "/account/delete/unfinished"


class DeletePassword(BaseModel):
    password: str


class DeleteCode(BaseModel):
    code: str


@router.get("/account/delete", response_class=HTMLResponse)
async def delete_page(
    request: Request,
    account: Account = Depends(current_account),
    ctx: PortalContext = Depends(portal_context),
) -> HTMLResponse:
    async with ctx.db.connection() as conn:
        owned = await deletion.preview(conn, account.id)
    return render(
        request,
        "delete_account.html",
        title="Delete your account",
        account=account,
        bases=owned,
    )


@router.post("/account/delete")
async def delete_account(
    form: DeletePassword,
    request: Request,
    account: Account = Depends(current_account),
    ctx: PortalContext = Depends(portal_context),
) -> JSONResponse:
    try:
        attempt, outcome = await deletion.start(
            ctx, account, form.password, client_ip(request)
        )
    except AuthentikFailedClosed as e:
        return failed_closed(e, DELETE_FAILED)
    if isinstance(outcome, NeedsTotp):
        response = JSONResponse({"step": "totp"})
        attempts.keep(ctx.flow_attempts, attempts.FLOW_COOKIE, attempt, ctx, response)
        return response
    return await _deletion_outcome(request, ctx, account, attempt, outcome)


@router.post("/account/delete/totp")
async def delete_account_totp(
    step: DeleteCode,
    request: Request,
    account: Account = Depends(current_account),
    ctx: PortalContext = Depends(portal_context),
) -> JSONResponse:
    key = request.cookies.get(attempts.FLOW_COOKIE)
    attempt = ctx.flow_attempts.get(key, ctx.clock.now())
    if (
        attempt is None
        or attempt.slug != ctx.settings.unenrollment_flow_slug
        or attempt.account_id != account.id
    ):
        return JSONResponse({"error": TIMED_OUT, "step": "password"}, status_code=400)
    try:
        outcome = await ctx.authentik.submit_code(attempt, step.code)
    except AuthentikFailedClosed as e:
        ctx.flow_attempts.drop(key)
        return failed_closed(e, DELETE_FAILED)
    if isinstance(outcome, Rejected) and outcome.stage == AUTHENTICATOR_VALIDATE:
        return JSONResponse({"error": WRONG_CODE}, status_code=401)
    ctx.flow_attempts.drop(key)
    response = await _deletion_outcome(request, ctx, account, attempt, outcome)
    response.delete_cookie(attempts.FLOW_COOKIE, path="/", secure=True, httponly=True)
    return response


async def _deletion_outcome(
    request: Request,
    ctx: PortalContext,
    account: Account,
    attempt: FlowAttempt,
    outcome: Outcome,
) -> JSONResponse:
    if isinstance(outcome, Rejected):
        if outcome.stage in (IDENTIFICATION, PASSWORD, ACCESS_DENIED):
            # ACCESS_DENIED: the account isn't in portal-users (the deny
            # stage). Answer as for a wrong password; never Authentik's text.
            return JSONResponse({"error": WRONG_PASSWORD}, status_code=401)
        return failed_closed(
            AuthentikFailedClosed(f"deletion refused at {outcome.stage!r}"),
            DELETE_FAILED,
        )
    if not isinstance(outcome, ReadyToDelete):
        return failed_closed(
            AuthentikFailedClosed(f"deletion flow gave {outcome!r}"), DELETE_FAILED
        )
    try:
        complete = await deletion.delete_account(
            ctx, account, attempt, client_ip(request)
        )
    except Exception:
        # The Portal's own changes rolled back as one, and the Authentik user
        # is untouched (it goes last); still signed in, they can try again.
        log.exception("account %s: deletion failed", account.id)
        return JSONResponse({"error": DELETE_UNFINISHED}, status_code=500)
    response = JSONResponse({"next": "/login" if complete else UNFINISHED_PATH})
    sessions.clear_cookie(response)
    return response


@router.get(UNFINISHED_PATH, response_class=HTMLResponse)
async def deletion_unfinished(request: Request) -> HTMLResponse:
    return render(
        request, "delete_unfinished.html", title="Account deletion unfinished"
    )
