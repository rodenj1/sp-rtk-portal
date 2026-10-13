"""Account security pages and actions: log out everywhere, and the review
of recent Shares after a password change or recovery."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, JSONResponse

from sp_rtk_portal.accounts import review, security, sessions
from sp_rtk_portal.accounts.deps import current_account
from sp_rtk_portal.accounts.store import Account
from sp_rtk_portal.context import PortalContext, portal_context
from sp_rtk_portal.shares import sharing
from sp_rtk_portal.web.client_ip import client_ip
from sp_rtk_portal.web.templates import render

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
