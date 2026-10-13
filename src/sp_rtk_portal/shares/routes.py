"""A base's Shares page (its Operator's only) and the Share actions."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from sp_rtk_portal.accounts.deps import current_account
from sp_rtk_portal.accounts.store import Account
from sp_rtk_portal.bases import store as bases
from sp_rtk_portal.context import PortalContext, portal_context
from sp_rtk_portal.ratelimit import try_again_in
from sp_rtk_portal.shares import sharing, store
from sp_rtk_portal.web.client_ip import client_ip
from sp_rtk_portal.web.templates import render

router = APIRouter()

NO_SUCH_BASE = "No such base."


class ShareRequest(BaseModel):
    email: str


@router.get("/bases/{base_id}/shares", response_class=HTMLResponse)
async def shares_page(
    base_id: str,
    request: Request,
    account: Account = Depends(current_account),
    ctx: PortalContext = Depends(portal_context),
) -> HTMLResponse:
    async with ctx.db.connection() as conn:
        base = await bases.reachable_by(conn, account.id, base_id)
        if base is None or base.role != bases.OPERATOR:
            return HTMLResponse(NO_SUCH_BASE, status_code=404)
        shared = await store.shared_users(conn, base_id)
        pending = await store.pending_shares(conn, base_id, ctx.clock.now())
    return render(
        request,
        "shares.html",
        title=f"Share {base.name}",
        account=account,
        base=base,
        shared=shared,
        pending=pending,
        max_shared=ctx.settings.max_shared_users_per_base,
        max_pending=ctx.settings.max_pending_shares_per_base,
        pending_days=ctx.settings.pending_share_lifetime.days,
    )


@router.post("/bases/{base_id}/shares")
async def share(
    base_id: str,
    body: ShareRequest,
    request: Request,
    account: Account = Depends(current_account),
    ctx: PortalContext = Depends(portal_context),
) -> JSONResponse:
    # Each Share emails someone: a cap per Operator an hour (ticket #98).
    s = ctx.settings
    wait = ctx.limits.over(
        "share",
        str(account.id),
        limit=s.shares_per_operator,
        period=s.rate_limit_period,
    )
    if wait is not None:
        return JSONResponse(
            {"error": f"Too many Shares. {try_again_in(wait)}"}, status_code=429
        )
    try:
        await sharing.share(
            ctx,
            base_id=base_id,
            operator=account,
            email=body.email,
            ip=client_ip(request),
        )
    except sharing.ShareRefused as refused:
        return JSONResponse({"error": str(refused)}, status_code=refused.status)
    ctx.limits.hit("share", str(account.id), period=s.rate_limit_period)
    return JSONResponse({"next": f"/bases/{base_id}/shares"})


@router.post("/bases/{base_id}/shares/{account_id}/remove")
async def remove_share(
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
    return JSONResponse({"next": f"/bases/{base_id}/shares"})


@router.post("/bases/{base_id}/pending-shares/{pending_id}/remove")
async def remove_pending_share(
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
    return JSONResponse({"next": f"/bases/{base_id}/shares"})


@router.post("/bases/{base_id}/leave")
async def leave_share(
    base_id: str,
    request: Request,
    account: Account = Depends(current_account),
    ctx: PortalContext = Depends(portal_context),
) -> JSONResponse:
    """A Shared user leaves the Share: the base leaves their list."""
    done = await sharing.leave(
        ctx, base_id=base_id, account_id=account.id, ip=client_ip(request)
    )
    if not done:
        return JSONResponse({"error": "No such Share."}, status_code=404)
    return JSONResponse({"next": "/"})
