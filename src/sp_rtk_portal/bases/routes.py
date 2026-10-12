"""The base list, and ``/claim`` where an Operator approves a pairing code."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from sp_rtk_portal.accounts.deps import current_account
from sp_rtk_portal.accounts.store import Account
from sp_rtk_portal.bases import claims, store
from sp_rtk_portal.context import PortalContext, portal_context
from sp_rtk_portal.web.client_ip import client_ip
from sp_rtk_portal.web.templates import render

router = APIRouter()


@router.get("/", response_class=HTMLResponse)
async def base_list(
    request: Request,
    account: Account = Depends(current_account),
    ctx: PortalContext = Depends(portal_context),
) -> HTMLResponse:
    async with ctx.db.connection() as conn:
        bases = await store.owned_by(conn, account.id)
    return render(
        request, "bases.html", title="Your bases", account=account, bases=bases
    )


@router.get("/claim", response_class=HTMLResponse)
async def claim_page(
    request: Request,
    code: str = "",
    account: Account = Depends(current_account),
    ctx: PortalContext = Depends(portal_context),
) -> HTMLResponse:
    user_code = claims.normalize_user_code(code)
    pending, problem = None, ""
    if user_code:
        now = ctx.clock.now()
        async with ctx.db.connection() as conn:
            pending = await claims.find(conn, user_code, now)
        if pending is None:
            problem = claims.WRONG_CODE.format(code=claims.display_code(user_code))
        elif pending.used:
            problem = claims.USED
        elif pending.expired:
            problem = claims.EXPIRED
    return render(
        request,
        "claim.html",
        title="Claim a base",
        account=account,
        code=claims.display_code(user_code),
        pending=pending if pending and not problem else None,
        problem=problem,
    )


class Approval(BaseModel):
    code: str
    name: str


@router.post("/claim")
async def approve_claim(
    approval: Approval,
    request: Request,
    account: Account = Depends(current_account),
    ctx: PortalContext = Depends(portal_context),
) -> JSONResponse:
    try:
        async with ctx.db.connection() as conn:
            await claims.approve(
                conn,
                now=ctx.clock.now(),
                account_id=account.id,
                user_code=claims.normalize_user_code(approval.code),
                name=approval.name,
                ip=client_ip(request),
                limit=ctx.settings.max_bases_per_account,
            )
    except claims.ApprovalRefused as refused:
        return JSONResponse({"error": str(refused)}, status_code=400)
    return JSONResponse({"next": "/"})
