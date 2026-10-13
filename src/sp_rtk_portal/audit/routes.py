"""The audit log page: ``/audit``."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse

from sp_rtk_portal.accounts.deps import current_account
from sp_rtk_portal.accounts.store import Account
from sp_rtk_portal.audit import log
from sp_rtk_portal.context import PortalContext, portal_context
from sp_rtk_portal.web.templates import render

router = APIRouter()

PATH = "/audit"


@router.get(PATH, response_class=HTMLResponse)
async def audit_page(
    request: Request,
    page: int = Query(0, ge=0, le=10_000),
    account: Account = Depends(current_account),
    ctx: PortalContext = Depends(portal_context),
) -> HTMLResponse:
    async with ctx.db.connection() as conn:
        entries, more = await log.visible_to(
            conn, account.id, ctx.clock.now(), page=page
        )
    return render(
        request,
        "audit.html",
        title="Audit log",
        account=account,
        entries=entries,
        page=page,
        more=more,
        days=log.RETENTION.days,
    )
