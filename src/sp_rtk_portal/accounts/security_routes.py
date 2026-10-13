"""Account page actions for account security: log out everywhere."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from sp_rtk_portal.accounts import security, sessions
from sp_rtk_portal.accounts.deps import current_account
from sp_rtk_portal.accounts.store import Account
from sp_rtk_portal.context import PortalContext, portal_context
from sp_rtk_portal.web.client_ip import client_ip

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
