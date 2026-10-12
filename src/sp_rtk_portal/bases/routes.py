"""The base list: the page a signed-in user lands on."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse

from sp_rtk_portal.accounts.deps import current_account
from sp_rtk_portal.accounts.store import Account
from sp_rtk_portal.web.templates import render

router = APIRouter()


@router.get("/", response_class=HTMLResponse)
async def base_list(
    request: Request, account: Account = Depends(current_account)
) -> HTMLResponse:
    # No Claims exist yet: the list is empty until the Claim ticket lands.
    return render(request, "bases.html", title="Your bases", account=account, bases=[])
