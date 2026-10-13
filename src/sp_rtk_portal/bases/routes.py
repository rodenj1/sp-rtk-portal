"""The base list, and ``/claim`` where an Operator approves a pairing code."""

from __future__ import annotations

from dataclasses import dataclass

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from sp_rtk_portal.accounts.deps import current_account
from sp_rtk_portal.accounts.store import Account
from sp_rtk_portal.agent_api import config as agent_config
from sp_rtk_portal.bases import claims, online, store
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
        bases = await store.listed_for(conn, account.id)
        config = await agent_config.current(conn, ctx.settings)
        notices = await agent_config.notices(conn)
        latest = await agent_config.latest_release(conn)
    now = ctx.clock.now()
    cards = [
        BaseCard(
            base=base,
            state=(state := online.state(base, config, now)),
            state_label=online.LABELS[state],
            poll_interval=online.interval(config, base.metered),
            update=latest
            if agent_config.update_available(base.software_version, latest)
            else None,
        )
        for base in bases
    ]
    return render(
        request,
        "bases.html",
        title="Your bases",
        account=account,
        bases=cards,
        notices=[n.text for n in notices],
    )


@dataclass(frozen=True)
class BaseCard:
    """One base as the list shows it."""

    base: store.BaseSummary
    state: online.State
    state_label: str
    poll_interval: int
    update: str | None
    """A newer sp-rtk-base release, shown as information."""


class Metered(BaseModel):
    metered: bool


@router.post("/bases/{base_id}/metered")
async def set_metered(
    base_id: str,
    body: Metered,
    account: Account = Depends(current_account),
    ctx: PortalContext = Depends(portal_context),
) -> JSONResponse:
    """The Operator marks their base metered (it then polls every 60 s), or
    not. The base learns it on its next poll."""
    async with ctx.db.connection() as conn:
        found = await store.set_metered(conn, base_id, account.id, body.metered)
    if not found:
        return JSONResponse({"error": "No such base."}, status_code=404)
    return JSONResponse({"next": "/"})


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
