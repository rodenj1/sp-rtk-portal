"""The base list, and ``/claim`` where an Operator approves a pairing code."""

from __future__ import annotations

from dataclasses import dataclass

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from sp_rtk_portal.accounts.deps import current_account
from sp_rtk_portal.accounts.store import Account
from sp_rtk_portal.agent_api import config as agent_config
from sp_rtk_portal.bases import claims, local, online, store, unclaim
from sp_rtk_portal.context import PortalContext, portal_context
from sp_rtk_portal.web.client_ip import client_ip
from sp_rtk_portal.web.security import allow_connect
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
    ip = client_ip(request)
    cards = [
        BaseCard(
            base=base,
            state=(state := online.state(base, config, now)),
            state_label=online.LABELS[state],
            poll_interval=online.interval(config, base.metered),
            update=latest
            if agent_config.update_available(base.software_version, latest)
            else None,
            local_access=local.local_access(
                base.lan_addresses,
                base.public_ip,
                ip,
                port=ctx.settings.base_ui_port,
            ),
        )
        for base in bases
    ]
    allow_connect(
        request,
        sorted({c.local_access.identity_url for c in cards if c.local_access}),
    )
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
    local_access: local.LocalAccess | None = None
    """Open locally, when the base reported a LAN address."""


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


@router.post("/bases/{base_id}/unclaim")
async def unclaim_base(
    base_id: str,
    request: Request,
    account: Account = Depends(current_account),
    ctx: PortalContext = Depends(portal_context),
) -> JSONResponse:
    """The Operator Un-claims their base (e.g. one they can no longer reach
    physically). Only its owner may: anyone else gets 404, Shared users
    included."""
    done = await unclaim.by_operator(
        ctx, base_id=base_id, account_id=account.id, ip=client_ip(request)
    )
    if not done:
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
    wait = _guessing_wait(ctx, account) if user_code else None
    if wait is not None:
        problem = _too_many_wrong_codes(wait)
    elif user_code:
        now = ctx.clock.now()
        async with ctx.db.connection() as conn:
            pending = await claims.find(conn, user_code, now)
        if pending is None:
            _wrong_code(ctx, account)
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
    wait = _guessing_wait(ctx, account)
    if wait is not None:
        return JSONResponse({"error": _too_many_wrong_codes(wait)}, status_code=429)
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
    except claims.WrongCode as refused:
        _wrong_code(ctx, account)
        return JSONResponse({"error": str(refused)}, status_code=400)
    except claims.ApprovalRefused as refused:
        return JSONResponse({"error": str(refused)}, status_code=400)
    return JSONResponse({"next": "/"})


# --- Wrong codes (ticket #98) ---------------------------------------------------
# A pairing code is 8 letters from 20 (2.56e10 codes), alive 10 minutes:
# guessing is hopeless as long as guesses are few. Each account gets
# ``wrong_codes_per_account`` an hour, and all accounts together
# ``wrong_codes_overall``. Over either, nothing is looked up, not even a
# right code, so a guesser learns nothing more.

_ALL = "*"


def _guessing_wait(ctx: PortalContext, account: Account) -> int | None:
    s = ctx.settings
    waits = [
        ctx.limits.over("wrong-code", key, limit=limit, period=s.rate_limit_period)
        for key, limit in (
            (str(account.id), s.wrong_codes_per_account),
            (_ALL, s.wrong_codes_overall),
        )
    ]
    return max((w for w in waits if w is not None), default=None)


def _wrong_code(ctx: PortalContext, account: Account) -> None:
    for key in (str(account.id), _ALL):
        ctx.limits.hit("wrong-code", key, period=ctx.settings.rate_limit_period)


def _too_many_wrong_codes(wait: int) -> str:
    minutes = max(1, -(-wait // 60))
    unit = "minute" if minutes == 1 else "minutes"
    return f"Too many wrong codes. Try again in {minutes} {unit}."
