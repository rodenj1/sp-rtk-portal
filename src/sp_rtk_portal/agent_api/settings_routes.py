"""``/settings``: the Portal owner tunes the fleet without touching a Pi.

The agent config block (a new revision on every save), notices for every
base, and the latest sp-rtk-base release (for "update available"). Only a
Portal owner (``Settings.owner_emails``, with a verified email) gets here;
every other account gets 403. The actions are state-changing requests, so
the Portal's request guard applies (JSON, ``X-Portal-Action``, Origin).
"""

from __future__ import annotations

import dataclasses
from typing import Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from sp_rtk_portal.accounts.deps import current_account
from sp_rtk_portal.accounts.store import Account
from sp_rtk_portal.agent_api import config as agent_config
from sp_rtk_portal.context import PortalContext, portal_context
from sp_rtk_portal.web.templates import render

router = APIRouter()

MAX_NOTICE = 500


class NotPortalOwner(Exception):
    """A signed-in account that isn't a Portal owner."""


def is_owner(account: Account, ctx: PortalContext) -> bool:
    return account.email_verified and account.email.lower() in {
        e.lower() for e in ctx.settings.owner_emails
    }


async def portal_owner(
    account: Account = Depends(current_account),
    ctx: PortalContext = Depends(portal_context),
) -> Account:
    if not is_owner(account, ctx):
        raise NotPortalOwner
    return account


async def not_portal_owner(request: Request, exc: Exception) -> JSONResponse:
    return JSONResponse({"error": "Only the Portal owner can do that."}, 403)


@router.get("/settings", response_class=HTMLResponse)
async def settings_page(
    request: Request,
    account: Account = Depends(portal_owner),
    ctx: PortalContext = Depends(portal_context),
) -> HTMLResponse:
    async with ctx.db.connection() as conn:
        config = await agent_config.current(conn, ctx.settings)
        notices = await agent_config.notices(conn)
        latest = await agent_config.latest_release(conn)
    values = dataclasses.asdict(config)
    return render(
        request,
        "settings.html",
        title="Portal settings",
        account=account,
        revision=values.pop("revision"),
        config=values,
        notices=notices,
        latest=latest or "",
    )


@router.post("/settings/agent-config")
async def save_agent_config(
    body: dict[str, Any],
    account: Account = Depends(portal_owner),
    ctx: PortalContext = Depends(portal_context),
) -> JSONResponse:
    async with ctx.db.connection() as conn:
        current = await agent_config.current(conn, ctx.settings)
        try:
            config = agent_config.updated(current, body, ctx.settings)
        except agent_config.ConfigRefused as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)
        await agent_config.save(
            conn, config, now=ctx.clock.now(), account_id=account.id
        )
    return JSONResponse({"next": "/settings"})


class NewNotice(BaseModel):
    text: str


@router.post("/settings/notices")
async def add_notice(
    body: NewNotice,
    account: Account = Depends(portal_owner),
    ctx: PortalContext = Depends(portal_context),
) -> JSONResponse:
    text = " ".join(body.text.split())
    if not text or len(text) > MAX_NOTICE:
        return JSONResponse(
            {"error": f"A notice is 1 to {MAX_NOTICE} characters."}, status_code=400
        )
    async with ctx.db.connection() as conn:
        await agent_config.add_notice(conn, text, ctx.clock.now())
    return JSONResponse({"next": "/settings"})


@router.post("/settings/notices/{notice_id}/delete")
async def remove_notice(
    notice_id: int,
    account: Account = Depends(portal_owner),
    ctx: PortalContext = Depends(portal_context),
) -> JSONResponse:
    async with ctx.db.connection() as conn:
        if not await agent_config.remove_notice(conn, notice_id):
            return JSONResponse({"error": "No such notice."}, status_code=404)
    return JSONResponse({"next": "/settings"})


class LatestRelease(BaseModel):
    version: str


@router.post("/settings/latest-release")
async def set_latest_release(
    body: LatestRelease,
    account: Account = Depends(portal_owner),
    ctx: PortalContext = Depends(portal_context),
) -> JSONResponse:
    version = body.version.strip().removeprefix("v")
    if agent_config.parse_version(version) is None:
        return JSONResponse(
            {"error": "A release is a version like 0.11.0."}, status_code=400
        )
    async with ctx.db.connection() as conn:
        await agent_config.set_latest_release(conn, version)
    return JSONResponse({"next": "/settings"})
