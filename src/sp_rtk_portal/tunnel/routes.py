"""Open remotely, the Session bar page and its status channel, and the
agent's end of the tunnel (``/agent/tunnel``)."""

from __future__ import annotations

import asyncio
import contextlib
import logging

from fastapi import APIRouter, Depends, Request, WebSocket
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
from sp_rtk_portal_protocol import (
    TUNNEL_PATH,
    VERSION_HEADER,
    ProofError,
    proof_from_authorization,
    verify_proof,
    version_from_header,
)
from starlette.websockets import WebSocketDisconnect

from sp_rtk_portal.accounts.deps import current_account, websocket_account
from sp_rtk_portal.accounts.store import Account
from sp_rtk_portal.agent_api import config as agent_config
from sp_rtk_portal.bases import local, online, store
from sp_rtk_portal.context import PortalContext, portal_context
from sp_rtk_portal.tunnel import bar
from sp_rtk_portal.web.client_ip import client_ip, rate_key
from sp_rtk_portal.web.templates import render

log = logging.getLogger(__name__)

router = APIRouter()

POLICY_VIOLATION = 1008

PAUSED_MESSAGE = (
    "Remote access is paused on this base. Someone at the base can resume it"
    " on its local Portal page."
)


# --- Open remotely and the Session bar ----------------------------------------


class OpenRemotely(BaseModel):
    try_anyway: bool = False
    """Wake the base even though it looks offline."""


@router.post("/bases/{base_id}/remote")
async def open_remotely(
    base_id: str,
    request: Request,
    body: OpenRemotely | None = None,
    account: Account = Depends(current_account),
    ctx: PortalContext = Depends(portal_context),
) -> JSONResponse:
    """Open remotely, Retry, Try anyway and Reconnect: start (or rejoin) the
    user's Remote session on the base, Waking it. An offline base is not
    Woken unless the user chose Try anyway: the Session bar says Offline."""
    async with ctx.db.connection() as conn:
        base = await store.reachable_by(conn, account.id, base_id)
        config = await agent_config.current(conn, ctx.settings)
    if base is None:
        return JSONResponse({"error": "No such base."}, status_code=404)
    if base.remote_paused:
        return JSONResponse({"error": PAUSED_MESSAGE}, status_code=409)
    try_anyway = body is not None and body.try_anyway
    if (
        ctx.tunnels.session_for(account.id, base_id) is None
        and not try_anyway
        and online.state(base, config, ctx.clock.now()) == "offline"
    ):
        return JSONResponse({"next": f"/bases/{base_id}"})
    await ctx.tunnels.start_session(account.id, base_id, client_ip(request))
    return JSONResponse({"next": f"/bases/{base_id}"})


@router.post("/bases/{base_id}/keep-going")
async def keep_going(
    base_id: str,
    account: Account = Depends(current_account),
    ctx: PortalContext = Depends(portal_context),
) -> JSONResponse:
    """Still there? -> Keep going: the user's Remote session on the base (all
    their tabs) gets a fresh hard cap."""
    session = ctx.tunnels.session_for(account.id, base_id)
    if session is None:
        return JSONResponse({"error": "No Remote session to keep."}, status_code=404)
    await ctx.tunnels.keep_going(session)
    return JSONResponse({})


@router.get("/bases/{base_id}", response_class=HTMLResponse)
async def session_bar(
    base_id: str,
    request: Request,
    account: Account = Depends(current_account),
    ctx: PortalContext = Depends(portal_context),
) -> HTMLResponse:
    async with ctx.db.connection() as conn:
        base = await store.reachable_by(conn, account.id, base_id)
        config = await agent_config.current(conn, ctx.settings)
    if base is None:
        return HTMLResponse("No such base.", status_code=404)
    session = ctx.tunnels.session_for(account.id, base_id)
    base_state = online.state(base, config, ctx.clock.now())
    if base_state == "paused":
        # Remote access paused on site (#92): its sessions were ended and it
        # ignores Wakes, so it would otherwise look like Didn't wake.
        state = "remote_paused"
    elif session is not None:
        state = ctx.tunnels.state(session)
    elif base_state == "offline":
        state = "offline"  # Open remotely Wakes nothing; Try anyway does
    else:
        state = "none"
    # More states are decided here, and get a label in ``bar.labels`` and a
    # ``data-show`` block in session.html.
    return render(
        request,
        "session.html",
        title=base.name,
        account=account,
        base=base,
        state=state,
        labels=bar.labels(base.name),
        poll_interval=online.interval(config, base.metered),
        last_seen=bar.last_seen(base),
        wake_mode=online.wake_mode(base, config),
        local_access=local.local_access(
            base.lan_addresses,
            base.public_ip,
            client_ip(request),
            port=ctx.settings.base_ui_port,
        ),
    )


@router.websocket("/bases/{base_id}/session")
async def session_channel(base_id: str, websocket: WebSocket) -> None:
    """The Session bar's status channel. While one is open, its user is
    present on the Remote session; each change is sent as one
    :func:`sp_rtk_portal.tunnel.bar.status` message."""
    ctx: PortalContext = websocket.app.state.portal
    account = await websocket_account(websocket, ctx)
    session = None
    if account is not None:
        session = ctx.tunnels.session_for(account.id, base_id)
    if session is None:
        await websocket.close(code=POLICY_VIOLATION)
        return
    broker = ctx.tunnels
    await websocket.accept()
    receiver = asyncio.ensure_future(_until_closed(websocket))
    try:
        async with broker.attend(session, client_ip(websocket)):
            seen = -1
            while True:
                version = broker.version(base_id)
                if version != seen:
                    seen = version
                    await websocket.send_json(await bar.status(ctx, session))
                if session.ended:
                    await websocket.close()
                    return
                waiter = asyncio.ensure_future(broker.wait_change(base_id, seen))
                done, _ = await asyncio.wait(
                    {receiver, waiter}, return_when=asyncio.FIRST_COMPLETED
                )
                if receiver in done:
                    waiter.cancel()
                    return
    except (WebSocketDisconnect, RuntimeError):
        return
    finally:
        receiver.cancel()


async def _until_closed(websocket: WebSocket) -> None:
    with contextlib.suppress(WebSocketDisconnect, RuntimeError):
        while True:
            message = await websocket.receive()
            if message["type"] == "websocket.disconnect":
                return


# --- The agent's end of the tunnel ------------------------------------------------


@router.websocket(TUNNEL_PATH)
async def agent_tunnel(websocket: WebSocket) -> None:
    """A Woken agent opens its tunnel: a GET signed with its base key whose
    proof echoes the Wake nonce. Anything else is refused (HTTP 403) before
    the websocket is accepted."""
    ctx: PortalContext = websocket.app.state.portal
    base_id = await _woken_base(websocket, ctx)
    if base_id is None:
        await websocket.close(code=POLICY_VIOLATION)
        return
    await websocket.accept()
    await ctx.tunnels.serve_tunnel(base_id, websocket)


async def _woken_base(websocket: WebSocket, ctx: PortalContext) -> str | None:
    """The base whose agent may open this tunnel, or ``None`` (refused).
    Each refusal counts against the client IP; past
    ``tunnel_refusals_per_ip`` an hour, its opens are refused unread."""
    ip = client_ip(websocket)
    s = ctx.settings
    limit = {"limit": s.tunnel_refusals_per_ip, "period": s.rate_limit_period}
    if ctx.limits.over("tunnel-refused", rate_key(ip), **limit) is not None:
        log.info("refused a tunnel open from %s: too many refused", ip)
        return None
    base_id = await _check_open(websocket, ctx, ip)
    if base_id is None:
        ctx.limits.hit("tunnel-refused", rate_key(ip), period=s.rate_limit_period)
    return base_id


async def _check_open(
    websocket: WebSocket, ctx: PortalContext, ip: str | None
) -> str | None:
    now = ctx.clock.now()
    try:
        proof = verify_proof(
            proof_from_authorization(websocket.headers.get("authorization")),
            method="GET",
            url=ctx.settings.public_origin + websocket.url.path,
            now=now,
        )
        ctx.agent_proofs.remember(proof, now=now)
    except ProofError as exc:
        log.info("refused a tunnel open from %s: %s", ip, exc)
        return None
    version = version_from_header(websocket.headers.get(VERSION_HEADER))
    if version is None or version < ctx.settings.min_protocol_version:
        log.info("refused a tunnel open from %s: protocol %s", ip, version)
        return None
    async with ctx.db.connection() as conn:
        cur = await conn.execute(
            "SELECT id FROM base WHERE key_thumbprint = %s", (proof.thumbprint,)
        )
        row = await cur.fetchone()
    if row is None:
        log.info("refused a tunnel open from %s: no base has this key", ip)
        return None
    if not ctx.tunnels.redeem(row["id"], proof.nonce):
        log.warning(
            "refused a tunnel open for base %s from %s: no such Wake", row["id"], ip
        )
        return None
    return str(row["id"])
