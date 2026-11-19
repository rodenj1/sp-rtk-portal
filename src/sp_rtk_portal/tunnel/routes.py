"""Open remotely, the Session bar page and its status channel, and the
agent's end of the tunnel (``/agent/tunnel``)."""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import random
from dataclasses import dataclass
from datetime import timedelta

from fastapi import APIRouter, Depends, Request, WebSocket
from fastapi.responses import HTMLResponse, JSONResponse, Response
from pydantic import BaseModel
from sp_rtk_portal_protocol import (
    HOLDING_VERSION,
    TUNNEL_PATH,
    VERSION_HEADER,
    CheckIn,
    ProofError,
    proof_from_authorization,
    verify_proof,
    version_from_header,
)
from starlette.websockets import WebSocketDisconnect

from sp_rtk_portal.accounts.deps import current_account, websocket_account
from sp_rtk_portal.accounts.store import Account
from sp_rtk_portal.agent_api import config as agent_config
from sp_rtk_portal.agent_api.auth import AgentRefused
from sp_rtk_portal.agent_api.routes import take_check_in
from sp_rtk_portal.bases import local, online, store
from sp_rtk_portal.context import PortalContext, portal_context
from sp_rtk_portal.tunnel import bar
from sp_rtk_portal.tunnel.broker import RemoteSession
from sp_rtk_portal.web.client_ip import client_ip, rate_key
from sp_rtk_portal.web.templates import render

log = logging.getLogger(__name__)

router = APIRouter()

POLICY_VIOLATION = 1008
BUSY_RETRY_AFTER = (10, 60)
"""The range a 503's random ``Retry-After`` is drawn from (seconds)."""

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
        connection=online.connection(base, config),
        holds=bar.holds(base),
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
    :func:`sp_rtk_portal.tunnel.bar.status` message. The bar sends only
    ``{"type": "renew"}`` (renew the lease), answered with a fresh status."""
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
    renewed: asyncio.Queue[None] = asyncio.Queue()
    receiver = asyncio.ensure_future(_receive(websocket, ctx, session, renewed))
    try:
        async with broker.attend(session, client_ip(websocket)):
            seen = -1
            answer = False
            while True:
                version = broker.version(base_id)
                if version != seen or answer:
                    seen, answer = version, False
                    await websocket.send_json(await bar.status(ctx, session))
                if session.ended:
                    await websocket.close()
                    return
                waiter = asyncio.ensure_future(broker.wait_change(base_id, seen))
                renewal = asyncio.ensure_future(renewed.get())
                done, _ = await asyncio.wait(
                    {receiver, waiter, renewal}, return_when=asyncio.FIRST_COMPLETED
                )
                waiter.cancel()
                renewal.cancel()
                if receiver in done:
                    return
                answer = renewal in done
    except (WebSocketDisconnect, RuntimeError):
        return
    finally:
        receiver.cancel()


async def _receive(
    websocket: WebSocket,
    ctx: PortalContext,
    session: RemoteSession,
    renewed: asyncio.Queue[None],
) -> None:
    """Read the bar's messages until it closes: each renewal renews the
    lease (unless the session ended) and asks for a status in answer."""
    with contextlib.suppress(WebSocketDisconnect, RuntimeError):
        while True:
            message = await websocket.receive()
            if message["type"] == "websocket.disconnect":
                return
            if _is_renewal(message.get("text")):
                await ctx.tunnels.renew(session)
                renewed.put_nowait(None)


def _is_renewal(text: str | None) -> bool:
    try:
        body = json.loads(text or "")
    except ValueError:
        return False
    return isinstance(body, dict) and body.get("type") == "renew"


# --- The agent's end of the tunnel ------------------------------------------------


@dataclass(frozen=True)
class _Open:
    base_id: str
    held: bool
    """Opened to hold (no nonce), not on a Wake."""
    thumbprint: str
    version: int


@router.websocket(TUNNEL_PATH)
async def agent_tunnel(websocket: WebSocket) -> None:
    """An agent opens its tunnel: a GET signed with its base key. A Claimed
    base on protocol version 2 or later signs it with no nonce, to hold it
    open (ADR 0006); otherwise the proof echoes a Wake nonce. Anything else
    is refused (HTTP 403) before the websocket is accepted.

    Opens are admitted at ``tunnel_opens_per_second`` from all bases
    together; above that the Portal answers 503 with a random
    ``Retry-After`` (:data:`BUSY_RETRY_AFTER`) before reading anything, so
    the bases a restart dropped come back spread out."""
    ctx: PortalContext = websocket.app.state.portal
    if _too_many_opens(ctx):
        retry_after = random.randint(*BUSY_RETRY_AFTER)
        log.debug("turned a tunnel open away: busy, retry after %ss", retry_after)
        await websocket.send_denial_response(
            Response(status_code=503, headers={"Retry-After": str(retry_after)})
        )
        return
    opened = await _admitted(websocket, ctx)
    if opened is None:
        await websocket.close(code=POLICY_VIOLATION)
        return
    ip = client_ip(websocket)

    async def on_check_in(msg: CheckIn) -> None:
        """A Check-in on the held tunnel, recorded as one over HTTPS."""
        try:
            await take_check_in(
                ctx,
                thumbprint=opened.thumbprint,
                protocol_version=opened.version,
                ip=ip,
                msg=msg,
                on_tunnel=True,
            )
        except AgentRefused as exc:
            log.info("ignored a Check-in on base %s's tunnel: %s", opened.base_id, exc)

    await ctx.tunnels.serve_tunnel(
        opened.base_id, websocket, held=opened.held, on_check_in=on_check_in
    )


def _too_many_opens(ctx: PortalContext) -> bool:
    """Admission: has the Portal let in its tunnel opens for this second?"""
    wait = ctx.limits.take(
        "tunnel-open",
        "all",
        limit=ctx.settings.tunnel_opens_per_second,
        period=timedelta(seconds=1),
    )
    return wait is not None


async def _admitted(websocket: WebSocket, ctx: PortalContext) -> _Open | None:
    """The base whose agent may open this tunnel, or ``None`` (refused).
    Each refusal counts against the client IP; past
    ``tunnel_refusals_per_ip`` an hour, its opens are refused unread."""
    ip = client_ip(websocket)
    s = ctx.settings
    limit = {"limit": s.tunnel_refusals_per_ip, "period": s.rate_limit_period}
    if ctx.limits.over("tunnel-refused", rate_key(ip), **limit) is not None:
        log.info("refused a tunnel open from %s: too many refused", ip)
        return None
    opened = await _check_open(websocket, ctx, ip)
    if opened is None:
        ctx.limits.hit("tunnel-refused", rate_key(ip), period=s.rate_limit_period)
    return opened


async def _check_open(
    websocket: WebSocket, ctx: PortalContext, ip: str | None
) -> _Open | None:
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
    if proof.nonce is None:
        if version < HOLDING_VERSION:
            log.info(
                "refused a tunnel open for base %s from %s: no Wake nonce, and"
                " protocol %s doesn't hold its tunnel",
                row["id"],
                ip,
                version,
            )
            return None
        return _Open(str(row["id"]), True, proof.thumbprint, version)
    if not ctx.tunnels.redeem(row["id"], proof.nonce):
        log.warning(
            "refused a tunnel open for base %s from %s: no such Wake", row["id"], ip
        )
        return None
    return _Open(str(row["id"]), False, proof.thumbprint, version)
