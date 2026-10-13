"""The Doorbell server's HTTPS interface (see the README).

``POST /doorbell/keepalives`` relays keepalives with the address and port
each came from; ``GET /doorbell/rings?wait=<s>`` long-polls for rings. Both
need ``Authorization: Bearer <Settings.doorbell_token>``; with no token set
(v1) both answer 404.
"""

from __future__ import annotations

import hmac
import ipaddress

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from sp_rtk_portal_protocol import (
    DoorbellError,
    HeardKeepalive,
    KeepalivesReply,
    KeepalivesReport,
    MessageError,
    Rings,
    doorbell,
)

from sp_rtk_portal.bases import presence
from sp_rtk_portal.context import PortalContext, portal_context
from sp_rtk_portal.db import Connection

router = APIRouter()

MAX_KEEPALIVES = 1000
"""Per report."""


def doorbell_server(
    request: Request, ctx: PortalContext = Depends(portal_context)
) -> None:
    token = ctx.settings.doorbell_token
    if not token:
        raise HTTPException(404)
    scheme, _, given = request.headers.get("authorization", "").partition(" ")
    if scheme.lower() != "bearer" or not hmac.compare_digest(
        given.encode(), token.encode()
    ):
        raise HTTPException(401, headers={"WWW-Authenticate": "Bearer"})


@router.post(doorbell.KEEPALIVES_PATH, dependencies=[Depends(doorbell_server)])
async def keepalives(
    request: Request, ctx: PortalContext = Depends(portal_context)
) -> JSONResponse:
    try:
        report = KeepalivesReport.from_json(await request.json())
    except (ValueError, MessageError) as exc:
        raise HTTPException(400, "not a keepalives report") from exc
    if len(report.keepalives) > MAX_KEEPALIVES:
        raise HTTPException(413, "too many keepalives in one report")
    async with ctx.db.connection() as conn:
        results = [await _keepalive(conn, ctx, k) for k in report.keepalives]
    return JSONResponse(KeepalivesReply(results=results).to_json())


async def _keepalive(
    conn: Connection, ctx: PortalContext, heard: HeardKeepalive
) -> str:
    now = ctx.clock.now()
    try:
        ipaddress.ip_address(heard.address)
        if not 0 < heard.port < 65536:
            raise ValueError("bad port")
        packet = doorbell.decode_packet(heard.packet)
        claimed = doorbell.read_keepalive(packet)
    except ValueError:  # DoorbellError is one
        return doorbell.KEEPALIVE_INVALID
    base = await presence.by_key(conn, claimed.thumbprint)
    if base is None:
        return doorbell.KEEPALIVE_UNKNOWN
    try:
        doorbell.verify_keepalive(packet, base.public_key, now=now)
    except DoorbellError:
        return doorbell.KEEPALIVE_INVALID
    if not ctx.doorbell.heard(base, claimed, heard.address, heard.port):
        return doorbell.KEEPALIVE_INVALID
    await presence.rang(conn, base_id=base.id, now=now)
    return doorbell.KEEPALIVE_OK


@router.get(doorbell.RINGS_PATH, dependencies=[Depends(doorbell_server)])
async def rings(
    wait: float = 0.0, ctx: PortalContext = Depends(portal_context)
) -> JSONResponse:
    return JSONResponse(Rings(rings=await ctx.doorbell.rings(wait)).to_json())
