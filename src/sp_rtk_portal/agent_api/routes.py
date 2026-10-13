"""Agent endpoints under ``/agent/``. Every one depends on ``agent_request``."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from sp_rtk_portal_protocol import (
    CHECK_IN_PATH,
    CLAIM_TOKEN_PATH,
    CLAIMS_PATH,
    POLL_PATH,
    CheckIn,
    CheckInReply,
    Claimed,
    ClaimStart,
    ClaimStarted,
    ClaimToken,
    ErrorReply,
    LiveSession,
    Poll,
    PollReply,
)

from sp_rtk_portal import audit
from sp_rtk_portal.agent_api import config as agent_config
from sp_rtk_portal.agent_api.auth import (
    AgentRefused,
    AgentRequest,
    agent_request,
    reply,
)
from sp_rtk_portal.bases import claims, presence
from sp_rtk_portal.context import PortalContext, portal_context
from sp_rtk_portal.db import Connection
from sp_rtk_portal.tunnel import broker

router = APIRouter()

PAUSED = "paused"
"""``Poll.state`` while remote access is paused on site."""


@router.post(CLAIMS_PATH)
async def start_claim(
    req: AgentRequest = Depends(agent_request),
    ctx: PortalContext = Depends(portal_context),
) -> JSONResponse:
    msg = req.message(ClaimStart)
    settings = ctx.settings
    try:
        async with ctx.db.connection() as conn:
            device_code, user_code = await claims.start(
                conn,
                now=ctx.clock.now(),
                lifetime=settings.claim_lifetime,
                public_key=req.proof.jwk,
                thumbprint=req.proof.thumbprint,
                suggested_name=msg.name,
                software_version=msg.software_version,
                protocol_version=req.protocol_version,
                ip=req.ip,
            )
    except claims.KeyAlreadyClaimed as exc:
        raise AgentRefused(
            400, ErrorReply.INVALID_REQUEST, "this key already belongs to a base"
        ) from exc
    verify_at = f"{settings.public_origin}/claim"
    return reply(
        ClaimStarted(
            device_code=device_code,
            user_code=user_code,
            verification_uri=verify_at,
            verification_uri_complete=f"{verify_at}?code={user_code}",
            expires_in=int(settings.claim_lifetime.total_seconds()),
            interval=settings.claim_poll_interval,
        )
    )


@router.post(CLAIM_TOKEN_PATH)
async def collect_claim(
    req: AgentRequest = Depends(agent_request),
    ctx: PortalContext = Depends(portal_context),
) -> JSONResponse:
    msg = req.message(ClaimToken)
    async with ctx.db.connection() as conn:
        result = await claims.collect(
            conn,
            now=ctx.clock.now(),
            thumbprint=req.proof.thumbprint,
            device_code=msg.device_code,
            interval=ctx.settings.claim_poll_interval,
        )
    if isinstance(result, Claimed):
        return reply(result)
    return reply(ErrorReply(error=result), 400)


# --- Polls and Check-ins (ADR 0002) -----------------------------------------


def _unclaimed() -> AgentRefused:
    return AgentRefused(401, ErrorReply.UNCLAIMED, "no base has this key")


@router.post(POLL_PATH)
async def poll(
    req: AgentRequest = Depends(agent_request),
    ctx: PortalContext = Depends(portal_context),
) -> JSONResponse:
    """A sign of life. The reply carries the agent config block, the metered
    flag, the notices, a Wake's nonce when one is pending, and the base's
    live Remote sessions (for its local Portal page).

    A poll saying ``paused`` (remote access paused on site) ends the base's
    live Remote sessions and closes its tunnel. A pending Wake is still
    sent: the agent is the one that ignores it, whatever the Portal does.
    """
    msg = req.message(Poll)
    paused = msg.state == PAUSED
    now = ctx.clock.now()
    async with ctx.db.connection() as conn:
        seen = await presence.polled(
            conn,
            thumbprint=req.proof.thumbprint,
            now=now,
            protocol_version=req.protocol_version,
            ip=req.ip,
            paused=paused,
        )
        if seen is None:
            raise _unclaimed()
        if seen.paused != seen.was_paused:
            await audit.record(
                conn,
                at=now,
                kind=audit.REMOTE_ACCESS_PAUSED
                if paused
                else audit.REMOTE_ACCESS_RESUMED,
                base_id=seen.base_id,
                ip=req.ip,
            )
        config = await agent_config.current(conn, ctx.settings)
        notices = await agent_config.wire_notices(conn)
        sessions = [] if paused else await _live_sessions(conn, ctx, seen)
    if paused:
        await ctx.tunnels.end_sessions(broker.PAUSED, base_id=seen.base_id)
        await ctx.tunnels.close_tunnel(seen.base_id)
    return reply(
        PollReply(
            config=config,
            metered=seen.metered,
            notices=notices,
            wake=ctx.tunnels.wake_for_poll(seen.base_id),
            sessions=sessions,
        )
    )


async def _live_sessions(
    conn: Connection, ctx: PortalContext, seen: presence.Seen
) -> list[LiveSession]:
    live = ctx.tunnels.live_sessions(seen.base_id)
    if not live:
        return []
    cur = await conn.execute(
        "SELECT id, email FROM account WHERE id = ANY(%s)",
        ([s.account_id for s in live],),
    )
    emails = {row["id"]: row["email"] for row in await cur.fetchall()}
    return [
        LiveSession(
            who=emails.get(s.account_id, "?"),
            since=s.started_at.isoformat(),
            shared=s.account_id != seen.owner_account_id,
        )
        for s in live
    ]


@router.post(CHECK_IN_PATH)
async def check_in(
    req: AgentRequest = Depends(agent_request),
    ctx: PortalContext = Depends(portal_context),
) -> JSONResponse:
    """The slow status report: versions, Doorbell health, LAN addresses."""
    msg = req.message(CheckIn)
    async with ctx.db.connection() as conn:
        seen = await presence.checked_in(
            conn,
            thumbprint=req.proof.thumbprint,
            now=ctx.clock.now(),
            protocol_version=req.protocol_version,
            ip=req.ip,
            check_in=msg,
        )
        if seen is None:
            raise _unclaimed()
        config = await agent_config.current(conn, ctx.settings)
        notices = await agent_config.wire_notices(conn)
    return reply(CheckInReply(config=config, metered=seen.metered, notices=notices))
