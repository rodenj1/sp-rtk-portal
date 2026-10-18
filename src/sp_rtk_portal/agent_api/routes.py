"""Agent endpoints under ``/agent/``. Every one depends on ``agent_request``."""

from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from sp_rtk_portal_protocol import (
    CHECK_IN_PATH,
    CLAIM_TOKEN_PATH,
    CLAIMS_PATH,
    POLL_PATH,
    RELEASE_PATH,
    AgentConfig,
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
    Release,
    Released,
)

from sp_rtk_portal import audit
from sp_rtk_portal.agent_api import config as agent_config
from sp_rtk_portal.agent_api.auth import (
    AgentRefused,
    AgentRequest,
    AgentSlowDown,
    agent_request,
    reply,
)
from sp_rtk_portal.bases import claims, copies, online, presence, unclaim
from sp_rtk_portal.context import PortalContext, portal_context
from sp_rtk_portal.db import Connection
from sp_rtk_portal.tunnel.end_reason import EndReason
from sp_rtk_portal.web.client_ip import rate_key

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
    wait = ctx.limits.take(
        "claim-start",
        rate_key(req.ip),
        limit=settings.claim_starts_per_ip,
        period=settings.rate_limit_period,
    )
    if wait is not None:
        raise AgentSlowDown(wait, "too many Claims started from this IP")
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


def _poll_interval(config: AgentConfig, base: presence.Pace) -> int:
    """The interval the base polls at: while a metered change is on its way
    to the agent, the shorter of the two."""
    return min(
        online.interval(config, base.metered),
        online.interval(config, base.polled_metered),
    )


def _keep_pace(ctx: PortalContext, kind: str, base_id: str, interval: int) -> None:
    """429 for a poll or Check-in sooner than ``agent_min_spacing`` of its
    interval after the last, once ``agent_burst`` early ones are spent."""
    s = ctx.settings
    wait = ctx.limits.spaced(
        kind, base_id, spacing=s.agent_min_spacing * interval, burst=s.agent_burst
    )
    if wait is not None:
        raise AgentSlowDown(wait, f"{kind} sooner than the agent config allows")


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
        config = await agent_config.current(conn, ctx.settings)
        base = await presence.pace(conn, req.proof.thumbprint)
    if base is None:
        raise _unclaimed()
    await copies.watch(ctx, base.base_id, req.ip)
    _keep_pace(ctx, "poll", base.base_id, _poll_interval(config, base))
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
        await _audit_pause(conn, seen, now, req.ip)
        if paused:
            await _cut_paused(ctx, seen.base_id)
        notices = await agent_config.wire_notices(conn)
        sessions = [] if paused else await _live_sessions(conn, ctx, seen)
    return reply(
        PollReply(
            config=config,
            metered=seen.metered,
            notices=notices,
            wake=ctx.tunnels.wake_for_poll(seen.base_id),
            sessions=sessions,
        )
    )


async def _audit_pause(
    conn: Connection, seen: presence.Seen, now: datetime, ip: str | None
) -> None:
    """Audit a change of remote access paused, in the sign of life's
    transaction."""
    if seen.paused != seen.was_paused:
        await audit.record(
            conn,
            at=now,
            kind=audit.REMOTE_ACCESS_PAUSED
            if seen.paused
            else audit.REMOTE_ACCESS_RESUMED,
            base_id=seen.base_id,
            ip=ip,
        )


async def _cut_paused(ctx: PortalContext, base_id: str) -> None:
    """Remote access is paused on site: its Remote sessions end and its
    tunnel closes (before the pause is recorded, as on Un-claim)."""
    await ctx.tunnels.end_for_base(base_id, EndReason.PAUSED)


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
    """The slow status report: versions, Doorbell health, LAN addresses and
    (from protocol package 0.9) remote access paused, handled as on a poll.
    The reply says whether the Portal hears the base's Doorbell, and gives it its
    ring key while the agent config names a Doorbell host."""
    msg = req.message(CheckIn)
    async with ctx.db.connection() as conn:
        config = await agent_config.current(conn, ctx.settings)
        base = await presence.pace(conn, req.proof.thumbprint)
    if base is None:
        raise _unclaimed()
    await copies.watch(ctx, base.base_id, req.ip)
    _keep_pace(ctx, "check-in", base.base_id, config.check_in_interval)
    now = ctx.clock.now()
    async with ctx.db.connection() as conn:
        seen = await presence.checked_in(
            conn,
            thumbprint=req.proof.thumbprint,
            now=now,
            protocol_version=req.protocol_version,
            ip=req.ip,
            check_in=msg,
        )
        if seen is None:
            raise _unclaimed()
        await _audit_pause(conn, seen, now, req.ip)
        if msg.paused:
            await _cut_paused(ctx, seen.base_id)
        notices = await agent_config.wire_notices(conn)
        ring_key = (
            await presence.ring_key(conn, seen.base_id)
            if config.doorbell_host
            else None
        )
    heard = (
        seen.last_doorbell_at is not None
        and now - seen.last_doorbell_at <= online.DOORBELL_OFFLINE_AFTER
    )
    return reply(
        CheckInReply(
            config=config,
            metered=seen.metered,
            notices=notices,
            doorbell_heard=heard and ring_key is not None,
            ring_key=ring_key,
        )
    )


@router.post(RELEASE_PATH)
async def release(
    req: AgentRequest = Depends(agent_request),
    ctx: PortalContext = Depends(portal_context),
) -> JSONResponse:
    """A local Un-claim: the base asks to be forgotten, signed with its key."""
    req.message(Release)
    base_id = await unclaim.by_base(ctx, thumbprint=req.proof.thumbprint, ip=req.ip)
    if base_id is None:
        raise _unclaimed()
    return reply(Released(base_id=base_id))
