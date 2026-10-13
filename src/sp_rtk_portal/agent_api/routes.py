"""Agent endpoints under ``/agent/``. Every one depends on ``agent_request``."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from sp_rtk_portal_protocol import (
    CHECK_IN_PATH,
    CLAIM_TOKEN_PATH,
    CLAIMS_PATH,
    POLL_PATH,
    RELEASE_PATH,
    CheckIn,
    CheckInReply,
    Claimed,
    ClaimStart,
    ClaimStarted,
    ClaimToken,
    ErrorReply,
    Poll,
    PollReply,
    Release,
    Released,
)

from sp_rtk_portal.agent_api import config as agent_config
from sp_rtk_portal.agent_api.auth import (
    AgentRefused,
    AgentRequest,
    agent_request,
    reply,
)
from sp_rtk_portal.bases import claims, online, presence, unclaim
from sp_rtk_portal.context import PortalContext, portal_context

router = APIRouter()


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
    flag, the notices, and a Wake's nonce when one is pending."""
    req.message(Poll)
    async with ctx.db.connection() as conn:
        seen = await presence.polled(
            conn,
            thumbprint=req.proof.thumbprint,
            now=ctx.clock.now(),
            protocol_version=req.protocol_version,
            ip=req.ip,
        )
        if seen is None:
            raise _unclaimed()
        config = await agent_config.current(conn, ctx.settings)
        notices = await agent_config.wire_notices(conn)
    return reply(
        PollReply(
            config=config,
            metered=seen.metered,
            notices=notices,
            wake=ctx.tunnels.wake_for_poll(seen.base_id),
        )
    )


@router.post(CHECK_IN_PATH)
async def check_in(
    req: AgentRequest = Depends(agent_request),
    ctx: PortalContext = Depends(portal_context),
) -> JSONResponse:
    """The slow status report: versions, Doorbell health, LAN addresses. The
    reply says whether the Portal hears the base's Doorbell, and gives it its
    ring key while the agent config names a Doorbell host."""
    msg = req.message(CheckIn)
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
        config = await agent_config.current(conn, ctx.settings)
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
