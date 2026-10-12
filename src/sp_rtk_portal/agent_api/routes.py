"""Agent endpoints under ``/agent/``. Every one depends on ``agent_request``."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from sp_rtk_portal_protocol import (
    CLAIM_TOKEN_PATH,
    CLAIMS_PATH,
    Claimed,
    ClaimStart,
    ClaimStarted,
    ClaimToken,
    ErrorReply,
)

from sp_rtk_portal.agent_api.auth import (
    AgentRefused,
    AgentRequest,
    agent_request,
    reply,
)
from sp_rtk_portal.bases import claims
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
