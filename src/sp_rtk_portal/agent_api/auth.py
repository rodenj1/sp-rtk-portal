"""Checks every agent request: a fresh proof signed by a base key, and the
protocol version header.

Use as a dependency: ``req: AgentRequest = Depends(agent_request)``. A request
that fails is answered by :func:`agent_refused` (registered in ``create_app``)
with an :class:`~sp_rtk_portal_protocol.ErrorReply` body.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any, TypeVar

from fastapi import Depends, Request
from fastapi.responses import JSONResponse, Response
from sp_rtk_portal_protocol import (
    VERSION_HEADER,
    ErrorReply,
    Message,
    MessageError,
    ProofError,
    UpgradeRequired,
    VerifiedProof,
    proof_from_authorization,
    verify_proof,
    version_from_header,
)

from sp_rtk_portal.bases import presence
from sp_rtk_portal.context import PortalContext, portal_context
from sp_rtk_portal.web.client_ip import client_ip

log = logging.getLogger(__name__)

M = TypeVar("M", bound=Message)


class AgentRefused(Exception):
    def __init__(self, status: int, error: str, description: str = "") -> None:
        super().__init__(f"{error}: {description}")
        self.status = status
        self.reply: Message = ErrorReply(error=error, error_description=description)


class AgentSlowDown(AgentRefused):
    """429: this agent (or its IP) asks too often. ``Retry-After`` says when
    it may ask again."""

    def __init__(self, retry_after: int, description: str) -> None:
        super().__init__(429, ErrorReply.SLOW_DOWN, description)
        self.retry_after = retry_after


class AgentTooOld(AgentRefused):
    """426: the agent's protocol version is no longer supported."""

    def __init__(self, version: int, min_version: int) -> None:
        super().__init__(426, "upgrade_required")
        self.reply = UpgradeRequired(
            min_version=min_version,
            message=(
                f"This sp-rtk-base speaks Portal protocol {version}; the Portal "
                f"needs {min_version} or later. Upgrade sp-rtk-base to keep "
                "using the Portal."
            ),
        )


@dataclass(frozen=True)
class AgentRequest:
    proof: VerifiedProof
    body: Any
    protocol_version: int
    ip: str | None

    def message(self, cls: type[M]) -> M:
        """The body as ``cls``; a mismatch is refused as ``invalid_request``."""
        try:
            return cls.from_json(self.body)
        except MessageError as exc:
            raise AgentRefused(400, ErrorReply.INVALID_REQUEST, str(exc)) from exc


async def agent_request(
    request: Request, ctx: PortalContext = Depends(portal_context)
) -> AgentRequest:
    now = ctx.clock.now()
    raw = await request.body()
    try:
        proof = verify_proof(
            proof_from_authorization(request.headers.get("authorization")),
            method=request.method,
            # Behind Cloudflare the Portal's own view of the URL differs: the
            # agent signs the public one.
            url=ctx.settings.public_origin + request.url.path,
            now=now,
            body=raw,
        )
        ctx.agent_proofs.remember(proof, now=now)
    except ProofError as exc:
        log.info("refused an agent request to %s: %s", request.url.path, exc)
        raise AgentRefused(401, ErrorReply.INVALID_PROOF, str(exc)) from exc
    version = version_from_header(request.headers.get(VERSION_HEADER))
    if version is None:
        raise AgentRefused(
            400, ErrorReply.INVALID_REQUEST, f"missing {VERSION_HEADER} header"
        )
    ip = client_ip(request)
    minimum = ctx.settings.min_protocol_version
    if version < minimum:
        log.info("refused protocol %s from %s (needs %s)", version, ip, minimum)
        async with ctx.db.connection() as conn:
            await presence.refused_as_too_old(
                conn,
                thumbprint=proof.thumbprint,
                now=now,
                protocol_version=version,
                ip=ip,
            )
        raise AgentTooOld(version, minimum)
    try:
        body = json.loads(raw) if raw else {}
    except ValueError as exc:
        raise AgentRefused(400, ErrorReply.INVALID_REQUEST, "body isn't JSON") from exc
    return AgentRequest(proof=proof, body=body, protocol_version=version, ip=ip)


async def agent_refused(request: Request, exc: Exception) -> Response:
    assert isinstance(exc, AgentRefused)
    response = reply(exc.reply, exc.status)
    if isinstance(exc, AgentSlowDown):
        response.headers["Retry-After"] = str(exc.retry_after)
    return response


def reply(message: Message, status: int = 200) -> JSONResponse:
    return JSONResponse(message.to_json(), status_code=status)
