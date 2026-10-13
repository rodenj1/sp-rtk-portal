"""A hand-driven agent: signs requests with the protocol package directly.

The real Portal agent (sp-rtk-base) runs in ``agent`` tests. This one exists
for what the real agent never does on purpose: bad signatures, replays, stale
proofs, other keys, polling too fast.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any

import httpx
from sp_rtk_portal_protocol import PROTOCOL_VERSION, VERSION_HEADER, BaseKey

from .portal import CLOUDFLARED, Portal

AGENT_IP = "198.51.100.20"


class SigningAgent:
    def __init__(self, portal: Portal, client: httpx.AsyncClient) -> None:
        self.portal = portal
        self.http = client
        self.key = BaseKey.generate()

    def headers(
        self,
        path: str,
        body: bytes,
        *,
        key: BaseKey | None = None,
        at: datetime | None = None,
    ) -> dict[str, str]:
        signer = key or self.key
        url = self.portal.origin + path
        now = at or self.portal.clock.now()
        return {
            "Authorization": signer.authorization("POST", url, now=now, body=body),
            VERSION_HEADER: str(PROTOCOL_VERSION),
            "Content-Type": "application/json",
        }

    async def post(
        self,
        path: str,
        body: dict[str, Any],
        *,
        key: BaseKey | None = None,
        at: datetime | None = None,
        headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        raw = json.dumps(body).encode()
        sent = self.headers(path, raw, key=key, at=at) | (headers or {})
        return await self.http.post(path, content=raw, headers=sent)


@asynccontextmanager
async def signing_agent(
    portal: Portal,
    ip: str | None = AGENT_IP,
    *,
    peer: str = CLOUDFLARED,
    real_ip: str | None = None,
) -> AsyncIterator[SigningAgent]:
    """An agent at public ``ip`` (``CF-Connecting-IP``; ``None``: no header)
    whose requests reach the Portal from ``peer``. ``real_ip``: an
    ``X-Real-Ip`` header too, as Traefik adds on the LAN route."""
    headers = {"CF-Connecting-IP": ip} if ip is not None else {}
    if real_ip is not None:
        headers["X-Real-Ip"] = real_ip
    transport = httpx.ASGITransport(app=portal.app, client=(peer, 40000))
    async with httpx.AsyncClient(
        transport=transport, base_url=portal.origin, headers=headers
    ) as client:
        yield SigningAgent(portal, client)
