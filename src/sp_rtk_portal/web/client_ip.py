"""The browser's IP address.

``CF-Connecting-IP`` is trusted because only ``cloudflared`` can reach the
Portal (see the spec's Deployment section). Without it (local development)
the peer address is used.
"""

from __future__ import annotations

from starlette.requests import HTTPConnection


def client_ip(conn: HTTPConnection) -> str | None:
    if ip := conn.headers.get("cf-connecting-ip"):
        return ip
    return conn.client.host if conn.client else None
