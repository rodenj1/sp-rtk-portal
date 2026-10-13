"""The client's IP address, when the Portal can believe it.

Two paths reach the Portal (the Deployment's NetworkPolicy admits nothing
else): ``cloudflared`` for the internet, and Traefik's LAN-only ``websecure``
entrypoint for browsers on the LAN. Cloudflare sets ``CF-Connecting-IP`` to
the client's address. Traefik's ``websecure`` trusts no forwarded headers, so
it sets ``X-Real-Ip`` to the connection's source, the LAN client, and the LAN
route strips any ``CF-Connecting-IP`` the client sent.

The app checks its side too: the headers are read only on a request whose
peer is in ``Settings.trusted_proxies`` (the pod network). There a valid
``CF-Connecting-IP`` is the client IP, else a valid ``X-Real-Ip``. Any other
request, or one with neither, is untrusted and has no client IP (``None``):
per-IP rate limits key it with every other untrusted request (see
:func:`rate_key`), possible-copy detection ignores it, and audit entries
record no IP. The peer address itself is never used: it is cloudflared's or
Traefik's.
"""

from __future__ import annotations

import ipaddress
from functools import lru_cache

from starlette.requests import HTTPConnection

UNTRUSTED = "untrusted"
"""The one rate-limit key every request without a client IP shares."""

Network = ipaddress.IPv4Network | ipaddress.IPv6Network


def check_networks(cidrs: tuple[str, ...]) -> None:
    """Raises ``ValueError`` on a setting that isn't a list of networks."""
    _networks(cidrs)


@lru_cache(maxsize=8)
def _networks(cidrs: tuple[str, ...]) -> tuple[Network, ...]:
    return tuple(ipaddress.ip_network(c, strict=False) for c in cidrs)


def client_ip(conn: HTTPConnection) -> str | None:
    peer = conn.client.host if conn.client else None
    if peer is None:
        return None
    try:
        peer_ip = ipaddress.ip_address(peer)
    except ValueError:
        return None
    if isinstance(peer_ip, ipaddress.IPv6Address) and peer_ip.ipv4_mapped:
        peer_ip = peer_ip.ipv4_mapped
    trusted = _networks(conn.app.state.portal.settings.trusted_proxies)
    if not any(peer_ip in net for net in trusted):
        return None
    for name in _CLIENT_IP_HEADERS:
        ip = _ip(conn.headers.get(name))
        if ip is not None:
            return ip
    return None


_CLIENT_IP_HEADERS = ("cf-connecting-ip", "x-real-ip")
"""In order: cloudflared's (Cloudflare sets it), then Traefik's on the LAN
route (its ``websecure`` entrypoint trusts no forwarded headers, so it sets
``X-Real-Ip`` to the connection's source)."""


def _ip(header: str | None) -> str | None:
    if header is None:
        return None
    try:
        return str(ipaddress.ip_address(header.strip()))
    except ValueError:
        return None


def rate_key(ip: str | None) -> str:
    """What a per-IP rate limit counts against."""
    return ip if ip is not None else UNTRUSTED
