"""Local access: how the Portal offers a base's own UI on its LAN (spec #82).

Local access is never a Remote session: the browser goes straight to
``http://<lan-ip>:8080/``, the base's unauthenticated UI (ADR 0001). The
Portal only offers the link. It puts Open locally first when the browser's
public IP is the base's (likely the same LAN); in Chrome and Edge the base
list also checks the base's identity endpoint at that address
(``static/local.js``) and, when it answers with the base's ``<id>``, makes
Open locally the way in.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Any

UI_PORT = 8080
"""The base's own web UI."""

IDENTITY_PATH = "api/portal/identity"
"""The base's identity endpoint, relative to ``LocalAccess.url``."""


@dataclass(frozen=True)
class LocalAccess:
    address: str
    """The base's primary LAN address, as its last Check-in reported it."""
    url: str
    """``http://<address>:8080/``."""
    first: bool
    """Open locally comes before Open remotely: the browser is behind the
    base's public IP."""

    @property
    def identity_url(self) -> str:
        """The base's identity endpoint at that address."""
        return self.url + IDENTITY_PATH


def local_access(
    lan_addresses: list[dict[str, Any]],
    public_ip: str | None,
    client_ip: str | None,
    *,
    port: int = UI_PORT,
) -> LocalAccess | None:
    """How to reach the base on its LAN, or ``None`` if it reported no usable
    address. Only an IP literal that isn't a global address is ever linked:
    the address comes from the base, and the link must not lead anywhere
    else."""
    address = _primary(lan_addresses)
    if address is None:
        return None
    host = f"[{address}]" if address.version == 6 else str(address)
    return LocalAccess(
        address=str(address),
        url=f"http://{host}:{port}/",
        first=public_ip is not None and _same(public_ip, client_ip),
    )


def _primary(
    lan_addresses: list[dict[str, Any]],
) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    usable = [
        (bool(entry.get("primary")), ip)
        for entry in lan_addresses
        if (ip := _local_ip(entry.get("address"))) is not None
    ]
    primary = [ip for is_primary, ip in usable if is_primary]
    others = [ip for _, ip in usable]
    return (primary or others or [None])[0]


def _local_ip(
    value: object,
) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    if not isinstance(value, str):
        return None
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return None
    if ip.is_global or ip.is_unspecified or ip.is_multicast:
        return None
    if ip.version == 6 and ip.is_link_local:  # needs a zone id: not linkable
        return None
    return ip


def _same(a: str, b: str | None) -> bool:
    if b is None:
        return False
    try:
        return ipaddress.ip_address(a) == ipaddress.ip_address(b)
    except ValueError:
        return False
