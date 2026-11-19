"""Protocol version.

An integer, starting at 1 and independent of the sp-rtk-base version. It is
sent as a header on every poll, Check-in and tunnel open. Additive changes
don't bump it, and both sides ignore unknown fields.

- 1: a tunnel opens only on a Wake, echoing its nonce.
- 2: a Claimed base holds its tunnel open (ADR 0006): it opens it without a
  nonce and keeps it open, pinging every ``AgentConfig.ping_interval``. A
  version 2 agent still answers a Wake with its nonce when it has no tunnel.
"""

from __future__ import annotations

PROTOCOL_VERSION = 2

HOLDING_VERSION = 2
"""The first version whose Claimed bases hold their tunnel open."""

VERSION_HEADER = "SP-RTK-Protocol-Version"
"""The header every agent request carries ``PROTOCOL_VERSION`` in."""


def version_from_header(value: str | None) -> int | None:
    """The version a request says it speaks, or ``None`` if it's unreadable."""
    try:
        version = int((value or "").strip())
    except ValueError:
        return None
    return version if version >= 1 else None
