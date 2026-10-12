"""Protocol version.

An integer, starting at 1 and independent of the sp-rtk-base version. It is
sent as a header on every poll, Check-in and tunnel open. Additive changes
don't bump it, and both sides ignore unknown fields.
"""

from __future__ import annotations

PROTOCOL_VERSION = 1

VERSION_HEADER = "SP-RTK-Protocol-Version"
"""The header every agent request carries ``PROTOCOL_VERSION`` in."""


def version_from_header(value: str | None) -> int | None:
    """The version a request says it speaks, or ``None`` if it's unreadable."""
    try:
        version = int((value or "").strip())
    except ValueError:
        return None
    return version if version >= 1 else None
