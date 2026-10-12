"""Claim: pairing a base's agent with an Operator's account (RFC 8628).

1. The agent starts a pairing (:func:`start`), signed with its new base key.
   It gets a device code (secret, for polling) and a user code (8 letters
   from a 20-consonant alphabet, RFC 8628 §6.1) that lives 10 minutes.
2. The Operator, signed in, enters or confirms the user code on ``/claim``,
   names the base and approves (:func:`approve`). That creates the base.
3. The agent polls (:func:`collect`) with the device code, signed by the same
   key, and gets the base's ``<id>``.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from psycopg import errors
from psycopg.types.json import Jsonb
from sp_rtk_portal_protocol import Claimed, ErrorReply

from sp_rtk_portal import audit
from sp_rtk_portal.db import Connection

USER_CODE_ALPHABET = "BCDFGHJKLMNPQRSTVWXZ"
USER_CODE_LENGTH = 8
NAME_MAX = 64

# A pairing stays this long after it expires, so a late approval can be told
# "expired" rather than "wrong code".
_KEEP_EXPIRED = timedelta(days=1)

WRONG_CODE = (
    "No base is waiting for code {code}. Check the code on the base's Portal page."
)
EXPIRED = (
    "That code has expired. Press Connect to Portal on the base again for a new one."
)
USED = "That code has already been used."
LIMIT = "You already have {limit} bases, the most one account can Claim."
NO_NAME = "Give the base a name."
LONG_NAME = f"Keep the name to {NAME_MAX} characters or fewer."


class ApprovalRefused(Exception):
    """The Operator's approval can't Claim anything. The message says why."""


class KeyAlreadyClaimed(Exception):
    """A pairing started with a key that already belongs to a base."""


@dataclass(frozen=True)
class Pending:
    """A pairing as the approve page shows it (RFC 8628 §5.4: say what's
    being approved, so a code phished from someone else is recognisable)."""

    user_code: str
    suggested_name: str
    software_version: str
    requested_at: datetime
    ip: str | None
    expired: bool
    used: bool


def normalize_user_code(text: str) -> str:
    """What the Operator typed, as stored: letters only, upper case."""
    return "".join(c for c in text.upper() if c.isalpha())


def display_code(code: str) -> str:
    return f"{code[:4]}-{code[4:]}" if len(code) == USER_CODE_LENGTH else code


def _new_user_code() -> str:
    return "".join(secrets.choice(USER_CODE_ALPHABET) for _ in range(USER_CODE_LENGTH))


def _new_base_id() -> str:
    """About 10 base32 characters (50 bits), opaque, new for every Claim."""
    return base64.b32encode(secrets.token_bytes(10)).decode().lower()[:10]


def _hash(device_code: str) -> bytes:
    return hashlib.sha256(device_code.encode()).digest()


async def start(
    conn: Connection,
    *,
    now: datetime,
    lifetime: timedelta,
    public_key: dict[str, str],
    thumbprint: str,
    suggested_name: str,
    software_version: str,
    protocol_version: int,
    ip: str | None,
) -> tuple[str, str]:
    """Record a new pairing. Returns ``(device_code, user_code)``."""
    claimed = await conn.execute(
        "SELECT 1 FROM base WHERE key_thumbprint = %s", (thumbprint,)
    )
    if await claimed.fetchone():
        raise KeyAlreadyClaimed
    await conn.execute(
        "DELETE FROM pairing WHERE expires_at < %s AND base_id IS NULL",
        (now - _KEEP_EXPIRED,),
    )
    device_code = secrets.token_urlsafe(32)
    for _ in range(5):
        user_code = _new_user_code()
        try:
            async with conn.transaction():
                await conn.execute(
                    "INSERT INTO pairing (device_code_hash, user_code, public_key,"
                    " key_thumbprint, suggested_name, software_version,"
                    " protocol_version, ip, requested_at, expires_at)"
                    " VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                    (
                        _hash(device_code),
                        user_code,
                        Jsonb(public_key),
                        thumbprint,
                        suggested_name[:NAME_MAX],
                        software_version[:32],
                        protocol_version,
                        ip,
                        now,
                        now + lifetime,
                    ),
                )
        except errors.UniqueViolation:
            continue
        return device_code, user_code
    raise RuntimeError("couldn't pick an unused pairing code")  # pragma: no cover


async def collect(
    conn: Connection,
    *,
    now: datetime,
    thumbprint: str,
    device_code: str,
    interval: int,
) -> Claimed | str:
    """The agent's poll: the Claim, or an RFC 8628 §3.5 error code."""
    cur = await conn.execute(
        "SELECT p.key_thumbprint, p.expires_at, p.last_polled_at, p.base_id,"
        " a.email"
        " FROM pairing p"
        " LEFT JOIN base b ON b.id = p.base_id"
        " LEFT JOIN account a ON a.id = b.owner_account_id"
        " WHERE p.device_code_hash = %s FOR UPDATE OF p",
        (_hash(device_code),),
    )
    row = await cur.fetchone()
    if row is None or row["key_thumbprint"] != thumbprint:
        return ErrorReply.INVALID_GRANT
    if row["base_id"] is not None:
        return Claimed(base_id=row["base_id"], account=row["email"])
    if now >= row["expires_at"]:
        return ErrorReply.EXPIRED_TOKEN
    await conn.execute(
        "UPDATE pairing SET last_polled_at = %s WHERE device_code_hash = %s",
        (now, _hash(device_code)),
    )
    last = row["last_polled_at"]
    if last is not None and now - last < timedelta(seconds=interval):
        return ErrorReply.SLOW_DOWN
    return ErrorReply.AUTHORIZATION_PENDING


async def find(conn: Connection, user_code: str, now: datetime) -> Pending | None:
    cur = await conn.execute(
        "SELECT user_code, suggested_name, software_version, requested_at,"
        " host(ip) AS ip, expires_at, base_id FROM pairing WHERE user_code = %s",
        (user_code,),
    )
    row = await cur.fetchone()
    if row is None:
        return None
    return Pending(
        user_code=row["user_code"],
        suggested_name=row["suggested_name"],
        software_version=row["software_version"],
        requested_at=row["requested_at"],
        ip=row["ip"],
        expired=now >= row["expires_at"],
        used=row["base_id"] is not None,
    )


async def approve(
    conn: Connection,
    *,
    now: datetime,
    account_id: int,
    user_code: str,
    name: str,
    ip: str | None,
    limit: int,
) -> str:
    """Claim the pairing's base for ``account_id``. Returns the base's id.

    Raises :class:`ApprovalRefused` with a message for the Operator.
    """
    name = name.strip()
    if not name:
        raise ApprovalRefused(NO_NAME)
    if len(name) > NAME_MAX:
        raise ApprovalRefused(LONG_NAME)
    cur = await conn.execute(
        "SELECT * FROM pairing WHERE user_code = %s FOR UPDATE", (user_code,)
    )
    pairing: dict[str, Any] | None = await cur.fetchone()
    if pairing is None:
        raise ApprovalRefused(WRONG_CODE.format(code=display_code(user_code)))
    if pairing["base_id"] is not None:
        raise ApprovalRefused(USED)
    if now >= pairing["expires_at"]:
        raise ApprovalRefused(EXPIRED)
    # One approval at a time per account, so two can't both squeeze under
    # the limit.
    await conn.execute("SELECT 1 FROM account WHERE id = %s FOR UPDATE", (account_id,))
    count = await conn.execute(
        "SELECT count(*) AS n FROM base WHERE owner_account_id = %s", (account_id,)
    )
    counted = await count.fetchone()
    if counted is not None and counted["n"] >= limit:
        raise ApprovalRefused(LIMIT.format(limit=limit))
    taken = await conn.execute(
        "SELECT 1 FROM base WHERE key_thumbprint = %s", (pairing["key_thumbprint"],)
    )
    if await taken.fetchone():
        raise ApprovalRefused(USED)
    base_id = _new_base_id()
    await conn.execute(
        "INSERT INTO base (id, public_key, key_thumbprint, name, owner_account_id,"
        " claimed_at, software_version, protocol_version)"
        " VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
        (
            base_id,
            Jsonb(pairing["public_key"]),
            pairing["key_thumbprint"],
            name,
            account_id,
            now,
            pairing["software_version"],
            pairing["protocol_version"],
        ),
    )
    await conn.execute(
        "UPDATE pairing SET base_id = %s WHERE device_code_hash = %s",
        (base_id, pairing["device_code_hash"]),
    )
    await audit.record(
        conn,
        at=now,
        kind=audit.CLAIM,
        account_id=account_id,
        base_id=base_id,
        ip=ip,
        detail={
            "name": name,
            "key_thumbprint": pairing["key_thumbprint"],
            "agent_ip": str(pairing["ip"]) if pairing["ip"] else None,
            "software_version": pairing["software_version"],
        },
    )
    return base_id
