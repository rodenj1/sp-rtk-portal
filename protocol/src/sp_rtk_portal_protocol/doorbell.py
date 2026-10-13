"""The Doorbell (ADR 0002): UDP packets between a base and a Doorbell server,
and the HTTPS interface the Doorbell server uses on the Portal.

A base whose agent config names a usable Doorbell host sends a **keepalive**
to it every :data:`DOORBELL_INTERVAL` seconds (± :data:`DOORBELL_JITTER`),
from one UDP socket, which holds a return path open through its router. To
Wake the base the Portal hands the Doorbell server a **ring**, which it sends
back down that path. Packets are binary, big-endian:

- keepalive (109 bytes): ``MAGIC`` (4) | kind 1 | time (8, Unix seconds) |
  key thumbprint (32, the raw SHA-256 behind the RFC 7638 thumbprint) |
  Ed25519 signature by the base key over everything before it (64).
- ring: ``MAGIC`` (4) | kind 2 | time (8) | nonce length (1) | nonce (ASCII,
  the Wake's one-time nonce) | HMAC-SHA256 over everything before it with the
  base's **ring key** (32).

The ring key is a per-base secret the Portal gives the agent in each
Check-in reply (over HTTPS). A ring carries only a Wake's nonce: the agent
then opens its tunnel exactly as for a polled Wake, echoing the nonce in a
request signed by its base key, so even a forged ring could only cause a
refused tunnel attempt. Both packets are refused more than
:data:`~sp_rtk_portal_protocol.proof.MAX_CLOCK_SKEW` away from now.

The Doorbell server holds no keys. It relays each keepalive it receives, with
the address and port it came from, to :data:`KEEPALIVES_PATH`; the Portal
checks the signature, records the sign of life and remembers the return
path. It collects rings from :data:`RINGS_PATH` (a long poll) and sends each
packet to the address and port given. Both requests carry
``Authorization: Bearer <the Doorbell token>``.
"""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import hmac
import secrets
import struct
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from sp_rtk_portal_protocol.messages import Message
from sp_rtk_portal_protocol.proof import MAX_CLOCK_SKEW, BaseKey

DOORBELL_INTERVAL = 20
"""Seconds between a base's keepalives (before jitter)."""
DOORBELL_JITTER = 5
"""Each gap is ``DOORBELL_INTERVAL`` ± up to this many seconds."""

MAGIC = b"SPDB"
KEEPALIVE = 1
RING = 2

_HEAD = struct.Struct(">4sBQ")  # magic, kind, time
_SIGNATURE = 64
_THUMBPRINT = 32
_MAC = 32
KEEPALIVE_SIZE = _HEAD.size + _THUMBPRINT + _SIGNATURE
MAX_NONCE = 255

KEEPALIVES_PATH = "/doorbell/keepalives"
"""POST (Doorbell server -> Portal): :class:`KeepalivesReport` ->
:class:`KeepalivesReply`."""
RINGS_PATH = "/doorbell/rings"
"""GET ``?wait=<seconds>`` (Doorbell server -> Portal), a long poll: ->
:class:`Rings` as soon as there are any, or empty after ``wait``."""

KEEPALIVE_OK = "ok"
KEEPALIVE_UNKNOWN = "unknown"
"""No Claimed base has this key."""
KEEPALIVE_INVALID = "invalid"
"""Not a keepalive, a bad signature, or too old or new."""


class DoorbellError(ValueError):
    """A packet that must be ignored. The message says why (for logs)."""


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64(text: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (ValueError, TypeError) as exc:
        raise DoorbellError("not base64url") from exc


def encode_packet(packet: bytes) -> str:
    """A packet as the HTTPS interface carries it (base64url, no padding)."""
    return _b64(packet)


def decode_packet(text: str) -> bytes:
    return _unb64(text)


def _when(at: int) -> datetime:
    try:
        return datetime.fromtimestamp(at, tz=timezone.utc)
    except (ValueError, OverflowError, OSError) as exc:
        raise DoorbellError("packet time is out of range") from exc


def _check_time(at: int, now: datetime) -> datetime:
    when = _when(at)
    if abs(now - when) > MAX_CLOCK_SKEW:
        raise DoorbellError("packet time is too far from now")
    return when


# --- Keepalives ------------------------------------------------------------


@dataclass(frozen=True)
class Keepalive:
    thumbprint: str
    """The base key's RFC 7638 thumbprint (find the base by it)."""
    at: datetime
    """When the base sent it (its clock)."""


def keepalive(key: BaseKey, *, now: datetime) -> bytes:
    """A keepalive signed by the base key."""
    body = _HEAD.pack(MAGIC, KEEPALIVE, int(now.timestamp())) + _unb64(key.thumbprint)
    return body + key.sign(body)


def _split_keepalive(packet: bytes) -> tuple[bytes, Keepalive, bytes]:
    if len(packet) != KEEPALIVE_SIZE:
        raise DoorbellError("not a keepalive")
    magic, kind, at = _HEAD.unpack_from(packet)
    if magic != MAGIC or kind != KEEPALIVE:
        raise DoorbellError("not a keepalive")
    body = packet[:-_SIGNATURE]
    thumbprint = _b64(body[_HEAD.size :])
    return body, Keepalive(thumbprint, _when(at)), packet[-_SIGNATURE:]


def read_keepalive(packet: bytes) -> Keepalive:
    """The keepalive's claims, NOT verified: only to look the base up."""
    return _split_keepalive(packet)[1]


def verify_keepalive(packet: bytes, jwk: dict[str, Any], *, now: datetime) -> Keepalive:
    """The keepalive, if the base key ``jwk`` signed it recently."""
    body, heard, signature = _split_keepalive(packet)
    try:
        public = Ed25519PublicKey.from_public_bytes(_unb64(str(jwk.get("x", ""))))
        public.verify(signature, body)
    except (InvalidSignature, ValueError) as exc:
        raise DoorbellError("bad signature") from exc
    _check_time(int(heard.at.timestamp()), now)
    return heard


# --- Rings ----------------------------------------------------------------


def new_ring_key() -> str:
    """A fresh ring key (256 bits, base64url)."""
    return _b64(secrets.token_bytes(32))


def ring(ring_key: str, nonce: str, *, now: datetime) -> bytes:
    """A ring carrying a Wake's ``nonce``, for the holder of ``ring_key``."""
    raw = nonce.encode("ascii")
    if not 0 < len(raw) <= MAX_NONCE:
        raise ValueError("nonce must be 1..255 ASCII characters")
    body = _HEAD.pack(MAGIC, RING, int(now.timestamp())) + bytes([len(raw)]) + raw
    return body + hmac.new(_unb64(ring_key), body, hashlib.sha256).digest()


def open_ring(ring_key: str, packet: bytes, *, now: datetime) -> str:
    """The nonce a genuine, recent ring carries."""
    if len(packet) < _HEAD.size + 1 + 1 + _MAC:
        raise DoorbellError("not a ring")
    magic, kind, at = _HEAD.unpack_from(packet)
    length = packet[_HEAD.size]
    if magic != MAGIC or kind != RING or len(packet) != _HEAD.size + 1 + length + _MAC:
        raise DoorbellError("not a ring")
    body, mac = packet[:-_MAC], packet[-_MAC:]
    expected = hmac.new(_unb64(ring_key), body, hashlib.sha256).digest()
    if not hmac.compare_digest(mac, expected):
        raise DoorbellError("bad ring signature")
    _check_time(at, now)
    try:
        return body[_HEAD.size + 1 :].decode("ascii")
    except UnicodeDecodeError as exc:
        raise DoorbellError("not a ring") from exc


# --- The Doorbell server's HTTPS interface -------------------------------------


@dataclass(frozen=True)
class HeardKeepalive(Message):
    packet: str
    """The datagram, base64url (:func:`encode_packet`)."""
    address: str
    """The source IP it came from (the base's router)."""
    port: int


@dataclass(frozen=True)
class KeepalivesReport(Message):
    keepalives: list[HeardKeepalive] = dataclasses.field(default_factory=list)


@dataclass(frozen=True)
class KeepalivesReply(Message):
    results: list[str] = dataclasses.field(default_factory=list)
    """One per reported keepalive, in order: ``KEEPALIVE_*``."""


@dataclass(frozen=True)
class Ring(Message):
    address: str
    port: int
    packet: str
    """Send this datagram (base64url) to ``address``:``port``, from the
    socket the keepalives arrived on."""


@dataclass(frozen=True)
class Rings(Message):
    rings: list[Ring] = dataclasses.field(default_factory=list)
