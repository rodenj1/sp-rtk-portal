"""Message shapes: JSON bodies of agent requests and Portal replies.

Every message is a frozen dataclass with ``to_json()`` and
``from_json(data)``. ``from_json`` ignores fields it doesn't know (both sides
must, so additive changes need no version bump) and raises
:class:`MessageError` for a missing or mistyped one.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass
from types import UnionType
from typing import Any, ClassVar, TypeVar, Union, get_args, get_origin, get_type_hints

T = TypeVar("T", bound="Message")


class MessageError(ValueError):
    """A body that isn't the message it should be."""


class Message:
    @classmethod
    def from_json(cls: type[T], data: Any) -> T:
        if not isinstance(data, dict):
            raise MessageError(f"{cls.__name__}: expected a JSON object")
        hints = get_type_hints(cls)
        values: dict[str, Any] = {}
        for field in dataclasses.fields(cls):  # type: ignore[arg-type]
            if field.name not in data:
                if (
                    field.default is dataclasses.MISSING
                    and field.default_factory is dataclasses.MISSING
                ):
                    raise MessageError(f"{cls.__name__}: missing {field.name}")
                continue
            try:
                values[field.name] = _parse(data[field.name], hints[field.name])
            except _Mistyped:
                raise MessageError(
                    f"{cls.__name__}: {field.name} is mistyped"
                ) from None
        return cls(**values)

    def to_json(self) -> dict[str, Any]:
        return dataclasses.asdict(self)  # type: ignore[call-overload,no-any-return]


class _Mistyped(Exception):
    pass


def _parse(value: Any, expected: Any) -> Any:
    """``value`` as the field type ``expected``: a plain type (``str``,
    ``int``, ``bool``...), a :class:`Message`, ``list[X]`` or ``X | None``."""
    origin = get_origin(expected)
    if origin is Union or origin is UnionType:
        for arm in get_args(expected):
            if arm is type(None):
                if value is None:
                    return None
                continue
            try:
                return _parse(value, arm)
            except (_Mistyped, MessageError):
                continue
        raise _Mistyped
    if origin is list:
        if not isinstance(value, list):
            raise _Mistyped
        (item,) = get_args(expected)
        return [_parse(v, item) for v in value]
    if isinstance(expected, type) and issubclass(expected, Message):
        try:
            return expected.from_json(value)
        except MessageError as exc:
            raise _Mistyped from exc
    if not isinstance(value, expected) or (expected is int and isinstance(value, bool)):
        raise _Mistyped
    return value


# --- Claim (RFC 8628 device authorization) ---------------------------------

CLAIMS_PATH = "/agent/claims"
"""POST, signed with the new base key: start a Claim (:class:`ClaimStart`)."""

CLAIM_TOKEN_PATH = "/agent/claims/token"
"""POST, signed with the same key: poll for the result (:class:`ClaimToken`)."""


@dataclass(frozen=True)
class ClaimStart(Message):
    """Body of a Claim start. The public key is the one in the proof."""

    name: str = ""
    """A suggested display name (the base's hostname). The Operator decides."""
    software_version: str = ""


@dataclass(frozen=True)
class ClaimStarted(Message):
    """RFC 8628 §3.2 device authorization response."""

    device_code: str
    user_code: str
    verification_uri: str
    verification_uri_complete: str
    expires_in: int
    interval: int


@dataclass(frozen=True)
class ClaimToken(Message):
    """RFC 8628 §3.4 poll."""

    device_code: str


@dataclass(frozen=True)
class Claimed(Message):
    """The poll's success: the base is Claimed."""

    base_id: str
    account: str
    """The owner account's email, shown on the base's local Portal page."""


@dataclass(frozen=True)
class ErrorReply(Message):
    """An error body (RFC 6749 §5.2 shape), with HTTP 400 or 401."""

    error: str
    error_description: str = ""

    # RFC 8628 §3.5, on the Claim poll (HTTP 400).
    AUTHORIZATION_PENDING: ClassVar[str] = "authorization_pending"
    SLOW_DOWN: ClassVar[str] = "slow_down"
    EXPIRED_TOKEN: ClassVar[str] = "expired_token"
    ACCESS_DENIED: ClassVar[str] = "access_denied"
    INVALID_GRANT: ClassVar[str] = "invalid_grant"
    """A device code that doesn't exist, or was started by another key."""
    # Any agent request (HTTP 400 / 401).
    INVALID_REQUEST: ClassVar[str] = "invalid_request"
    INVALID_PROOF: ClassVar[str] = "invalid_proof"
    UNCLAIMED: ClassVar[str] = "unclaimed"
    """No base has this key: the agent wipes its key and goes idle."""


# --- Polls and Check-ins (ADR 0002) ----------------------------------------
#
# A Claimed base polls (``POST /agent/poll``) every ``poll_interval`` seconds,
# or ``metered_poll_interval`` when its Operator marked it metered, and
# Checks in (``POST /agent/check-in``) every ``check_in_interval``. Both are
# signed with the base key; an unknown key gets 401 ``unclaimed`` and an
# unsupported protocol version gets 426 :class:`UpgradeRequired`. Both
# replies carry the agent config block, the metered flag and any notices.

POLL_PATH = "/agent/poll"
"""POST, signed with the base key: :class:`Poll` -> :class:`PollReply`."""

CHECK_IN_PATH = "/agent/check-in"
"""POST, signed with the base key: :class:`CheckIn` -> :class:`CheckInReply`."""

TUNNEL_PATH = "/agent/tunnel"
"""The tunnel's websocket path; the agent's built-in tunnel URL is
``wss://<Portal host>`` + this."""

# Doorbell health, as a Check-in reports it.
DOORBELL_OFF = "off"
"""No Doorbell host in the agent config: the base polls."""
DOORBELL_IGNORED = "ignored"
"""The configured host didn't resolve, or resolved to a private, loopback or
link-local address: the agent ignores it and polls."""
DOORBELL_UNAVAILABLE = "unavailable"
"""A usable host is configured but this agent can't ring it (yet): it polls."""
DOORBELL_OK = "ok"
"""The Doorbell answers: the base is woken by it (wake mode Doorbell)."""


@dataclass(frozen=True)
class AgentConfig(Message):
    """The agent config block, edited on the Portal by the Portal owner.

    The agent applies a block only when ``revision`` differs from the one it
    holds, persists it, and uses the built-in defaults below until it has
    one. Times are in seconds.
    """

    revision: int
    poll_interval: int = 20
    metered_poll_interval: int = 60
    check_in_interval: int = 300
    doorbell_host: str | None = None
    doorbell_port: int | None = None
    tunnel_url: str = ""
    """``wss://`` on the Portal's own host; empty means the agent's built-in
    ``wss://<Portal host>/agent/tunnel``. The agent ignores any other."""
    tunnel_idle_timeout: int = 120
    """Close the tunnel this long after the last browser leaves."""
    tunnel_hard_cap: int = 3600
    """A Remote session's hard cap."""


@dataclass(frozen=True)
class Notice(Message):
    """A message for the Operator (e.g. a deprecation date), shown on the
    base's local Portal page and on the base in the Portal's list."""

    text: str


@dataclass(frozen=True)
class Poll(Message):
    """Body of a poll: the agent's own state."""

    state: str = "connected"
    """``connected``, or ``paused`` when remote access is paused locally."""


@dataclass(frozen=True)
class PollReply(Message):
    config: AgentConfig
    metered: bool = False
    """The Operator marked the base metered: poll every
    ``config.metered_poll_interval`` instead of ``config.poll_interval``."""
    notices: list[Notice] = dataclasses.field(default_factory=list)
    wake: str | None = None
    """A Wake: a one-time nonce, and nothing else. The agent opens the tunnel
    at its own (checked) tunnel URL with a GET signed by its base key whose
    proof echoes this in its ``nonce`` claim. The Portal refuses any other
    nonce, so a forged Wake can only cause a refused tunnel attempt."""


@dataclass(frozen=True)
class LanAddress(Message):
    address: str
    """A private IPv4 address on an active interface."""
    interface: str = ""
    primary: bool = False
    """On the interface that holds the default route."""


@dataclass(frozen=True)
class CheckIn(Message):
    """Body of a Check-in. The protocol version is in the version header; the
    base's public IP is the one Cloudflare reports."""

    software_version: str = ""
    doorbell: str = DOORBELL_OFF
    """Doorbell health: one of the ``DOORBELL_*`` values."""
    lan_addresses: list[LanAddress] = dataclasses.field(default_factory=list)


@dataclass(frozen=True)
class CheckInReply(Message):
    config: AgentConfig
    metered: bool = False
    notices: list[Notice] = dataclasses.field(default_factory=list)


@dataclass(frozen=True)
class UpgradeRequired(Message):
    """HTTP 426 body: this agent's protocol version is no longer supported.

    The agent keeps its key and Claim, stops regular polling and retries once
    a day; its local page says "Upgrade sp-rtk-base to keep using the Portal".
    """

    min_version: int
    message: str = ""
    error: str = "upgrade_required"
