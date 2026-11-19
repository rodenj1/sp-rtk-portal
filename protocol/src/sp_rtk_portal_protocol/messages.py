"""Message shapes: JSON bodies of agent requests and Portal replies.

Every message is a frozen dataclass with ``to_json()`` and
``from_json(data)``. ``from_json`` ignores fields it doesn't know (both sides
must, so additive changes need no version bump) and raises
:class:`MessageError` for a missing or mistyped one.
"""

from __future__ import annotations

import dataclasses
import json
from dataclasses import dataclass
from types import UnionType
from typing import (
    Any,
    ClassVar,
    Final,
    Literal,
    TypeVar,
    Union,
    get_args,
    get_origin,
    get_type_hints,
)

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
    ``int``, ``bool``...), a :class:`Message`, ``list[X]``, ``X | None`` or
    a ``Literal`` of strings."""
    origin = get_origin(expected)
    if origin is Literal:
        if value not in get_args(expected):
            raise _Mistyped
        return value
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


# --- Release (local Un-claim) ----------------------------------------------

RELEASE_PATH = "/agent/release"
"""POST, signed with the base key: :class:`Release` -> :class:`Released`, or
401 ``unclaimed`` when the Portal has no base with this key (already
Un-claimed there). Best effort: the agent wipes its key either way."""


@dataclass(frozen=True)
class Release(Message):
    """Body of a release: nothing. The signing key names the base, and the
    Portal Un-claims it (deletes its record, Shares and Remote sessions)."""


@dataclass(frozen=True)
class Released(Message):
    base_id: str
    """The ``<id>`` that no longer exists."""


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
    tunnel_url: str = ""
    """``wss://`` on the Portal's own host; empty means the agent's built-in
    ``wss://<Portal host>/agent/tunnel``. The agent ignores any other."""
    tunnel_idle_timeout: int = 120
    """End a Remote session this long after its last Session bar closed."""
    tunnel_hard_cap: int = 3600
    """A Remote session's hard cap."""
    ping_interval: int = 50
    """How often an agent holding its tunnel pings the Portal (the Portal
    never pings)."""
    tunnel_silence_timeout: int = 120
    """The Portal closes a held tunnel that sent nothing for this long
    (informational for the agent: it pings well within it)."""
    lease_length: int = 300
    """How long a Remote session's path token lives after its Session bar
    last renewed it (Session bar only: the agent ignores it)."""
    lease_renewal_interval: int = 60
    """How often the Session bar renews the lease (Session bar only)."""
    reconnect_backoff_cap: int = 600
    """The longest an agent waits between tries to open its tunnel again
    after a drop (it backs off up to this, with jitter)."""
    fallback_failures: int = 3
    """Tunnel opens failed in a row (while HTTPS gets through) after which
    the agent falls back to polling (a count, not seconds)."""
    fallback_retry_interval: int = 900
    """How often an agent that fell back to polling tries its tunnel
    again."""


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
class LiveSession(Message):
    """A live Remote session on the base, for its local Portal page and its
    own record of Remote sessions (the Event log)."""

    who: str
    """The user's email."""
    since: str
    """When the Remote session started (ISO 8601, UTC)."""
    shared: bool = False
    """The user has the base through a Share (not its Operator)."""
    id: str = ""
    """The Remote session's id, unique on the Portal (protocol package
    0.10.0), so the agent can match an :class:`EndedSession` to its start.
    Empty from an older Portal."""


END_LEFT = "left"
"""The user left: logged out, or left the Share."""
END_IDLE = "idle"
"""Nobody had the Session bar open for the idle timeout."""
END_PAUSED = "paused"
"""Remote access was paused on the base."""
END_LEASE_EXPIRED = "lease_expired"
"""The path token's lease ran out (the Session bar stopped renewing it)."""
END_REVOKED = "revoked"
"""The Portal took the user's access away: un-Share, Un-claim, account
deletion."""
END_HARD_CAP = "hard_cap"
"""The Remote session reached its hard cap."""

END_REASONS = (
    END_LEFT,
    END_IDLE,
    END_PAUSED,
    END_LEASE_EXPIRED,
    END_REVOKED,
    END_HARD_CAP,
)
"""Why a Remote session ended, as the base hears it. A reader shows any
other value as is (a newer Portal may add reasons)."""


@dataclass(frozen=True)
class EndedSession(Message):
    """A Remote session that ended, with its reason: the whole record, so
    the base can log a session it never saw live. A poll reply carries the
    recent ones; the tunnel's Session ended message carries the same."""

    id: str
    """As in :attr:`LiveSession.id`."""
    who: str
    since: str
    """When it started (ISO 8601, UTC)."""
    at: str
    """When it ended (ISO 8601, UTC)."""
    reason: str
    """One of :data:`END_REASONS`."""
    shared: bool = False


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
    sessions: list[LiveSession] = dataclasses.field(default_factory=list)
    """The base's live Remote sessions, oldest first (protocol package
    0.6.0): its local Portal page lists them."""
    ended: list[EndedSession] = dataclasses.field(default_factory=list)
    """Remote sessions on the base that ended lately, oldest first (protocol
    package 0.10.0). The same end may come in several replies: the agent
    keeps each id once."""


@dataclass(frozen=True)
class LanAddress(Message):
    address: str
    """A private IPv4 address on an active interface."""
    interface: str = ""
    primary: bool = False
    """On the interface that holds the default route."""


MODE_HOLDING: Final = "holding"
"""Connection mode: the agent holds its tunnel open (protocol version 2)."""
MODE_RECONNECTING: Final = "reconnecting"
"""Connection mode: a version 2 agent whose held tunnel isn't open (yet, or
any more): it backs off and tries again."""
MODE_POLLING: Final = "polling"
"""Connection mode: the Portal reaches the base only by Waking it through
its polls (a version 1 agent, or a version 2 agent that fell back)."""

ConnectionMode = Literal["holding", "reconnecting", "polling"]
"""How the Portal reaches a Claimed base (ADR 0006). Offline isn't one: the
Portal tells it from when it last heard from the base."""

CONNECTION_MODES: tuple[ConnectionMode, ...] = (
    MODE_HOLDING,
    MODE_RECONNECTING,
    MODE_POLLING,
)


@dataclass(frozen=True)
class CheckIn(Message):
    """Body of a Check-in. The protocol version is in the version header; the
    base's public IP is the one Cloudflare reports."""

    software_version: str = ""
    lan_addresses: list[LanAddress] = dataclasses.field(default_factory=list)
    paused: bool | None = None
    """Remote access paused on site, as on a poll (``Poll.state``). ``None``:
    an agent from before this field, which says nothing either way."""
    mode: ConnectionMode | None = None
    """The agent's connection mode (one of :data:`CONNECTION_MODES`;
    protocol package 0.10.0). ``None`` from an older agent."""


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


# --- Control messages on a held tunnel (ADR 0006) ---------------------------
#
# A base holding its tunnel sends no polls or Check-ins: each side sends
# control messages on the tunnel instead (a ``CONTROL`` frame each, see
# :mod:`.tunnel`). The agent sends a :class:`CheckIn` on connect, every
# ``check_in_interval`` and whenever its contents change; the Portal sends a
# :class:`TunnelUpdate` on connect and whenever it changes, and a
# :class:`EndedSession` for each Remote session that ends.


@dataclass(frozen=True)
class TunnelUpdate(Message):
    """What a poll reply carries, minus the Wake: the agent config block,
    the metered flag, the notices and the live Remote sessions. Each one is
    the whole picture, replacing the last."""

    config: AgentConfig
    metered: bool = False
    notices: list[Notice] = dataclasses.field(default_factory=list)
    sessions: list[LiveSession] = dataclasses.field(default_factory=list)


CONTROL_TYPES: dict[str, type[Message]] = {
    "check_in": CheckIn,
    "update": TunnelUpdate,
    "session_ended": EndedSession,
}
"""Each control message's ``type``. A receiver ignores a type it doesn't
know (a newer peer may add some)."""


def control_message(message: Message) -> bytes:
    """``message`` as a control frame's payload: its JSON with its ``type``."""
    for name, cls in CONTROL_TYPES.items():
        if type(message) is cls:
            body = {"type": name, **message.to_json()}
            return json.dumps(body, separators=(",", ":")).encode()
    raise TypeError(f"{type(message).__name__} isn't a control message")


def read_control(payload: bytes) -> Message | None:
    """A control frame's message, or ``None`` for a type this side doesn't
    know. Raises :class:`MessageError` for one that isn't a message."""
    try:
        body = json.loads(payload)
    except ValueError:
        raise MessageError("a control message that isn't JSON") from None
    if not isinstance(body, dict) or not isinstance(body.get("type"), str):
        raise MessageError("a control message without a type")
    cls = CONTROL_TYPES.get(body["type"])
    return cls.from_json(body) if cls is not None else None
