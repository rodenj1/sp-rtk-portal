"""Message shapes: JSON bodies of agent requests and Portal replies.

Every message is a frozen dataclass with ``to_json()`` and
``from_json(data)``. ``from_json`` ignores fields it doesn't know (both sides
must, so additive changes need no version bump) and raises
:class:`MessageError` for a missing or mistyped one.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass
from typing import Any, ClassVar, TypeVar, get_type_hints

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
            value = data[field.name]
            expected = hints[field.name]
            if not isinstance(value, expected) or (
                expected is int and isinstance(value, bool)
            ):
                raise MessageError(f"{cls.__name__}: {field.name} is mistyped")
            values[field.name] = value
        return cls(**values)

    def to_json(self) -> dict[str, Any]:
        return dataclasses.asdict(self)  # type: ignore[call-overload,no-any-return]


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
