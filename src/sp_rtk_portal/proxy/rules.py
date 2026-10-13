"""The base proxy's header and path rules (ADR 0004, spec "Base proxy rules").

Pure functions: what a request to ``/b/<id>/s/<token>/<tail>`` names, which
of the browser's headers go on to the base, and what every base response
carries back.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from urllib.parse import unquote, urlsplit, urlunsplit

PREFIX = "/b/"

SANDBOX = "allow-scripts allow-forms allow-downloads"
"""The frame's sandbox flags: no ``allow-same-origin``, ``allow-top-navigation``
or ``allow-popups``. The Session bar's iframe and every base response's CSP
use the same set."""

BASE_HOST = "localhost:8080"
"""The ``Host`` the agent gives every stream; a base redirect to it means
"my own page"."""

Headers = list[tuple[bytes, bytes]]

_TOKEN = re.compile(r"[A-Za-z0-9_-]{1,128}")
_BASE_ID = re.compile(r"[A-Za-z0-9_-]{1,64}")


@dataclass(frozen=True)
class Target:
    """A ``/b/`` request split up: whose session, and the path the base sees."""

    base_id: str
    token: str
    prefix: str
    """``/b/<id>/s/<token>``, what the base gets as ``X-Forwarded-Prefix``."""
    tail: bytes
    """The base's path (raw, still percent-encoded), with the query."""


class NotAFrame(Exception):
    """Not the shape of a frame URL (``/b/<id>/s/<token>/…``)."""


class NeedsSlash(Exception):
    """``/b/<id>/s/<token>`` without the slash: redirect to it."""

    def __init__(self, location: str) -> None:
        self.location = location


def target(raw_path: bytes, query: bytes) -> Target:
    parts = raw_path.split(b"/", 5)
    if len(parts) < 5 or parts[0] != b"" or parts[1] != b"b" or parts[3] != b"s":
        raise NotAFrame
    base_id = unquote(parts[2].decode("latin-1"))
    token = parts[4].decode("latin-1")
    if not _BASE_ID.fullmatch(base_id) or not _TOKEN.fullmatch(token):
        raise NotAFrame
    prefix = f"/b/{base_id}/s/{token}"
    if len(parts) == 5:
        raise NeedsSlash(
            prefix + "/" + (f"?{query.decode('latin-1')}" if query else "")
        )
    tail = b"/" + parts[5]
    if query:
        tail += b"?" + query
    return Target(base_id, token, prefix, tail)


# --- Requests ---------------------------------------------------------------------

_DOCUMENT_DESTS = frozenset({"document", "frame", "embed", "object", "fencedframe"})


def refused_load(headers: Iterable[tuple[bytes, bytes]]) -> bool:
    """A document load anywhere but in a frame (``Sec-Fetch-Dest`` other than
    ``iframe``): a leaked link opened on its own, or embedded some other way.
    Subresources, fetches and websockets are not document loads."""
    found = {k.lower(): v.decode("latin-1").lower() for k, v in headers}
    dest = found.get(b"sec-fetch-dest")
    if dest == "iframe":
        return False
    return dest in _DOCUMENT_DESTS or found.get(b"sec-fetch-mode") == "navigate"


_NEVER_FORWARDED = frozenset(
    {
        # one hop's own
        b"connection",
        b"keep-alive",
        b"proxy-connection",
        b"te",
        b"trailer",
        b"transfer-encoding",
        b"upgrade",
        b"expect",
        b"host",
        b"content-length",
        # credentials: the Portal's cookie, and anything else of the user's
        b"cookie",
        b"authorization",
        b"proxy-authorization",
        # the frame's opaque origin (``null``) means nothing to the base
        b"origin",
        # forwarding headers: the Portal sets its own
        b"forwarded",
        b"x-real-ip",
        b"true-client-ip",
        b"x-client-ip",
        # a websocket's handshake is the relay's own
        b"sec-websocket-key",
        b"sec-websocket-version",
        b"sec-websocket-extensions",
        b"sec-websocket-accept",
        b"sec-websocket-protocol",
    }
)
_NEVER_FORWARDED_PREFIXES = (b"x-forwarded-", b"cf-")


def request_headers(
    client: Iterable[tuple[bytes, bytes]], prefix: str, public_origin: str
) -> Headers:
    """The browser's headers as the base gets them. Forwarding headers are
    the Portal's own, never the client's; the client's IP is not passed on
    (a base's pages are untrusted, and may be a Shared user's)."""
    kept = [
        (k.lower(), v)
        for k, v in client
        if k.lower() not in _NEVER_FORWARDED
        and not k.lower().startswith(_NEVER_FORWARDED_PREFIXES)
    ]
    origin = urlsplit(public_origin)
    return [
        (b"host", BASE_HOST.encode()),
        *kept,
        (b"x-forwarded-prefix", prefix.encode()),
        (b"x-forwarded-proto", origin.scheme.encode()),
        (b"x-forwarded-host", origin.netloc.encode()),
    ]


# --- Responses --------------------------------------------------------------------


def stamp(public_origin: str) -> Headers:
    """On every base response, whatever its status (ADR 0004)."""
    return [
        (
            b"content-security-policy",
            f"sandbox {SANDBOX}; frame-ancestors {public_origin}".encode(),
        ),
        (b"access-control-allow-origin", b"*"),
        (b"referrer-policy", b"no-referrer"),
    ]


_NEVER_RETURNED = frozenset(
    {
        b"connection",
        b"keep-alive",
        b"proxy-connection",
        b"te",
        b"trailer",
        b"transfer-encoding",
        b"upgrade",
        b"set-cookie",
        b"set-cookie2",
        # the Portal's own, stamped below
        b"content-security-policy",
        b"content-security-policy-report-only",
        b"x-frame-options",
        b"access-control-allow-origin",
        b"access-control-allow-credentials",
        b"referrer-policy",
    }
)


def response_headers(
    base: Iterable[tuple[bytes, bytes]], prefix: str, public_origin: str
) -> Headers:
    kept: Headers = []
    for k, v in base:
        name = k.lower()
        if name in _NEVER_RETURNED:
            continue
        if name == b"location":
            v = location(v.decode("latin-1"), prefix).encode("latin-1")
        kept.append((name, v))
    return kept + stamp(public_origin)


def location(value: str, prefix: str) -> str:
    """Keep a base's redirect to its own pages inside its frame."""
    parts = urlsplit(value)
    if parts.scheme or parts.netloc:
        if parts.netloc.lower() not in (BASE_HOST, "127.0.0.1:8080"):
            return value
        path = urlunsplit(("", "", parts.path or "/", parts.query, parts.fragment))
    elif value.startswith("/"):
        path = value
    else:
        return value  # relative: already resolves inside the frame
    if path == prefix or path.startswith(prefix + "/"):
        return path
    return prefix + path
