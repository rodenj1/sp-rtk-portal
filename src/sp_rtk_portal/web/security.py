"""Security rules for the Portal's own pages and endpoints.

- Every Portal response carries a strict CSP with ``frame-ancestors 'none'``.
  The sign-up and recovery pages also allow Cloudflare Turnstile's script and
  frame (``TURNSTILE_PAGES``), and nothing else does. The Session bar page
  (``/bases/<id>``) may frame its own origin (the base proxy) and ``blob:``,
  with COOP ``same-origin-allow-popups`` instead of ``same-origin``.
- Every state-changing request (anything but GET/HEAD/OPTIONS) must have a JSON
  body, carry ``ACTION_HEADER``, and send an ``Origin`` equal to the Portal's.
  That makes requests from a sandboxed base frame (``Origin: null``) and from
  other sites harmless.
- A request the browser marks cross-site or same-site (``Sec-Fetch-Site``) is
  refused, reads included, unless it opens a page (a top-level navigation,
  e.g. a link in an email). A sandboxed base frame's requests are cross-site.

Paths under ``EXEMPT_PREFIXES`` are not Portal pages: ``/b/`` is the base proxy,
which stamps its own headers (ADR 0004), ``/agent/`` is the agent API,
authenticated by signed proofs rather than cookies, and ``/doorbell/`` is the
Doorbell server's interface, authenticated by its bearer token.
"""

from __future__ import annotations

import re

from starlette.datastructures import Headers, MutableHeaders
from starlette.requests import HTTPConnection
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

ACTION_HEADER = "X-Portal-Action"

EXEMPT_PREFIXES = ("/b/", "/agent/", "/doorbell/")

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

_CSP = {
    "default-src": "'none'",
    "script-src": "'self'",
    "style-src": "'self'",
    "img-src": "'self'",
    "connect-src": "'self'",
    "form-action": "'self'",
    "base-uri": "'none'",
    "frame-ancestors": "'none'",
}


def _policy(extra: dict[str, str]) -> str:
    merged = dict(_CSP)
    for directive, source in extra.items():
        merged[directive] = (
            f"{merged[directive]} {source}" if directive in merged else source
        )
    return "; ".join(f"{k} {v}" for k, v in merged.items())


CONTENT_SECURITY_POLICY = _policy({})

# Cloudflare Turnstile loads its script and an iframe from here. Only the pages
# that show it (sign-up and recovery) allow it.
TURNSTILE_ORIGIN = "https://challenges.cloudflare.com"
TURNSTILE_PAGES = frozenset({"/signup", "/recover"})
TURNSTILE_POLICY = _policy(
    {"script-src": TURNSTILE_ORIGIN, "frame-src": TURNSTILE_ORIGIN}
)

# The Session bar frames the base proxy (``/b/…``, on this origin) and
# nothing else. Its own ``frame-ancestors`` stays ``'none'``. ``blob:`` is for
# a framed page's own downloads: NiceGUI's ``ui.download`` clicks a
# ``target=_blank`` link to a ``blob:`` URL, which Firefox checks against this
# page's ``frame-src``. A ``blob:`` document in the frame is still under the
# iframe's sandbox attribute.
SESSION_BAR_PAGE = re.compile(r"/bases/[^/]+")
SESSION_BAR_POLICY = _policy({"frame-src": "'self' blob:"})

PAGE_HEADERS = {
    "Content-Security-Policy": CONTENT_SECURITY_POLICY,
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "same-origin",
    "Cross-Origin-Opener-Policy": "same-origin",
}


# With plain ``same-origin``, Firefox and WebKit refuse a sandboxed frame's
# ``window.open(url, "_self")``, which is how NiceGUI's ``ui.navigate.to``
# moves a page. ``same-origin-allow-popups`` still cuts a cross-origin opener
# off from the Session bar; the frame can't open popups (no ``allow-popups``).
SESSION_BAR_HEADERS = {
    **PAGE_HEADERS,
    "Content-Security-Policy": SESSION_BAR_POLICY,
    "Cross-Origin-Opener-Policy": "same-origin-allow-popups",
}


def page_headers(path: str) -> dict[str, str]:
    if path in TURNSTILE_PAGES:
        return {**PAGE_HEADERS, "Content-Security-Policy": TURNSTILE_POLICY}
    if SESSION_BAR_PAGE.fullmatch(path):
        return SESSION_BAR_HEADERS
    return PAGE_HEADERS


_CONNECT_STATE = "csp_connect_src"


def allow_connect(request: HTTPConnection, sources: list[str]) -> None:
    """Let this one page also ``fetch`` from ``sources`` (exact URLs). The base
    list uses it for its bases' identity endpoints (Local access, #97)."""
    setattr(request.state, _CONNECT_STATE, list(sources))


def _with_connect(policy: str, sources: list[str]) -> str:
    if not sources:
        return policy
    directives = []
    for directive in policy.split("; "):
        if directive.startswith("connect-src "):
            directive = " ".join([directive, *sources])
        directives.append(directive)
    return "; ".join(directives)


def _from_elsewhere(headers: Headers) -> bool:
    """Another site, or a sandboxed base frame (an opaque origin, so
    "cross-site" even on this host), asking for anything but a page to open:
    a fetch, a subresource, or a frame's own navigation. Browsers without
    Fetch Metadata (and agents, curl) send no ``Sec-Fetch-Site``."""
    if headers.get("sec-fetch-site") not in ("cross-site", "same-site"):
        return False
    opens_a_page = (
        headers.get("sec-fetch-mode") == "navigate"
        and headers.get("sec-fetch-dest") == "document"
    )
    return not opens_a_page


def refusal(origin: str, headers: Headers, method: str) -> str | None:
    """Why a request must be refused, or None if it may proceed."""
    if _from_elsewhere(headers):
        # Even a read: WebKit sends the SameSite=Lax cookie with a sandboxed
        # frame's requests to this host, so the cookie can't vouch for them.
        return "cross-site request"
    if method in SAFE_METHODS:
        return None
    if headers.get(ACTION_HEADER) != "1":
        return "missing action header"
    content_type = headers.get("content-type", "").split(";")[0].strip().lower()
    if content_type != "application/json":
        return "body must be JSON"
    if headers.get("origin") != origin:
        return "cross-origin request"
    return None


class PortalSecurityMiddleware:
    def __init__(self, app: ASGIApp, *, origin: str) -> None:
        self.app = app
        self.origin = origin

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope["path"].startswith(EXEMPT_PREFIXES):
            await self.app(scope, receive, send)
            return

        stamped = page_headers(scope["path"])

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                for name, value in stamped.items():
                    headers[name] = value
                extra = scope.get("state", {}).get(_CONNECT_STATE)
                if extra:
                    csp = headers["Content-Security-Policy"]
                    headers["Content-Security-Policy"] = _with_connect(csp, extra)
            await send(message)

        reason = refusal(self.origin, Headers(scope=scope), scope["method"])
        if reason is not None:
            response = JSONResponse({"error": reason}, status_code=403)
            await response(scope, receive, send_with_headers)
            return
        await self.app(scope, receive, send_with_headers)
