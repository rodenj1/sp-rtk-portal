"""Security rules for the Portal's own pages and endpoints.

- Every Portal response carries a strict CSP with ``frame-ancestors 'none'``.
- Every state-changing request (anything but GET/HEAD/OPTIONS) must have a JSON
  body, carry ``ACTION_HEADER``, and send an ``Origin`` equal to the Portal's.
  That makes requests from a sandboxed base frame (``Origin: null``) and from
  other sites harmless.

Paths under ``EXEMPT_PREFIXES`` are not Portal pages: ``/b/`` is the base proxy,
which stamps its own headers (ADR 0004), and ``/agent/`` is the agent API,
authenticated by signed proofs rather than cookies.
"""

from __future__ import annotations

from starlette.datastructures import Headers, MutableHeaders
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

ACTION_HEADER = "X-Portal-Action"

EXEMPT_PREFIXES = ("/b/", "/agent/")

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

CONTENT_SECURITY_POLICY = "; ".join(
    [
        "default-src 'none'",
        "script-src 'self'",
        "style-src 'self'",
        "img-src 'self'",
        "connect-src 'self'",
        "form-action 'self'",
        "base-uri 'none'",
        "frame-ancestors 'none'",
    ]
)

PAGE_HEADERS = {
    "Content-Security-Policy": CONTENT_SECURITY_POLICY,
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "same-origin",
    "Cross-Origin-Opener-Policy": "same-origin",
}


def refusal(origin: str, headers: Headers, method: str) -> str | None:
    """Why a request must be refused, or None if it may proceed."""
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

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                for name, value in PAGE_HEADERS.items():
                    headers[name] = value
            await send(message)

        reason = refusal(self.origin, Headers(scope=scope), scope["method"])
        if reason is not None:
            response = JSONResponse({"error": reason}, status_code=403)
            await response(scope, receive, send_with_headers)
            return
        await self.app(scope, receive, send_with_headers)
