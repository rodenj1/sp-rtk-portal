"""The base proxy: everything under ``/b/`` (ADR 0004).

It sits in front of the whole app, so nothing else (session renewal, the
Portal's own headers) touches a base response, and nothing outside ``/b/``
ever reaches a base.

Per request or websocket upgrade: the path token must belong to a live
Remote session on that base (checked every time; a revoked token stops
working at once, and open websockets and responses on it are cut); a
document load anywhere but in a frame is refused; the request goes down a
new tunnel stream with the prefix stripped and the Portal's own forwarding
headers. Every answer, refusals included, carries the sandbox CSP,
``frame-ancestors`` limited to the Portal, ``Access-Control-Allow-Origin: *``
and ``Referrer-Policy: no-referrer``. Cookies and ``Authorization`` never
cross in either direction.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING

from sp_rtk_portal_protocol import Stream
from starlette.types import ASGIApp, Receive, Scope, Send

from sp_rtk_portal.proxy import relay, rules
from sp_rtk_portal.tunnel.broker import RemoteSession, TunnelBroker, TunnelDown

if TYPE_CHECKING:
    from sp_rtk_portal.context import PortalContext

log = logging.getLogger(__name__)

ENDED = "This Remote session has ended, or this link is not valid. Open the base again from the Portal."
NOT_IN_FRAME = "Base pages open only inside the Portal's Session bar."
UNREACHABLE = "The base is not connected right now."


def frame_path(session: RemoteSession) -> str:
    """Where the Session bar's frame loads the base: ``/b/<id>/s/<token>/``."""
    return f"{rules.PREFIX}{session.base_id}/s/{session.token}/"


def is_base_path(path: str) -> bool:
    return path == "/b" or path.startswith(rules.PREFIX)


class BaseProxy:
    def __init__(self, app: ASGIApp, *, ctx: PortalContext) -> None:
        self.app = app
        self.ctx = ctx

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket") or not is_base_path(
            scope["path"]
        ):
            await self.app(scope, receive, send)
            return
        if scope["type"] == "http":
            await self._http(scope, receive, send)
        else:
            await self._websocket(scope, receive, send)

    @property
    def _origin(self) -> str:
        return self.ctx.settings.public_origin

    @property
    def _broker(self) -> TunnelBroker:
        return self.ctx.tunnels

    def _session(
        self, scope: Scope
    ) -> tuple[rules.Target | None, RemoteSession | None, tuple[int, str, str | None]]:
        """The target and its live session, or why not: (status, text, location)."""
        raw = scope.get("raw_path") or scope["path"].encode()
        raw = raw.split(b"?", 1)[0]
        try:
            target = rules.target(raw, scope.get("query_string", b""))
        except rules.NeedsSlash as redirect:
            return None, None, (307, "", redirect.location)
        except rules.NotAFrame:
            return None, None, (404, ENDED, None)
        session = self._broker.lookup(target.base_id, target.token)
        if session is None:
            return target, None, (403, ENDED, None)
        return target, session, (200, "", None)

    # --- HTTP ---------------------------------------------------------------

    async def _refuse(
        self, send: Send, status: int, text: str, location: str | None = None
    ) -> None:
        headers = [(b"content-type", b"text/plain; charset=utf-8")]
        if location is not None:
            headers.append((b"location", location.encode("latin-1")))
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": headers + rules.stamp(self._origin),
            }
        )
        await send({"type": "http.response.body", "body": text.encode()})

    async def _http(self, scope: Scope, receive: Receive, send: Send) -> None:
        target, session, (status, text, location) = self._session(scope)
        if session is None or target is None:
            await self._refuse(send, status, text, location)
            return
        if rules.refused_load(scope["headers"]):
            await self._refuse(send, 403, NOT_IN_FRAME)
            return
        self._broker.touch(session)
        try:
            stream = await self._broker.open_stream(session.base_id)
        except TunnelDown:
            await self._refuse(send, 502, UNREACHABLE)
            return
        started = False

        def on_start() -> None:
            nonlocal started
            started = True

        async def proxied() -> None:
            await relay.http(
                stream,
                scope["method"].encode(),
                target,
                scope["headers"],
                receive,
                send,
                self._origin,
                on_start,
            )

        try:
            ended = await self._until_ended(session, stream, proxied())
        except relay.BaseUnreachable as exc:
            log.info("base %s gave no answer: %s", session.base_id, exc)
            await self._refuse(send, 502, UNREACHABLE)
            return
        if ended:
            if started:
                await send({"type": "http.response.body", "body": b""})
            else:
                await self._refuse(send, 403, ENDED)

    # --- Websockets -----------------------------------------------------------

    async def _websocket(self, scope: Scope, receive: Receive, send: Send) -> None:
        connect = await receive()
        if connect["type"] != "websocket.connect":
            return
        refuse = self._ws_refusal(scope, send)
        target, session, (status, text, _) = self._session(scope)
        if session is None or target is None:
            await refuse(403 if status == 307 else status, text or ENDED)
            return
        self._broker.touch(session)
        try:
            stream = await self._broker.open_stream(session.base_id)
        except TunnelDown:
            await refuse(502, UNREACHABLE)
            return

        def on_message() -> None:
            self._broker.touch(session)

        proxied = relay.websocket(
            stream,
            target,
            scope["headers"],
            receive,
            send,
            self._origin,
            on_message,
            refuse,
        )
        try:
            ended = await self._until_ended(session, stream, proxied)
        except relay.BaseUnreachable as exc:
            log.info("base %s refused a websocket: %s", session.base_id, exc)
            await refuse(502, UNREACHABLE)
            return
        if ended:
            with contextlib.suppress(Exception):
                await send({"type": "websocket.close", "code": 1008})

    def _ws_refusal(
        self, scope: Scope, send: Send
    ) -> Callable[[int, str], Awaitable[None]]:
        async def refuse(status: int, text: str) -> None:
            if "websocket.http.response" in scope.get("extensions", {}):
                await send(
                    {
                        "type": "websocket.http.response.start",
                        "status": status,
                        "headers": [
                            (b"content-type", b"text/plain; charset=utf-8"),
                            *rules.stamp(self._origin),
                        ],
                    }
                )
                await send(
                    {"type": "websocket.http.response.body", "body": text.encode()}
                )
            else:
                await send({"type": "websocket.close", "code": 1008})

        return refuse

    # --- Revocation -------------------------------------------------------------

    async def _until_ended(
        self, session: RemoteSession, stream: Stream, proxied: Awaitable[None]
    ) -> bool:
        """Run ``proxied`` unless the session ends first (then cut it short and
        return True). The stream is closed either way."""
        work = asyncio.ensure_future(proxied)
        watch = asyncio.ensure_future(self._ended(session))
        try:
            done, _ = await asyncio.wait(
                {work, watch}, return_when=asyncio.FIRST_COMPLETED
            )
            if work in done:
                work.result()
                return False
            return True
        finally:
            for task in (work, watch):
                task.cancel()
                with contextlib.suppress(BaseException):
                    await task
            with contextlib.suppress(Exception):
                await stream.close()

    async def _ended(self, session: RemoteSession) -> None:
        seen = self._broker.version(session.base_id)
        while not session.ended:
            seen = await self._broker.wait_change(session.base_id, seen)
