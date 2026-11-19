"""A stub playing sp-rtk-base's UI on ``:8080``: an HTTP catch-all and an
echo websocket at ``/ws``, recording every request that reaches it.

A few paths answer like a misbehaving or ordinary base would, for the base
proxy's tests: ``/missing`` is a 404, ``/redirect`` a 302 to its own
``http://localhost:8080/survey``, ``/set-cookie`` sets a cookie,
``/clear-site-data`` asks the browser to wipe the origin's cookies and
storage. With ``answering`` off it takes every HTTP request and answers
none, until turned back on (a base whose UI hangs). Every answer also carries headers the proxy must override (its own CSP,
``X-Frame-Options``, ``Access-Control-Allow-Origin``, ``Referrer-Policy``).

The real agent is told this stub's port (its ``app_port``, a test-only
argument: nothing from the Portal can change it), so "every stream reaches
the :8080 stub and nothing else" is checked against what it saw.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import PlainTextResponse, RedirectResponse, Response
from starlette.routing import Route, WebSocketRoute
from starlette.websockets import WebSocket, WebSocketDisconnect

from .server import serving

BASE_OWN_HEADERS = {
    "Content-Security-Policy": "default-src *",
    "X-Frame-Options": "DENY",
    "Access-Control-Allow-Origin": "https://base.example",
    "Referrer-Policy": "unsafe-url",
}


@dataclass
class Seen:
    method: str
    path: str
    host: str | None
    headers: dict[str, str]
    body: bytes = b""


class BaseUi:
    def __init__(self) -> None:
        self.seen: list[Seen] = []
        self.port = 0
        self._answering = asyncio.Event()
        self._answering.set()
        self.app = Starlette(
            routes=[
                WebSocketRoute("/ws", self._ws),
                Route(
                    "/{path:path}",
                    self._page,
                    methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
                ),
            ]
        )

    @property
    def answering(self) -> bool:
        return self._answering.is_set()

    @answering.setter
    def answering(self, value: bool) -> None:
        """Off: HTTP requests wait unanswered; on again: they get their
        answers."""
        if value:
            self._answering.set()
        else:
            self._answering.clear()

    async def _page(self, request: Request) -> Response:
        body = await request.body()
        self.seen.append(
            Seen(
                request.method,
                request.url.path,
                request.headers.get("host"),
                dict(request.headers),
                body,
            )
        )
        await self._answering.wait()
        path = request.url.path
        response: Response
        if path == "/missing":
            response = PlainTextResponse("no such page", status_code=404)
        elif path == "/redirect":
            response = RedirectResponse("http://localhost:8080/survey", 302)
        else:
            response = PlainTextResponse(f"base page {path}")
        if path == "/set-cookie":
            response.set_cookie("base_cookie", "from-the-base")
        if path == "/clear-site-data":
            response.headers["Clear-Site-Data"] = '"cookies", "storage", "*"'
        response.headers.update(BASE_OWN_HEADERS)
        return response

    async def _ws(self, websocket: WebSocket) -> None:
        self.seen.append(
            Seen(
                "WEBSOCKET",
                websocket.url.path,
                websocket.headers.get("host"),
                dict(websocket.headers),
            )
        )
        await websocket.accept()
        try:
            while True:
                text = await websocket.receive_text()
                await websocket.send_text("echo " + text)
        except WebSocketDisconnect:
            return


@asynccontextmanager
async def base_ui() -> AsyncIterator[BaseUi]:
    ui = BaseUi()
    async with serving(ui.app) as port:
        ui.port = port
        try:
            yield ui
        finally:
            ui.answering = True  # nothing left hanging at shutdown
