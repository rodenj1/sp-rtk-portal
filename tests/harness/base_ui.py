"""A stub playing sp-rtk-base's UI on ``:8080``: an HTTP catch-all and an
echo websocket at ``/ws``, recording every request that reaches it.

The real agent is told this stub's port (its ``app_port``, a test-only
argument: nothing from the Portal can change it), so "every stream reaches
the :8080 stub and nothing else" is checked against what it saw.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import PlainTextResponse
from starlette.routing import Route, WebSocketRoute
from starlette.websockets import WebSocket, WebSocketDisconnect

from .server import serving


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

    async def _page(self, request: Request) -> PlainTextResponse:
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
        return PlainTextResponse(f"base page {request.url.path}")

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
        yield ui
