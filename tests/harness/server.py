"""Serving an ASGI app over real TCP (uvicorn, on a free 127.0.0.1 port).

httpx's ASGITransport can't carry websockets, so the tunnel, the Session
bar's status channel and the browser tests reach the app this way. The
Portal's lifespan is already running (``running_portal``), so uvicorn
doesn't run it again.
"""

from __future__ import annotations

import asyncio
import socket
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import uvicorn


def free_socket() -> socket.socket:
    """A listening-ready socket on a free 127.0.0.1 port (know the port
    before building the app, e.g. for its public origin)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    return sock


@asynccontextmanager
async def serving(app: Any, sock: socket.socket | None = None) -> AsyncIterator[int]:
    """Serve ``app`` until the block ends; yields the port."""
    sock = sock or free_socket()
    port = int(sock.getsockname()[1])
    server = uvicorn.Server(
        uvicorn.Config(app, lifespan="off", log_level="warning", ws="websockets-sansio")
    )
    server.install_signal_handlers = lambda: None  # type: ignore[method-assign]
    task = asyncio.create_task(server.serve(sockets=[sock]))
    while not server.started:
        if task.done():
            task.result()
        await asyncio.sleep(0.01)
    try:
        yield port
    finally:
        server.should_exit = True
        await task
