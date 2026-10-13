"""Carrying one browser request (or one websocket) down one tunnel stream.

A stream is one raw HTTP/1.1 exchange with the base's UI (see the protocol
package's ``tunnel`` module): h11 frames the request and parses the answer;
for a websocket, wsproto does the handshake and the framing on the stream
while the browser's side stays plain ASGI.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Awaitable, Callable

import h11
from sp_rtk_portal_protocol import Stream, StreamClosed
from starlette.types import Receive, Send
from wsproto import ConnectionType, WSConnection
from wsproto.events import (
    AcceptConnection,
    BytesMessage,
    CloseConnection,
    Message,
    Ping,
    RejectConnection,
    Request,
    TextMessage,
)

from sp_rtk_portal.proxy import rules


class BaseUnreachable(Exception):
    """The base's UI gave no usable answer (closed the stream, garbage)."""


async def http(
    stream: Stream,
    method: bytes,
    target: rules.Target,
    headers: rules.Headers,
    receive: Receive,
    send: Send,
    public_origin: str,
    on_start: Callable[[], None],
) -> None:
    """Relay one HTTP request. Raises :class:`BaseUnreachable` (before
    anything was sent to the browser) when the base gave no answer."""
    conn = h11.Connection(h11.CLIENT)
    framing = [h for h in headers if h[0] in (b"content-length", b"transfer-encoding")]
    forwarded = rules.request_headers(headers, target.prefix, public_origin)
    if any(name == b"content-length" for name, _ in framing):
        forwarded += [h for h in framing if h[0] == b"content-length"]
    elif framing:
        forwarded.append((b"transfer-encoding", b"chunked"))
    has_body = bool(framing)
    try:
        await stream.write(
            conn.send(h11.Request(method=method, target=target.tail, headers=forwarded))
        )
        more = True
        while more:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            body = message.get("body", b"")
            if body and has_body:
                await stream.write(conn.send(h11.Data(data=body)))
            more = message.get("more_body", False)
        await stream.write(conn.send(h11.EndOfMessage()))
    except (StreamClosed, h11.LocalProtocolError) as exc:
        raise BaseUnreachable(str(exc)) from exc

    async def next_event() -> object:
        while True:
            event = conn.next_event()
            if event is not h11.NEED_DATA:
                return event
            conn.receive_data(await stream.read())

    try:
        while True:
            event = await next_event()
            if isinstance(event, h11.Response):
                break
            if not isinstance(event, h11.InformationalResponse):
                raise BaseUnreachable(f"unexpected {event!r}")
    except h11.RemoteProtocolError as exc:
        raise BaseUnreachable(str(exc)) from exc

    on_start()
    await send(
        {
            "type": "http.response.start",
            "status": event.status_code,
            "headers": rules.response_headers(
                event.headers, target.prefix, public_origin
            ),
        }
    )
    try:
        while True:
            event = await next_event()
            if isinstance(event, h11.Data):
                await send(
                    {
                        "type": "http.response.body",
                        "body": event.data,
                        "more_body": True,
                    }
                )
            else:
                break
    except h11.RemoteProtocolError:
        pass  # cut short: end what was sent
    await send({"type": "http.response.body", "body": b""})


async def websocket(
    stream: Stream,
    target: rules.Target,
    headers: rules.Headers,
    receive: Receive,
    send: Send,
    public_origin: str,
    on_message: Callable[[], None],
    refuse: Callable[[int, str], Awaitable[None]],
) -> None:
    """Relay one websocket: the upgrade, then messages both ways until
    either side closes."""
    ws = WSConnection(ConnectionType.CLIENT)
    subprotocols = [
        p.strip()
        for name, value in headers
        if name.lower() == b"sec-websocket-protocol"
        for p in value.decode("latin-1").split(",")
        if p.strip()
    ]
    extra = [
        h
        for h in rules.request_headers(headers, target.prefix, public_origin)
        if h[0] != b"host"
    ]
    try:
        await stream.write(
            ws.send(
                Request(
                    host=rules.BASE_HOST,
                    target=target.tail.decode("latin-1"),
                    subprotocols=subprotocols,
                    extra_headers=extra,
                )
            )
        )
        accepted = None
        while accepted is None:
            data = await stream.read()
            if not data:
                raise BaseUnreachable("closed during the handshake")
            ws.receive_data(data)
            for event in ws.events():
                if isinstance(event, AcceptConnection):
                    accepted = event
                    break
                if isinstance(event, RejectConnection):
                    await refuse(event.status_code, "The base refused the websocket.")
                    return
    except StreamClosed as exc:
        raise BaseUnreachable(str(exc)) from exc

    await send(
        {
            "type": "websocket.accept",
            "subprotocol": accepted.subprotocol,
            "headers": rules.stamp(public_origin),
        }
    )

    async def browser_to_base() -> None:
        while True:
            message = await receive()
            if message["type"] == "websocket.disconnect":
                with contextlib.suppress(Exception):
                    await stream.write(
                        ws.send(CloseConnection(code=message.get("code", 1000)))
                    )
                return
            if message["type"] != "websocket.receive":
                continue
            on_message()
            if message.get("text") is not None:
                await stream.write(ws.send(Message(data=message["text"])))
            elif message.get("bytes") is not None:
                await stream.write(ws.send(Message(data=message["bytes"])))

    async def base_to_browser() -> None:
        text: list[str] = []
        binary: list[bytes] = []
        while True:
            data = await stream.read()
            ws.receive_data(data or None)
            for event in ws.events():
                if isinstance(event, TextMessage):
                    text.append(event.data)
                    if event.message_finished:
                        await send({"type": "websocket.send", "text": "".join(text)})
                        text.clear()
                elif isinstance(event, BytesMessage):
                    binary.append(bytes(event.data))
                    if event.message_finished:
                        await send(
                            {"type": "websocket.send", "bytes": b"".join(binary)}
                        )
                        binary.clear()
                elif isinstance(event, Ping):
                    await stream.write(ws.send(event.response()))
                elif isinstance(event, CloseConnection):
                    with contextlib.suppress(Exception):
                        await stream.write(ws.send(event.response()))
                    await send(
                        {"type": "websocket.close", "code": _sendable(event.code)}
                    )
                    return
            if not data:
                await send({"type": "websocket.close", "code": 1011})
                return

    await first_of(browser_to_base(), base_to_browser())


def _sendable(code: int) -> int:
    """Close codes that only report (1005 none, 1006 abnormal, 1015 TLS)
    can't be sent."""
    return 1011 if code in (1005, 1006, 1015) else code


async def first_of(*coros: Awaitable[None]) -> None:
    """Run until the first finishes (re-raising its error); cancel the rest."""
    tasks = [asyncio.ensure_future(c) for c in coros]
    try:
        done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            if not task.cancelled() and task.exception() is not None:
                raise task.exception()  # type: ignore[misc]
    finally:
        for task in tasks:
            task.cancel()
        for task in tasks:
            with contextlib.suppress(BaseException):
                await task
