"""The tunnel: many byte streams multiplexed over one websocket.

A Woken agent opens ``wss://<Portal host>/agent/tunnel`` (a GET signed with
its base key, echoing the Wake nonce in the proof's ``nonce`` claim). Inside,
every binary websocket message is one frame (SniTun-style):

====  ========  =========  ==============================================
byte  1         4          rest
====  ========  =========  ==============================================
      type      stream id  payload
            (big-endian)
====  ========  =========  ==============================================

Types (:class:`Kind`):

- ``NEW`` (1): the Portal opens stream ``id``. **No payload, ever**: there
  is no address, host, port or URL to carry. The agent connects every
  stream to the base's own UI (``127.0.0.1:8080``) and nowhere else.
- ``DATA`` (2): 1..:data:`MAX_DATA` bytes for stream ``id``.
- ``CLOSE`` (3): stream ``id`` is finished, both ways. No payload.
- ``PING`` (4) / ``PONG`` (5): stream 0, up to :data:`MAX_PING` bytes; a
  ``PING`` is answered with a ``PONG`` carrying the same payload.
- ``PAUSE`` (6) / ``RESUME`` (7): flow control for stream ``id``: stop
  (resume) sending ``DATA`` on it. No payload.

Anything else (an unknown type, a payload where none belongs, stream 0 for
a stream frame, a ``NEW`` from the agent, a second ``NEW`` for a live
stream) is a :class:`FrameError`: the receiver closes the whole tunnel.

Only the Portal opens streams; the agent only accepts them. Each stream
carries one HTTP request (or one websocket) to the base.

:class:`Tunnel` is one end, independent of the websocket library: give it a
``send`` coroutine for outgoing frames and :meth:`Tunnel.feed` it every
incoming one.
"""

from __future__ import annotations

import asyncio
import contextlib
import enum
import logging
import struct
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Literal

logger = logging.getLogger(__name__)

MAX_DATA = 64 * 1024
"""The largest ``DATA`` payload."""
MAX_PING = 125
DEFAULT_WINDOW = 256 * 1024
"""Bytes a stream buffers unread before its reader asks for a ``PAUSE``."""

_HEADER = struct.Struct("!BI")


class FrameError(Exception):
    """A frame that must close the tunnel. The message says why (for logs)."""


class StreamClosed(Exception):
    """Writing to a stream that is closed (or whose tunnel is)."""


class TunnelClosed(Exception):
    """Opening a stream on a tunnel that is closed."""


class Kind(enum.IntEnum):
    NEW = 1
    DATA = 2
    CLOSE = 3
    PING = 4
    PONG = 5
    PAUSE = 6
    RESUME = 7


_NO_PAYLOAD = frozenset({Kind.NEW, Kind.CLOSE, Kind.PAUSE, Kind.RESUME})
_CONNECTION = frozenset({Kind.PING, Kind.PONG})


@dataclass(frozen=True)
class Frame:
    kind: Kind
    stream: int
    payload: bytes = b""


def _check(frame: Frame) -> None:
    if frame.kind in _CONNECTION:
        if frame.stream != 0:
            raise FrameError(f"{frame.kind.name} on stream {frame.stream}")
        if len(frame.payload) > MAX_PING:
            raise FrameError(f"{frame.kind.name} payload too long")
        return
    if frame.stream == 0:
        raise FrameError(f"{frame.kind.name} on stream 0")
    if frame.kind in _NO_PAYLOAD and frame.payload:
        raise FrameError(
            f"{frame.kind.name} frame carries {len(frame.payload)} bytes; "
            "it has no fields (a stream never names a destination)"
        )
    if frame.kind == Kind.DATA and not 0 < len(frame.payload) <= MAX_DATA:
        raise FrameError(f"DATA frame of {len(frame.payload)} bytes")


def encode(frame: Frame) -> bytes:
    _check(frame)
    return _HEADER.pack(frame.kind, frame.stream) + frame.payload


def decode(data: bytes) -> Frame:
    """One websocket message as a frame. Raises :class:`FrameError`."""
    if len(data) < _HEADER.size:
        raise FrameError(f"frame of {len(data)} bytes is shorter than its header")
    kind_value, stream = _HEADER.unpack_from(data)
    try:
        kind = Kind(kind_value)
    except ValueError:
        raise FrameError(f"unknown frame type {kind_value}") from None
    frame = Frame(kind, stream, bytes(data[_HEADER.size :]))
    _check(frame)
    return frame


def signed_url(ws_url: str) -> str:
    """The URL a tunnel open's proof is made for (its ``htu``): the
    websocket URL with ``wss``/``ws`` read as ``https``/``http``, since the
    opening handshake is an HTTP GET for that resource (RFC 6455 §4.1)."""
    for ws, http in (("wss://", "https://"), ("ws://", "http://")):
        if ws_url.startswith(ws):
            return http + ws_url[len(ws) :]
    return ws_url


Send = Callable[[bytes], Awaitable[None]]


class Stream:
    """One byte stream inside a tunnel. Made by :meth:`Tunnel.open_stream`
    (Portal) or handed to ``on_new_stream`` (agent)."""

    def __init__(self, tunnel: Tunnel, stream_id: int) -> None:
        self.id = stream_id
        self._tunnel = tunnel
        self._buffer = bytearray()
        self._readable = asyncio.Event()
        self._may_send = asyncio.Event()
        self._may_send.set()
        self._paused_peer = False
        self.closed = False
        """Closed by either side, or with its tunnel: reads drain what's
        buffered, then return ``b""``."""

    async def read(self, n: int = -1) -> bytes:
        """Up to ``n`` bytes (any amount if ``n`` < 0); ``b""`` at the end."""
        while not self._buffer and not self.closed:
            self._readable.clear()
            await self._readable.wait()
        if not self._buffer:
            return b""
        size = len(self._buffer) if n < 0 else min(n, len(self._buffer))
        data = bytes(self._buffer[:size])
        del self._buffer[:size]
        if self._paused_peer and len(self._buffer) <= self._tunnel.window // 2:
            self._paused_peer = False
            await self._tunnel._send_frame(Frame(Kind.RESUME, self.id))
        return data

    async def write(self, data: bytes) -> None:
        """Send ``data``, waiting while the other end has paused the stream.
        Raises :class:`StreamClosed`."""
        view = memoryview(data)
        while view:
            await self._may_send.wait()
            if self.closed:
                raise StreamClosed(f"stream {self.id} is closed")
            chunk, view = view[: self._tunnel.chunk], view[self._tunnel.chunk :]
            await self._tunnel._send_frame(Frame(Kind.DATA, self.id, bytes(chunk)))

    async def close(self) -> None:
        """End the stream both ways (sends ``CLOSE`` once)."""
        if self.closed:
            return
        self._ended()
        self._tunnel._forget(self)
        with contextlib.suppress(TunnelClosed):
            await self._tunnel._send_frame(Frame(Kind.CLOSE, self.id))

    def _ended(self) -> None:
        self.closed = True
        self._readable.set()
        self._may_send.set()  # wake a paused writer so it sees the close

    async def _received(self, payload: bytes) -> None:
        self._buffer += payload
        self._readable.set()
        if len(self._buffer) > self._tunnel.window and not self._paused_peer:
            self._paused_peer = True
            await self._tunnel._send_frame(Frame(Kind.PAUSE, self.id))
        if len(self._buffer) > 4 * self._tunnel.window + MAX_DATA:
            logger.warning("stream %s ignored PAUSE; closing it", self.id)
            await self.close()


class Tunnel:
    """One end of a tunnel.

    ``role="portal"`` opens streams (:meth:`open_stream`); ``role="agent"``
    accepts them, calling ``on_new_stream(stream)`` in a task of its own for
    each. :meth:`feed` raises :class:`FrameError` for a frame that must close
    the tunnel; the caller then closes the websocket and calls
    :meth:`close`.
    """

    def __init__(
        self,
        send: Send,
        *,
        role: Literal["portal", "agent"],
        on_new_stream: Callable[[Stream], Awaitable[None]] | None = None,
        window: int = DEFAULT_WINDOW,
    ) -> None:
        self._send = send
        self.role = role
        self._on_new_stream = on_new_stream
        self.window = window
        self.chunk = min(MAX_DATA, max(1, window // 4))
        self._streams: dict[int, Stream] = {}
        self._next_id = 1
        self._send_lock = asyncio.Lock()
        self._tasks: set[asyncio.Task[None]] = set()
        self.closed = False

    @property
    def streams(self) -> int:
        """Streams open now."""
        return len(self._streams)

    async def open_stream(self) -> Stream:
        if self.role != "portal":
            raise RuntimeError("only the Portal opens streams")
        if self.closed:
            raise TunnelClosed("the tunnel is closed")
        stream = Stream(self, self._next_id)
        self._next_id += 1
        self._streams[stream.id] = stream
        await self._send_frame(Frame(Kind.NEW, stream.id))
        return stream

    async def ping(self, payload: bytes = b"") -> None:
        await self._send_frame(Frame(Kind.PING, 0, payload))

    async def feed(self, data: bytes) -> None:
        """Handle one incoming websocket message."""
        frame = decode(data)
        if frame.kind == Kind.PING:
            await self._send_frame(Frame(Kind.PONG, 0, frame.payload))
            return
        if frame.kind == Kind.PONG:
            return
        if frame.kind == Kind.NEW:
            self._accept(frame.stream)
            return
        stream = self._streams.get(frame.stream)
        if stream is None:
            return  # a stream closed here while this was in flight
        if frame.kind == Kind.DATA:
            await stream._received(frame.payload)
        elif frame.kind == Kind.CLOSE:
            stream._ended()
            self._forget(stream)
        elif frame.kind == Kind.PAUSE:
            stream._may_send.clear()
        else:  # RESUME
            stream._may_send.set()

    def _accept(self, stream_id: int) -> None:
        if self.role != "agent" or self._on_new_stream is None:
            raise FrameError("the agent may not open streams")
        if stream_id in self._streams:
            raise FrameError(f"stream {stream_id} is already open")
        stream = Stream(self, stream_id)
        self._streams[stream_id] = stream
        task = asyncio.ensure_future(self._serve(stream))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _serve(self, stream: Stream) -> None:
        assert self._on_new_stream is not None
        try:
            await self._on_new_stream(stream)
        except Exception:
            logger.exception("stream %s failed", stream.id)
        finally:
            await stream.close()

    def _forget(self, stream: Stream) -> None:
        if self._streams.get(stream.id) is stream:
            del self._streams[stream.id]

    async def _send_frame(self, frame: Frame) -> None:
        if self.closed:
            raise TunnelClosed("the tunnel is closed")
        data = encode(frame)
        async with self._send_lock:
            await self._send(data)

    def close(self) -> None:
        """The websocket is gone: end every stream and stop their tasks."""
        self.closed = True
        for stream in list(self._streams.values()):
            stream._ended()
        self._streams.clear()
        for task in list(self._tasks):
            task.cancel()
