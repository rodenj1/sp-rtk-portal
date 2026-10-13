"""Tunnel framing and multiplexing: what the Portal and the agent exchange
inside the tunnel's websocket.

Two ``Tunnel`` ends are wired back to back in memory, as the websocket
would carry them: each binary message is one frame.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable

import pytest

from sp_rtk_portal_protocol import tunnel
from sp_rtk_portal_protocol.tunnel import Frame, FrameError, Kind, Stream, Tunnel

# --- Framing ---------------------------------------------------------------


@pytest.mark.parametrize(
    "frame",
    [
        Frame(Kind.NEW, 1),
        Frame(Kind.DATA, 1, b"GET / HTTP/1.1\r\n\r\n"),
        Frame(Kind.CLOSE, 7),
        Frame(Kind.PING, 0, b"t=1"),
        Frame(Kind.PONG, 0, b"t=1"),
        Frame(Kind.PAUSE, 2),
        Frame(Kind.RESUME, 2),
    ],
)
def test_every_frame_kind_round_trips(frame: Frame):
    assert tunnel.decode(tunnel.encode(frame)) == frame


def test_the_layout_is_one_type_byte_then_a_big_endian_stream_id():
    assert tunnel.encode(Frame(Kind.DATA, 258, b"hi")) == b"\x02\x00\x00\x01\x02hi"


@pytest.mark.parametrize(
    ("raw", "why"),
    [
        (
            b"\x01\x00\x00\x00\x01" + b"10.0.0.1:22",
            "new-stream frame with a destination",
        ),
        (b"\x01\x00\x00\x00\x01" + b'{"host":"nas"}', "new-stream frame with a host"),
        (b"\x03\x00\x00\x00\x01x", "close frame with a payload"),
        (b"\x06\x00\x00\x00\x01x", "pause frame with a payload"),
        (b"\x09\x00\x00\x00\x01", "unknown frame type"),
        (b"\x00\x00\x00\x00\x01", "frame type zero"),
        (b"\x02\x00\x00", "short header"),
        (b"", "empty message"),
        (b"\x02\x00\x00\x00\x00data", "stream frame on stream 0"),
        (b"\x01\x00\x00\x00\x00", "new stream 0"),
        (b"\x04\x00\x00\x00\x05", "ping on a stream"),
        (b"\x02\x00\x00\x00\x01", "empty data frame"),
        (b"\x02\x00\x00\x00\x01" + b"x" * (tunnel.MAX_DATA + 1), "oversized data"),
        (b"\x04\x00\x00\x00\x00" + b"x" * 200, "oversized ping"),
    ],
)
def test_a_malformed_or_unknown_frame_is_refused(raw: bytes, why: str):
    with pytest.raises(FrameError):
        tunnel.decode(raw)


def test_encoding_refuses_a_new_stream_frame_with_a_payload():
    with pytest.raises(FrameError):
        tunnel.encode(Frame(Kind.NEW, 1, b"example.com:80"))


# --- Multiplexing ------------------------------------------------------------


class Pair:
    """A Portal end and an agent end, joined in memory."""

    def __init__(self, on_new_stream: Callable[[Stream], object], window: int) -> None:
        self.portal_to_agent: list[bytes] = []
        self.agent_to_portal: list[bytes] = []
        self.agent_error: FrameError | None = None

        async def to_agent(data: bytes) -> None:
            self.portal_to_agent.append(data)
            try:
                await self.agent.feed(data)
            except FrameError as exc:
                self.agent_error = exc

        async def to_portal(data: bytes) -> None:
            self.agent_to_portal.append(data)
            await self.portal.feed(data)

        self.portal = Tunnel(to_agent, role="portal", window=window)
        self.agent = Tunnel(
            to_portal,
            role="agent",
            on_new_stream=on_new_stream,  # type: ignore[arg-type]
            window=window,
        )


async def echo_upper(stream: Stream) -> None:
    while data := await stream.read():
        await stream.write(data.upper())
    await stream.close()


async def test_a_stream_the_portal_opens_reaches_the_agent_and_answers():
    pair = Pair(echo_upper, window=tunnel.DEFAULT_WINDOW)
    stream = await pair.portal.open_stream()

    await stream.write(b"hello")
    assert await stream.read() == b"HELLO"
    await stream.close()

    assert await stream.read() == b""
    assert tunnel.decode(pair.portal_to_agent[0]) == Frame(Kind.NEW, stream.id)


async def test_streams_are_kept_apart_on_one_tunnel():
    pair = Pair(echo_upper, window=tunnel.DEFAULT_WINDOW)
    first = await pair.portal.open_stream()
    second = await pair.portal.open_stream()
    assert first.id != second.id

    await first.write(b"one")
    await second.write(b"two")
    await first.write(b"-more")

    assert await second.read() == b"TWO"
    assert await first.read(3) == b"ONE"
    assert await first.read() == b"-MORE"


async def test_closing_a_stream_from_the_agent_ends_the_portal_s_reads():
    async def say_and_close(stream: Stream) -> None:
        await stream.write(b"bye")
        await stream.close()

    pair = Pair(say_and_close, window=tunnel.DEFAULT_WINDOW)
    stream = await pair.portal.open_stream()

    assert await stream.read() == b"bye"
    assert await stream.read() == b""
    with pytest.raises(tunnel.StreamClosed):
        await stream.write(b"too late")


async def test_a_slow_reader_pauses_the_writer_until_it_catches_up():
    accepted: asyncio.Queue[Stream] = asyncio.Queue()

    async def hold(stream: Stream) -> None:
        await accepted.put(stream)
        await asyncio.Event().wait()  # the stream lives while this runs

    pair = Pair(hold, window=1024)
    stream = await pair.portal.open_stream()
    agent_side = await accepted.get()

    writer = asyncio.ensure_future(stream.write(b"x" * 10_000))
    await asyncio.sleep(0.05)
    assert not writer.done()  # paused: the agent hasn't read anything
    kinds = [tunnel.decode(f).kind for f in pair.agent_to_portal]
    assert Kind.PAUSE in kinds

    received = b""
    while len(received) < 10_000:
        received += await agent_side.read()
    await asyncio.wait_for(writer, 1)
    assert received == b"x" * 10_000
    assert Kind.RESUME in [tunnel.decode(f).kind for f in pair.agent_to_portal]


async def test_the_agent_end_cannot_open_streams_and_the_portal_refuses_its_new_frames():
    pair = Pair(echo_upper, window=tunnel.DEFAULT_WINDOW)

    with pytest.raises(RuntimeError):
        await pair.agent.open_stream()
    with pytest.raises(FrameError):
        await pair.portal.feed(tunnel.encode(Frame(Kind.NEW, 1)))


async def test_a_second_new_frame_for_a_live_stream_is_refused():
    pair = Pair(lambda s: asyncio.sleep(1), window=tunnel.DEFAULT_WINDOW)
    stream = await pair.portal.open_stream()

    with pytest.raises(FrameError):
        await pair.agent.feed(tunnel.encode(Frame(Kind.NEW, stream.id)))


async def test_data_for_an_unknown_stream_is_dropped():
    pair = Pair(echo_upper, window=tunnel.DEFAULT_WINDOW)

    # A stream either side just closed may still have data in flight.
    await pair.agent.feed(tunnel.encode(Frame(Kind.DATA, 99, b"late")))


async def test_a_ping_is_answered_with_a_pong_carrying_its_payload():
    pair = Pair(echo_upper, window=tunnel.DEFAULT_WINDOW)

    await pair.portal.ping(b"42")

    assert tunnel.decode(pair.agent_to_portal[-1]) == Frame(Kind.PONG, 0, b"42")


async def test_closing_the_tunnel_ends_every_stream():
    accepted: asyncio.Queue[Stream] = asyncio.Queue()

    async def hold(stream: Stream) -> None:
        await accepted.put(stream)
        await asyncio.Event().wait()  # the stream lives while this runs

    pair = Pair(hold, window=tunnel.DEFAULT_WINDOW)
    stream = await pair.portal.open_stream()
    agent_side = await accepted.get()

    pair.portal.close()
    pair.agent.close()

    assert await stream.read() == b""
    assert await agent_side.read() == b""
    with pytest.raises(tunnel.TunnelClosed):
        await pair.portal.open_stream()


# --- Opening the tunnel ------------------------------------------------------


@pytest.mark.parametrize(
    ("ws_url", "signed"),
    [
        (
            "wss://sp-rtk-base.big-spray.com/agent/tunnel",
            "https://sp-rtk-base.big-spray.com/agent/tunnel",
        ),
        ("ws://127.0.0.1:8000/agent/tunnel", "http://127.0.0.1:8000/agent/tunnel"),
    ],
)
def test_the_tunnel_open_is_signed_for_the_http_form_of_its_url(ws_url, signed):
    assert tunnel.signed_url(ws_url) == signed
