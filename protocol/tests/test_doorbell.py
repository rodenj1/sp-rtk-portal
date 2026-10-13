"""Doorbell packets: a keepalive signed by the base key, and a ring
authenticated with the base's ring key."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from sp_rtk_portal_protocol import (
    AgentConfig,
    BaseKey,
    CheckInReply,
    DoorbellError,
    HeardKeepalive,
    KeepalivesReply,
    KeepalivesReport,
    Ring,
    Rings,
    doorbell,
)

NOW = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)


def test_a_keepalive_is_small_and_names_the_base_key():
    key = BaseKey.generate()

    packet = doorbell.keepalive(key, now=NOW)

    assert len(packet) <= 128
    heard = doorbell.verify_keepalive(packet, key.public_jwk, now=NOW)
    assert heard.thumbprint == key.thumbprint
    assert heard.at == NOW
    assert doorbell.read_keepalive(packet).thumbprint == key.thumbprint


def test_a_keepalive_signed_by_another_key_is_refused():
    key, other = BaseKey.generate(), BaseKey.generate()
    packet = doorbell.keepalive(other, now=NOW)

    with pytest.raises(DoorbellError):
        doorbell.verify_keepalive(packet, key.public_jwk, now=NOW)


def test_a_tampered_keepalive_is_refused():
    key = BaseKey.generate()
    packet = bytearray(doorbell.keepalive(key, now=NOW))
    packet[6] ^= 1  # its time

    with pytest.raises(DoorbellError):
        doorbell.verify_keepalive(bytes(packet), key.public_jwk, now=NOW)


def test_a_stale_keepalive_is_refused():
    key = BaseKey.generate()
    packet = doorbell.keepalive(key, now=NOW - timedelta(minutes=2))

    with pytest.raises(DoorbellError):
        doorbell.verify_keepalive(packet, key.public_jwk, now=NOW)


@pytest.mark.parametrize("packet", [b"", b"SPDB", b"x" * 109, b"\x00" * 300])
def test_garbage_is_not_a_keepalive(packet: bytes):
    with pytest.raises(DoorbellError):
        doorbell.read_keepalive(packet)


def test_a_ring_carries_the_nonce_to_the_holder_of_the_ring_key():
    ring_key = doorbell.new_ring_key()

    packet = doorbell.ring(ring_key, "n0nce-from-the-portal", now=NOW)

    assert doorbell.open_ring(ring_key, packet, now=NOW) == "n0nce-from-the-portal"


def test_a_ring_made_with_another_key_is_refused():
    packet = doorbell.ring(doorbell.new_ring_key(), "nonce", now=NOW)

    with pytest.raises(DoorbellError):
        doorbell.open_ring(doorbell.new_ring_key(), packet, now=NOW)


def test_a_stale_or_tampered_ring_is_refused():
    ring_key = doorbell.new_ring_key()
    stale = doorbell.ring(ring_key, "nonce", now=NOW - timedelta(minutes=2))
    tampered = bytearray(doorbell.ring(ring_key, "nonce", now=NOW))
    tampered[-40] ^= 1

    for packet in (stale, bytes(tampered), b"", b"SPDB\x02"):
        with pytest.raises(DoorbellError):
            doorbell.open_ring(ring_key, packet, now=NOW)


def test_a_keepalive_is_not_a_ring():
    key = BaseKey.generate()
    with pytest.raises(DoorbellError):
        doorbell.open_ring(
            doorbell.new_ring_key(), doorbell.keepalive(key, now=NOW), now=NOW
        )


def test_the_doorbell_server_interface_round_trips():
    report = KeepalivesReport(
        keepalives=[HeardKeepalive(packet="abc", address="198.51.100.30", port=40000)]
    )
    rings = Rings(rings=[Ring(address="198.51.100.30", port=40000, packet="xyz")])

    assert KeepalivesReport.from_json(report.to_json()) == report
    assert Rings.from_json(rings.to_json()) == rings
    reply = KeepalivesReply(results=["ok", "unknown"])
    assert KeepalivesReply.from_json(reply.to_json()) == reply


def test_a_check_in_reply_tells_the_agent_its_doorbell_was_heard():
    reply = CheckInReply(
        config=AgentConfig(revision=1), doorbell_heard=True, ring_key="k" * 43
    )

    assert CheckInReply.from_json(reply.to_json()) == reply
    assert CheckInReply.from_json({"config": {"revision": 1}}).ring_key is None
