"""Poll and Check-in shapes: nested messages, lists and optional fields."""

from __future__ import annotations

import pytest

from sp_rtk_portal_protocol import (
    AgentConfig,
    CheckIn,
    CheckInReply,
    LanAddress,
    LiveSession,
    MessageError,
    Notice,
    Poll,
    PollReply,
    UpgradeRequired,
)


def test_a_poll_reply_round_trips_with_its_config_and_notices():
    reply = PollReply(
        config=AgentConfig(
            revision=3,
            poll_interval=20,
            metered_poll_interval=60,
            check_in_interval=300,
            doorbell_host="bell.example.com",
            doorbell_port=4500,
            tunnel_url="wss://sp-rtk-base.big-spray.com/agent/tunnel",
            tunnel_idle_timeout=120,
            tunnel_hard_cap=3600,
        ),
        metered=True,
        notices=[Notice(text="Protocol 1 is retired on 2027-06-01.")],
    )

    assert PollReply.from_json(reply.to_json()) == reply


def test_a_check_in_round_trips_with_its_lan_addresses():
    check_in = CheckIn(
        software_version="0.11.0",
        doorbell="off",
        lan_addresses=[
            LanAddress(address="192.168.1.20", interface="eth0", primary=True),
            LanAddress(address="10.0.0.5", interface="wlan0", primary=False),
        ],
    )

    assert CheckIn.from_json(check_in.to_json()) == check_in


def test_the_config_block_takes_built_in_defaults_for_what_it_lacks():
    config = AgentConfig.from_json({"revision": 1})

    assert config.poll_interval == 20
    assert config.metered_poll_interval == 60
    assert config.check_in_interval == 300
    assert config.doorbell_host is None
    assert config.doorbell_port is None
    assert config.tunnel_url == ""  # the agent's built-in tunnel URL
    assert config.tunnel_idle_timeout == 120
    assert config.tunnel_hard_cap == 3600


def test_unknown_fields_are_ignored_at_every_level():
    reply = CheckInReply.from_json(
        {
            "config": {"revision": 2, "later": True},
            "notices": [{"text": "hi", "later": 1}],
            "later": [],
        }
    )

    assert reply == CheckInReply(
        config=AgentConfig(revision=2), metered=False, notices=[Notice(text="hi")]
    )


def test_a_poll_says_whether_remote_access_is_paused():
    assert Poll.from_json({}) == Poll(state="connected")
    assert Poll(state="paused").to_json() == {"state": "paused"}


@pytest.mark.parametrize(
    ("cls", "data"),
    [
        (PollReply, {}),
        (PollReply, {"config": "x"}),
        (PollReply, {"config": {"revision": 1}, "notices": "x"}),
        (PollReply, {"config": {"revision": 1}, "notices": [1]}),
        (PollReply, {"config": {"revision": 1}, "metered": 1}),
        (AgentConfig, {"revision": 1, "doorbell_port": "4500"}),
        (AgentConfig, {"revision": True}),
        (CheckIn, {"lan_addresses": [{"interface": "eth0"}]}),
    ],
)
def test_a_mistyped_field_is_refused(cls, data):
    with pytest.raises(MessageError):
        cls.from_json(data)


def test_an_optional_field_may_be_null():
    config = AgentConfig.from_json({"revision": 1, "doorbell_host": None})

    assert config.doorbell_host is None


def test_upgrade_required_names_the_minimum_version():
    body = UpgradeRequired(min_version=2, message="Upgrade sp-rtk-base.").to_json()

    assert body == {
        "error": "upgrade_required",
        "min_version": 2,
        "message": "Upgrade sp-rtk-base.",
    }
    assert UpgradeRequired.from_json(body).min_version == 2


def test_a_poll_reply_carries_a_wake_nonce_only_when_there_is_one():
    plain = PollReply(config=AgentConfig(revision=1))
    woken = PollReply(config=AgentConfig(revision=1), wake="n0nce")

    assert plain.wake is None
    assert PollReply.from_json(plain.to_json()).wake is None
    assert PollReply.from_json(woken.to_json()).wake == "n0nce"
    # An older Portal's reply has no wake field at all.
    assert PollReply.from_json({"config": {"revision": 1}}).wake is None


def test_a_poll_reply_carries_the_live_remote_sessions():
    reply = PollReply(
        config=AgentConfig(revision=1),
        sessions=[
            LiveSession(who="op@example.com", since="2026-01-01T12:00:00+00:00"),
            LiveSession(
                who="sam@example.com", since="2026-01-01T12:05:00+00:00", shared=True
            ),
        ],
    )

    assert PollReply.from_json(reply.to_json()) == reply


def test_an_older_portals_poll_reply_has_no_sessions():
    assert PollReply.from_json({"config": {"revision": 1}}).sessions == []


def test_a_check_in_says_whether_remote_access_is_paused():
    paused = CheckIn(software_version="0.11.0", paused=True)

    assert CheckIn.from_json(paused.to_json()) == paused
    # An agent from before the field existed says nothing either way.
    assert CheckIn.from_json({"software_version": "0.11.0"}).paused is None
