"""Claim message shapes: both sides ignore unknown fields."""

from __future__ import annotations

import pytest

from sp_rtk_portal_protocol import (
    PROTOCOL_VERSION,
    VERSION_HEADER,
    Claimed,
    ClaimStart,
    ClaimStarted,
    ClaimToken,
    ErrorReply,
    MessageError,
    version_from_header,
)


def test_the_protocol_version_is_an_integer_starting_at_1():
    assert PROTOCOL_VERSION == 1
    assert VERSION_HEADER == "SP-RTK-Protocol-Version"


def test_a_message_round_trips_through_json():
    started = ClaimStarted(
        device_code="d" * 43,
        user_code="BCDFGHJK",
        verification_uri="https://p/claim",
        verification_uri_complete="https://p/claim?code=BCDFGHJK",
        expires_in=600,
        interval=5,
    )

    assert ClaimStarted.from_json(started.to_json()) == started


def test_unknown_fields_are_ignored():
    msg = Claimed.from_json({"base_id": "abcdefghij", "account": "a@b", "later": 1})

    assert msg == Claimed(base_id="abcdefghij", account="a@b")


def test_optional_fields_take_their_default():
    assert ClaimStart.from_json({}) == ClaimStart(name="", software_version="")


@pytest.mark.parametrize(
    ("cls", "data"),
    [
        (ClaimToken, {}),
        (ClaimToken, {"device_code": 7}),
        (ClaimStarted, {"device_code": "x"}),
        (ClaimToken, ["device_code"]),
        (
            ClaimStarted,
            {
                "device_code": "x",
                "user_code": "y",
                "verification_uri": "u",
                "verification_uri_complete": "u",
                "expires_in": True,
                "interval": 5,
            },
        ),
    ],
)
def test_a_missing_or_mistyped_field_is_an_error(cls, data):
    with pytest.raises(MessageError):
        cls.from_json(data)


def test_an_error_reply_carries_an_rfc_8628_code():
    reply = ErrorReply.from_json({"error": "authorization_pending"})

    assert reply.error == ErrorReply.AUTHORIZATION_PENDING
    assert reply.error_description == ""


@pytest.mark.parametrize(
    ("value", "expected"),
    [("1", 1), (" 2 ", 2), (None, None), ("x", None), ("-1", None)],
)
def test_the_version_header_parses_to_an_integer(value, expected):
    assert version_from_header(value) == expected
