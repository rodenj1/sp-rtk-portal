"""Release message shapes: a local Un-claim tells the Portal (ticket #93)."""

from __future__ import annotations

from sp_rtk_portal_protocol import RELEASE_PATH, Release, Released


def test_a_release_is_an_empty_signed_post_to_its_own_path():
    assert RELEASE_PATH == "/agent/release"
    assert Release().to_json() == {}
    assert Release.from_json({"anything": "ignored"}) == Release()


def test_released_names_the_base_that_went_away():
    assert Released.from_json({"base_id": "b1x"}) == Released(base_id="b1x")
