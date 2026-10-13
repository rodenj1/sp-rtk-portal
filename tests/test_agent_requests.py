"""Every agent request must carry a fresh, valid proof and the protocol version.

Uses the Claim start as the request under test: it's the first one an agent
makes, and a refused one must leave nothing behind.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from datetime import timedelta

import pytest
from sp_rtk_portal_protocol import VERSION_HEADER

from .harness.portal import Portal
from .harness.signer import SigningAgent, signing_agent

BODY = {"name": "pi", "software_version": "0.11.0"}


@pytest.fixture
async def agent(portal: Portal) -> AsyncIterator[SigningAgent]:
    async with signing_agent(portal) as a:
        yield a


async def _no_pairing(portal: Portal) -> bool:
    return await portal.query("SELECT * FROM pairing") == []


def _refused(resp) -> bool:
    return resp.status_code == 401 and resp.json()["error"] == "invalid_proof"


async def test_a_request_without_a_proof_is_refused(
    portal: Portal, agent: SigningAgent
):
    resp = await agent.http.post(
        "/agent/claims", json=BODY, headers={VERSION_HEADER: "1"}
    )

    assert _refused(resp)
    assert await _no_pairing(portal)


async def test_a_bad_signature_is_refused(portal: Portal, agent: SigningAgent):
    raw = json.dumps(BODY).encode()
    headers = agent.headers("/agent/claims", raw)
    proof = headers["Authorization"]
    headers["Authorization"] = proof[:-4] + ("AAAA" if proof[-4:] != "AAAA" else "BBBB")

    resp = await agent.http.post("/agent/claims", content=raw, headers=headers)

    assert _refused(resp)
    assert await _no_pairing(portal)


async def test_a_replayed_request_is_refused(portal: Portal, agent: SigningAgent):
    raw = json.dumps(BODY).encode()
    headers = agent.headers("/agent/claims", raw)
    first = await agent.http.post("/agent/claims", content=raw, headers=headers)

    again = await agent.http.post("/agent/claims", content=raw, headers=headers)

    assert first.status_code == 200
    assert _refused(again)
    assert len(await portal.query("SELECT * FROM pairing")) == 1


@pytest.mark.parametrize("age", [timedelta(seconds=61), timedelta(seconds=-61)])
async def test_a_stale_timestamp_is_refused(portal: Portal, agent: SigningAgent, age):
    resp = await agent.post("/agent/claims", BODY, at=portal.clock.now() - age)

    assert _refused(resp)
    assert await _no_pairing(portal)


async def test_a_proof_for_another_path_is_refused(portal: Portal, agent: SigningAgent):
    raw = json.dumps(BODY).encode()
    headers = agent.headers("/agent/claims/token", raw)

    resp = await agent.http.post("/agent/claims", content=raw, headers=headers)

    assert _refused(resp)


async def test_a_proof_for_another_body_is_refused(portal: Portal, agent: SigningAgent):
    headers = agent.headers("/agent/claims", b'{"name": "other"}')

    resp = await agent.http.post(
        "/agent/claims", content=json.dumps(BODY).encode(), headers=headers
    )

    assert _refused(resp)
    assert await _no_pairing(portal)


@pytest.mark.parametrize("version", [None, "", "one"])
async def test_a_request_without_a_protocol_version_is_refused(
    portal: Portal, agent: SigningAgent, version
):
    raw = json.dumps(BODY).encode()
    headers = agent.headers("/agent/claims", raw)
    if version is None:
        del headers[VERSION_HEADER]
    else:
        headers[VERSION_HEADER] = version

    resp = await agent.http.post("/agent/claims", content=raw, headers=headers)

    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_request"
    assert await _no_pairing(portal)


async def test_a_body_that_is_not_the_message_is_refused(
    portal: Portal, agent: SigningAgent
):
    resp = await agent.post("/agent/claims", {"name": 7})

    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_request"


async def test_unknown_fields_are_ignored(agent: SigningAgent):
    resp = await agent.post("/agent/claims", BODY | {"from_the_future": True})

    assert resp.status_code == 200


async def test_agent_requests_skip_the_browser_request_guard(agent: SigningAgent):
    """No X-Portal-Action or Origin: the proof is what protects /agent/."""
    resp = await agent.post("/agent/claims", BODY)

    assert resp.status_code == 200
    assert "frame-ancestors" not in resp.headers.get("content-security-policy", "")
