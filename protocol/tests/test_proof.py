"""Request proofs: what the agent signs and what the Portal accepts."""

from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone

import pytest

from sp_rtk_portal_protocol import (
    BaseKey,
    ProofError,
    ReplayCache,
    jwk_thumbprint,
    proof_from_authorization,
    verify_proof,
)

NOW = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
URL = "https://sp-rtk-base.big-spray.com/agent/claims"


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _parts(proof: str) -> tuple[dict, dict, str]:
    header, payload, sig = proof.split(".")
    return json.loads(_unb64(header)), json.loads(_unb64(payload)), sig


def test_thumbprint_matches_rfc_8037_example():
    # RFC 8037 appendix A.3.
    jwk = {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
    }
    assert jwk_thumbprint(jwk) == "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"


def test_a_proof_verifies_and_names_the_key():
    key = BaseKey.generate()

    proof = verify_proof(
        key.proof("POST", URL, now=NOW), method="POST", url=URL, now=NOW
    )

    assert proof.thumbprint == key.thumbprint
    assert proof.jwk == key.public_jwk
    assert proof.issued_at == NOW


def test_the_proof_is_a_dpop_style_jws():
    key = BaseKey.generate()

    header, payload, _ = _parts(key.proof("POST", URL, now=NOW))

    assert header == {"typ": "dpop+jwt", "alg": "EdDSA", "jwk": key.public_jwk}
    assert payload["htm"] == "POST"
    assert payload["htu"] == URL
    assert payload["iat"] == int(NOW.timestamp())
    assert len(payload["jti"]) >= 16


def test_the_key_survives_pem_round_trip():
    key = BaseKey.generate()

    again = BaseKey.from_pem(key.to_pem())

    assert again.thumbprint == key.thumbprint
    assert b"PRIVATE KEY" in key.to_pem()


def test_query_and_fragment_are_not_part_of_the_url():
    key = BaseKey.generate()
    proof = key.proof("GET", URL + "?a=1#x", now=NOW)

    assert verify_proof(proof, method="GET", url=URL, now=NOW).thumbprint


@pytest.mark.parametrize(
    ("method", "url"),
    [
        ("GET", URL),
        ("POST", URL + "/token"),
        ("POST", "https://evil.example/agent/claims"),
    ],
)
def test_a_proof_for_another_request_is_refused(method, url):
    proof = BaseKey.generate().proof("POST", URL, now=NOW)

    with pytest.raises(ProofError):
        verify_proof(proof, method=method, url=url, now=NOW)


def test_a_bad_signature_is_refused():
    proof = BaseKey.generate().proof("POST", URL, now=NOW)
    header, payload, sig = proof.split(".")
    flipped = _b64(bytes([_unb64(sig)[0] ^ 1]) + _unb64(sig)[1:])

    with pytest.raises(ProofError, match="signature"):
        verify_proof(f"{header}.{payload}.{flipped}", method="POST", url=URL, now=NOW)


def test_a_proof_signed_by_another_key_than_it_names_is_refused():
    key, other = BaseKey.generate(), BaseKey.generate()
    _, payload, sig = key.proof("POST", URL, now=NOW).split(".")
    header = _b64(
        json.dumps(
            {"typ": "dpop+jwt", "alg": "EdDSA", "jwk": other.public_jwk}
        ).encode()
    )

    with pytest.raises(ProofError, match="signature"):
        verify_proof(f"{header}.{payload}.{sig}", method="POST", url=URL, now=NOW)


@pytest.mark.parametrize("skew", [timedelta(seconds=61), timedelta(seconds=-61)])
def test_a_stale_or_future_proof_is_refused(skew):
    proof = BaseKey.generate().proof("POST", URL, now=NOW - skew)

    with pytest.raises(ProofError, match="time"):
        verify_proof(proof, method="POST", url=URL, now=NOW)


def test_a_proof_within_a_minute_is_accepted():
    proof = BaseKey.generate().proof("POST", URL, now=NOW - timedelta(seconds=59))

    assert verify_proof(proof, method="POST", url=URL, now=NOW)


@pytest.mark.parametrize(
    "garbage",
    ["", "a.b", "a.b.c", "....", "eyJ9.eyJ9.AA"],
)
def test_garbage_is_refused(garbage):
    with pytest.raises(ProofError):
        verify_proof(garbage, method="POST", url=URL, now=NOW)


def test_another_algorithm_is_refused():
    key = BaseKey.generate()
    _, payload, sig = key.proof("POST", URL, now=NOW).split(".")
    header = _b64(
        json.dumps({"typ": "dpop+jwt", "alg": "none", "jwk": key.public_jwk}).encode()
    )

    with pytest.raises(ProofError):
        verify_proof(f"{header}.{payload}.{sig}", method="POST", url=URL, now=NOW)


def test_the_body_is_bound_to_the_proof():
    key = BaseKey.generate()
    proof = key.proof("POST", URL, now=NOW, body=b'{"device_code": "a"}')

    assert verify_proof(
        proof, method="POST", url=URL, now=NOW, body=b'{"device_code": "a"}'
    )
    with pytest.raises(ProofError, match="body"):
        verify_proof(
            proof, method="POST", url=URL, now=NOW, body=b'{"device_code": "b"}'
        )


def test_a_body_without_a_body_hash_is_refused():
    proof = BaseKey.generate().proof("POST", URL, now=NOW)

    with pytest.raises(ProofError, match="body"):
        verify_proof(proof, method="POST", url=URL, now=NOW, body=b"{}")


def test_the_replay_cache_refuses_a_proof_seen_before():
    cache = ReplayCache()
    proof = verify_proof(
        BaseKey.generate().proof("POST", URL, now=NOW), method="POST", url=URL, now=NOW
    )

    cache.remember(proof, now=NOW)
    with pytest.raises(ProofError, match="replayed"):
        cache.remember(proof, now=NOW + timedelta(seconds=30))


def test_the_replay_cache_forgets_once_a_proof_is_stale_anyway():
    cache = ReplayCache()
    key = BaseKey.generate()
    old = verify_proof(key.proof("POST", URL, now=NOW), method="POST", url=URL, now=NOW)
    cache.remember(old, now=NOW)

    later = NOW + timedelta(minutes=5)
    cache.remember(
        verify_proof(
            key.proof("POST", URL, now=later), method="POST", url=URL, now=later
        ),
        now=later,
    )

    assert len(cache) == 1


def test_authorization_header_carries_the_proof():
    key = BaseKey.generate()
    header = key.authorization("POST", URL, now=NOW)

    assert header.startswith("Signature ")
    assert verify_proof(
        proof_from_authorization(header), method="POST", url=URL, now=NOW
    )


@pytest.mark.parametrize("header", [None, "", "Bearer abc", "Signature"])
def test_a_missing_or_other_authorization_is_refused(header):
    with pytest.raises(ProofError):
        proof_from_authorization(header)
