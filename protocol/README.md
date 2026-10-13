# sp-rtk-portal-protocol

The agent-to-Portal protocol, published from the `sp-rtk-portal` repo so the Portal and sp-rtk-base's Portal agent share one definition: message shapes, request signing and verification, tunnel framing, and the protocol version.

## What's in it

- `PROTOCOL_VERSION` (an integer, starting at 1, independent of either side's release version) and `VERSION_HEADER` (`SP-RTK-Protocol-Version`), sent on every agent request. Additive changes don't bump it: both sides ignore fields they don't know.
- **Request proofs** (`proof.py`). The agent's Ed25519 **base key** (`BaseKey`) signs every request with a DPoP-style JWS (RFC 9449), sent as `Authorization: Signature <proof>`: header `{"typ": "dpop+jwt", "alg": "EdDSA", "jwk": <public key>}`, claims `htm`, `htu` (URL without query), `iat` (seconds), `jti`, `bh` (base64url SHA-256 of the body, when there is one) and optional `nonce`. `verify_proof` checks the signature, the request it was made for, the body and that `iat` is within 60 s; `ReplayCache` refuses a `jti` seen before. The Portal identifies a base by the key's RFC 7638 thumbprint and stores only the public key.
- **Message shapes** (`messages.py`): frozen dataclasses with `to_json()` / `from_json()`. `from_json` ignores unknown fields and raises `MessageError` for a missing or mistyped one.
  - Claim (RFC 8628): `POST /agent/claims` with `ClaimStart` → `ClaimStarted`; `POST /agent/claims/token` with `ClaimToken` → `Claimed`, or HTTP 400 `ErrorReply` (`authorization_pending`, `slow_down`, `expired_token`, `access_denied`, `invalid_grant`). Both requests are signed with the new key, so only the key that started a Claim can collect it.
  - Polls and Check-ins (a Claimed base, signed with its key): `POST /agent/poll` with `Poll(state)` → `PollReply(config, metered, notices)`; `POST /agent/check-in` with `CheckIn(software_version, doorbell, lan_addresses)` → `CheckInReply(config, metered, notices)`. `config` is the revisioned `AgentConfig` block (poll intervals, Check-in interval, Doorbell host and port, tunnel URL, tunnel timeouts; the agent applies it only on a new revision). An unknown key gets 401 `ErrorReply("unclaimed")`.
  - Release (a local Un-claim, signed with the base key): `POST /agent/release` with `Release()` → `Released(base_id)`, or 401 `unclaimed` if the Portal already forgot the key. Best effort: the agent wipes its key either way.
  - An agent below the Portal's minimum protocol version gets HTTP 426 `UpgradeRequired(min_version, message)` on any request.
  - Messages may nest messages, lists of them and optional (`X | None`) fields.
  - A refused proof is HTTP 401 `ErrorReply("invalid_proof")`.
  - A Wake: `PollReply.wake` carries a one-time nonce (and nothing else).
  - `PollReply.sessions`: the base's live Remote sessions (`LiveSession(who, since, shared)`), for its local Portal page. `Poll.state` is `paused` while remote access is paused on site; a paused agent ignores Wakes.
- **Tunnel** (`tunnel.py`). The agent opens `wss://<Portal host>/agent/tunnel` with a GET signed for `https://<Portal host>/agent/tunnel` (`signed_url`) whose proof's `nonce` claim echoes the Wake. Each binary websocket message is one frame: a type byte, a big-endian 4-byte stream id, then the payload. Types: `NEW` (1, no payload ever: a stream never names a destination), `DATA` (2, 1..64 KiB), `CLOSE` (3), `PING`/`PONG` (4/5, stream 0), `PAUSE`/`RESUME` (6/7, flow control). An unknown type, a payload where none belongs, or a `NEW` from the agent raises `FrameError`, and the receiver closes the whole tunnel. `Tunnel` is one end of it (independent of the websocket library: give it a `send` coroutine and `feed` it each message); only the Portal end opens streams (`open_stream()` -> `Stream` with `read`/`write`/`close`).

The package version (`pyproject.toml`) is bumped on every change, so a pinned consumer can tell which shapes it has.

sp-rtk-base depends on it as a Git subdirectory dependency:

```toml
[project]
dependencies = ["sp-rtk-portal-protocol"]

[tool.uv.sources]
sp-rtk-portal-protocol = { git = "https://github.com/rodenj1/sp-rtk-portal", subdirectory = "protocol", rev = "<commit or tag>" }
```

The `rev` is a full commit sha of this repo. Bump it when the agent needs a newer protocol.

For local development against a checkout next to it, use `{ path = "../sp-rtk-portal/protocol", editable = true }` instead.
