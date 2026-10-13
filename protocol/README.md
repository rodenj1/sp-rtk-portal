# sp-rtk-portal-protocol

The agent-to-Portal protocol, published from the `sp-rtk-portal` repo so the Portal and sp-rtk-base's Portal agent share one definition: message shapes, request signing and verification, tunnel framing, and the protocol version.

## What's in it

- `PROTOCOL_VERSION` (an integer, starting at 1, independent of either side's release version) and `VERSION_HEADER` (`SP-RTK-Protocol-Version`), sent on every agent request. Additive changes don't bump it: both sides ignore fields they don't know.
- **Request proofs** (`proof.py`). The agent's Ed25519 **base key** (`BaseKey`) signs every request with a DPoP-style JWS (RFC 9449), sent as `Authorization: Signature <proof>`: header `{"typ": "dpop+jwt", "alg": "EdDSA", "jwk": <public key>}`, claims `htm`, `htu` (URL without query), `iat` (seconds), `jti`, `bh` (base64url SHA-256 of the body, when there is one) and optional `nonce`. `verify_proof` checks the signature, the request it was made for, the body and that `iat` is within 60 s; `ReplayCache` refuses a `jti` seen before. The Portal identifies a base by the key's RFC 7638 thumbprint and stores only the public key.
- **Message shapes** (`messages.py`): frozen dataclasses with `to_json()` / `from_json()`. `from_json` ignores unknown fields and raises `MessageError` for a missing or mistyped one.
  - Claim (RFC 8628): `POST /agent/claims` with `ClaimStart` → `ClaimStarted`; `POST /agent/claims/token` with `ClaimToken` → `Claimed`, or HTTP 400 `ErrorReply` (`authorization_pending`, `slow_down`, `expired_token`, `access_denied`, `invalid_grant`). Both requests are signed with the new key, so only the key that started a Claim can collect it.
  - Polls and Check-ins (a Claimed base, signed with its key): `POST /agent/poll` with `Poll(state)` → `PollReply(config, metered, notices)`; `POST /agent/check-in` with `CheckIn(software_version, doorbell, lan_addresses, paused)` (`paused` from 0.9; `None` from older agents) → `CheckInReply(config, metered, notices)`. `config` is the revisioned `AgentConfig` block (poll intervals, Check-in interval, Doorbell host and port, tunnel URL, tunnel timeouts; the agent applies it only on a new revision). An unknown key gets 401 `ErrorReply("unclaimed")`.
  - Release (a local Un-claim, signed with the base key): `POST /agent/release` with `Release()` → `Released(base_id)`, or 401 `unclaimed` if the Portal already forgot the key. Best effort: the agent wipes its key either way.
  - An agent below the Portal's minimum protocol version gets HTTP 426 `UpgradeRequired(min_version, message)` on any request.
  - Messages may nest messages, lists of them and optional (`X | None`) fields.
  - A refused proof is HTTP 401 `ErrorReply("invalid_proof")`.
  - A Wake: `PollReply.wake` carries a one-time nonce (and nothing else).
  - `PollReply.sessions`: the base's live Remote sessions (`LiveSession(who, since, shared)`), for its local Portal page. `Poll.state` is `paused` while remote access is paused on site; a paused agent ignores Wakes.
- **Doorbell** (`doorbell.py`). UDP packets between a base and a Doorbell server: a keepalive signed by the base key (`keepalive`, `read_keepalive`, `verify_keepalive`; 109 bytes) and a ring carrying a Wake's nonce, authenticated with the base's ring key (`ring`, `open_ring`, `new_ring_key`); both refused more than 60 s from now. `DOORBELL_INTERVAL` (20 s) and `DOORBELL_JITTER` (5 s). `CheckInReply.doorbell_heard` and `.ring_key` tell the agent the Portal hears its keepalives and give it the ring key. The Doorbell server's HTTPS interface on the Portal: `KEEPALIVES_PATH` (`KeepalivesReport` → `KeepalivesReply`) and `RINGS_PATH` (→ `Rings`); see the Portal README.
- **Tunnel** (`tunnel.py`). The agent opens `wss://<Portal host>/agent/tunnel` with a GET signed for `https://<Portal host>/agent/tunnel` (`signed_url`) whose proof's `nonce` claim echoes the Wake. Each binary websocket message is one frame: a type byte, a big-endian 4-byte stream id, then the payload. Types: `NEW` (1, no payload ever: a stream never names a destination), `DATA` (2, 1..64 KiB), `CLOSE` (3), `PING`/`PONG` (4/5, stream 0), `PAUSE`/`RESUME` (6/7, flow control). An unknown type, a payload where none belongs, or a `NEW` from the agent raises `FrameError`, and the receiver closes the whole tunnel. `Tunnel` is one end of it (independent of the websocket library: give it a `send` coroutine and `feed` it each message); only the Portal end opens streams (`open_stream()` -> `Stream` with `read`/`write`/`close`).

The package version (`pyproject.toml`) is bumped on every change, so a pinned consumer can tell which shapes it has.

It is published to PyPI, and sp-rtk-base depends on it from there:

```toml
[project]
dependencies = ["sp-rtk-portal-protocol>=0.9.0,<1"]
```

Raise the lower bound when the agent needs newer shapes. The Portal uses this directory directly, as a uv workspace member.

For local development of both sides at once, point sp-rtk-base at a checkout next to it with `[tool.uv.sources] sp-rtk-portal-protocol = { path = "../sp-rtk-portal/protocol", editable = true }`, and don't commit that.

## Releasing

`.github/workflows/protocol-release.yml` publishes this package to PyPI when a GitHub Release with a `protocol-v<version>` tag is published, the same pipeline as sp-rtk-base's `release.yml`. It refuses a draft or pre-release Release, checks the tag against `version` in this `pyproject.toml`, and refuses a version already on PyPI. Then it runs ruff and pyright, runs these tests on Python 3.10 to 3.13, builds with `uv build` and runs `twine check`. A smoke job installs the wheel with pip into a plain Python 3.10 venv and imports it. The workflow uploads with PyPI Trusted Publishing (OIDC, no token), then signs the files with sigstore and attaches them to the Release.

Portal releases share this repo. The image workflow runs on pushed `v*` tags, and this one skips every Release whose tag isn't `protocol-v*`, so neither triggers the other. The Portal's release stays the repo's **Latest**: never mark a protocol Release as Latest.

Once, before the first release:

1. On pypi.org, under Your account > Publishing > Add a new pending publisher > GitHub, enter:
   - PyPI project name: `sp-rtk-portal-protocol`
   - Owner: `rodenj1`
   - Repository name: `sp-rtk-portal`
   - Workflow name: `protocol-release.yml`
   - Environment name: `pypi`
2. On GitHub, in the sp-rtk-portal repo's Settings > Environments, create an environment named `pypi` (optionally with required reviewers, to approve each upload).

   GitHub offers environments in a private repo only on a paid plan (Pro, Team or Enterprise). If Settings has no Environments page, leave the environment name blank in step 1, and delete the `environment:` block from the workflow's `publish-pypi` job.

Each release:

1. Bump `version` in this `pyproject.toml` on `main` (PyPI never accepts the same version twice).
2. Tag that commit and push the tag:

   ```sh
   git tag protocol-v0.10.0
   git push origin protocol-v0.10.0
   ```

3. Publish a GitHub Release for the tag, not a pre-release and not Latest:

   ```sh
   gh release create protocol-v0.10.0 --verify-tag --latest=false \
     --title "sp-rtk-portal-protocol 0.10.0" --generate-notes
   ```

   In the web form, untick **Set as the latest release**. If a protocol Release ever becomes Latest, mark the newest Portal release as Latest again.
4. Watch the protocol-release run under Actions. Once the version is on PyPI, raise sp-rtk-base's lower bound if the agent needs it, then run `uv lock` there.

**Release order.** Publish an sp-rtk-base release only after every `sp-rtk-portal-protocol` version it requires is on PyPI: a base installs the protocol from PyPI, not from this repo. sp-rtk-base's release workflow enforces this too, because its smoke job pip-installs the wheel with its dependencies from PyPI.

To rerun a failed release before anything reached PyPI, run the workflow by hand (Actions > protocol-release > Run workflow) with the tag.

### A version already on PyPI

The workflow refuses to build or upload a version PyPI already has, and fails early with a pointer to `attach_only`. To give such a version its signed files on GitHub (for example 0.9.0, which went to PyPI before this workflow made Releases):

1. If the Release doesn't exist yet, create it on the existing tag, as in step 3. A Release on a tag whose commit has this workflow starts a run, which fails at the PyPI check and uploads nothing. A tag older than the Release trigger (such as `protocol-v0.9.0`) starts no run.
2. Run the workflow by hand from `main` with the tag and **attach_only** ticked:

   ```sh
   gh workflow run protocol-release.yml --ref main \
     -f tag=protocol-v0.9.0 -f attach_only=true
   ```

   It downloads that version's files from PyPI, checks each sha256 against PyPI's JSON API, smoke-tests the wheel, then signs the files and attaches them to the Release. It builds nothing and uploads nothing to PyPI.
