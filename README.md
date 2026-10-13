# sp-rtk-portal

Hosted Portal for reaching [sp-rtk-base](https://github.com/rodenj1/sp-rtk-base) base stations remotely: Portal accounts, Claims, Shares, Wake and the on-demand tunnel to a base's own web UI. Also publishes the agent-to-Portal protocol package that sp-rtk-base depends on.

The spec and tickets live in [rodenj1/rtk_development](https://github.com/rodenj1/rtk_development/issues/82), where this repo is a submodule.

## Layout

- `src/sp_rtk_portal/`: the Portal server (FastAPI, server-rendered Jinja2 pages, a little JavaScript).
  - `app.py` builds the app; `main.py` runs it (`sp-rtk-portal`, logs to stdout).
  - `accounts/`: Accounts & login, the headless Authentik backend-for-frontend (ADR 0003) and Portal sessions.
  - `bases/`, `shares/`, `agent_api/`, `tunnel/`, `proxy/`, `audit/`, `ratelimit/`: the spec's internal modules.
  - `web/`: security headers and the state-changing request guard, templates, static files.
  - `db/`: the Postgres pool and plain-SQL migrations (`db/migrations/NNNN_name.sql`, applied at startup).
- `protocol/`: the `sp-rtk-portal-protocol` package that sp-rtk-base's Portal agent depends on. See its README.
- `tests/`: the seam-1 suite. `tests/harness/` holds the fixtures' machinery.
- `protocol/`: the agent-to-Portal protocol package (see its README), a uv workspace member; its tests in `protocol/tests/` run with the suite.

## Running

Configuration is read from the environment:

| Variable | Meaning |
| --- | --- |
| `PORTAL_DATABASE_URL` | Postgres URL |
| `PORTAL_AUTHENTIK_URL` | Authentik base URL, e.g. `https://auth.example.com` |
| `PORTAL_OIDC_CLIENT_ID`, `PORTAL_OIDC_CLIENT_SECRET` | The Portal's OIDC client |
| `PORTAL_PUBLIC_ORIGIN` | Default `https://sp-rtk-base.big-spray.com` |
| `PORTAL_LOGIN_FLOW_SLUG` | Default `portal-login` |
| `PORTAL_ENROLLMENT_FLOW_SLUG`, `PORTAL_RECOVERY_FLOW_SLUG` | Default `portal-enrollment`, `portal-recovery` |
| `PORTAL_TOTP_SETUP_FLOW_SLUG`, `PORTAL_PASSWORD_CHANGE_FLOW_SLUG` | Default `portal-totp-setup`, `portal-password-change` |
| `PORTAL_AUTHENTIK_API_TOKEN` | Service account API token (lists and removes a user's TOTP device) |
| `PORTAL_TURNSTILE_SITE_KEY` | Cloudflare Turnstile site key shown on sign-up and recovery |
| `PORTAL_OIDC_APP_SLUG` | Default `sp-rtk-portal` |
| `PORTAL_MAX_BASES_PER_ACCOUNT` | Claimed bases per account, default 25 |
| `PORTAL_OWNER_EMAILS` | Comma-separated verified emails of the Portal owner(s), who get `/settings` (agent config, notices, latest sp-rtk-base release) |
| `PORTAL_MIN_PROTOCOL_VERSION` | Oldest agent protocol version served, default 1; older agents get 426 and their bases show "needs upgrade". Raise it only after 6 months' notice (a notice on `/settings`) |
| `PORTAL_DOORBELL_TOKEN` | The Doorbell server's bearer token for `/doorbell/*`. Unset (v1, no Doorbell server): those paths answer 404 |
| `PORTAL_HOST`, `PORTAL_PORT`, `PORTAL_LOG_LEVEL` | Default `0.0.0.0`, `8000`, `INFO` |

```sh
uv sync
uv run sp-rtk-portal
```

The OIDC client's redirect URI is `<public origin>/login/callback`. No browser ever visits it: the Portal reads the code off Authentik's redirect itself.

## Polling and the agent config

A Claimed base polls `POST /agent/poll` every 20 s (60 s when its Operator marks it metered in the list) and Checks in at `POST /agent/check-in` every 5 min (versions, Doorbell health, private LAN addresses). It is online until about 3 polls of its current mode are missed. Every reply carries the agent config block, which the Portal owner edits on `/settings`: each save is a new revision, applied by every agent on its next poll. Notices added there show on every base and on its local Portal page. At the default interval polling costs about 0.3 GB a month (`tests/test_polling.py` measures it).

## Wake, the tunnel and Remote sessions

"Open remotely" (`POST /bases/<id>/remote`) starts the user's Remote session on the base (one per user per base, shared by their tabs) and Wakes the base: its next poll reply carries a one-time nonce. The agent then opens `wss://<Portal>/agent/tunnel` with a GET signed by its base key that echoes the nonce; any other open is refused with 403 before the websocket is accepted. Inside, the protocol package's framing multiplexes streams, each to the base's own UI on `127.0.0.1:8080` (a stream can't name a destination). One tunnel per base serves all its Remote sessions.

The Session bar page `/bases/<id>` shows Waking (with the poll-interval hint) and then Connected over a status websocket, `/bases/<id>/session`, on the Portal's own origin. While one is open its user is present. A Remote session ends when nobody has been present for the agent config's idle timeout (2 min), or at its hard cap (60 min); its path token is revoked at once and, when it was the base's last, the tunnel is closed. Remote session start and end are audited. All of this is in-process state (one Portal instance); a restart ends every Remote session.

## The base proxy

Once Connected, the Session bar loads the base's own UI in `<iframe sandbox="allow-scripts allow-forms allow-downloads">` from `/b/<id>/s/<token>/` on the Portal's hostname (ADR 0004). Every request and websocket upgrade there is checked against a live Remote session's token, so a revoked token (session ended, un-Share, Un-claim...) stops working at once, open websockets included. The proxy strips the prefix and sends it as `X-Forwarded-Prefix` (sp-rtk-base builds its URLs from it), sets its own forwarding headers, never forwards cookies or `Authorization` and never returns a `Set-Cookie`, refuses a document load outside a frame (`Sec-Fetch-Dest`) with 403, and stamps `Content-Security-Policy: sandbox ...; frame-ancestors <Portal>`, `Access-Control-Allow-Origin: *` and `Referrer-Policy: no-referrer` on every answer, refusals and errors included. Nothing outside `/b/` reaches a base. The code is in `src/sp_rtk_portal/proxy/`.

## The Doorbell

Polling is all v1 deploys (ADR 0002 records when to add the Doorbell server). The agent already supports a Doorbell, and the Portal already has the HTTPS interface a Doorbell server uses, so adding one is: run the server, set `PORTAL_DOORBELL_TOKEN` on both, and set the Doorbell host and port on `/settings`.

- **On the base.** With a Doorbell host in the agent config that resolves to a public address (checked before every packet; a private, loopback or link-local answer is ignored and logged, and the base stays on polling), the agent sends a keepalive signed by its base key every 20 s ± 5 s, from one UDP socket. That holds a return path open through its router. Once a Check-in reply says the Portal hears the keepalives, the agent stops polling (wake mode Doorbell: the list shows "Doorbell", the local page too) and only Checks in; if the Portal stops hearing them, the next Check-in reply puts it back on polling.
- **Online state.** A relayed, verified keepalive is a sign of life. A base on a Doorbell is offline after 3 missed keepalives (75 s), not 3 missed polls.
- **Rings.** Every Wake also asks for a ring. A ring is a UDP packet carrying only the Wake's one-time nonce, authenticated with the base's ring key (a per-base secret the Portal hands the agent in Check-in replies). The agent then opens its tunnel exactly as for a polled Wake, echoing the nonce in a request signed by its base key, so a forged ring can only cause a refused tunnel attempt. A base that isn't on a Doorbell still gets the Wake in its next poll.

### Doorbell server interface

The Doorbell server holds no keys: it relays packets and the Portal checks them. Both requests carry `Authorization: Bearer <PORTAL_DOORBELL_TOKEN>`; without it (or with another) they get 401. Bodies are the protocol package's `sp_rtk_portal_protocol.doorbell` shapes; packets travel base64url-encoded without padding (`encode_packet`/`decode_packet`).

- `POST /doorbell/keepalives` with `{"keepalives": [{"packet": "<base64url datagram>", "address": "<source IP>", "port": <source port>}, ...]}` (up to 1000) → `{"results": ["ok" | "unknown" | "invalid", ...]}`, one per keepalive in order. `ok`: signed by a Claimed base's key, within 60 s of the Portal's clock and newer than the last one from that base; the Portal records the sign of life and the return path. `unknown`: no Claimed base has that key. `invalid`: anything else (not a keepalive, bad signature, stale or replayed). Relay keepalives as they arrive (batching delays sign of life and rings).
- `GET /doorbell/rings?wait=<seconds>` (long poll, at most 30 s) → `{"rings": [{"address": ..., "port": ..., "packet": "<base64url datagram>"}, ...]}` as soon as any are due, or an empty list after `wait`. Send each packet to its address and port **from the socket the keepalives arrived on** (that's the path the base's router holds open). Call again at once. A Wake is rung up to 5 times, 2 s apart, until the base opens its tunnel.

The packets (`protocol/src/sp_rtk_portal_protocol/doorbell.py`): a keepalive is 109 bytes (`SPDB`, kind 1, time, the key's thumbprint, an Ed25519 signature; the spec's "~32 B" can't hold a signature); a ring is `SPDB`, kind 2, time, the nonce and an HMAC-SHA256. The return paths and pending rings live in the Portal's memory (one instance), so a restart forgets paths until the next keepalives (20 s).

`tests/test_doorbell.py` runs the real agent against a stub Doorbell server (`tests/harness/doorbell_server.py`) that does exactly the above over real UDP.

## Local access

On the base's own LAN the user can skip the Portal: each base in the list has "Open locally", a plain link to `http://<primary LAN IP>:8080/` from its last Check-in (only a non-global IP literal is ever linked). It comes before "Open remotely" when the browser's public IP is the base's, after it otherwise. In Chrome and Edge, `static/local.js` also asks each base's identity endpoint (`/api/portal/identity`, which answers only the Portal's origin) over Local Network Access: quietly when the `local-network` permission is already granted, otherwise only after "Detect bases on this network" is clicked, so the Portal never prompts on its own. A base answering with its own `<id>` is "On this network": Open locally becomes the way in, with "Open remotely instead". Firefox, Safari and iOS never check. Local access is never a Remote session. The code is in `src/sp_rtk_portal/bases/local.py`.

## Un-claim

An Operator Un-claims a base on the Portal (`POST /bases/<id>/unclaim`, the list's Un-claim button; anyone else gets 404), or the base does it from its local Portal page with a signed `POST /agent/release`. Either way the Portal deletes the base record and its key, runs the `ctx.base_events.on_unclaimed` hooks (Shares remove themselves there), writes an `unclaim` audit entry, then ends the base's Remote sessions (reason `un_claim`, revoking their `/b/` tokens) and closes its tunnel. An agent Un-claimed on the Portal learns it from the 401 `unclaimed` on its next request and wipes its key. Claiming again makes a new key and `<id>`.

## Container image

`Dockerfile` builds the image the homelab runs (non-root uid 1000, read-only root filesystem, listening on `PORTAL_PORT`, default 8000). Pushing a `v*` tag runs `.github/workflows/image.yml`: the tests, then a push to `ghcr.io/rodenj1/sp-rtk-portal` tagged `<version>`, `<major>.<minor>` and `sha-<short>`. The run summary prints the digest, which [homelab-talos](https://github.com/rodenj1/homelab-talos) pins in `clusters/production/apps/sp-rtk-portal/deployment.yaml`.

```sh
git tag v0.1.0 && git push origin v0.1.0
```

## Tests

```sh
uv sync
uv run pytest             # the whole suite
uv run pytest tests/test_login.py -k totp
uv run ruff check . && uv run ruff format --check .
```

The suite runs the real app in-process against a throwaway Postgres, a fake Authentik and a faked clock, with the real Portal agent alongside it (`tests/harness/agent.py`). The agent is sp-rtk-base's own code, a dev dependency on the sibling checkout `../sp-rtk-base` (the submodule next to this one in the rtk_development meta repo); a checkout elsewhere needs sp-rtk-base cloned beside it. The image's test job checks it out the same way (sp-rtk-base `main`, or a ref given to a manual run). The Docker image never installs it. Websocket tests serve the same app over TCP with uvicorn (`tests/harness/server.py`), and a stub (`tests/harness/base_ui.py`) plays the base's UI. The Session bar's browser tests drive Chromium and Firefox with Playwright, one of them against the real sp-rtk-base server (`tests/harness/real_base.py`) behind the proxy; install them once with `uv run playwright install chromium firefox`. Postgres comes from, in order: `PORTAL_TEST_DATABASE_URL` (a superuser URL you provide), Docker via testcontainers if Docker is available, or `pgserver` (Postgres binaries installed from PyPI as a dev dependency). Nothing else needs installing beyond `uv sync`.
