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

Base pages are untrusted, so the Portal's own paths refuse anything a framed page sends as the user. Every state-changing request needs a JSON body, the `X-Portal-Action` header and the Portal's `Origin` (a framed page sends `Origin: null`). And any request the browser marks cross-site or same-site (`Sec-Fetch-Site`; a sandboxed frame's requests are cross-site) is refused, reads included, unless it opens a page. That last rule exists because WebKit sends the `SameSite=Lax` session cookie with a sandboxed frame's requests to the same host. The Session bar page itself sends `frame-src 'self' blob:` (NiceGUI's `ui.download` is a `blob:` link, which Firefox checks against it) and `Cross-Origin-Opener-Policy: same-origin-allow-popups` (with `same-origin`, Firefox and WebKit refuse the `window.open(url, "_self")` behind `ui.navigate.to`).

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

The suite runs the real app in-process against a throwaway Postgres, a fake Authentik and a faked clock, with the real Portal agent alongside it (`tests/harness/agent.py`). The agent is sp-rtk-base's own code, a dev dependency on the sibling checkout `../sp-rtk-base` (the submodule next to this one in the rtk_development meta repo); a checkout elsewhere needs sp-rtk-base cloned beside it. The image's test job checks it out the same way (sp-rtk-base `main`, or a ref given to a manual run). The Docker image never installs it. Websocket tests serve the same app over TCP with uvicorn (`tests/harness/server.py`), and a stub (`tests/harness/base_ui.py`) plays the base's UI. The Session bar's browser tests drive Chromium and Firefox with Playwright; install them once with `uv run playwright install chromium firefox webkit`.

The browser suite `tests/test_frame_browser.py` runs the real sp-rtk-base server (`tests/harness/real_base.py`) in the Session bar's frame through the real Portal, in Chromium, Firefox and WebKit. It checks that every base page renders as it does directly, stays live, and that its links, `ui.navigate.to` and `ui.download` work. It also checks that nothing in the frame can reach the Portal page or act as the user, and that the iframe's sandbox attribute and the proxy's CSP sandbox header each hold on their own. The Portal is served over HTTPS there with a throwaway certificate, because WebKit keeps the `__Host-` cookie only over HTTPS, even on localhost. WebKit needs system libraries (`uv run playwright install-deps webkit`). Where it can't launch, its tests are skipped with the reason, unless `PORTAL_TEST_REQUIRE_WEBKIT=1` is set (CI sets it). `PORTAL_TEST_WEBKIT=<path>` runs a different WebKit executable, for example a wrapper that supplies its libraries without installing them system-wide (then also set `PLAYWRIGHT_SKIP_VALIDATE_HOST_REQUIREMENTS=1`). Postgres comes from, in order: `PORTAL_TEST_DATABASE_URL` (a superuser URL you provide), Docker via testcontainers if Docker is available, or `pgserver` (Postgres binaries installed from PyPI as a dev dependency). Nothing else needs installing beyond `uv sync`.

## Launch checklist

- [ ] **Safari, by hand.** The browser suite runs Playwright's WebKit, not Safari. On a Mac (and an iPhone), sign in to the Portal in Safari, open a base remotely, and check that:
  - [ ] every base page renders as it does on the base directly, the Event log shows live entries, and a drawer link and the GPS config page's "Survey" link move the frame while the Session bar stays put;
  - [ ] exporting a GPS profile downloads the `.json` file;
  - [ ] in Web Inspector's console, with the base's frame selected, `self.origin` is `"null"`, and `document.cookie`, `parent.document`, `top.location.href` and `indexedDB.open("x")` throw;
  - [ ] in the same console, `fetch("/account", {credentials: "include"})` gets a 403 from the Portal (Network tab: `Origin: null`). Note whether the request carried the Portal cookie, as Playwright's WebKit does (the Portal refuses it either way).
