# sp-rtk-portal

Hosted Portal for reaching [sp-rtk-base](https://github.com/rodenj1/sp-rtk-base) base stations remotely: Portal accounts, Claims, Shares, and the tunnel each base holds open to reach its own web UI. Also publishes the agent-to-Portal protocol package that sp-rtk-base depends on.

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
| `PORTAL_UNENROLLMENT_FLOW_SLUG` | Default `portal-unenrollment` (account deletion) |
| `PORTAL_AUTHENTIK_API_TOKEN` | Service account API token: finds a user by uuid, lists and removes their TOTP device. It can't change or delete users: account deletion runs a flow as the user |
| `PORTAL_TURNSTILE_SITE_KEY` | Cloudflare Turnstile site key shown on sign-up and recovery |
| `PORTAL_OIDC_APP_SLUG` | Default `sp-rtk-portal` |
| `PORTAL_MAX_BASES_PER_ACCOUNT` | Claimed bases per account, default 25 |
| `PORTAL_OWNER_EMAILS` | Comma-separated verified emails of the Portal owner(s), who get `/settings` (agent config, notices, latest sp-rtk-base release) |
| `PORTAL_MIN_PROTOCOL_VERSION` | Oldest agent protocol version served, default 1; older agents get 426 and their bases show "needs upgrade". Raise it only after 6 months' notice (a notice on `/settings`) |
| `PORTAL_SMTP_HOST`, `PORTAL_SMTP_PORT`, `PORTAL_SMTP_USERNAME`, `PORTAL_SMTP_PASSWORD`, `PORTAL_SMTP_FROM` | The SMTP server Authentik uses, for the Portal's own email (Share notifications). Port default 587, STARTTLS unless `PORTAL_SMTP_STARTTLS=false`. No host: nothing is sent (logged) |
| `PORTAL_MAX_SHARED_USERS_PER_BASE`, `PORTAL_MAX_PENDING_SHARES_PER_BASE` | Share limits per base, default 20 and 10 |
| `PORTAL_TRUSTED_PROXIES` | Comma-separated networks (CIDR) of the proxies in front of the Portal (the `cloudflared` and Traefik pods), e.g. `10.244.0.0/16`. Client-IP headers are believed only on a request whose peer is in one (see [Client IP](#client-ip)); any other request has no client IP (per-IP rate limits count it with every other such request, possible-copy detection ignores it, audit entries record no IP). **Required**: unset or empty stops startup, since every request would then share one IP (fleet-wide rate limits, no possible-copy detection). `none` trusts nothing on purpose (development only). A bad value stops startup |
| `PORTAL_AGENT_MIN_SPACING`, `PORTAL_AGENT_BURST` | A poll or Check-in sooner than this fraction of its interval after the last gets 429 with `Retry-After` once this many early ones are spent. Default 0.5 and 3 |
| `PORTAL_CLAIM_STARTS_PER_IP` | Claim starts an hour per public IP, default 10 (429 past it) |
| `PORTAL_WRONG_CODES_PER_ACCOUNT`, `PORTAL_WRONG_CODES_OVERALL` | Wrong approve codes an hour per account, default 10, and across all accounts, default 100. Past either, no code is looked up (also on `/claim?code=`) |
| `PORTAL_SHARES_PER_OPERATOR` | Shares an hour per Operator, default 30 (each emails someone) |
| `PORTAL_TUNNEL_REFUSALS_PER_IP` | Refused tunnel opens an hour per IP, default 30; past it, opens from that IP are refused unread |
| `PORTAL_HOST`, `PORTAL_PORT`, `PORTAL_LOG_LEVEL` | Default `0.0.0.0`, `8000`, `INFO` |

```sh
uv sync
uv run sp-rtk-portal
```

The OIDC client's redirect URI is `<public origin>/login/callback`. No browser ever visits it: the Portal reads the code off Authentik's redirect itself.

## Polling and the agent config

A Claimed base polls `POST /agent/poll` every 20 s (60 s when its Operator marks it metered in the list) and Checks in at `POST /agent/check-in` every 5 min (versions, private LAN addresses, and whether remote access is paused on site, as polls say too). A polling base is online until about 3 polls are missed; a base holding its tunnel is online while it's connected and for 2 min after it drops (see below). The base list's Connection row says which ("Holding its tunnel", "Reconnecting its tunnel", or "Polling every 20 s"). Every reply carries the agent config block, which the Portal owner edits on `/settings`: each save is a new revision, applied by every agent on its next poll. Notices added there show on every base and on its local Portal page. At the default interval polling costs about 0.3 GB a month (`tests/test_polling.py` measures it).

## The tunnel, Wakes and Remote sessions

A Claimed base on protocol version 2 holds its tunnel open (ADR 0006): its agent opens `wss://<Portal>/agent/tunnel` on Claim and on start with a GET signed by its base key and no nonce, and keeps it open. Only the agent pings (a `PING` frame every `ping_interval`, 50 s); the Portal never pings (uvicorn's websocket pings are off) and closes a held tunnel that sent nothing for `tunnel_silence_timeout` (120 s). A new tunnel from the same base replaces the old one. The base's connection mode is `holding` while it's connected and `reconnecting` once it drops (online for 2 min after it was last heard from); a Portal restart makes every holding base `reconnecting`. A version 1 agent, which only polls, is `polling`: "Open remotely" Wakes it, and its next poll reply carries a one-time nonce that its tunnel open echoes. A nonce-less open from a version 1 agent, an unclaimed key or a bad proof, or one echoing no pending Wake, is refused with 403 before the websocket is accepted.

"Open remotely" (`POST /bases/<id>/remote`) starts the user's Remote session on the base (one per user per base, shared by their tabs): on a holding base its streams open at once, with no Wake; a polling base is Woken first. Inside, the protocol package's framing multiplexes streams, each to the base's own UI on `127.0.0.1:8080` (a stream can't name a destination). One tunnel per base serves all its Remote sessions.

The Session bar page `/bases/<id>` shows Waking (with the poll-interval hint) and then Connected over a status websocket, `/bases/<id>/session`, on the Portal's own origin. While one is open its user is present. A Remote session ends when nobody has been present for the agent config's idle timeout (2 min), at its hard cap (60 min), or when the Portal ends it (logging out, un-Share, Un-claim, pause...; `TunnelBroker.end_for_account` and `end_for_base` are the only two ways; a caller with a transaction of its own ends them inside it, before it commits, and the end stands whatever becomes of it); its path token is revoked at once and, when it was a polling base's last, its Woken tunnel is closed (a held tunnel stays open). Remote session start and end are audited. All of this is in-process state (one Portal instance); a restart ends every Remote session.

The bar's states come from the Portal, never the browser's clock: **Waking**; **Didn't wake** once a Wake has gone unanswered for the poll interval + 15 s (35 s, or 75 s metered), with last-seen, wake mode and Retry; **Offline** when the base was already offline, so Open remotely Wakes nothing until the user picks Try anyway; **Reconnecting** after the tunnel drops under live sessions, when the Portal Wakes the base once more on its own (same token, the frame stays loaded) and shows Didn't wake if that fails too; **Still there?** 5 min before the hard cap, where Keep going (`POST /bases/<id>/keep-going`) restarts the hour for all of the user's tabs; **Session paused** at the hard cap, with the frame unloaded, the token revoked and Reconnect starting a new session with a new token. The bar also lists the other users connected to the base ("Also connected: ... (Shared user)") and has a full-screen toggle.

## The base proxy

Once Connected, the Session bar loads the base's own UI in `<iframe sandbox="allow-scripts allow-forms allow-downloads">` from `/b/<id>/s/<token>/` on the Portal's hostname (ADR 0004). Every request and websocket upgrade there is checked against a live Remote session's token, so a revoked token (session ended, un-Share, Un-claim...) stops working at once, open websockets included. The proxy strips the prefix and sends it as `X-Forwarded-Prefix` (sp-rtk-base builds its URLs from it), sets its own forwarding headers, never forwards cookies or `Authorization` and never returns a `Set-Cookie`, refuses a document load outside a frame (`Sec-Fetch-Dest`) with 403, and stamps `Content-Security-Policy: sandbox ...; frame-ancestors <Portal>`, `Access-Control-Allow-Origin: *` and `Referrer-Policy: no-referrer` on every answer, refusals and errors included. Nothing outside `/b/` reaches a base. The code is in `src/sp_rtk_portal/proxy/`.

Base pages are untrusted, so the Portal's own paths refuse anything a framed page sends as the user. Every state-changing request needs a JSON body, the `X-Portal-Action` header and the Portal's `Origin` (a framed page sends `Origin: null`). And any request the browser marks cross-site or same-site (`Sec-Fetch-Site`; a sandboxed frame's requests are cross-site) is refused, reads included, unless it opens a page. That last rule exists because WebKit sends the `SameSite=Lax` session cookie with a sandboxed frame's requests to the same host. The Session bar page itself sends `frame-src 'self' blob:` (NiceGUI's `ui.download` is a `blob:` link, which Firefox checks against it) and `Cross-Origin-Opener-Policy: same-origin-allow-popups` (with `same-origin`, Firefox and WebKit refuse the `window.open(url, "_self")` behind `ui.navigate.to`).

## Local access

On the base's own LAN the user can skip the Portal: each base in the list has "Open locally", a plain link to `http://<primary LAN IP>:8080/` from its last Check-in (only a non-global IP literal is ever linked). It comes before "Open remotely" when the browser's public IP is the base's, after it otherwise. In Chrome and Edge, `static/local.js` also asks each base's identity endpoint (`/api/portal/identity`, which answers only the Portal's origin) over Local Network Access: quietly when the `local-network` permission is already granted, otherwise only after "Detect bases on this network" is clicked, so the Portal never prompts on its own. A base answering with its own `<id>` is "On this network": Open locally becomes the way in, with "Open remotely instead". Firefox, Safari and iOS never check. Local access is never a Remote session. The code is in `src/sp_rtk_portal/bases/local.py`.

## Un-claim

An Operator Un-claims a base on the Portal (`POST /bases/<id>/unclaim`, the list's Un-claim button; anyone else gets 404), or the base does it from its local Portal page with a signed `POST /agent/release`. Either way the Portal ends the base's Remote sessions (reason `un_claim`, revoking their `/b/` tokens) and closes its tunnel, then deletes the base record and its key, runs the `ctx.base_events.on_unclaimed` hooks (Shares remove themselves there) and writes an `unclaim` audit entry, all in one transaction. An agent Un-claimed on the Portal learns it from the 401 `unclaimed` on its next request and wipes its key. Claiming again makes a new key and `<id>`.
## Remote access paused

An Operator on site can pause remote access from the base's local Portal page. The agent keeps its key and Claim and keeps polling, but each poll says `paused` and it ignores any Wake. On that poll the Portal ends the base's live Remote sessions (reason `paused`, tokens revoked), closes its tunnel and audits the pause; the base list shows "Remote access paused" with Open remotely disabled (and `POST /bases/<id>/remote` answers 409). Only the base can resume. Each poll reply also lists the base's live Remote sessions (who and since when) for its local Portal page.

## Shares

An Operator Shares a base by email on its Shares page (`/bases/<id>/shares`, linked from the list). An account with that verified email gets a Share at once; otherwise a Pending share waits 14 days and becomes a Share on the first login with that verified email (bound to the account, i.e. its `(iss, sub)`). The recipient and the base's Operator are both emailed every time, even when the Operator made the Share. A Shared user sees the base in their list marked Shared and opens it like the Operator, but gets 403 on Share and 404 on the Shares page and Un-claim. The Operator removes a Shared user (`POST /bases/<id>/shares/<account>/remove`) or withdraws a Pending share; a Shared user leaves (`POST /bases/<id>/leave`). Removing or leaving ends that user's Remote sessions on the base at once, revoking their `/b/` token. Un-claim removes all of the base's Shares. Limits: 20 Shared users and 10 live Pending shares per base. Every Share change is audited. The code is in `src/sp_rtk_portal/shares/` and email in `src/sp_rtk_portal/mail.py`.

## Client IP

The Portal is reached two ways: from the internet through Cloudflare and `cloudflared`, and from the LAN through Traefik's LAN-only `websecure` entrypoint. On a request whose peer is in `PORTAL_TRUSTED_PROXIES`, the client IP is:

1. `CF-Connecting-IP`, if it is a valid IP (Cloudflare sets it);
2. otherwise `X-Real-Ip`, if it is a valid IP (Traefik's `websecure` trusts no forwarded headers, so it sets this to the LAN client's address; the LAN route also strips any `CF-Connecting-IP` the client sent);
3. otherwise none.

A request from any other peer has no client IP, whatever headers it carries. The peer address itself is never used: it is the proxy's. The code is in `src/sp_rtk_portal/web/client_ip.py`; the cluster side is in homelab-talos `docs/SP_RTK_PORTAL_DEPLOYMENT.md`.

## Rate limits and possible copy

Limits (see the `PORTAL_*` settings above) are counted in the Portal process's memory: one replica, so a restart forgets them and only ever lets a little more through. A refused agent request gets 429 with `Retry-After` and an `ErrorReply("slow_down")`; the agent waits that long (at least twice its poll interval for a poll). A refused browser action gets 429 with `{"error": "... Try again in N minutes."}`.

A base key seen from two public IPs in turns (A, B, A) within 5 minutes, by polls or Check-ins, marks the base "possible copy" on the base list and emails its Operator once (audit kind `possible_copy`). Nothing is blocked; the flag stays until the base is Un-claimed (Claiming again gives it a new key). An IPv6 /64 counts as one place (privacy addresses rotate within it), and IPv4 and IPv6 are watched apart, so a dual-stack base switching families is not a copy (a copy on the other family is missed).

## Account security

Logging out (`POST /logout`) ends the Portal session and, with it, every Remote session of the account (reason `logged_out`, revoking its `/b/` token; a Remote session is per account, shared by all its browsers), and open Session bars close. The account page (`/account`) has **Log out everywhere** (`POST /account/logout-everywhere`): every Portal session of the account ends, this one included, and every Remote session (reason `log_out_everywhere`, revoking its `/b/` token). It also runs automatically after a password change (keeping the session that made it) or a recovery (keeping only the recovering browser), through the `PasswordChanged` hook. Each run is audited `log_out_everywhere` with `trigger` `button`, `password_change` or `password_recovery`.

After a password change or recovery the user lands on `/account/review`: the Shares and Pending shares created from their account in the last 30 days, each with a one-click remove. "Skip for now" leaves it due, so every login lands there again until "Done" (`POST /account/review/done`).

Email is Authentik's: accounts are keyed on `(iss, sub)` and email is re-read at every login, so a changed email keeps its bases and Shares.

**Delete account** (`/account/delete`) lists the bases it will Un-claim and asks for the password, then the TOTP code if the account has one (`POST /account/delete`, then `POST /account/delete/totp`). It runs Authentik's `portal-unenrollment` flow as the user, in this order:

1. The flow proves the password, the `portal-users` deny stage and the TOTP code, and stops at its confirmation prompt, right before its `user_delete` stage. The Portal identifies with the account's own email and checks that the flow's pending user is the account's own Authentik user (by uuid, through the admin API) before it sends the password. A wrong password or code answers "Wrong password." or "Wrong code.", an account outside `portal-users` gets "Wrong password.", and an unknown stage or another user answers 502. In every one of these cases nothing is deleted.
2. In one transaction, the Portal Un-claims every base the account Claimed (audit `unclaim` with `by: account_deleted`), removes the Shares it holds on other bases (`share_left`, `reason: account_deleted`), ends its sessions, marks the account `deleted_at` and audits `account_deleted`. If this fails, nothing changes on either side (500) and the user can try again.
3. The Portal confirms the flow, which deletes the Authentik user, and checks through the admin API that the user is gone. If this last step fails, the Portal's data is already gone but the sign-in remains. The Portal logs an ERROR with the user's uuid, audits `account_deletion_incomplete` (`email`, `sub`, `error`), and sends the user to `/account/delete/unfinished`. That page tells them to sign in again, which gives them their now empty account back, and delete it again. The owner can also delete the user in Authentik by hand.

The account row stays so the audit log keeps saying who did what. Signing up again with the same email creates a new Authentik user, with a new `sub`, so it gets a new account. A tombstoned account is never matched by email, so a Share to that email reaches the new account. The code is in `src/sp_rtk_portal/accounts/` (`security.py`, `review.py`, `deletion.py`).

## Audit log

`/audit` (linked from the base list and the account page) lists, newest first, the audit entries of the last 90 days the signed-in user may see: an Operator sees every entry about their bases (owned now, or Claimed by them and since Un-claimed), whoever acted, plus their own; everyone sees their own entries and those naming them as the Shared user. On the latter, the Operator's email and IP are hidden. Each row shows what, who, base, when (UTC) and IP. Kinds the page doesn't know still show, as words plus their detail. Entries are deleted after 90 days (`audit/retention.py`, at startup and every `audit_purge_interval` seconds, measured on the Portal clock). The code is in `src/sp_rtk_portal/audit/`.

## Container image

`Dockerfile` builds the image the homelab runs (non-root uid 1000, read-only root filesystem, listening on `PORTAL_PORT`, default 8000). Pushing a `v*` tag runs `.github/workflows/image.yml`: CI's lint and tests (it calls `ci.yml`), then a push to `ghcr.io/rodenj1/sp-rtk-portal` tagged `<version>`, `<major>.<minor>` and `sha-<short>`. The run summary prints the digest, which [homelab-talos](https://github.com/rodenj1/homelab-talos) pins in `clusters/production/apps/sp-rtk-portal/deployment.yaml`.

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

The suite runs the real app in-process against a throwaway Postgres, a fake Authentik and a faked clock, with the real Portal agent alongside it (`tests/harness/agent.py`). The agent is sp-rtk-base's own code, a dev dependency on the sibling checkout `../sp-rtk-base` (the submodule next to this one in the rtk_development meta repo); a checkout elsewhere needs sp-rtk-base cloned beside it. CI checks it out the same way (see below). The Docker image never installs it. Websocket tests serve the same app over TCP with uvicorn (`tests/harness/server.py`); tests about the agent's HTTPS connection itself (reuse, bytes per poll) send it over a real TLS wire that counts connections and bytes (`tests/harness/wire.py`), and a stub (`tests/harness/base_ui.py`) plays the base's UI. Email goes over real SMTP to an in-process aiosmtpd server (`tests/harness/fake_smtp.py`, fixture `smtp`). The Session bar's browser tests drive Chromium and Firefox with Playwright; install them once with `uv run playwright install chromium firefox webkit`.

The browser suite `tests/test_frame_browser.py` runs the real sp-rtk-base server (`tests/harness/real_base.py`) in the Session bar's frame through the real Portal, in Chromium, Firefox and WebKit. It checks that every base page renders as it does directly, stays live, and that its links, `ui.navigate.to` and `ui.download` work. It also checks that nothing in the frame can reach the Portal page or act as the user, and that the iframe's sandbox attribute and the proxy's CSP sandbox header each hold on their own. The Portal is served over HTTPS there with a throwaway certificate, because WebKit keeps the `__Host-` cookie only over HTTPS, even on localhost. WebKit needs system libraries (`uv run playwright install-deps webkit`). Where it can't launch, its tests are skipped with the reason, unless `PORTAL_TEST_REQUIRE_WEBKIT=1` is set (CI sets it). `PORTAL_TEST_WEBKIT=<path>` runs a different WebKit executable, for example a wrapper that supplies its libraries without installing them system-wide (then also set `PLAYWRIGHT_SKIP_VALIDATE_HOST_REQUIREMENTS=1`). Postgres comes from, in order: `PORTAL_TEST_DATABASE_URL` (a superuser URL you provide), Docker via testcontainers if Docker is available, or `pgserver` (Postgres binaries installed from PyPI as a dev dependency). Nothing else needs installing beyond `uv sync`.

### CI

`.github/workflows/ci.yml` runs on every push to `main`, every pull request and by hand, and cancels a superseded run on the same branch or PR:

- **lint**: ruff check and ruff format --check over the repo (the ruff `uv.lock` pins), and pyright on `protocol/` on Python 3.10.
- **protocol**: the protocol package's tests alone on Python 3.10 and 3.13, installed as a consumer installs it.
- **test**: `uv run pytest` (the whole suite, protocol tests included) on Python 3.12, with Postgres from Docker via testcontainers and Chromium, Firefox and WebKit (`PORTAL_TEST_REQUIRE_WEBKIT=1`).

The sibling sp-rtk-base is the branch with the same name as the PR's head branch or the pushed branch if rodenj1/sp-rtk-base has one, and `main` otherwise, so a change spanning both repos is tested against its own agent code: push the sp-rtk-base branch first. The run prints which ref it used. A manual run (CI or image) can name the ref instead (`sp_rtk_base_ref`).

## Launch checklist

- [ ] **Safari, by hand.** The browser suite runs Playwright's WebKit, not Safari. On a Mac (and an iPhone), sign in to the Portal in Safari, open a base remotely, and check that:
  - [ ] every base page renders as it does on the base directly, the Event log shows live entries, and a drawer link and the GPS config page's "Survey" link move the frame while the Session bar stays put;
  - [ ] exporting a GPS profile downloads the `.json` file;
  - [ ] in Web Inspector's console, with the base's frame selected, `self.origin` is `"null"`, and `document.cookie`, `parent.document`, `top.location.href` and `indexedDB.open("x")` throw;
  - [ ] in the same console, `fetch("/account", {credentials: "include"})` gets a 403 from the Portal (Network tab: `Origin: null`). Note whether the request carried the Portal cookie, as Playwright's WebKit does (the Portal refuses it either way).
