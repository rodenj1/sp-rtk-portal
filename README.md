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

The suite runs the real app in-process against a throwaway Postgres, a fake Authentik and a faked clock, with the real Portal agent alongside it (`tests/harness/agent.py`). The agent is sp-rtk-base's own code, a dev dependency on the sibling checkout `../sp-rtk-base` (the submodule next to this one in the rtk_development meta repo); a checkout elsewhere needs sp-rtk-base cloned beside it. The image's test job checks it out the same way (sp-rtk-base `main`, or a ref given to a manual run). The Docker image never installs it. Postgres comes from, in order: `PORTAL_TEST_DATABASE_URL` (a superuser URL you provide), Docker via testcontainers if Docker is available, or `pgserver` (Postgres binaries installed from PyPI as a dev dependency). Nothing needs installing beyond `uv sync`.
