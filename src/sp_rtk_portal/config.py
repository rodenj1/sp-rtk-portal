"""Portal settings, read from ``PORTAL_*`` environment variables in production."""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import timedelta

FALSE = ("0", "false", "no", "off")


@dataclass(frozen=True)
class Settings:
    database_url: str
    authentik_url: str
    oidc_client_id: str
    oidc_client_secret: str
    public_origin: str = "https://sp-rtk-base.big-spray.com"
    # The flow-executor service account's API token: reads and removes a
    # user's TOTP device (Authentik has no flow stage that removes one).
    authentik_api_token: str = ""
    turnstile_site_key: str = ""
    login_flow_slug: str = "portal-login"
    enrollment_flow_slug: str = "portal-enrollment"
    recovery_flow_slug: str = "portal-recovery"
    totp_setup_flow_slug: str = "portal-totp-setup"
    password_change_flow_slug: str = "portal-password-change"
    oidc_app_slug: str = "sp-rtk-portal"
    session_lifetime: timedelta = timedelta(days=30)
    login_attempt_lifetime: timedelta = timedelta(minutes=10)
    # Claim (RFC 8628): how long a pairing code lives, how often the agent may
    # poll for the result, and how many bases one account may Claim.
    claim_lifetime: timedelta = timedelta(minutes=10)
    claim_poll_interval: int = 5
    max_bases_per_account: int = 25
    # The Portal owner(s): may edit the agent config, notices and the latest
    # sp-rtk-base release on /settings. Matched on a verified email.
    owner_emails: tuple[str, ...] = ()
    # The oldest agent protocol version still served; older agents get 426.
    # Raise it only after at least 6 months' notice to affected Operators.
    min_protocol_version: int = 1
    # Tunnel broker (ticket #88): how long a Wake's nonce may be redeemed,
    # and how often (seconds, real time) Remote session timeouts are checked.
    wake_lifetime: timedelta = timedelta(minutes=5)
    tunnel_sweep_interval: float = 1.0
    # Email (Shares, #94): the SMTP server Authentik uses. Port 587 with
    # STARTTLS and login. No host: nothing is sent (logged instead).
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_from: str = ""
    smtp_starttls: bool = True
    # Shares (#94): per-base limits, and how long a Pending share waits for
    # its recipient's first login.
    max_shared_users_per_base: int = 20
    max_pending_shares_per_base: int = 10
    pending_share_lifetime: timedelta = timedelta(days=14)
    # Local access (ticket #97): the port of a base's own UI on its LAN.
    # Always 8080 in production; browser tests point it at a test server.
    base_ui_port: int = 8080

    @property
    def oidc_issuer(self) -> str:
        return f"{self.authentik_url}/application/o/{self.oidc_app_slug}/"

    @property
    def oidc_redirect_uri(self) -> str:
        # Registered with Authentik but never visited by a browser: the Portal
        # reads the code off Authentik's redirect server-side (ADR 0003).
        return f"{self.public_origin}/login/callback"

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> Settings:
        env = dict(os.environ if env is None else env)

        def opt(name: str) -> dict[str, str]:
            key = f"PORTAL_{name.upper()}"
            return {name: env[key]} if key in env else {}

        return cls(
            database_url=env["PORTAL_DATABASE_URL"],
            authentik_url=env["PORTAL_AUTHENTIK_URL"].rstrip("/"),
            oidc_client_id=env["PORTAL_OIDC_CLIENT_ID"],
            oidc_client_secret=env["PORTAL_OIDC_CLIENT_SECRET"],
            **opt("public_origin"),
            **opt("authentik_api_token"),
            **opt("turnstile_site_key"),
            **opt("login_flow_slug"),
            **opt("enrollment_flow_slug"),
            **opt("recovery_flow_slug"),
            **opt("totp_setup_flow_slug"),
            **opt("password_change_flow_slug"),
            **opt("oidc_app_slug"),
            **opt("smtp_host"),
            **opt("smtp_username"),
            **opt("smtp_password"),
            **opt("smtp_from"),
            **{
                name: int(env[f"PORTAL_{name.upper()}"])
                for name in (
                    "max_bases_per_account",
                    "min_protocol_version",
                    "smtp_port",
                    "max_shared_users_per_base",
                    "max_pending_shares_per_base",
                )
                if f"PORTAL_{name.upper()}" in env
            },
            **(
                {"smtp_starttls": env["PORTAL_SMTP_STARTTLS"].lower() not in FALSE}
                if "PORTAL_SMTP_STARTTLS" in env
                else {}
            ),
            owner_emails=tuple(
                e.strip().lower()
                for e in env.get("PORTAL_OWNER_EMAILS", "").split(",")
                if e.strip()
            ),
        )
