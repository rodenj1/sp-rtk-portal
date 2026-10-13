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
    # The Session bar asks "Still there?" this long before the hard cap (#90).
    still_there_warning: timedelta = timedelta(minutes=5)
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
    # The Doorbell server's bearer token for /doorbell/* (ticket #100). Empty
    # (the default, v1 has no Doorbell server): that interface answers 404.
    doorbell_token: str = ""
    # Local access (ticket #97): the port of a base's own UI on its LAN.
    # Always 8080 in production; browser tests point it at a test server.
    base_ui_port: int = 8080
    # Client IP (ticket #98): CF-Connecting-IP is believed only on requests
    # whose peer is in one of these networks (the cloudflared pods). Empty:
    # never believed, every request is untrusted (no client IP). From the
    # environment it must be set: ``none`` asks for empty on purpose.
    trusted_proxies: tuple[str, ...] = ()
    # Rate limits (ticket #98). A poll or Check-in sooner than
    # agent_min_spacing x its interval after the last is refused 429 once
    # agent_burst early ones are used up (a restart, a resumed pause or a
    # Doorbell change each bring one forward).
    agent_min_spacing: float = 0.5
    agent_burst: int = 3
    claim_starts_per_ip: int = 10
    wrong_codes_per_account: int = 10
    wrong_codes_overall: int = 100
    # Refused tunnel opens (bad proof, forged or replayed Wake) per IP; past
    # it, opens from that IP are refused unread for the rest of the hour.
    tunnel_refusals_per_ip: int = 30
    # Above max_shared_users_per_base: one base can be filled in a sitting.
    shares_per_operator: int = 30
    rate_limit_period: timedelta = timedelta(hours=1)
    # Possible copy: the same base key polling from two public IPs,
    # interleaved within this long.
    possible_copy_window: timedelta = timedelta(minutes=5)
    # Audit log (#99): how often (seconds, real time) entries older than 90
    # days are deleted.
    audit_purge_interval: float = 3600.0

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
            **opt("doorbell_token"),
            **{
                name: int(env[f"PORTAL_{name.upper()}"])
                for name in (
                    "max_bases_per_account",
                    "min_protocol_version",
                    "smtp_port",
                    "max_shared_users_per_base",
                    "max_pending_shares_per_base",
                    "agent_burst",
                    "claim_starts_per_ip",
                    "wrong_codes_per_account",
                    "wrong_codes_overall",
                    "shares_per_operator",
                    "tunnel_refusals_per_ip",
                )
                if f"PORTAL_{name.upper()}" in env
            },
            **(
                {"agent_min_spacing": float(env["PORTAL_AGENT_MIN_SPACING"])}
                if "PORTAL_AGENT_MIN_SPACING" in env
                else {}
            ),
            **(
                {"smtp_starttls": env["PORTAL_SMTP_STARTTLS"].lower() not in FALSE}
                if "PORTAL_SMTP_STARTTLS" in env
                else {}
            ),
            trusted_proxies=_trusted_proxies(env),
            owner_emails=tuple(
                e.strip().lower()
                for e in env.get("PORTAL_OWNER_EMAILS", "").split(",")
                if e.strip()
            ),
        )


TRUSTED_PROXIES_NONE = "none"


class TrustedProxiesUnset(ValueError):
    """``PORTAL_TRUSTED_PROXIES`` is missing or empty."""


def _trusted_proxies(env: dict[str, str]) -> tuple[str, ...]:
    """The cloudflared networks. Unset is refused: every request would then
    share one "untrusted" client IP, so per-IP limits would hit the whole
    fleet at once and possible-copy detection would be off. ``none`` says
    "no client IPs, I know" (development)."""
    raw = env.get("PORTAL_TRUSTED_PROXIES", "").strip()
    if raw.lower() == TRUSTED_PROXIES_NONE:
        return ()
    networks = tuple(n.strip() for n in raw.split(",") if n.strip())
    if not networks:
        raise TrustedProxiesUnset(
            "PORTAL_TRUSTED_PROXIES must be set: the cloudflared pods' "
            "networks (e.g. 10.244.0.0/16), or 'none' for no client IPs"
        )
    return networks
