"""Portal settings, read from ``PORTAL_*`` environment variables in production."""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import timedelta


@dataclass(frozen=True)
class Settings:
    database_url: str
    authentik_url: str
    oidc_client_id: str
    oidc_client_secret: str
    public_origin: str = "https://sp-rtk-base.big-spray.com"
    login_flow_slug: str = "portal-login"
    oidc_app_slug: str = "sp-rtk-portal"
    session_lifetime: timedelta = timedelta(days=30)
    login_attempt_lifetime: timedelta = timedelta(minutes=10)

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
            **opt("login_flow_slug"),
            **opt("oidc_app_slug"),
        )
