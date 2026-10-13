"""Settings read from the environment (``Settings.from_env``)."""

from __future__ import annotations

import pytest

from sp_rtk_portal.config import Settings, TrustedProxiesUnset

REQUIRED = {
    "PORTAL_DATABASE_URL": "postgresql://portal@db/portal",
    "PORTAL_AUTHENTIK_URL": "https://auth.example.com/",
    "PORTAL_OIDC_CLIENT_ID": "sp-rtk-portal",
    "PORTAL_OIDC_CLIENT_SECRET": "secret",
}


@pytest.mark.parametrize("value", [None, "", " , "])
def test_the_portal_refuses_to_start_without_trusted_proxies(value: str | None):
    """Unset, every request would share one "untrusted" bucket: fleet-wide
    Claim-start limits and tunnel lockouts, and no possible-copy detection."""
    env = dict(REQUIRED)
    if value is not None:
        env["PORTAL_TRUSTED_PROXIES"] = value

    with pytest.raises(TrustedProxiesUnset, match="PORTAL_TRUSTED_PROXIES"):
        Settings.from_env(env)


def test_trusted_proxies_are_networks():
    settings = Settings.from_env(
        REQUIRED | {"PORTAL_TRUSTED_PROXIES": "10.244.0.0/16, fd00::/8"}
    )

    assert settings.trusted_proxies == ("10.244.0.0/16", "fd00::/8")


@pytest.mark.parametrize("value", ["none", "NONE", " none "])
def test_none_opts_out_of_client_ips_on_purpose(value: str):
    """For development: no request has a client IP, and the operator said so."""
    settings = Settings.from_env(REQUIRED | {"PORTAL_TRUSTED_PROXIES": value})

    assert settings.trusted_proxies == ()
