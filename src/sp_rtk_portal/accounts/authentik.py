"""Headless Authentik login (ADR 0003).

The Portal runs the pinned login flow through Authentik's flow executor API,
then completes OIDC authorization code + PKCE itself, as a
backend-for-frontend. The browser never talks to Authentik.

Anything unexpected (an unknown stage, a redirect somewhere else, a bad
token response) raises ``AuthentikFailedClosed``: the Portal shows an error and
never follows Authentik anywhere. The Portal keeps no Authentik tokens: they
are read once to learn who signed in, then dropped.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from urllib.parse import parse_qs, urlencode, urljoin, urlsplit

import httpx

from sp_rtk_portal.clock import Clock
from sp_rtk_portal.config import Settings

IDENTIFICATION = "ak-stage-identification"
PASSWORD = "ak-stage-password"
AUTHENTICATOR_VALIDATE = "ak-stage-authenticator-validate"
ACCESS_DENIED = "ak-stage-access-denied"
REDIRECT = "xak-flow-redirect"


class AuthentikFailedClosed(Exception):
    """Authentik did something the Portal doesn't expect. Sign-in stops."""


@dataclass(frozen=True)
class Identity:
    """Who signed in. Email and its verified flag are fresh from this login."""

    iss: str
    sub: str
    email: str
    email_verified: bool


@dataclass(frozen=True)
class NeedsTotp:
    pass


@dataclass(frozen=True)
class Rejected:
    """Authentik refused the credentials or the code."""

    message: str


Outcome = Identity | NeedsTotp | Rejected


@dataclass
class LoginAttempt:
    """One run of the login flow. Lives server-side between the login steps."""

    client_ip: str | None
    cookies: httpx.Cookies = field(default_factory=httpx.Cookies)
    state: str = field(default_factory=lambda: secrets.token_urlsafe(24))
    nonce: str = field(default_factory=lambda: secrets.token_urlsafe(24))
    code_verifier: str = field(default_factory=lambda: secrets.token_urlsafe(48))
    stage: str = IDENTIFICATION


class Authentik:
    def __init__(
        self,
        settings: Settings,
        clock: Clock,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._settings = settings
        self._clock = clock
        self._transport = transport

    # --- the steps the login page drives ---------------------------------

    async def sign_in(
        self, email: str, password: str, client_ip: str | None
    ) -> tuple[LoginAttempt, Outcome]:
        """Start the flow and submit email + password."""
        attempt = LoginAttempt(client_ip=client_ip)
        challenge = await self._executor(attempt, "GET")
        _expect(challenge, IDENTIFICATION)
        body: dict[str, Any] = {"component": IDENTIFICATION, "uid_field": email}
        if challenge.get("password_fields"):
            body["password"] = password
            outcome = await self._advance(attempt, body)
            if outcome is None:
                raise AuthentikFailedClosed("password asked for twice")
            return attempt, outcome
        outcome = await self._advance(attempt, body)
        if outcome is None:  # a separate password stage
            body = {"component": PASSWORD, "password": password}
            outcome = await self._advance(attempt, body)
        if outcome is None:
            raise AuthentikFailedClosed("password stage repeated")
        return attempt, outcome

    async def submit_totp(self, attempt: LoginAttempt, code: str) -> Outcome:
        if attempt.stage != AUTHENTICATOR_VALIDATE:
            raise AuthentikFailedClosed(f"TOTP submitted at stage {attempt.stage!r}")
        body = {"component": AUTHENTICATOR_VALIDATE, "code": code}
        outcome = await self._advance(attempt, body)
        if outcome is None:
            raise AuthentikFailedClosed("password stage after TOTP")
        return outcome

    # --- flow executor ---------------------------------------------------

    async def _advance(
        self, attempt: LoginAttempt, body: dict[str, Any]
    ) -> Outcome | None:
        """Answer the current stage. ``None`` means Authentik now wants a
        separate password stage."""
        challenge = await self._executor(attempt, "POST", body)
        component = challenge.get("component")
        if challenge.get("response_errors"):
            # Authentik re-sent the stage we answered: wrong password or code.
            _expect(challenge, attempt.stage)
            return Rejected(_first_error(challenge["response_errors"]))
        if component == PASSWORD and attempt.stage == IDENTIFICATION:
            attempt.stage = PASSWORD
            return None
        if component == AUTHENTICATOR_VALIDATE and attempt.stage in (
            IDENTIFICATION,
            PASSWORD,
        ):
            classes = {
                d.get("device_class") for d in challenge.get("device_challenges", [])
            }
            if "totp" not in classes:
                raise AuthentikFailedClosed(f"unsupported authenticator {classes}")
            attempt.stage = AUTHENTICATOR_VALIDATE
            return NeedsTotp()
        if component == ACCESS_DENIED:
            return Rejected(challenge.get("error_message") or "Access denied.")
        if component == REDIRECT:
            attempt.stage = REDIRECT
            return await self._complete(attempt, str(challenge.get("to", "")))
        raise AuthentikFailedClosed(
            f"unexpected stage {component!r} after {attempt.stage!r}"
        )

    async def _executor(
        self, attempt: LoginAttempt, method: str, body: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        slug = self._settings.login_flow_slug
        params = {"query": urlencode({"next": self._authorize_path(attempt)})}
        async with self._client(attempt) as client:
            resp = await client.request(
                method, f"/api/v3/flows/executor/{slug}/", params=params, json=body
            )
        if resp.status_code != 200:
            raise AuthentikFailedClosed(f"flow executor returned {resp.status_code}")
        challenge = resp.json()
        if not isinstance(challenge, dict):
            raise AuthentikFailedClosed("flow executor returned a non-object")
        return challenge

    # --- OIDC code + PKCE, server-side -----------------------------------

    def _authorize_path(self, attempt: LoginAttempt) -> str:
        challenge = _b64url(hashlib.sha256(attempt.code_verifier.encode()).digest())
        query = urlencode(
            {
                "client_id": self._settings.oidc_client_id,
                "response_type": "code",
                "redirect_uri": self._settings.oidc_redirect_uri,
                "scope": "openid email",
                "state": attempt.state,
                "nonce": attempt.nonce,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            }
        )
        return f"/application/o/authorize/?{query}"

    async def _complete(self, attempt: LoginAttempt, to: str) -> Identity:
        base = self._settings.authentik_url
        expected = urljoin(base, self._authorize_path(attempt))
        if urljoin(base + "/", to) != expected:
            raise AuthentikFailedClosed(f"flow redirected to {to!r}")
        async with self._client(attempt) as client:
            resp = await client.get(expected)
            code = self._code_from(resp, attempt)
            token = await client.post(
                "/application/o/token/",
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": self._settings.oidc_redirect_uri,
                    "code_verifier": attempt.code_verifier,
                    "client_id": self._settings.oidc_client_id,
                    "client_secret": self._settings.oidc_client_secret,
                },
            )
            if token.status_code != 200:
                raise AuthentikFailedClosed(
                    f"token endpoint returned {token.status_code}"
                )
            tokens = token.json()
            claims = self._id_token_claims(str(tokens.get("id_token", "")), attempt)
            info = await client.get(
                "/application/o/userinfo/",
                headers={"Authorization": f"Bearer {tokens.get('access_token', '')}"},
            )
        if info.status_code != 200:
            raise AuthentikFailedClosed(f"userinfo returned {info.status_code}")
        user = info.json()
        if user.get("sub") != claims["sub"] or not user.get("email"):
            raise AuthentikFailedClosed("userinfo doesn't match the ID token")
        return Identity(
            iss=claims["iss"],
            sub=claims["sub"],
            email=str(user["email"]),
            email_verified=user.get("email_verified") is True,
        )

    def _code_from(self, resp: httpx.Response, attempt: LoginAttempt) -> str:
        location = resp.headers.get("location", "")
        if resp.status_code not in (302, 303) or not location.startswith(
            self._settings.oidc_redirect_uri + "?"
        ):
            raise AuthentikFailedClosed("authorize didn't return a code")
        query = parse_qs(urlsplit(location).query)
        if query.get("state") != [attempt.state] or "code" not in query:
            raise AuthentikFailedClosed("authorize returned a bad state or no code")
        return query["code"][0]

    def _id_token_claims(self, id_token: str, attempt: LoginAttempt) -> dict[str, Any]:
        # Received straight from the token endpoint over TLS, so the TLS server
        # check stands in for the signature (OIDC Core 3.1.3.7).
        try:
            payload = id_token.split(".")[1]
            claims: dict[str, Any] = json.loads(_b64url_decode(payload))
        except (IndexError, ValueError) as e:
            raise AuthentikFailedClosed("unreadable ID token") from e
        aud = claims.get("aud")
        auds = aud if isinstance(aud, list) else [aud]
        exp = claims.get("exp")
        now = self._clock.now()
        if (
            claims.get("iss") != self._settings.oidc_issuer
            or self._settings.oidc_client_id not in auds
            or claims.get("nonce") != attempt.nonce
            or not isinstance(exp, int | float)
            or datetime.fromtimestamp(exp, UTC) <= now
            or not claims.get("sub")
        ):
            raise AuthentikFailedClosed("ID token claims don't check out")
        return claims

    # --- plumbing ----------------------------------------------------------

    @asynccontextmanager
    async def _client(self, attempt: LoginAttempt) -> AsyncIterator[httpx.AsyncClient]:
        """An HTTP client carrying this attempt's Authentik session cookies."""
        headers = {"Accept": "application/json"}
        if attempt.client_ip:
            # Authentik trusts the Portal as a proxy for the client IP.
            headers["CF-Connecting-IP"] = attempt.client_ip
            headers["X-Forwarded-For"] = attempt.client_ip
        async with httpx.AsyncClient(
            base_url=self._settings.authentik_url,
            transport=self._transport,
            cookies=attempt.cookies,
            headers=headers,
            follow_redirects=False,
            timeout=10.0,
        ) as client:
            try:
                yield client
            except httpx.HTTPError as e:
                raise AuthentikFailedClosed(f"Authentik unreachable: {e!r}") from e
            finally:
                attempt.cookies = client.cookies


def _expect(challenge: dict[str, Any], component: str) -> None:
    if challenge.get("component") != component:
        raise AuthentikFailedClosed(
            f"expected stage {component!r}, got {challenge.get('component')!r}"
        )


def _first_error(errors: Any) -> str:
    if isinstance(errors, dict):
        for messages in errors.values():
            if isinstance(messages, list) and messages:
                first = messages[0]
                if isinstance(first, dict) and first.get("string"):
                    return str(first["string"])
    return "Rejected."


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
