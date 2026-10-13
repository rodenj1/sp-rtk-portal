"""Headless Authentik (ADR 0003): login, enrollment, recovery, TOTP setup and
password change, all on the Portal's own pages.

The Portal runs the pinned Portal flows through Authentik's flow executor API.
Each flow is driven the same way: the Portal answers the stages it was given
answers for, and stops at the first stage that needs the user (a TOTP code, an
emailed link) or ends the flow. A login (or a recovery, which signs the user
in) then completes OIDC authorization code + PKCE itself, as a
backend-for-frontend. The browser never talks to Authentik.

Anything unexpected (an unknown stage, a stage coming back without errors, a
redirect somewhere else, a bad token response) raises
``AuthentikFailedClosed``: the Portal shows an error and never follows
Authentik anywhere. The Portal keeps no Authentik tokens: they are read once
to learn who signed in, then dropped.

Emailed links land on the Portal (``/verify?t=`` and ``/reset?t=``). Opening
one runs the flow again with ``flow_token=<t>``, which makes Authentik restore
the paused flow in a new session, so the link works in any browser.
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
CAPTCHA = "ak-stage-captcha"
PROMPT = "ak-stage-prompt"
EMAIL = "ak-stage-email"
AUTHENTICATOR_VALIDATE = "ak-stage-authenticator-validate"
AUTHENTICATOR_TOTP = "ak-stage-authenticator-totp"
ACCESS_DENIED = "ak-stage-access-denied"
REDIRECT = "xak-flow-redirect"

CAPTCHA_FAILED = "The captcha check failed. Please try again."
# Hops back to the executor one request may take (each runs one stage).
MAX_HOPS = 10


class AuthentikFailedClosed(Exception):
    """Authentik did something the Portal doesn't expect. The flow stops."""


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
    """Authentik refused an answer. ``stage`` is the component it re-sent."""

    message: str
    stage: str = ""


@dataclass(frozen=True)
class EmailSent:
    """The flow paused until the user opens the emailed link."""


@dataclass(frozen=True)
class LinkExpired:
    """The emailed link was already used, or has expired."""


@dataclass(frozen=True)
class TotpSetup:
    """A new TOTP secret to show the user, waiting for a confirmation code."""

    config_url: str
    secret: str


@dataclass(frozen=True)
class Done:
    """The flow finished without signing anyone in."""


Outcome = Identity | NeedsTotp | Rejected | EmailSent | LinkExpired | TotpSetup | Done


@dataclass
class FlowAttempt:
    """One run of a flow. Lives server-side between the steps of a page."""

    client_ip: str | None
    slug: str = ""
    # The answer to give each stage, by component. Each is given once.
    answers: dict[str, dict[str, Any]] = field(default_factory=dict)
    answered: set[str] = field(default_factory=set)
    # Extra query for the first executor call (``flow_token``).
    query: dict[str, str] = field(default_factory=dict)
    # The Portal account a signed-in flow (TOTP setup) belongs to.
    account_id: int | None = None
    cookies: httpx.Cookies = field(default_factory=httpx.Cookies)
    state: str = field(default_factory=lambda: secrets.token_urlsafe(24))
    nonce: str = field(default_factory=lambda: secrets.token_urlsafe(24))
    code_verifier: str = field(default_factory=lambda: secrets.token_urlsafe(48))
    stage: str = ""
    # The challenge the flow stopped at last.
    challenge: dict[str, Any] = field(default_factory=dict)
    totp_setup: TotpSetup | None = None


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
        s = settings
        # Where each flow may stop. Anything else fails closed.
        self._endings: dict[str, frozenset[str]] = {
            s.login_flow_slug: frozenset({AUTHENTICATOR_VALIDATE, REDIRECT}),
            s.enrollment_flow_slug: frozenset({EMAIL, REDIRECT}),
            s.recovery_flow_slug: frozenset({EMAIL, AUTHENTICATOR_VALIDATE, REDIRECT}),
            s.totp_setup_flow_slug: frozenset({AUTHENTICATOR_TOTP, REDIRECT}),
            s.password_change_flow_slug: frozenset({AUTHENTICATOR_VALIDATE, REDIRECT}),
        }
        # The stages before the email stage. Getting one back after opening an
        # emailed link (``flow_token=``) means Authentik didn't accept the
        # token and started the flow over: the link was used or has expired.
        self._before_email: dict[str, frozenset[str]] = {
            s.enrollment_flow_slug: frozenset({CAPTCHA, PROMPT}),
            s.recovery_flow_slug: frozenset({CAPTCHA, IDENTIFICATION}),
        }

    # --- login -------------------------------------------------------------

    async def sign_in(
        self, email: str, password: str, client_ip: str | None
    ) -> tuple[FlowAttempt, Outcome]:
        """Start the login flow and submit email + password.

        Gives ``Identity``, ``NeedsTotp`` (then ``submit_code``) or ``Rejected``.
        """
        attempt = FlowAttempt(
            client_ip=client_ip,
            slug=self._settings.login_flow_slug,
            answers=_credentials(email, password),
        )
        return attempt, await self._start(attempt)

    async def submit_code(self, attempt: FlowAttempt, code: str) -> Outcome:
        """Answer the TOTP stage the flow stopped at: a sign-in code, or the
        code confirming a new TOTP device. ``Rejected`` allows another try."""
        if attempt.stage not in (AUTHENTICATOR_VALIDATE, AUTHENTICATOR_TOTP):
            raise AuthentikFailedClosed(f"code submitted at stage {attempt.stage!r}")
        body = {"component": attempt.stage, "code": code}
        challenge = await self._executor(attempt, "POST", body)
        if challenge.get("response_errors"):
            _expect(challenge, attempt.stage)
            return Rejected(_first_error(challenge["response_errors"]), attempt.stage)
        return await self._settle(attempt, await self._drive(attempt, challenge))

    # Kept for the login route's name for it.
    submit_totp = submit_code

    async def retry(
        self, attempt: FlowAttempt, component: str, answer: dict[str, Any]
    ) -> Outcome:
        """Answer again a stage that rejected its answer (e.g. a new password
        that didn't meet the policy), in the same flow session."""
        if attempt.challenge.get("component") != component:
            raise AuthentikFailedClosed(f"no rejected {component!r} to answer again")
        attempt.answers[component] = answer
        attempt.answered.discard(component)
        challenge = {
            k: v for k, v in attempt.challenge.items() if k != "response_errors"
        }
        return await self._settle(attempt, await self._drive(attempt, challenge))

    # --- enrollment ----------------------------------------------------------

    async def enroll(
        self,
        email: str,
        password: str,
        password_repeat: str,
        turnstile: str,
        client_ip: str | None,
    ) -> Outcome:
        """Start sign-up. Gives ``EmailSent`` or ``Rejected``."""
        attempt = FlowAttempt(
            client_ip=client_ip,
            slug=self._settings.enrollment_flow_slug,
            answers={
                CAPTCHA: {"token": turnstile},
                PROMPT: {
                    "username": email,
                    "email": email,
                    "password": password,
                    "password_repeat": password_repeat,
                },
            },
        )
        return await self._start(attempt)

    async def verify_email(self, token: str, client_ip: str | None) -> Outcome:
        """Finish sign-up from the emailed link. Gives ``Done`` or ``LinkExpired``."""
        attempt = FlowAttempt(
            client_ip=client_ip,
            slug=self._settings.enrollment_flow_slug,
            query={"flow_token": token},
        )
        return await self._start(attempt, from_link=True)

    # --- recovery --------------------------------------------------------------

    async def request_recovery(
        self, email: str, turnstile: str, client_ip: str | None
    ) -> Outcome:
        """Email a recovery link. Gives ``EmailSent`` (whether or not the
        account exists) or ``Rejected`` (the captcha)."""
        attempt = FlowAttempt(
            client_ip=client_ip,
            slug=self._settings.recovery_flow_slug,
            answers={
                CAPTCHA: {"token": turnstile},
                IDENTIFICATION: {"uid_field": email},
            },
        )
        outcome = await self._start(attempt)
        if isinstance(outcome, Rejected) and outcome.stage == ACCESS_DENIED:
            # Authentik's email stage refuses when no such user exists. Say
            # the same as for a real account, so emails can't be probed.
            return EmailSent()
        return outcome

    async def reset_password(
        self, token: str, password: str, password_repeat: str, client_ip: str | None
    ) -> tuple[FlowAttempt, Outcome]:
        """Set a new password from the emailed link; the user is then signed in.

        Gives ``Identity``, ``NeedsTotp`` (then ``submit_code``), ``Rejected``
        or ``LinkExpired``.
        """
        attempt = FlowAttempt(
            client_ip=client_ip,
            slug=self._settings.recovery_flow_slug,
            query={"flow_token": token},
            answers={
                PROMPT: {"password": password, "password_repeat": password_repeat}
            },
        )
        return attempt, await self._start(attempt, from_link=True)

    # --- a signed-in user's settings -------------------------------------------

    async def start_totp_setup(
        self, email: str, password: str, client_ip: str | None, account_id: int
    ) -> tuple[FlowAttempt, Outcome]:
        """Re-check the password and get a new TOTP secret.

        Gives ``TotpSetup`` (then ``submit_code`` with the app's code) or
        ``Rejected``.
        """
        attempt = FlowAttempt(
            client_ip=client_ip,
            slug=self._settings.totp_setup_flow_slug,
            answers=_credentials(email, password),
            account_id=account_id,
        )
        return attempt, await self._start(attempt)

    async def change_password(
        self,
        email: str,
        current: str,
        password: str,
        password_repeat: str,
        client_ip: str | None,
        account_id: int,
    ) -> tuple[FlowAttempt, Outcome]:
        """Gives ``Done``, ``NeedsTotp`` (then ``submit_code``) or ``Rejected``."""
        answers = _credentials(email, current)
        answers[PROMPT] = {"password": password, "password_repeat": password_repeat}
        attempt = FlowAttempt(
            client_ip=client_ip,
            slug=self._settings.password_change_flow_slug,
            answers=answers,
            account_id=account_id,
        )
        return attempt, await self._start(attempt)

    async def has_totp(self, sub: str) -> bool:
        """Whether the user has a TOTP device (admin API)."""
        return bool(await self._totp_devices(sub))

    async def remove_totp(self, sub: str) -> None:
        """Delete the user's TOTP devices (admin API): Authentik has no flow
        stage that removes one."""
        for device in await self._totp_devices(sub):
            await self._api("DELETE", f"/api/v3/authenticators/admin/totp/{device}/")

    async def deactivate_user(self, sub: str) -> None:
        """Deactivate the user (admin API): account deletion. They can no
        longer sign in, and Authentik keeps the record."""
        pk = await self._user_pk(sub)
        user = await self._api(
            "PATCH", f"/api/v3/core/users/{pk}/", json={"is_active": False}
        )
        if not isinstance(user, dict) or user.get("is_active") is not False:
            raise AuthentikFailedClosed("user wasn't deactivated")

    # --- flow executor ---------------------------------------------------

    async def _start(self, attempt: FlowAttempt, *, from_link: bool = False) -> Outcome:
        challenge = await self._executor(attempt, "GET")
        attempt.query = {}
        if (
            from_link
            and challenge.get("component") in self._before_email[attempt.slug]
            and not challenge.get("response_errors")
        ):
            return LinkExpired()
        return await self._settle(attempt, await self._drive(attempt, challenge))

    async def _drive(
        self, attempt: FlowAttempt, challenge: dict[str, Any]
    ) -> dict[str, Any]:
        """Answer every stage we have an answer for. Returns the challenge we
        stopped at: one that needs the user, an error, or the flow's end."""
        while True:
            component = str(challenge.get("component"))
            if challenge.get("response_errors") or component not in attempt.answers:
                return challenge
            if component in attempt.answered:
                raise AuthentikFailedClosed(f"stage {component!r} came back")
            attempt.answered.add(component)
            attempt.stage = component
            body = _answer(challenge, attempt.answers[component])
            challenge = await self._executor(attempt, "POST", body)

    async def _settle(self, attempt: FlowAttempt, challenge: dict[str, Any]) -> Outcome:
        attempt.challenge = challenge
        component = str(challenge.get("component"))
        if challenge.get("response_errors"):
            # Authentik re-sent the stage we answered: a wrong answer.
            _expect(challenge, attempt.stage)
            if component == CAPTCHA:
                return Rejected(CAPTCHA_FAILED, CAPTCHA)
            return Rejected(_first_error(challenge["response_errors"]), component)
        if component == ACCESS_DENIED:
            message = challenge.get("error_message") or "Access denied."
            return Rejected(str(message), ACCESS_DENIED)
        if component not in self._endings.get(attempt.slug, frozenset()):
            raise AuthentikFailedClosed(
                f"unexpected stage {component!r} after {attempt.stage!r}"
                f" in {attempt.slug!r}"
            )
        attempt.stage = component
        if component == AUTHENTICATOR_VALIDATE:
            classes = {
                d.get("device_class") for d in challenge.get("device_challenges", [])
            }
            if "totp" not in classes:
                raise AuthentikFailedClosed(f"unsupported authenticator {classes}")
            return NeedsTotp()
        if component == AUTHENTICATOR_TOTP:
            attempt.totp_setup = _totp_setup(challenge)
            return attempt.totp_setup
        if component == EMAIL:
            return EmailSent()
        # The flow ended (REDIRECT).
        if attempt.slug == self._settings.login_flow_slug:
            return await self._complete(attempt, str(challenge.get("to", "")))
        if attempt.slug == self._settings.recovery_flow_slug:
            # The restored plan may redirect wherever the first session asked;
            # the Portal never follows it, it asks for its own code instead.
            return await self._complete(attempt, None)
        return Done()

    async def _executor(
        self, attempt: FlowAttempt, method: str, body: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """One answer (or a GET) to the executor, through Authentik's hops.

        When a stage passes and more follow, Authentik answers with a hop
        back to the executor: an HTTP 302 to the same executor URL, or a
        ``xak-flow-redirect`` to it should the query string differ. Its own
        client then GETs it, which runs the next stage. The Portal does the
        same, and only for its own executor path: any other redirect is the
        caller's to judge."""
        query = {"next": self._authorize_path(attempt), **attempt.query}
        path = f"/api/v3/flows/executor/{attempt.slug}/"
        url = f"{path}?{urlencode({'query': urlencode(query)})}"
        async with self._client(attempt) as client:
            for _ in range(MAX_HOPS):
                resp = await client.request(method, url, json=body)
                if resp.status_code in (301, 302, 303, 307):
                    url = self._hop(resp.headers.get("location", ""), path)
                    method, body = "GET", None
                    continue
                if resp.status_code != 200:
                    raise AuthentikFailedClosed(
                        f"flow executor returned {resp.status_code}"
                    )
                challenge = resp.json()
                if not isinstance(challenge, dict):
                    raise AuthentikFailedClosed("flow executor returned a non-object")
                if challenge.get("component") == REDIRECT and _is_executor(
                    str(challenge.get("to", "")), path, self._settings.authentik_url
                ):
                    url = str(challenge["to"])
                    method, body = "GET", None
                    continue
                return challenge
        raise AuthentikFailedClosed("flow executor kept redirecting")

    def _hop(self, location: str, path: str) -> str:
        if not _is_executor(location, path, self._settings.authentik_url):
            raise AuthentikFailedClosed(f"flow executor redirected to {location!r}")
        return location

    # --- admin API ---------------------------------------------------------------

    async def _user_pk(self, sub: str) -> int:
        users = await self._api("GET", "/api/v3/core/users/", {"uuid": sub})
        results = users.get("results") if isinstance(users, dict) else None
        if not isinstance(results, list) or len(results) != 1:
            raise AuthentikFailedClosed("user lookup by uuid didn't find one user")
        pk = results[0].get("pk")
        if not isinstance(pk, int) or isinstance(pk, bool):
            raise AuthentikFailedClosed("user lookup gave no pk")
        return pk

    async def _totp_devices(self, sub: str) -> list[int]:
        pk = await self._user_pk(sub)
        devices = await self._api(
            "GET", "/api/v3/authenticators/admin/all/", {"user": str(pk)}
        )
        if not isinstance(devices, list):
            raise AuthentikFailedClosed("device list isn't a list")
        return [
            int(d["pk"])
            for d in devices
            if str(d.get("type", "")).lower().endswith("totpdevice")
        ]

    async def _api(
        self,
        method: str,
        path: str,
        params: dict[str, str] | None = None,
        json: dict[str, Any] | None = None,
    ) -> Any:
        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {self._settings.authentik_api_token}",
        }
        try:
            async with httpx.AsyncClient(
                base_url=self._settings.authentik_url,
                transport=self._transport,
                headers=headers,
                follow_redirects=False,
                timeout=10.0,
            ) as client:
                resp = await client.request(method, path, params=params, json=json)
        except httpx.HTTPError as e:
            raise AuthentikFailedClosed(f"Authentik unreachable: {e!r}") from e
        if resp.status_code == 204:
            return None
        if resp.status_code != 200:
            raise AuthentikFailedClosed(f"{method} {path} returned {resp.status_code}")
        return resp.json()

    # --- OIDC code + PKCE, server-side -----------------------------------

    def _authorize_path(self, attempt: FlowAttempt) -> str:
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

    async def _complete(self, attempt: FlowAttempt, to: str | None) -> Identity:
        """Get a code for this attempt's Authentik session and redeem it.
        ``to`` (where the flow redirected) must be our own authorize URL, unless
        None: then the redirect is ignored rather than followed."""
        base = self._settings.authentik_url
        expected = urljoin(base, self._authorize_path(attempt))
        if to is not None and urljoin(base + "/", to) != expected:
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

    def _code_from(self, resp: httpx.Response, attempt: FlowAttempt) -> str:
        location = resp.headers.get("location", "")
        if resp.status_code not in (302, 303) or not location.startswith(
            self._settings.oidc_redirect_uri + "?"
        ):
            raise AuthentikFailedClosed("authorize didn't return a code")
        query = parse_qs(urlsplit(location).query)
        if query.get("state") != [attempt.state] or "code" not in query:
            raise AuthentikFailedClosed("authorize returned a bad state or no code")
        return query["code"][0]

    def _id_token_claims(self, id_token: str, attempt: FlowAttempt) -> dict[str, Any]:
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
    async def _client(self, attempt: FlowAttempt) -> AsyncIterator[httpx.AsyncClient]:
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


def _credentials(email: str, password: str) -> dict[str, dict[str, Any]]:
    """Answers for an identification stage, with or without its own password
    field, and for a separate password stage."""
    return {
        IDENTIFICATION: {"uid_field": email, "password": password},
        PASSWORD: {"password": password},
    }


def _answer(challenge: dict[str, Any], answer: dict[str, Any]) -> dict[str, Any]:
    component = challenge["component"]
    body = dict(answer)
    if component == IDENTIFICATION and not challenge.get("password_fields"):
        body.pop("password", None)  # a separate password stage follows
    if component == PROMPT:
        # Fill exactly the fields the pinned prompt has; any field we have no
        # answer for means the flow changed.
        keys = [f.get("field_key") for f in challenge.get("fields", [])]
        missing = [k for k in keys if k not in answer]
        if missing:
            raise AuthentikFailedClosed(f"prompt asks for unknown fields {missing}")
        body = {k: answer[k] for k in keys}
    return {"component": component, **body}


def _totp_setup(challenge: dict[str, Any]) -> TotpSetup:
    url = str(challenge.get("config_url", ""))
    parts = urlsplit(url)
    secret = parse_qs(parts.query).get("secret", [""])[0]
    if parts.scheme != "otpauth" or parts.netloc != "totp" or not secret:
        raise AuthentikFailedClosed("TOTP setup without a usable otpauth URL")
    return TotpSetup(config_url=url, secret=secret)


def _is_executor(location: str, path: str, authentik_url: str) -> bool:
    """Whether ``location`` is this flow's executor on our Authentik."""
    parts = urlsplit(location)
    own = urlsplit(authentik_url)
    same_host = not parts.netloc or (parts.scheme, parts.netloc) == (
        own.scheme,
        own.netloc,
    )
    return same_host and parts.path == path


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
