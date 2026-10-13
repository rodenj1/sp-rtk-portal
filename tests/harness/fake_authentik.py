"""A fake Authentik at its HTTP API: the flow executor, the OIDC endpoints and
the few admin API calls the Portal makes.

The Portal reaches it through ``transport()``, the same way it would reach the
real one over HTTPS, so the Portal's whole headless path is exercised.

Each Portal flow is a list of stages, mirroring the blueprint (#102):

- ``portal-login``: identification (with password) → deny unless in
  ``portal-users`` → TOTP if the user has one → login.
- ``portal-enrollment``: Turnstile → prompt (username, email, password,
  password_repeat) → user write (inactive, into ``portal-users``) →
  verification email (link to ``/verify?t=``) → login.
- ``portal-recovery``: Turnstile → identification (email only, pretends unknown
  users exist, so the email stage then denies access) → deny unless in
  ``portal-users`` → recovery email (link to ``/reset?t=``) → TOTP if the user
  has one → prompt (password, password_repeat) → user write → login.
- ``portal-totp-setup``: identification (with password) → deny unless in
  ``portal-users`` → TOTP setup.
- ``portal-password-change``: identification (with password) → deny unless in
  ``portal-users`` → TOTP if the user has one → prompt (password,
  password_repeat) → user write.

The deny stage answers ``ak-stage-access-denied`` (``DENY_MESSAGE``) for a
known user outside ``portal-users`` (e.g. a homelab admin) and ends the flow.

Scripting:

- ``add_user(email, password, totp=...)`` creates an account. ``totp`` is a
  fixed code the login flow then asks for; a TOTP device set up through the
  Portal uses a real RFC 6238 secret instead (``totp_code(secret)``).
- ``script_challenge({...})`` makes the next executor response that challenge
  instead of the real next stage, to test fail-closed handling.
- ``executor_requests`` records the headers of every executor call, e.g. to
  check that the client IP reaches Authentik; ``executor_calls`` records
  ``(method, slug)`` of each.
- ``outbox`` holds the emails the flows sent (``SentEmail.link``).
- ``turnstile_token`` is the one captcha answer Cloudflare would accept.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import struct
import uuid
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, quote, urlencode

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response

from .clock import FakeClock

SESSION_COOKIE = "authentik_session"
PORTAL_ORIGIN = "https://sp-rtk-base.big-spray.com"
PORTAL_USERS = "portal-users"
# The blueprint's deny stage message. The Portal must never show it.
DENY_MESSAGE = "This account can't use the SP RTK Portal."


@dataclass
class FakeUser:
    email: str
    password: str
    totp: str | None = None
    email_verified: bool = True
    is_active: bool = True
    # Accounts made by the Portal's sign-up are in portal-users; pass e.g.
    # ``groups=["admins"]`` for one that isn't (a homelab admin).
    groups: list[str] = field(default_factory=lambda: [PORTAL_USERS])
    totp_secret: str | None = None
    sub: str = field(default_factory=lambda: str(uuid.uuid4()))
    pk: int = field(default_factory=lambda: secrets.randbelow(10**6) + 1)

    @property
    def has_totp(self) -> bool:
        return bool(self.totp or self.totp_secret)


@dataclass(frozen=True)
class SentEmail:
    to: str
    subject: str
    link: str


@dataclass
class _FlowSession:
    slug: str
    next_url: str
    index: int = 0
    user: FakeUser | None = None
    authenticated: bool = False
    prompt: dict[str, Any] = field(default_factory=dict)
    totp_secret: str | None = None


@dataclass
class _Grant:
    user: FakeUser
    client_id: str
    redirect_uri: str
    code_challenge: str
    nonce: str | None


FLOWS: dict[str, list[str]] = {
    "portal-login": [
        "identification+password",
        "deny-non-portal-users",
        "validate",
        "login",
    ],
    "portal-enrollment": [
        "captcha",
        "prompt-enrollment",
        "user-write-new",
        "email-verify",
        "login",
    ],
    "portal-recovery": [
        "captcha",
        "identification",
        "deny-non-portal-users",
        "email-recovery",
        "validate",
        "prompt-password",
        "user-write",
        "login",
    ],
    "portal-totp-setup": [
        "identification+password",
        "deny-non-portal-users",
        "totp-setup",
    ],
    "portal-password-change": [
        "identification+password",
        "deny-non-portal-users",
        "validate",
        "prompt-password",
        "user-write",
    ],
}

_INVALID_LOGIN = {
    "non_field_errors": [{"string": "Failed to authenticate.", "code": "invalid"}]
}


class FakeAuthentik:
    base_url = "https://auth.example.test"
    login_flow_slug = "portal-login"
    enrollment_flow_slug = "portal-enrollment"
    recovery_flow_slug = "portal-recovery"
    totp_setup_flow_slug = "portal-totp-setup"
    password_change_flow_slug = "portal-password-change"
    app_slug = "sp-rtk-portal"
    client_id = "portal-client-id"
    client_secret = "portal-client-secret"
    api_token = "portal-api-token"
    turnstile_site_key = "1x00000000000000000000AA"
    turnstile_token = "turnstile-pass"

    def __init__(self, clock: FakeClock) -> None:
        self.clock = clock
        self.users: dict[str, FakeUser] = {}
        self.outbox: list[SentEmail] = []
        self.executor_requests: list[httpx.Headers] = []
        self.executor_calls: list[tuple[str, str]] = []
        self.api_calls: list[tuple[str, str]] = []
        self._scripted: list[dict[str, Any]] = []
        self._sessions: dict[str, _FlowSession] = {}
        self._flow_tokens: dict[str, _FlowSession] = {}
        self._grants: dict[str, _Grant] = {}
        self._access_tokens: dict[str, FakeUser] = {}
        self.app = self._build_app()

    @property
    def issuer(self) -> str:
        return f"{self.base_url}/application/o/{self.app_slug}/"

    def transport(self) -> httpx.AsyncBaseTransport:
        return httpx.ASGITransport(app=self.app)

    # --- scripting -------------------------------------------------------

    def add_user(self, email: str, password: str, **kwargs: Any) -> FakeUser:
        user = FakeUser(email=email, password=password, **kwargs)
        self.users[email.lower()] = user
        return user

    def change_email(self, user: FakeUser, email: str) -> None:
        self.users.pop(user.email.lower(), None)
        user.email = email
        self.users[email.lower()] = user

    def script_challenge(self, challenge: dict[str, Any]) -> None:
        self._scripted.append(challenge)

    def totp_code(self, secret: str) -> str:
        """The code an authenticator app shows for ``secret`` right now."""
        return _totp(secret, int(self.clock.now().timestamp()))

    # --- the fake API ----------------------------------------------------

    def _build_app(self) -> FastAPI:
        app = FastAPI()
        executor = "/api/v3/flows/executor/{slug}/"
        app.get(executor)(self._executor_get)
        app.post(executor)(self._executor_post)
        app.get("/application/o/authorize/")(self._authorize)
        app.post("/application/o/token/")(self._token)
        app.get("/application/o/userinfo/")(self._userinfo)
        app.get("/api/v3/core/users/")(self._api_users)
        app.patch("/api/v3/core/users/{pk}/")(self._api_patch_user)
        app.get("/api/v3/authenticators/admin/all/")(self._api_devices)
        app.delete("/api/v3/authenticators/admin/totp/{pk}/")(self._api_delete_totp)
        return app

    def _respond(self, challenge: dict[str, Any]) -> JSONResponse:
        if self._scripted:
            challenge = self._scripted.pop(0)
        return JSONResponse(challenge)

    async def _executor_get(self, slug: str, request: Request) -> Response:
        self.executor_requests.append(httpx.Headers(request.headers.items()))
        self.executor_calls.append(("GET", slug))
        if slug not in FLOWS:
            return JSONResponse({"detail": "Not found."}, status_code=404)
        query = parse_qs(request.query_params.get("query", ""))
        next_url = query.get("next", ["/"])[0]
        token = query.get("flow_token", [""])[0]
        session = self._flow_tokens.pop(token, None)
        if session is not None and session.slug == slug:
            # The emailed link was opened: the email stage is done, and the
            # plan carries on in this new session.
            session.index += 1
            if session.user is not None and slug == self.enrollment_flow_slug:
                session.user.is_active = True
                session.user.email_verified = True
            session.next_url = next_url
        else:
            session = _FlowSession(slug=slug, next_url=next_url)
        session_id = secrets.token_urlsafe(16)
        self._sessions[session_id] = session
        resp = self._respond(self._run(session))
        resp.set_cookie(SESSION_COOKIE, session_id, httponly=True, secure=True)
        return resp

    async def _executor_post(self, slug: str, request: Request) -> Response:
        self.executor_requests.append(httpx.Headers(request.headers.items()))
        self.executor_calls.append(("POST", slug))
        session = self._sessions.get(request.cookies.get(SESSION_COOKIE, ""))
        if session is None or session.slug != slug:
            return JSONResponse({"detail": "No flow in progress."}, status_code=400)
        stages = FLOWS[slug]
        if session.index >= len(stages):
            return JSONResponse({"detail": "Flow already done."}, status_code=400)
        body = await request.json()
        error = self._answer(session, stages[session.index], body)
        if error is not None:
            return self._respond(error)
        session.index += 1
        return self._respond(self._run(session))

    # --- the stage machine ---------------------------------------------------

    def _run(self, session: _FlowSession) -> dict[str, Any]:
        """Run stages without a challenge until one needs the client."""
        stages = FLOWS[session.slug]
        while session.index < len(stages):
            challenge = self._challenge(session, stages[session.index])
            if challenge is not None:
                return challenge
            session.index += 1
        return {"component": "xak-flow-redirect", "to": session.next_url}

    def _challenge(self, session: _FlowSession, stage: str) -> dict[str, Any] | None:
        user = session.user
        match stage:
            case "identification+password":
                return _identification(password_fields=True)
            case "identification":
                return _identification(password_fields=False)
            case "captcha":
                return _captcha(self.turnstile_site_key)
            case "prompt-enrollment" | "prompt-password":
                return _prompt(_prompt_fields(stage))
            case "validate":
                return _authenticator_validate() if user and user.has_totp else None
            case "totp-setup":
                assert user is not None
                session.totp_secret = session.totp_secret or _new_secret()
                return _totp_setup(user.email, session.totp_secret)
            case "email-verify" | "email-recovery":
                if user is None:
                    # Like Authentik's email stage with no pending user.
                    return {
                        "component": "ak-stage-access-denied",
                        "error_message": "No pending user.",
                    }
                self._send_email(session, stage)
                return {"component": "ak-stage-email", "flow_info": {}}
            case "user-write-new":
                data = session.prompt
                new = self.add_user(
                    data["email"],
                    data["password"],
                    is_active=False,
                    groups=[PORTAL_USERS],
                )
                new.email_verified = False
                session.user = new
                return None
            case "user-write":
                assert user is not None
                user.password = session.prompt["password"]
                return None
            case "deny-non-portal-users":
                # The blueprint's deny stage, bound with a negated portal-users
                # group policy: it runs only for a known user outside the group
                # (an unknown address in recovery has no saved user, so it's
                # skipped). It ends the flow.
                if user is None or PORTAL_USERS in user.groups:
                    return None
                session.index = len(FLOWS[session.slug])
                return {
                    "component": "ak-stage-access-denied",
                    "error_message": DENY_MESSAGE,
                }
            case "login":
                session.authenticated = True
                return None
        raise AssertionError(f"unknown stage {stage}")

    def _answer(
        self, session: _FlowSession, stage: str, body: dict[str, Any]
    ) -> dict[str, Any] | None:
        """Check the client's answer. Returns the stage re-sent with errors,
        or None to move on."""
        user = session.user
        match stage:
            case "identification+password":
                found = self.users.get(str(body.get("uid_field", "")).lower())
                if (
                    found is None
                    or not found.is_active
                    or body.get("password") != found.password
                ):
                    return _identification(password_fields=True, errors=_INVALID_LOGIN)
                session.user = found
            case "identification":
                # Pretends unknown users exist: the flow carries on silently.
                found = self.users.get(str(body.get("uid_field", "")).lower())
                session.user = found if found and found.is_active else None
            case "captcha":
                if body.get("token") != self.turnstile_token:
                    return _captcha(self.turnstile_site_key, errors=_error("token"))
            case "prompt-enrollment" | "prompt-password":
                fields = _prompt_fields(stage)
                errors = _prompt_errors(body, fields, self.users, stage)
                if errors:
                    return _prompt(fields, errors=errors)
                session.prompt = {k: body[k] for k in fields}
            case "validate":
                assert user is not None
                if not self._totp_ok(user, body.get("code")):
                    return _authenticator_validate(
                        errors=_error("code", "Invalid Token")
                    )
            case "totp-setup":
                assert user is not None and session.totp_secret is not None
                if body.get("code") != self.totp_code(session.totp_secret):
                    return _totp_setup(
                        user.email,
                        session.totp_secret,
                        errors=_error("code", "Code does not match"),
                    )
                user.totp_secret = session.totp_secret
            case "email-verify" | "email-recovery":
                # Answering the email stage doesn't move it on: only the link does.
                return {"component": "ak-stage-email", "flow_info": {}}
        return None

    def _totp_ok(self, user: FakeUser, code: Any) -> bool:
        if user.totp is not None and code == user.totp:
            return True
        return user.totp_secret is not None and code == self.totp_code(user.totp_secret)

    def _send_email(self, session: _FlowSession, stage: str) -> None:
        assert session.user is not None
        token = secrets.token_urlsafe(24)
        self._flow_tokens[token] = session
        # The blueprint's custom templates (#102): the link lands on the Portal.
        if stage == "email-verify":
            path, subject = "/verify", "Confirm your email"
        else:
            path, subject = "/reset", "Reset your password"
        link = f"{PORTAL_ORIGIN}{path}?t={quote(token)}"
        self.outbox.append(SentEmail(to=session.user.email, subject=subject, link=link))

    # --- admin API (the Portal's service account token) ------------------------

    def _api_allowed(self, request: Request) -> bool:
        self.api_calls.append((request.method, request.url.path))
        return request.headers.get("authorization") == f"Bearer {self.api_token}"

    def _by_pk(self, pk: int) -> FakeUser | None:
        return next((u for u in self.users.values() if u.pk == pk), None)

    async def _api_users(self, request: Request) -> Response:
        if not self._api_allowed(request):
            return JSONResponse({"detail": "Unauthorized"}, status_code=403)
        wanted = request.query_params.get("uuid")
        found = [u for u in self.users.values() if u.sub == wanted]
        results = [{"pk": u.pk, "uuid": u.sub, "email": u.email} for u in found]
        return JSONResponse({"pagination": {"count": len(results)}, "results": results})

    async def _api_patch_user(self, pk: int, request: Request) -> Response:
        """Only ``is_active`` (account deletion deactivates the user)."""
        if not self._api_allowed(request):
            return JSONResponse({"detail": "Unauthorized"}, status_code=403)
        user = self._by_pk(pk)
        if user is None:
            return JSONResponse({"detail": "Not found."}, status_code=404)
        body = await request.json()
        if set(body) != {"is_active"} or not isinstance(body["is_active"], bool):
            return JSONResponse({"detail": "unexpected fields"}, status_code=400)
        user.is_active = body["is_active"]
        return JSONResponse(
            {"pk": user.pk, "uuid": user.sub, "is_active": user.is_active}
        )

    async def _api_devices(self, request: Request) -> Response:
        if not self._api_allowed(request):
            return JSONResponse({"detail": "Unauthorized"}, status_code=403)
        user = self._by_pk(int(request.query_params.get("user", "0")))
        devices = []
        if user is not None and user.has_totp:
            devices.append(
                {
                    "pk": user.pk,
                    "name": "Authenticator app",
                    "type": "authentik_stages_authenticator_totp.TOTPDevice",
                    "confirmed": True,
                }
            )
        return JSONResponse(devices)

    async def _api_delete_totp(self, pk: int, request: Request) -> Response:
        if not self._api_allowed(request):
            return JSONResponse({"detail": "Unauthorized"}, status_code=403)
        user = self._by_pk(pk)
        if user is None or not user.has_totp:
            return JSONResponse({"detail": "Not found."}, status_code=404)
        user.totp = None
        user.totp_secret = None
        return Response(status_code=204)

    # --- OIDC ------------------------------------------------------------------

    async def _authorize(self, request: Request) -> Response:
        session = self._sessions.get(request.cookies.get(SESSION_COOKIE, ""))
        q = request.query_params
        if session is None or not session.authenticated or session.user is None:
            # The real Authentik would bounce the browser to its login page.
            return RedirectResponse(f"{self.base_url}/if/flow/login/", status_code=302)
        if (
            q.get("client_id") != self.client_id
            or q.get("response_type") != "code"
            or q.get("code_challenge_method") != "S256"
            or "openid" not in q.get("scope", "").split()
        ):
            return JSONResponse({"error": "invalid_request"}, status_code=400)
        code = secrets.token_urlsafe(16)
        self._grants[code] = _Grant(
            user=session.user,
            client_id=q["client_id"],
            redirect_uri=q["redirect_uri"],
            code_challenge=q["code_challenge"],
            nonce=q.get("nonce"),
        )
        params = urlencode({"code": code, "state": q.get("state", "")})
        return RedirectResponse(f"{q['redirect_uri']}?{params}", status_code=302)

    async def _token(self, request: Request) -> Response:
        form = await request.form()
        grant = self._grants.pop(str(form.get("code", "")), None)
        verifier = str(form.get("code_verifier", ""))
        if (
            grant is None
            or form.get("grant_type") != "authorization_code"
            or form.get("client_id") != self.client_id
            or form.get("client_secret") != self.client_secret
            or form.get("redirect_uri") != grant.redirect_uri
            or _s256(verifier) != grant.code_challenge
        ):
            return JSONResponse({"error": "invalid_grant"}, status_code=400)
        access_token = secrets.token_urlsafe(24)
        self._access_tokens[access_token] = grant.user
        now = int(self.clock.now().timestamp())
        claims = {
            "iss": self.issuer,
            "aud": self.client_id,
            "sub": grant.user.sub,
            "iat": now,
            "exp": now + 300,
            "nonce": grant.nonce,
        }
        return JSONResponse(
            {
                "access_token": access_token,
                "token_type": "Bearer",
                "expires_in": 300,
                "id_token": _unsigned_jwt(claims),
            }
        )

    async def _userinfo(self, request: Request) -> Response:
        token = request.headers.get("authorization", "").removeprefix("Bearer ")
        user = self._access_tokens.get(token)
        if user is None:
            return JSONResponse({"error": "invalid_token"}, status_code=401)
        return JSONResponse(
            {
                "sub": user.sub,
                "email": user.email,
                "email_verified": user.email_verified,
            }
        )


# --- challenges, shaped like Authentik's ------------------------------------------


def _error(key: str, text: str = "Failed to validate token") -> dict[str, Any]:
    return {key: [{"string": text, "code": "invalid"}]}


def _with_errors(
    challenge: dict[str, Any], errors: dict[str, Any] | None
) -> dict[str, Any]:
    if errors:
        challenge["response_errors"] = errors
    return challenge


def _identification(
    *, password_fields: bool, errors: dict[str, Any] | None = None
) -> dict[str, Any]:
    return _with_errors(
        {
            "component": "ak-stage-identification",
            "user_fields": ["email"],
            "password_fields": password_fields,
            "flow_info": {"title": "Portal"},
        },
        errors,
    )


def _captcha(site_key: str, errors: dict[str, Any] | None = None) -> dict[str, Any]:
    return _with_errors(
        {
            "component": "ak-stage-captcha",
            "site_key": site_key,
            "js_url": "https://challenges.cloudflare.com/turnstile/v0/api.js",
        },
        errors,
    )


def _prompt(fields: list[str], errors: dict[str, Any] | None = None) -> dict[str, Any]:
    kinds = {"email": "email", "password": "password", "password_repeat": "password"}
    return _with_errors(
        {
            "component": "ak-stage-prompt",
            "fields": [
                {"field_key": k, "type": kinds.get(k, "text"), "required": True}
                for k in fields
            ],
        },
        errors,
    )


def _prompt_fields(stage: str) -> list[str]:
    if stage == "prompt-enrollment":
        return ["username", "email", "password", "password_repeat"]
    return ["password", "password_repeat"]


def _prompt_errors(
    body: dict[str, Any], fields: list[str], users: dict[str, FakeUser], stage: str
) -> dict[str, Any]:
    errors: dict[str, Any] = {}
    for key in fields:
        if not body.get(key):
            errors |= _error(key, "This field is required.")
    if body.get("password") != body.get("password_repeat"):
        errors |= _error("non_field_errors", "Passwords don't match.")
    elif len(str(body.get("password", ""))) < 8:
        errors |= _error("password", "Password is too short.")
    if stage == "prompt-enrollment" and str(body.get("email", "")).lower() in users:
        errors |= _error("email", "Email address already in use.")
    return errors


def _authenticator_validate(errors: dict[str, Any] | None = None) -> dict[str, Any]:
    return _with_errors(
        {
            "component": "ak-stage-authenticator-validate",
            "device_challenges": [
                {"device_class": "totp", "device_uid": "1", "challenge": {}}
            ],
        },
        errors,
    )


def _totp_setup(
    email: str, secret: str, errors: dict[str, Any] | None = None
) -> dict[str, Any]:
    label = quote(f"authentik:{email}")
    config_url = (
        f"otpauth://totp/{label}?secret={secret}&algorithm=SHA1&digits=6&period=30"
        "&issuer=authentik"
    )
    return _with_errors(
        {"component": "ak-stage-authenticator-totp", "config_url": config_url}, errors
    )


def _new_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _totp(secret: str, unix_time: int) -> str:
    key = base64.b32decode(secret + "=" * (-len(secret) % 8))
    digest = hmac.new(key, struct.pack(">Q", unix_time // 30), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    number = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return f"{number % 1_000_000:06d}"


def _s256(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def _unsigned_jwt(claims: dict[str, Any]) -> str:
    def b64(obj: dict[str, Any]) -> str:
        raw = json.dumps(obj).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    # The Portal reads the ID token straight from the token endpoint over TLS
    # (OIDC Core 3.1.3.7), so it checks claims, not the signature.
    return f"{b64({'alg': 'RS256', 'typ': 'JWT'})}.{b64(claims)}.c2ln"
