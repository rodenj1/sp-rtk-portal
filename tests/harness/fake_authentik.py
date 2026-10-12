"""A fake Authentik at its HTTP API: the flow executor and the OIDC endpoints.

The Portal reaches it through ``transport()``, the same way it would reach the
real one over HTTPS, so the Portal's whole headless-login path is exercised.

Scripting:

- ``add_user(email, password, totp=...)`` creates an account. With ``totp`` the
  login flow asks for that code after the password.
- ``script_challenge({...})`` makes the next executor response that challenge
  instead of the real next stage, to test fail-closed handling.
- ``executor_requests`` records the headers of every executor call, e.g. to
  check that the client IP reaches Authentik.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import uuid
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, urlencode

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response

from .clock import FakeClock

SESSION_COOKIE = "authentik_session"


@dataclass
class FakeUser:
    email: str
    password: str
    totp: str | None = None
    email_verified: bool = True
    sub: str = field(default_factory=lambda: str(uuid.uuid4()))


@dataclass
class _FlowSession:
    next_url: str
    stage: str = "identification"
    user: FakeUser | None = None
    authenticated: bool = False


@dataclass
class _Grant:
    user: FakeUser
    client_id: str
    redirect_uri: str
    code_challenge: str
    nonce: str | None


class FakeAuthentik:
    base_url = "https://auth.example.test"
    login_flow_slug = "portal-login"
    app_slug = "sp-rtk-portal"
    client_id = "portal-client-id"
    client_secret = "portal-client-secret"

    def __init__(self, clock: FakeClock) -> None:
        self.clock = clock
        self.users: dict[str, FakeUser] = {}
        self.executor_requests: list[httpx.Headers] = []
        self._scripted: list[dict[str, Any]] = []
        self._sessions: dict[str, _FlowSession] = {}
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

    # --- the fake API ----------------------------------------------------

    def _build_app(self) -> FastAPI:
        app = FastAPI()
        executor = "/api/v3/flows/executor/{slug}/"
        app.get(executor)(self._executor_get)
        app.post(executor)(self._executor_post)
        app.get("/application/o/authorize/")(self._authorize)
        app.post("/application/o/token/")(self._token)
        app.get("/application/o/userinfo/")(self._userinfo)
        return app

    def _challenge(self, challenge: dict[str, Any]) -> JSONResponse:
        if self._scripted:
            challenge = self._scripted.pop(0)
        return JSONResponse(challenge)

    async def _executor_get(self, slug: str, request: Request) -> Response:
        self.executor_requests.append(httpx.Headers(request.headers.items()))
        if slug != self.login_flow_slug:
            return JSONResponse({"detail": "Not found."}, status_code=404)
        query = parse_qs(request.query_params.get("query", ""))
        session_id = secrets.token_urlsafe(16)
        self._sessions[session_id] = _FlowSession(next_url=query["next"][0])
        resp = self._challenge(_identification())
        resp.set_cookie(SESSION_COOKIE, session_id, httponly=True, secure=True)
        return resp

    async def _executor_post(self, slug: str, request: Request) -> Response:
        self.executor_requests.append(httpx.Headers(request.headers.items()))
        session = self._sessions.get(request.cookies.get(SESSION_COOKIE, ""))
        if session is None or slug != self.login_flow_slug:
            return JSONResponse({"detail": "No flow in progress."}, status_code=400)
        body = await request.json()
        if session.stage == "identification":
            user = self.users.get(str(body.get("uid_field", "")).lower())
            if user is None or body.get("password") != user.password:
                return self._challenge(
                    _identification(
                        errors={
                            "non_field_errors": [
                                {"string": "Failed to authenticate.", "code": "invalid"}
                            ]
                        }
                    )
                )
            session.user = user
            if user.totp:
                session.stage = "totp"
                return self._challenge(_authenticator_validate())
        elif session.stage == "totp":
            assert session.user is not None
            if body.get("code") != session.user.totp:
                return self._challenge(
                    _authenticator_validate(
                        errors={
                            "code": [{"string": "Invalid Token", "code": "invalid"}]
                        }
                    )
                )
        session.stage = "done"
        session.authenticated = True
        return self._challenge(
            {"component": "xak-flow-redirect", "to": session.next_url}
        )

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


def _identification(errors: dict[str, Any] | None = None) -> dict[str, Any]:
    challenge: dict[str, Any] = {
        "component": "ak-stage-identification",
        "user_fields": ["email"],
        "password_fields": True,
        "flow_info": {"title": "Portal login"},
    }
    if errors:
        challenge["response_errors"] = errors
    return challenge


def _authenticator_validate(errors: dict[str, Any] | None = None) -> dict[str, Any]:
    challenge: dict[str, Any] = {
        "component": "ak-stage-authenticator-validate",
        "device_challenges": [
            {"device_class": "totp", "device_uid": "1", "challenge": {}}
        ],
    }
    if errors:
        challenge["response_errors"] = errors
    return challenge


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
