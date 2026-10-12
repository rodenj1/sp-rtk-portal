"""Login attempts waiting for their next step (the TOTP code).

Held in memory: the Portal runs as a single instance (spec), and losing them
on restart only means typing the password again. The browser holds a random
key in a short-lived ``__Host-`` cookie.
"""

from __future__ import annotations

import secrets
from datetime import datetime, timedelta

from sp_rtk_portal.accounts.authentik import LoginAttempt

COOKIE = "__Host-portal_login"


class PendingAttempts:
    def __init__(self, lifetime: timedelta) -> None:
        self.lifetime = lifetime
        self._items: dict[str, tuple[datetime, LoginAttempt]] = {}

    def put(self, attempt: LoginAttempt, now: datetime) -> str:
        self._expire(now)
        key = secrets.token_urlsafe(32)
        self._items[key] = (now + self.lifetime, attempt)
        return key

    def get(self, key: str | None, now: datetime) -> LoginAttempt | None:
        self._expire(now)
        item = self._items.get(key or "")
        return item[1] if item else None

    def drop(self, key: str | None) -> None:
        self._items.pop(key or "", None)

    def _expire(self, now: datetime) -> None:
        for key in [k for k, (exp, _) in self._items.items() if exp <= now]:
            del self._items[key]
