"""Account events other modules react to.

``PasswordChanged`` fires when a user changes their password on the account
page, or sets a new one through recovery. It runs inside the transaction that
records the change, so a hook's writes commit (or roll back) with it. Log out
everywhere (#96) hooks in here to end the account's other sessions:

    ctx.account_events.on_password_changed(end_other_sessions)

where ``async def end_other_sessions(conn, event: PasswordChanged) -> None``.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Literal

from sp_rtk_portal.db import Connection

CHANGE = "change"
RECOVERY = "recovery"


@dataclass(frozen=True)
class PasswordChanged:
    account_id: int
    at: datetime
    how: Literal["change", "recovery"]
    # The session that made the change, which stays signed in. None after a
    # recovery: the hook runs before the recovering browser's new session
    # starts, so every existing session can go.
    keep_session_token: str | None


PasswordChangedHook = Callable[[Connection, PasswordChanged], Awaitable[None]]


class AccountEvents:
    def __init__(self) -> None:
        self._password_changed: list[PasswordChangedHook] = []

    def on_password_changed(self, hook: PasswordChangedHook) -> None:
        self._password_changed.append(hook)

    async def password_changed(self, conn: Connection, event: PasswordChanged) -> None:
        for hook in self._password_changed:
            await hook(conn, event)
