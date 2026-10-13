"""Base events other modules react to.

``Unclaimed`` fires when a base is Un-claimed, from its local UI (a signed
release) or on the Portal by its Operator. It runs inside the transaction
that deletes the base and writes the audit entry, just BEFORE the base row
is deleted (so rows that reference it can be removed first), and a hook's
writes commit (or roll back) with it. Shares (#94) hook in here to remove the base's Shares
and Pending shares:

    ctx.base_events.on_unclaimed(remove_shares)

where ``async def remove_shares(conn, event: Unclaimed) -> None``.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Literal

from sp_rtk_portal.db import Connection

BY_BASE = "base"
BY_PORTAL = "portal"


@dataclass(frozen=True)
class Unclaimed:
    base_id: str
    owner_account_id: int
    at: datetime
    by: Literal["base", "portal"]
    """Where the Un-claim came from: the base's local UI, or the Portal."""


UnclaimedHook = Callable[[Connection, Unclaimed], Awaitable[None]]


class BaseEvents:
    def __init__(self) -> None:
        self._unclaimed: list[UnclaimedHook] = []

    def on_unclaimed(self, hook: UnclaimedHook) -> None:
        self._unclaimed.append(hook)

    async def unclaimed(self, conn: Connection, event: Unclaimed) -> None:
        for hook in self._unclaimed:
            await hook(conn, event)
