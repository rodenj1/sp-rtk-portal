"""Reading the audit log: which entries a user may see, and how they read.

An Operator sees every entry about their bases (the ones they own now, and
ones they Claimed in the last 90 days and have since Un-claimed), whoever
acted. Everyone also sees their own entries, and the entries that name
them as the Shared user (a Share given to them or taken away). Nothing
else: a Shared user never sees other users of the base. On an entry that
is only theirs because it names them, someone else's IP and email are
hidden ("The Operator").

Entries of a kind this module doesn't know (written by a later ticket)
still show: their kind as words, plus their detail when the viewer may see
the whole entry.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sp_rtk_portal.db import Connection

RETENTION = timedelta(days=90)
PAGE_SIZE = 200

_VISIBLE = """
WITH mine AS (
    SELECT id AS base_id FROM base WHERE owner_account_id = %(me)s
    UNION
    SELECT base_id FROM audit_entry
     WHERE kind = 'claim' AND account_id = %(me)s AND base_id IS NOT NULL
)
SELECT e.id, e.at, e.kind, e.account_id, a.email, e.base_id,
       host(e.ip) AS ip, e.detail,
       e.base_id IN (SELECT base_id FROM mine) AS as_operator,
       COALESCE(
           b.name,
           (SELECT c.detail->>'name' FROM audit_entry c
             WHERE c.base_id = e.base_id AND c.kind IN ('claim', 'unclaim')
               AND c.detail ? 'name'
             ORDER BY c.at DESC, c.id DESC LIMIT 1)
       ) AS base_name
  FROM audit_entry e
  LEFT JOIN account a ON a.id = e.account_id
  LEFT JOIN base b ON b.id = e.base_id
 WHERE e.at >= %(since)s
   AND (e.base_id IN (SELECT base_id FROM mine)
        OR e.account_id = %(me)s
        OR e.detail->>'shared_user' = %(me_text)s)
 ORDER BY e.at DESC, e.id DESC
 LIMIT %(limit)s OFFSET %(offset)s
"""


@dataclass(frozen=True)
class Entry:
    """One row of the audit page."""

    at: datetime
    kind: str
    what: str
    who: str
    base: str
    """The base's name (or id, when the name is gone); "" if none."""
    base_id: str | None
    ip: str
    """The client IP, or "" when there is none or the viewer may not see it."""


async def visible_to(
    conn: Connection, account_id: int, now: datetime, *, page: int = 0
) -> tuple[list[Entry], bool]:
    """``account_id``'s audit entries, newest first, and whether there are
    older ones (on the next ``page``)."""
    cur = await conn.execute(
        _VISIBLE,
        {
            "me": account_id,
            "me_text": str(account_id),
            "since": now - RETENTION,
            "limit": PAGE_SIZE + 1,
            "offset": page * PAGE_SIZE,
        },
    )
    rows = await cur.fetchall()
    return [_entry(row, account_id) for row in rows[:PAGE_SIZE]], len(rows) > PAGE_SIZE


def _entry(row: dict[str, Any], viewer: int) -> Entry:
    whole = bool(row["as_operator"]) or row["account_id"] == viewer
    detail: dict[str, Any] = row["detail"] or {}
    if not whole:
        who = "The Operator" if row["kind"] in OPERATOR_ACTS else "Someone else"
    elif row["email"]:
        who = row["email"]
    elif row["account_id"] is not None:
        who = "A deleted account"
    elif row["base_id"] is not None:
        who = "The base"  # e.g. the agent reporting a pause
    else:
        who = "The Portal"
    return Entry(
        at=row["at"],
        kind=row["kind"],
        what=describe(row["kind"], detail, whole=whole),
        who=who,
        base=(row["base_name"] or row["base_id"] or "") if row["base_id"] else "",
        base_id=row["base_id"],
        ip=(row["ip"] or "") if whole else "",
    )


OPERATOR_ACTS = frozenset(
    {"share_added", "share_removed", "pending_share_created", "pending_share_removed"}
)
"""Kinds where only the base's Operator can be someone else acting on the
viewer (Sharing with them or taking the Share away)."""

END_REASONS = {
    "left": "idle",
    "hard_cap": "time limit reached",
    "portal_restart": "the Portal restarted",
    "un_share": "Share removed",
    "share_left": "left the Share",
    "un_claim": "base Un-claimed",
    "log_out_everywhere": "logged out everywhere",
    "account_deleted": "account deleted",
    "paused": "remote access paused on the base",
}
TRIGGERS = {
    "button": "",
    "password_change": "after a password change",
    "password_recovery": "after a password recovery",
}
UNCLAIMED_BY = {
    "portal": "",
    "base": "from the base itself",
    "account_deleted": "when the account was deleted",
}
SHARE_REASONS = {"un_claim": "base Un-claimed", "account_deleted": "account deleted"}

LABELS = {
    "login": "Signed in",
    "log_out_everywhere": "Logged out everywhere",
    "password_change": "Changed the password",
    "password_recovery": "Recovered the account (new password)",
    "totp_enabled": "Turned on two-step sign-in",
    "totp_disabled": "Turned off two-step sign-in",
    "account_deleted": "Deleted the account",
    "claim": "Claimed the base",
    "unclaim": "Un-claimed the base",
    "remote_session_start": "Remote session started",
    "remote_session_end": "Remote session ended",
    "share_added": "Shared the base with {email}",
    "share_removed": "Removed {email}'s Share",
    "share_left": "Left the Share",
    "pending_share_created": "Pending share for {email}",
    "pending_share_removed": "Withdrew the Pending share for {email}",
    "remote_access_paused": "Remote access paused on the base",
    "remote_access_resumed": "Remote access resumed on the base",
    "possible_copy": "Possible copy: the same base key polled from two places",
}


def describe(kind: str, detail: dict[str, Any], *, whole: bool = True) -> str:
    """What happened, in words. ``whole``: the viewer may see the entry's
    detail (unknown kinds show it as ``key: value``)."""
    label = LABELS.get(kind)
    if label is None:
        text = kind.replace("_", " ").replace(".", " ").strip().capitalize() or "Event"
        extra = _detail_text(detail) if whole else ""
        return f"{text} ({extra})" if extra else text
    text = label.format(email=detail.get("email") or "someone")
    note = ""
    if kind == "remote_session_end":
        reason = str(detail.get("reason", ""))
        note = END_REASONS.get(reason, reason.replace("_", " "))
    elif kind == "log_out_everywhere":
        note = TRIGGERS.get(str(detail.get("trigger", "")), "")
    elif kind == "unclaim":
        note = UNCLAIMED_BY.get(str(detail.get("by", "")), "")
    elif kind in ("share_removed", "share_left", "pending_share_removed"):
        reason = str(detail.get("reason", ""))
        note = SHARE_REASONS.get(reason, reason.replace("_", " "))
    elif kind == "share_added" and "from_pending_share" in detail:
        text = "Accepted a Pending share (first sign-in)"
    elif kind == "possible_copy" and whole and detail.get("ips"):
        note = " and ".join(str(ip) for ip in detail["ips"])
    return f"{text} ({note})" if note else text


def _detail_text(detail: dict[str, Any]) -> str:
    parts = []
    for key, value in sorted(detail.items()):
        if isinstance(value, list):
            value = ", ".join(str(v) for v in value)
        elif isinstance(value, dict):
            continue
        parts.append(f"{key.replace('_', ' ')}: {value}")
    return "; ".join(parts)
