"""Why a Remote session ended: one value per cause, stored as is in
``remote_session.end_reason`` and the ``remote_session_end`` audit detail,
and sent to Session bars in the status channel's ``reason``."""

from __future__ import annotations

from enum import StrEnum


class EndReason(StrEnum):
    LEFT = "left"
    """Idle: nobody had the Session bar open for the idle timeout."""
    HARD_CAP = "hard_cap"
    """The session reached its hard cap (the bar offers Reconnect)."""
    PORTAL_RESTART = "portal_restart"
    """Still open in the database when the Portal started."""
    UN_SHARE = "un_share"
    """The Operator removed the Share."""
    SHARE_LEFT = "share_left"
    """The Shared user left the Share."""
    UN_CLAIM = "un_claim"
    """The base was Un-claimed (also a Share's removal reason then)."""
    LOG_OUT_EVERYWHERE = "log_out_everywhere"
    ACCOUNT_DELETED = "account_deleted"
    """The account was deleted (also a Share's removal reason then)."""
    PAUSED = "paused"
    """Remote access was paused on the base."""
