"""Why a Remote session ended: one value per cause, stored as is in
``remote_session.end_reason`` and the ``remote_session_end`` audit detail,
and sent to Session bars in the status channel's ``reason``. The base hears
it in its own, coarser words (:func:`for_base`)."""

from __future__ import annotations

from enum import StrEnum

from sp_rtk_portal_protocol import END_IDLE, END_LEFT, END_REVOKED


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
    LOGGED_OUT = "logged_out"
    """The user logged out of the Portal."""
    LOG_OUT_EVERYWHERE = "log_out_everywhere"
    ACCOUNT_DELETED = "account_deleted"
    """The account was deleted (also a Share's removal reason then)."""
    PAUSED = "paused"
    """Remote access was paused on the base."""


_FOR_BASE = {
    EndReason.LEFT: END_IDLE,
    EndReason.LOGGED_OUT: END_LEFT,
    EndReason.LOG_OUT_EVERYWHERE: END_LEFT,
    EndReason.SHARE_LEFT: END_LEFT,
    EndReason.UN_SHARE: END_REVOKED,
    EndReason.UN_CLAIM: END_REVOKED,
    EndReason.ACCOUNT_DELETED: END_REVOKED,
}


def for_base(reason: EndReason) -> str:
    """``reason`` in the base's words (the protocol's ``END_REASONS``): the
    Portal's ``left`` is the base's ``idle``, the user leaving is ``left``
    and the Portal taking access away is ``revoked``. Others (``paused``,
    ``hard_cap``, ``lease_expired``) are the same word on both sides."""
    return _FOR_BASE.get(reason, reason.value)
