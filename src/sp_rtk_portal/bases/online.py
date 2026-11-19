"""Online state (ADRs 0002, 0006).

A base holding its tunnel is online while the tunnel is connected, and for
:data:`HELD_GRACE` after its last sign of life once it drops
(``reconnecting``), so a Portal restart or a short glitch doesn't flash it
offline. A polling base is online from its latest sign of life (a poll or a
Check-in) until about 3 beats are missed.
An online base whose agent reports remote access paused is "paused": it
keeps in touch, but ignores Wakes.

The beat is the poll interval from the agent config, the metered one when
the base is metered. Just after the Operator unmarks metered, the base may
still sleep the metered interval it was last told, so the longer of the two
counts until its next poll.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Literal

from sp_rtk_portal_protocol import AgentConfig

from sp_rtk_portal.bases.store import BaseSummary

MISSED_BEATS = 3

HELD_GRACE = timedelta(minutes=2)
"""How long a base whose held tunnel dropped stays online."""

State = Literal["online", "offline", "needs-upgrade", "never-seen", "paused"]

LABELS: dict[State, str] = {
    "online": "Online",
    "paused": "Remote access paused",
    "offline": "Offline",
    "needs-upgrade": "Needs upgrade",
    "never-seen": "Never seen",
}


def interval(config: AgentConfig, metered: bool) -> int:
    return config.metered_poll_interval if metered else config.poll_interval


def offline_after(base: BaseSummary, config: AgentConfig) -> timedelta:
    if base.connection_mode == "reconnecting":
        return HELD_GRACE
    beat = max(interval(config, base.metered), interval(config, base.polled_metered))
    return timedelta(seconds=MISSED_BEATS * beat)


def state(base: BaseSummary, config: AgentConfig, now: datetime) -> State:
    if base.needs_upgrade:
        return "needs-upgrade"  # not offline: it asks once a day
    if base.last_seen_at is None:
        return "never-seen"
    if base.connection_mode != "holding" and (
        now - base.last_seen_at > offline_after(base, config)
    ):
        return "offline"
    if base.remote_paused:
        return "paused"  # online, but it won't wake until resumed on site
    return "online"


def connection(base: BaseSummary, config: AgentConfig) -> str:
    """How the Portal reaches the base (its connection mode), in words."""
    if base.connection_mode == "holding":
        return "Holding its tunnel"
    if base.connection_mode == "reconnecting":
        return "Reconnecting its tunnel"
    mode = f"Polling every {interval(config, base.metered)} s"
    return mode + " (metered)" if base.metered else mode
