"""Online state (ADR 0002): a base is online from its latest sign of life
(a poll or a Check-in) until about 3 beats of its current mode are missed.

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

State = Literal["online", "offline", "needs-upgrade", "never-seen"]

LABELS: dict[State, str] = {
    "online": "Online",
    "offline": "Offline",
    "needs-upgrade": "Needs upgrade",
    "never-seen": "Never seen",
}


def interval(config: AgentConfig, metered: bool) -> int:
    return config.metered_poll_interval if metered else config.poll_interval


def offline_after(base: BaseSummary, config: AgentConfig) -> timedelta:
    beat = max(interval(config, base.metered), interval(config, base.polled_metered))
    return timedelta(seconds=MISSED_BEATS * beat)


def state(base: BaseSummary, config: AgentConfig, now: datetime) -> State:
    if base.needs_upgrade:
        return "needs-upgrade"  # not offline: it asks once a day
    if base.last_seen_at is None:
        return "never-seen"
    if now - base.last_seen_at > offline_after(base, config):
        return "offline"
    return "online"
