"""The tunnel broker: Wakes, tunnels, Remote sessions and their timeouts.

All of it is process-local state (the Portal is a single instance, ADR
0002); the database keeps Remote session records and the audit log.

- **Wake.** :meth:`TunnelBroker.wake` makes a one-time nonce for a base
  (:attr:`Settings.wake_lifetime`); the base's polls carry it
  (:meth:`TunnelBroker.wake_for_poll`) until a tunnel open redeems it
  (:meth:`TunnelBroker.redeem`).
- **Tunnel.** One per base, shared by all its Remote sessions
  (:meth:`TunnelBroker.serve_tunnel` runs it; :meth:`TunnelBroker.open_stream`
  opens a stream to the base's UI); a new one from the same base replaces
  the old. A Claimed base on protocol version 2 *holds* its tunnel open
  (ADR 0006): the Portal never closes a held tunnel for want of Remote
  sessions, only when it sent nothing (not even its agent's ping) for the
  agent config's ``tunnel_silence_timeout``. It never pings it either. A
  tunnel opened on a Wake (a polling base) closes with the base's last
  Remote session.
- **Control messages.** A held tunnel carries what polls and Check-ins
  carry for a polling base (ticket #205): the agent's Check-ins come in on
  it (``on_check_in``, each answered as over HTTPS), and the broker sends
  the agent a
  :class:`~sp_rtk_portal_protocol.TunnelUpdate` (agent config, metered,
  notices, live Remote sessions) in answer to each Check-in (the agent
  sends one on connect) and on every change
  (:meth:`TunnelBroker.push`), and each Remote session's end. Anything the
  tunnel receives is a sign of life: the base's last-seen advances (at most
  every :data:`SEEN_EVERY`, so with each ping).
- **Remote session.** Per user per base: :meth:`TunnelBroker.start_session`
  returns the live one, or starts one with a fresh path token (≥128 random
  bits). A Session bar's status channel :meth:`TunnelBroker.attend`\\ s it.
  It ends when nobody attended it for the idle timeout, at the hard cap, or
  when the Portal ends it: :meth:`TunnelBroker.end_for_account` (un-Share,
  leaving, logging out, account deletion) or :meth:`TunnelBroker.end_for_base`
  (Un-claim, pause; a paused base keeps its held tunnel, refusing its
  streams). Ending always revokes the token at once.
- **Lease.** A path token works only until its lease expires (ADR 0005):
  starting or rejoining the session, opening a status channel and
  :meth:`TunnelBroker.renew` each give it a fresh lease. The broker asks the
  session's open Session bars to renew (:meth:`TunnelBroker.renewal_due`)
  every renewal interval on its own clock, so a hidden tab's throttled
  timers don't matter; a bar that stops answering lets the lease expire,
  which ends the session (:attr:`EndReason.LEASE_EXPIRED`). An ended
  (paused) session is never renewed.

Ending and the caller's transaction: callers end Remote sessions *inside*
their own transaction (an Un-claim, a Share removal, a log out...), before
it commits, and the broker records each end (the session's row and its
audit entry) at once on a connection of its own. So the end stands whatever
becomes of the caller's transaction, failing safe: a rolled-back Un-claim
leaves a base whose Remote sessions ended, with the record saying why, and
its users open it again. The record never waits on a caller, and a row is
open exactly while its session is live (``remote_session_live_idx``).

The broker keeps each base's Remote sessions that ended in the last
:data:`ENDS_KEPT`, with their reasons, for the base's own record (its
polls list them, :meth:`TunnelBroker.recent_ends`).

Idle timeout, hard cap and lease come from the agent config current when the
session started.

What a Session bar shows (:meth:`TunnelBroker.state`) follows the base's
current attempt to reach it. A polling base is **waking** after Open
remotely, **reconnecting** after its tunnel dropped under live sessions (the
broker Wakes it once more on its own), and **didnt_wake** once an attempt
has gone unanswered for the poll interval + :data:`WAKE_GRACE`. A holding
base is never Woken: Open remotely finds its tunnel up (**connected** at
once) or else is **connecting** until it comes back, for
:data:`WAKE_GRACE`; after a drop it's **reconnecting** for
:data:`HELD_RECONNECT`, since it comes back by itself. Either way an
unanswered attempt ends in **didnt_wake**. So does a Remote session whose
first request down an open tunnel the base's UI leaves unanswered for
:data:`WAKE_GRACE` (:meth:`TunnelBroker.asking`), until an answer comes. Retry (Open remotely again)
starts a new attempt. **Still there?** (:meth:`TunnelBroker.still_there`) comes
:attr:`Settings.still_there_warning` before the hard cap;
:meth:`TunnelBroker.keep_going` restarts the hard cap.
"""

from __future__ import annotations

import asyncio
import contextlib
import hmac
import logging
import secrets
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Literal

from sp_rtk_portal_protocol import (
    MODE_POLLING,
    CheckIn,
    EndedSession,
    FrameError,
    LiveSession,
    Message,
    Stream,
    Tunnel,
    TunnelClosed,
    TunnelUpdate,
    control_message,
    read_control_frame,
)
from starlette.websockets import WebSocket, WebSocketDisconnect

from sp_rtk_portal.agent_api import config as agent_config
from sp_rtk_portal.bases import online, presence
from sp_rtk_portal.bases import store as base_store
from sp_rtk_portal.clock import Clock
from sp_rtk_portal.config import Settings
from sp_rtk_portal.db import Database
from sp_rtk_portal.tunnel import store
from sp_rtk_portal.tunnel.end_reason import EndReason, for_base

log = logging.getLogger(__name__)

TOKEN_BYTES = 32
"""Remote session path tokens: 256 random bits."""


WAKE_GRACE = timedelta(seconds=15)
"""How much longer than one poll interval a Wake may take before the bar says
Didn't wake (35 s, or 75 s metered, with the default intervals), how long
a holding base whose tunnel isn't up may take to answer Open remotely, and
how long a base's UI may leave a request down its open tunnel unanswered."""


HELD_RECONNECT = timedelta(seconds=75)
"""How long the bar waits for a holding base's dropped tunnel to come back
before it says Didn't wake: the agent's first retry comes after a random
0-60 s, plus :data:`WAKE_GRACE`."""


ENDS_KEPT = timedelta(minutes=10)
"""How long a base's ended Remote sessions are kept for its polls: several
poll intervals, even metered (the agent keeps each end once)."""


SEEN_EVERY = timedelta(seconds=10)
"""How often a held tunnel's traffic advances the base's last-seen: well
within the agent's ping interval, so every ping does, without a database
write for every frame of a busy tunnel."""

OnCheckIn = Callable[[CheckIn], Awaitable[None]]
"""Records a Check-in that came in on a held tunnel."""


class TunnelDown(Exception):
    """The base has no tunnel open."""


@dataclass
class RemoteSession:
    """A live Remote session (the database keeps the record)."""

    id: int
    account_id: int
    base_id: str
    token: str
    """The path token (``/b/<id>/s/<token>/``). Only ever in memory."""
    started_at: datetime
    last_activity_at: datetime
    idle_timeout: timedelta
    hard_cap: timedelta
    ip: str | None
    attendants: int = 0
    """Session bar status channels open now (a user's tabs)."""
    left_at: datetime | None = None
    """When the last status channel closed (start, until one opens)."""
    ended: bool = False
    end_reason: EndReason | None = None
    warned: bool = False
    """Its bars were told Still there? (until Keep going)."""
    who: str = ""
    """The user's email, at the start."""
    shared: bool = False
    """The user has the base through a Share (not its Operator)."""
    ended_at: datetime | None = None
    lease: timedelta = timedelta(minutes=5)
    lease_renewal: timedelta = timedelta(minutes=1)
    lease_expires_at: datetime | None = None
    """The path token is refused from then on (set at start)."""
    renewal_asked_at: datetime | None = None
    """When its bars were last asked to renew (since the last renewal)."""
    answered: bool = False
    """The base's UI answered a request in it: from then on a slow answer
    isn't Didn't wake."""


SessionState = Literal[
    "waking", "connecting", "reconnecting", "didnt_wake", "connected", "ended"
]

AttemptKind = Literal["waking", "connecting", "reconnecting"]


@dataclass
class _Attempt:
    """A Wake (or, for a holding base, its tunnel's return) the base hasn't
    answered yet: its tunnel isn't up."""

    kind: AttemptKind
    deadline: datetime
    overdue: bool = False
    """Its bars were told Didn't wake."""


@dataclass
class _Unanswered:
    """Requests in a Remote session that its base's UI hasn't answered, up
    to its first answer."""

    since: datetime
    """When the first of them went down the tunnel (or Retry started
    over)."""
    requests: int = 0
    overdue: bool = False
    """Its bars were told Didn't wake."""


@dataclass
class _Wake:
    nonce: str
    expires_at: datetime


@dataclass
class _Attached:
    tunnel: Tunnel
    websocket: WebSocket
    opened_at: datetime
    held: bool = False
    """Opened to hold (protocol version 2, no Wake), not on a Wake."""
    silence: timedelta = timedelta(0)
    """A held tunnel that sent nothing for this long is closed."""
    heard_at: datetime | None = None
    """When it last sent anything (opening counts)."""
    seen_at: datetime | None = None
    """When its traffic last advanced the base's last-seen."""
    closing: bool = False

    def silent(self, now: datetime) -> bool:
        heard = self.heard_at or self.opened_at
        return self.held and now - heard >= self.silence


@dataclass
class _Base:
    """Change notification for one base's Session bars."""

    version: int = 0
    changed: asyncio.Condition = field(default_factory=asyncio.Condition)


class TunnelBroker:
    def __init__(self, settings: Settings, clock: Clock, db: Database) -> None:
        self._settings = settings
        self._clock = clock
        self._db = db
        self._wakes: dict[str, _Wake] = {}
        self._tunnels: dict[str, _Attached] = {}
        self._sessions: dict[int, RemoteSession] = {}
        self._bases: dict[str, _Base] = {}
        self._attempts: dict[str, _Attempt] = {}
        self._unanswered: dict[int, _Unanswered] = {}
        """By Remote session id."""
        self._ends: dict[str, list[RemoteSession]] = {}
        self._stopping = False
        self._sweeper: asyncio.Task[None] | None = None

    # --- lifecycle ---------------------------------------------------------

    async def start(self) -> None:
        async with self._db.connection() as conn:
            ended = await store.end_leftovers(conn, self._clock.now())
            gone = await presence.tunnels_gone(conn)
        if ended:
            log.info("ended %s Remote sessions left by a previous run", ended)
        if gone:
            log.info("%s bases held a tunnel to a previous run", gone)
        self._sweeper = asyncio.create_task(self._sweep_forever())

    async def stop(self) -> None:
        self._stopping = True
        if self._sweeper is not None:
            self._sweeper.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._sweeper
        for attached in list(self._tunnels.values()):
            await self._close_tunnel(attached)

    # --- Wakes ---------------------------------------------------------------

    def wake(self, base_id: str) -> str:
        """Wake the base: its next poll carries this nonce. Reuses an
        unexpired one."""
        now = self._clock.now()
        pending = self._wakes.get(base_id)
        if pending is None or pending.expires_at <= now:
            pending = _Wake(
                secrets.token_urlsafe(24), now + self._settings.wake_lifetime
            )
            self._wakes[base_id] = pending
        return pending.nonce

    def wake_for_poll(self, base_id: str) -> str | None:
        """The nonce for this base's poll reply, if a Wake is pending."""
        pending = self._wakes.get(base_id)
        if pending is None:
            return None
        if pending.expires_at <= self._clock.now():
            del self._wakes[base_id]
            return None
        return pending.nonce

    def redeem(self, base_id: str, nonce: str | None) -> bool:
        """A tunnel open echoed ``nonce``: valid once, for this base only."""
        pending = self._wakes.get(base_id)
        if (
            nonce is None
            or pending is None
            or pending.expires_at <= self._clock.now()
            or not hmac.compare_digest(pending.nonce, nonce)
        ):
            return False
        del self._wakes[base_id]
        return True

    # --- Tunnels -------------------------------------------------------------

    def tunnel_up(self, base_id: str) -> bool:
        attached = self._tunnels.get(base_id)
        return attached is not None and not attached.closing

    async def open_stream(self, base_id: str) -> Stream:
        """A new stream to the base's own UI. Raises :class:`TunnelDown`."""
        attached = self._tunnels.get(base_id)
        if attached is None or attached.closing:
            raise TunnelDown(base_id)
        try:
            return await attached.tunnel.open_stream()
        except TunnelClosed as exc:
            raise TunnelDown(base_id) from exc

    @contextlib.asynccontextmanager
    async def asking(
        self, session: RemoteSession
    ) -> AsyncIterator[Callable[[], Awaitable[None]]]:
        """A request in ``session`` is on its way to the base's UI down its
        tunnel, until the block ends; await the function it gives once the UI
        answers. Until the session's first answer, a request left unanswered
        for :data:`WAKE_GRACE` makes its Session bars say Didn't wake."""
        waiting = None
        if not session.answered:
            waiting = self._unanswered.setdefault(
                session.id, _Unanswered(self._clock.now())
            )
            waiting.requests += 1

        async def answered() -> None:
            session.answered = True
            await self._forget_unanswered(session, waiting)

        try:
            yield answered
        finally:
            if waiting is not None:
                waiting.requests -= 1
                if not waiting.requests:  # given up on, or cut short
                    await self._forget_unanswered(session, waiting)

    async def _forget_unanswered(
        self, session: RemoteSession, waiting: _Unanswered | None
    ) -> None:
        if waiting is not None and self._unanswered.get(session.id) is waiting:
            del self._unanswered[session.id]
            if waiting.overdue:
                await self._changed(session.base_id)

    def _unanswered_overdue(self, session: RemoteSession) -> bool:
        waiting = self._unanswered.get(session.id)
        return waiting is not None and self._clock.now() - waiting.since >= WAKE_GRACE

    async def serve_tunnel(
        self,
        base_id: str,
        websocket: WebSocket,
        *,
        held: bool = False,
        on_check_in: OnCheckIn | None = None,
    ) -> None:
        """Accept a tunnel websocket the route admitted, and run it until
        either side closes it. ``held``: the base holds it open (no Wake
        opened it). The base's record says so before the agent sees it
        open. A held tunnel's Check-ins go to ``on_check_in``."""

        async def on_control(payload: bytes) -> None:
            message = read_control_frame(payload)
            if held and isinstance(message, CheckIn) and on_check_in is not None:
                await on_check_in(message)
                await self.push(base_id)  # its answer, as an HTTPS Check-in's

        tunnel = Tunnel(websocket.send_bytes, role="portal", on_control=on_control)
        now = self._clock.now()
        attached = _Attached(tunnel, websocket, now, held=held, seen_at=now)
        if held:
            async with self._db.connection() as conn:
                config = await agent_config.current(conn, self._settings)
                await presence.tunnel_held(conn, base_id, now)
            attached.silence = timedelta(seconds=config.tunnel_silence_timeout)
        await websocket.accept()
        previous = self._tunnels.get(base_id)
        self._tunnels[base_id] = attached
        self._attempts.pop(base_id, None)
        if previous is not None:
            await self._close_tunnel(previous)
        log.info("tunnel %s for base %s", "held" if held else "open", base_id)
        await self._changed(base_id)
        try:
            if not held and not self._live(base_id):
                # Woken, but every Remote session ended meanwhile.
                await self._close_tunnel(attached)
            if held:
                # The answer to its first Check-in brings the rest.
                for session in self.recent_ends(base_id):
                    await self._tell(attached, as_ended(session))
            while not attached.closing:
                message = await websocket.receive()
                if message["type"] == "websocket.disconnect":
                    break
                await self._heard(base_id, attached)
                data = message.get("bytes")
                if data is None:
                    raise FrameError("a text message (frames are binary)")
                await tunnel.feed(data)
        except FrameError as exc:
            log.warning("closing base %s's tunnel: %s", base_id, exc)
        except (WebSocketDisconnect, RuntimeError):
            pass
        finally:
            tunnel.close()
            with contextlib.suppress(Exception):
                await websocket.close()
            if self._tunnels.get(base_id) is attached:
                del self._tunnels[base_id]
                if held:
                    with contextlib.suppress(Exception):
                        async with self._db.connection() as conn:
                            await presence.tunnel_dropped(
                                conn, base_id, attached.heard_at or attached.opened_at
                            )
                if self._live(base_id) and not self._stopping:
                    # Dropped under live sessions: Wake a polling base once
                    # more; a holding one comes back by itself.
                    with contextlib.suppress(Exception):
                        await self._attempt(base_id, opening=False)
            log.info("tunnel closed for base %s", base_id)
            await self._changed(base_id)

    async def _heard(self, base_id: str, attached: _Attached) -> None:
        """The tunnel sent something: a held one's base is seen now."""
        now = attached.heard_at = self._clock.now()
        if attached.held and now - (attached.seen_at or now) >= SEEN_EVERY:
            attached.seen_at = now
            try:
                async with self._db.connection() as conn:
                    await presence.heard(conn, base_id, now)
            except Exception:
                log.exception("couldn't record base %s as seen", base_id)

    async def push(self, base_id: str | None = None) -> None:
        """Something in a :class:`TunnelUpdate` changed (the agent config or
        notices for every base, else ``base_id``'s metered flag or Remote
        sessions): send it on the held tunnels concerned."""
        for held_by, attached in list(self._tunnels.items()):
            if attached.held and base_id in (None, held_by):
                try:
                    await self._tell(attached, await self._update(held_by))
                except Exception:
                    # The change stands; the base hears it on reconnecting.
                    log.exception("couldn't send base %s its update", held_by)

    async def _update(self, base_id: str) -> TunnelUpdate:
        async with self._db.connection() as conn:
            config = await agent_config.current(conn, self._settings)
            notices = await agent_config.wire_notices(conn)
            base = await base_store.by_id(conn, base_id)
        return TunnelUpdate(
            config=config,
            metered=bool(base and base.metered),
            notices=notices,
            sessions=self.reported_sessions(
                base_id, paused=bool(base and base.remote_paused)
            ),
        )

    async def _tell(self, attached: _Attached, message: Message) -> None:
        """Send the agent a control message on its held tunnel (best effort:
        a tunnel that's going away doesn't need it)."""
        if attached.closing:
            return
        try:
            await attached.tunnel.send_control(control_message(message))
        except (TunnelClosed, WebSocketDisconnect, RuntimeError, OSError) as exc:
            log.info("couldn't tell a base on its tunnel: %s", exc)

    async def _close_tunnel(self, attached: _Attached) -> None:
        if attached.closing:
            return
        attached.closing = True
        attached.tunnel.close()
        with contextlib.suppress(Exception):
            await attached.websocket.close(code=1000)

    # --- Remote sessions -----------------------------------------------------

    def _live(self, base_id: str) -> list[RemoteSession]:
        return [s for s in self._sessions.values() if s.base_id == base_id]

    def live_sessions(self, base_id: str) -> list[RemoteSession]:
        """The base's live Remote sessions, oldest first."""
        return sorted(self._live(base_id), key=lambda s: (s.started_at, s.id))

    def reported_sessions(self, base_id: str, *, paused: bool) -> list[LiveSession]:
        """The base's live Remote sessions as its agent hears of them: none
        while remote access is paused on it."""
        return [] if paused else [as_live(s) for s in self.live_sessions(base_id)]

    def session_for(self, account_id: int, base_id: str) -> RemoteSession | None:
        for session in self._sessions.values():
            if session.account_id == account_id and session.base_id == base_id:
                return session
        return None

    async def start_session(
        self, account_id: int, base_id: str, ip: str | None
    ) -> RemoteSession:
        """The user's live Remote session on this base, or a new one; the
        base is Woken unless its tunnel is up. The caller has checked the
        user may reach the base."""
        session = self.session_for(account_id, base_id)
        if session is None:
            now = self._clock.now()
            token = secrets.token_urlsafe(TOKEN_BYTES)
            async with self._db.connection() as conn:
                config = await agent_config.current(conn, self._settings)
                cur = await conn.execute(
                    "SELECT a.email, b.owner_account_id IS DISTINCT FROM a.id"
                    " AS shared FROM account a, base b WHERE a.id = %s AND b.id = %s",
                    (account_id, base_id),
                )
                user = await cur.fetchone()
                lease = timedelta(seconds=config.lease_length)
                session_id = await store.started(
                    conn,
                    account_id=account_id,
                    base_id=base_id,
                    token=token,
                    now=now,
                    ip=ip,
                    lease_expires_at=now + lease,
                )
            session = RemoteSession(
                id=session_id,
                account_id=account_id,
                base_id=base_id,
                token=token,
                started_at=now,
                last_activity_at=now,
                idle_timeout=timedelta(seconds=config.tunnel_idle_timeout),
                hard_cap=timedelta(seconds=config.tunnel_hard_cap),
                ip=ip,
                left_at=now,
                who=user["email"] if user else "",
                shared=bool(user and user["shared"]),
                lease=lease,
                lease_expires_at=now + lease,
                lease_renewal=timedelta(seconds=config.lease_renewal_interval),
            )
            self._sessions[session.id] = session
            log.info("Remote session %s started on base %s", session.id, base_id)
            await self.push(base_id)
        else:
            await self.renew(session)
        if not self.tunnel_up(base_id):
            attempt = self._attempts.get(base_id)
            if attempt is None or attempt.deadline <= self._clock.now():
                await self._attempt(base_id, opening=True)  # first, or Retry
        elif self._unanswered_overdue(session):
            waiting = self._unanswered[session.id]  # Retry: wait for it again
            waiting.since, waiting.overdue = self._clock.now(), False
        await self._changed(base_id)
        return session

    async def _attempt(self, base_id: str, *, opening: bool) -> None:
        """Start an attempt to reach the base, on Open remotely (``opening``)
        or after its tunnel dropped: a Wake for a polling base, answered
        within its poll interval + :data:`WAKE_GRACE`; a holding base comes
        back by itself."""
        async with self._db.connection() as conn:
            config = await agent_config.current(conn, self._settings)
            base = await base_store.by_id(conn, base_id)
        kind: AttemptKind
        if base is None or base.connection_mode == MODE_POLLING:
            self.wake(base_id)
            kind = "waking" if opening else "reconnecting"
            beat = online.interval(config, bool(base and base.metered))
            wait = timedelta(seconds=beat) + WAKE_GRACE
        elif opening:
            kind, wait = "connecting", WAKE_GRACE
        else:
            kind, wait = "reconnecting", HELD_RECONNECT
        self._attempts[base_id] = _Attempt(kind, self._clock.now() + wait)

    def lookup(self, base_id: str, token: str) -> RemoteSession | None:
        """The live Remote session this path token belongs to, on this base
        (``None``: unknown, revoked or ended). Constant-time on the token."""
        found = None
        for session in self._sessions.values():
            if hmac.compare_digest(session.token, token) and session.base_id == base_id:
                found = session
        if found is not None and self._lease_expired(found):
            return None  # the sweep ends it
        return found

    def recent_ends(self, base_id: str) -> list[RemoteSession]:
        """The base's Remote sessions that ended in the last
        :data:`ENDS_KEPT`, oldest first."""
        since = self._clock.now() - ENDS_KEPT
        return [
            s for s in self._ends.get(base_id, []) if s.ended_at and s.ended_at > since
        ]

    async def renew(self, session: RemoteSession) -> None:
        """A fresh lease for the session's path token (not once it ended),
        recorded on the session's row."""
        if session.ended:
            return
        session.lease_expires_at = self._clock.now() + session.lease
        session.renewal_asked_at = None
        async with self._db.connection() as conn:
            await store.leased(conn, session.id, session.lease_expires_at)

    def renewal_due(self, session: RemoteSession) -> bool:
        """Its Session bars should renew the lease now."""
        if session.ended or session.lease_expires_at is None:
            return False
        renewed_at = session.lease_expires_at - session.lease
        return self._clock.now() >= renewed_at + session.lease_renewal

    def _lease_expired(self, session: RemoteSession) -> bool:
        expires = session.lease_expires_at
        return expires is not None and self._clock.now() >= expires

    def touch(self, session: RemoteSession) -> None:
        """Record activity (a proxied request)."""
        session.last_activity_at = self._clock.now()

    def state(self, session: RemoteSession) -> SessionState:
        if session.ended:
            return "ended"
        if self.tunnel_up(session.base_id):
            if self._unanswered_overdue(session):
                return "didnt_wake"
            return "connected"
        attempt = self._attempts.get(session.base_id)
        if attempt is None:
            return "waking"
        if attempt.deadline <= self._clock.now():
            return "didnt_wake"
        return attempt.kind

    def cap_at(self, session: RemoteSession) -> datetime:
        """When the hard cap pauses ``session``."""
        return session.started_at + session.hard_cap

    def still_there(self, session: RemoteSession) -> bool:
        """Time to ask Still there? (the hard cap is near)."""
        warning = min(self._settings.still_there_warning, session.hard_cap)
        return not session.ended and self._clock.now() >= self.cap_at(session) - warning

    async def keep_going(self, session: RemoteSession) -> None:
        """Keep going: the hard cap starts over from now."""
        if session.ended:
            return
        session.started_at = self._clock.now()
        session.warned = False
        await self._changed(session.base_id)

    def present(self, base_id: str) -> list[RemoteSession]:
        """The base's Remote sessions with a Session bar open now."""
        return [s for s in self._live(base_id) if s.attendants > 0]

    @contextlib.asynccontextmanager
    async def attend(
        self, session: RemoteSession, ip: str | None = None
    ) -> AsyncIterator[None]:
        """A Session bar's status channel is open on ``session``."""
        session.attendants += 1
        session.left_at = None
        await self.renew(session)
        if ip:
            session.ip = ip
        if session.attendants == 1:
            await self._changed(session.base_id)  # presence
        try:
            yield
        finally:
            session.attendants -= 1
            if session.attendants == 0:
                session.left_at = self._clock.now()
                await self._changed(session.base_id)

    async def wait_change(self, base_id: str, seen: int) -> int:
        """Wait until anything about ``base_id``'s tunnel or sessions changed
        since version ``seen``; returns the new version."""
        base = self._bases.setdefault(base_id, _Base())
        async with base.changed:
            await base.changed.wait_for(lambda: base.version != seen)
            return base.version

    def version(self, base_id: str) -> int:
        return self._bases.setdefault(base_id, _Base()).version

    async def _changed(self, base_id: str) -> None:
        base = self._bases.setdefault(base_id, _Base())
        async with base.changed:
            base.version += 1
            base.changed.notify_all()

    async def end_for_account(
        self,
        account_id: int,
        reason: EndReason,
        *,
        base_id: str | None = None,
        ip: str | None = None,
    ) -> None:
        """The user is out: end their live Remote sessions (on ``base_id``
        only, if given), revoking their tokens. A Woken tunnel closes when
        its base's last Remote session goes."""
        for session in list(self._sessions.values()):
            if session.account_id == account_id and (
                base_id is None or session.base_id == base_id
            ):
                await self._end(session, reason, ip=ip)

    async def end_for_base(
        self,
        base_id: str,
        reason: EndReason,
        *,
        ip: str | None = None,
        keep_held: bool = False,
    ) -> None:
        """The base is gone or unreachable (Un-claim, pause): end every
        Remote session on it, revoking their tokens, drop any pending Wake
        and close its tunnel. ``keep_held`` (pause): a held tunnel stays
        open, the agent refusing its streams."""
        for session in self._live(base_id):
            await self._end(session, reason, ip=ip)
        self._wakes.pop(base_id, None)
        self._attempts.pop(base_id, None)
        attached = self._tunnels.get(base_id)
        if attached is not None and not (keep_held and attached.held):
            await self._close_tunnel(attached)
        await self._changed(base_id)

    async def _end(
        self, session: RemoteSession, reason: EndReason, *, ip: str | None = None
    ) -> None:
        """End ``session`` and revoke its token; closes the base's Woken
        tunnel if it was the last (a held one stays open)."""
        if session.ended or self._sessions.get(session.id) is not session:
            return
        session.ended, session.end_reason = True, reason
        session.ended_at = self._clock.now()
        del self._sessions[session.id]
        self._unanswered.pop(session.id, None)
        self._ends.setdefault(session.base_id, []).append(session)
        async with self._db.connection() as conn:
            await store.ended(
                conn,
                session_id=session.id,
                account_id=session.account_id,
                base_id=session.base_id,
                now=self._clock.now(),
                last_activity=session.last_activity_at,
                reason=reason,
                ip=ip or session.ip,
            )
        log.info("Remote session %s ended: %s", session.id, reason)
        attached = self._tunnels.get(session.base_id)
        if attached is not None and attached.held:
            await self._tell(attached, as_ended(session))
            await self.push(session.base_id)
        if not self._live(session.base_id):
            self._wakes.pop(session.base_id, None)
            self._attempts.pop(session.base_id, None)
            if attached is not None and not attached.held:
                await self._close_tunnel(attached)
        await self._changed(session.base_id)

    # --- timeouts ------------------------------------------------------------

    async def sweep(self) -> None:
        """End Remote sessions past their idle timeout, hard cap or lease,
        close held tunnels gone silent, and tell Session bars when a Wake
        went unanswered, the hard cap is near or the lease is due for
        renewal."""
        now = self._clock.now()
        for base_id, attached in list(self._tunnels.items()):
            if not attached.closing and attached.silent(now):
                log.info("closing base %s's tunnel: silent", base_id)
                await self._close_tunnel(attached)
        for session in list(self._sessions.values()):
            if now - session.started_at >= session.hard_cap:
                await self._end(session, EndReason.HARD_CAP)
                continue
            if self._lease_expired(session):
                await self._end(session, EndReason.LEASE_EXPIRED)
                continue
            if self._ask_renewal(session, now):
                await self._changed(session.base_id)
            if not session.warned and self.still_there(session):
                session.warned = True
                await self._changed(session.base_id)
            elif (
                session.attendants == 0
                and session.left_at is not None
                and now - session.left_at >= session.idle_timeout
            ):
                await self._end(session, EndReason.LEFT)
        for base_id in list(self._ends):
            if not (kept := self.recent_ends(base_id)):
                del self._ends[base_id]
            else:
                self._ends[base_id] = kept
        for base_id, pending in list(self._wakes.items()):
            if pending.expires_at <= now:
                del self._wakes[base_id]
        for base_id, attempt in list(self._attempts.items()):
            if not attempt.overdue and attempt.deadline <= now:
                attempt.overdue = True
                await self._changed(base_id)
        for session in list(self._sessions.values()):
            waiting = self._unanswered.get(session.id)
            if waiting and not waiting.overdue and self._unanswered_overdue(session):
                waiting.overdue = True
                await self._changed(session.base_id)

    def _ask_renewal(self, session: RemoteSession, now: datetime) -> bool:
        """Time to ask the session's open bars to renew (once per renewal
        interval while they don't)."""
        if session.attendants == 0 or not self.renewal_due(session):
            return False
        asked = session.renewal_asked_at
        if asked is not None and now - asked < session.lease_renewal:
            return False
        session.renewal_asked_at = now
        return True

    async def _sweep_forever(self) -> None:
        while True:
            await asyncio.sleep(self._settings.tunnel_sweep_interval)
            try:
                await self.sweep()
            except Exception:
                log.exception("Remote session sweep failed")


def as_live(session: RemoteSession) -> LiveSession:
    """A live Remote session as the base hears of it."""
    return LiveSession(
        who=session.who,
        since=session.started_at.isoformat(),
        shared=session.shared,
        id=str(session.id),
    )


def as_ended(session: RemoteSession) -> EndedSession:
    """An ended Remote session as the base hears of it, with its reason in
    the base's words."""
    assert session.ended_at is not None and session.end_reason is not None
    return EndedSession(
        id=str(session.id),
        who=session.who,
        since=session.started_at.isoformat(),
        at=session.ended_at.isoformat(),
        reason=for_base(session.end_reason),
        shared=session.shared,
    )
