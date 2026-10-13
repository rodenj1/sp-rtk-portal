"""The tunnel broker: Wakes, tunnels, Remote sessions and their timeouts.

All of it is process-local state (the Portal is a single instance, ADR
0002); the database keeps Remote session records and the audit log.

- **Wake.** :meth:`TunnelBroker.wake` makes a one-time nonce for a base
  (:attr:`Settings.wake_lifetime`); the base's polls carry it
  (:meth:`TunnelBroker.wake_for_poll`) until a tunnel open redeems it
  (:meth:`TunnelBroker.redeem`). Whatever registered with
  :meth:`TunnelBroker.on_wake` (the Doorbell) hears of each Wake too.
- **Tunnel.** One per base, shared by all its Remote sessions
  (:meth:`TunnelBroker.serve_tunnel` runs it; :meth:`TunnelBroker.open_stream`
  opens a stream to the base's UI).
- **Remote session.** Per user per base: :meth:`TunnelBroker.start_session`
  returns the live one, or starts one with a fresh path token (≥128 random
  bits). A Session bar's status channel :meth:`TunnelBroker.attend`\\ s it.
  It ends when nobody attended it for the idle timeout, at the hard cap, or
  when something revokes it (:meth:`TunnelBroker.end_session`,
  :meth:`TunnelBroker.end_sessions`); its token stops working at once.
  When a base's last Remote session ends, its tunnel is closed.

Idle timeout and hard cap come from the agent config current when the
session started.

What a Session bar shows (:meth:`TunnelBroker.state`) follows the base's
current Wake attempt: **waking** after Open remotely, **reconnecting** after
the tunnel dropped under live sessions (the broker Wakes the base once more
on its own), and **didnt_wake** once an attempt has gone unanswered for the
poll interval + :data:`WAKE_GRACE`. Retry (Open remotely again) starts a new
attempt. **Still there?** (:meth:`TunnelBroker.still_there`) comes
:attr:`Settings.still_there_warning` before the hard cap;
:meth:`TunnelBroker.keep_going` restarts the hard cap.
"""

from __future__ import annotations

import asyncio
import contextlib
import hmac
import logging
import secrets
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Literal

from sp_rtk_portal_protocol import FrameError, Stream, Tunnel, TunnelClosed
from starlette.websockets import WebSocket, WebSocketDisconnect

from sp_rtk_portal.agent_api import config as agent_config
from sp_rtk_portal.bases import online
from sp_rtk_portal.clock import Clock
from sp_rtk_portal.config import Settings
from sp_rtk_portal.db import Database
from sp_rtk_portal.tunnel import store
from sp_rtk_portal.tunnel.end_reason import EndReason

log = logging.getLogger(__name__)

TOKEN_BYTES = 32
"""Remote session path tokens: 256 random bits."""


WAKE_GRACE = timedelta(seconds=15)
"""How much longer than one poll interval a Wake may take before the bar says
Didn't wake (35 s, or 75 s metered, with the default intervals)."""


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


SessionState = Literal["waking", "reconnecting", "didnt_wake", "connected", "ended"]


@dataclass
class _Attempt:
    """A Wake the base hasn't answered yet (its tunnel isn't up)."""

    kind: Literal["waking", "reconnecting"]
    deadline: datetime
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
    closing: bool = False


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
        self._stopping = False
        self._sweeper: asyncio.Task[None] | None = None
        self._wake_hooks: list[Callable[[str], None]] = []

    # --- lifecycle ---------------------------------------------------------

    async def start(self) -> None:
        async with self._db.connection() as conn:
            ended = await store.end_leftovers(conn, self._clock.now())
        if ended:
            log.info("ended %s Remote sessions left by a previous run", ended)
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

    def on_wake(self, hook: Callable[[str], None]) -> None:
        """Call ``hook(base_id)`` on every Wake (the Doorbell rings it)."""
        self._wake_hooks.append(hook)

    def wake(self, base_id: str) -> str:
        """Wake the base: its next poll carries this nonce (or a Doorbell
        ring does). Reuses an unexpired one."""
        now = self._clock.now()
        pending = self._wakes.get(base_id)
        if pending is None or pending.expires_at <= now:
            pending = _Wake(
                secrets.token_urlsafe(24), now + self._settings.wake_lifetime
            )
            self._wakes[base_id] = pending
        for hook in self._wake_hooks:
            hook(base_id)
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

    async def serve_tunnel(self, base_id: str, websocket: WebSocket) -> None:
        """Run an accepted tunnel websocket until either side closes it."""
        tunnel = Tunnel(websocket.send_bytes, role="portal")
        attached = _Attached(tunnel, websocket, self._clock.now())
        previous = self._tunnels.get(base_id)
        if previous is not None:
            await self._close_tunnel(previous)
        self._tunnels[base_id] = attached
        self._attempts.pop(base_id, None)
        log.info("tunnel open for base %s", base_id)
        await self._changed(base_id)
        try:
            if not self._live(base_id):
                # Woken, but every Remote session ended meanwhile.
                await self._close_tunnel(attached)
            while not attached.closing:
                message = await websocket.receive()
                if message["type"] == "websocket.disconnect":
                    break
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
                if self._live(base_id) and not self._stopping:
                    # Dropped under live sessions: Wake the base once more.
                    with contextlib.suppress(Exception):
                        await self._attempt_wake(base_id, "reconnecting")
            log.info("tunnel closed for base %s", base_id)
            await self._changed(base_id)

    async def _close_tunnel(self, attached: _Attached) -> None:
        if attached.closing:
            return
        attached.closing = True
        attached.tunnel.close()
        with contextlib.suppress(Exception):
            await attached.websocket.close(code=1000)

    async def close_tunnel(self, base_id: str) -> None:
        """Close the base's tunnel now (e.g. on Un-claim)."""
        attached = self._tunnels.get(base_id)
        if attached is not None:
            await self._close_tunnel(attached)

    # --- Remote sessions -----------------------------------------------------

    def _live(self, base_id: str) -> list[RemoteSession]:
        return [s for s in self._sessions.values() if s.base_id == base_id]

    def live_sessions(self, base_id: str) -> list[RemoteSession]:
        """The base's live Remote sessions, oldest first."""
        return sorted(self._live(base_id), key=lambda s: (s.started_at, s.id))

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
                session_id = await store.started(
                    conn,
                    account_id=account_id,
                    base_id=base_id,
                    token=token,
                    now=now,
                    ip=ip,
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
            )
            self._sessions[session.id] = session
            log.info("Remote session %s started on base %s", session.id, base_id)
        if not self.tunnel_up(base_id):
            attempt = self._attempts.get(base_id)
            if attempt is None or attempt.deadline <= self._clock.now():
                await self._attempt_wake(base_id, "waking")  # first, or Retry
        await self._changed(base_id)
        return session

    async def _attempt_wake(
        self, base_id: str, kind: Literal["waking", "reconnecting"]
    ) -> None:
        async with self._db.connection() as conn:
            config = await agent_config.current(conn, self._settings)
            cur = await conn.execute(
                "SELECT metered FROM base WHERE id = %s", (base_id,)
            )
            row = await cur.fetchone()
        beat = timedelta(seconds=online.interval(config, bool(row and row["metered"])))
        self.wake(base_id)
        self._attempts[base_id] = _Attempt(kind, self._clock.now() + beat + WAKE_GRACE)

    def lookup(self, base_id: str, token: str) -> RemoteSession | None:
        """The live Remote session this path token belongs to, on this base
        (``None``: unknown, revoked or ended). Constant-time on the token."""
        found = None
        for session in self._sessions.values():
            if hmac.compare_digest(session.token, token) and session.base_id == base_id:
                found = session
        return found

    def touch(self, session: RemoteSession) -> None:
        """Record activity (a proxied request)."""
        session.last_activity_at = self._clock.now()

    def state(self, session: RemoteSession) -> SessionState:
        if session.ended:
            return "ended"
        if self.tunnel_up(session.base_id):
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

    async def end_session(
        self, session: RemoteSession, reason: EndReason, ip: str | None = None
    ) -> None:
        """End ``session`` and revoke its token; closes the base's tunnel if
        it was the last."""
        if session.ended or self._sessions.get(session.id) is not session:
            return
        session.ended, session.end_reason = True, reason
        del self._sessions[session.id]
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
        if not self._live(session.base_id):
            self._wakes.pop(session.base_id, None)
            self._attempts.pop(session.base_id, None)
            await self.close_tunnel(session.base_id)
        await self._changed(session.base_id)

    async def end_sessions(
        self,
        reason: EndReason,
        *,
        account_id: int | None = None,
        base_id: str | None = None,
        ip: str | None = None,
    ) -> int:
        """End every live Remote session matching ``account_id`` and/or
        ``base_id`` (un-Share, Un-claim, log out everywhere, account
        deletion). Returns how many ended."""
        if account_id is None and base_id is None:
            raise ValueError("name an account or a base")
        matching = [
            s
            for s in list(self._sessions.values())
            if (account_id is None or s.account_id == account_id)
            and (base_id is None or s.base_id == base_id)
        ]
        for session in matching:
            await self.end_session(session, reason, ip)
        return len(matching)

    async def forget_base(self, base_id: str) -> None:
        """The base was Un-claimed: end its Remote sessions (revoking their
        tokens), drop any pending Wake and close its tunnel."""
        await self.end_sessions(EndReason.UN_CLAIM, base_id=base_id)
        self._wakes.pop(base_id, None)
        await self.close_tunnel(base_id)
        await self._changed(base_id)

    # --- timeouts ------------------------------------------------------------

    async def sweep(self) -> None:
        """End Remote sessions past their idle timeout or hard cap, and tell
        Session bars when a Wake went unanswered or the hard cap is near."""
        now = self._clock.now()
        for session in list(self._sessions.values()):
            if now - session.started_at >= session.hard_cap:
                await self.end_session(session, EndReason.HARD_CAP)
                continue
            if not session.warned and self.still_there(session):
                session.warned = True
                await self._changed(session.base_id)
            elif (
                session.attendants == 0
                and session.left_at is not None
                and now - session.left_at >= session.idle_timeout
            ):
                await self.end_session(session, EndReason.LEFT)
        for base_id, pending in list(self._wakes.items()):
            if pending.expires_at <= now:
                del self._wakes[base_id]
        for base_id, attempt in list(self._attempts.items()):
            if not attempt.overdue and attempt.deadline <= now:
                attempt.overdue = True
                await self._changed(base_id)

    async def _sweep_forever(self) -> None:
        while True:
            await asyncio.sleep(self._settings.tunnel_sweep_interval)
            try:
                await self.sweep()
            except Exception:
                log.exception("Remote session sweep failed")
