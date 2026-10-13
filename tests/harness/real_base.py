"""The real sp-rtk-base UI, for browser tests of the sandboxed frame.

It is the sibling checkout's own server (``python -m sp_rtk_base.main``, a
dev dependency), started in a subprocess on a free port with a throwaway
``$HOME`` and none of its host integrations (update backend, systemd, the
Portal agent's socket) pointed at anything real. The agent under test is told
this port as the base's ``app_port``. Mirrors sp-rtk-base's own e2e fixture.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import tempfile
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

import httpx


@dataclass
class RealBase:
    port: int
    url: str
    log: Path
    _source: socket.socket | None = None

    def start_relay(self) -> str:
        """Start the Relay from a TCP input; returns the text of the live
        event this sends to every open Event log. ``stop_relay`` undoes it."""
        self._source = socket.create_server(("127.0.0.1", 0))
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            out_port = probe.getsockname()[1]
        api = self.url + "/api"
        resp = httpx.put(
            f"{api}/input",
            json={
                "source": "tcp",
                "config": {
                    "host": "127.0.0.1",
                    "port": self._source.getsockname()[1],
                },
            },
            timeout=5,
        )
        assert resp.status_code in (200, 201), resp.text
        resp = httpx.post(
            f"{api}/destinations",
            json={
                "name": RELAY_DESTINATION,
                "type": "tcp_server",
                "enabled": True,
                "filter": {"mode": "pass_all", "message_ids": []},
                "config": {"host": "127.0.0.1", "port": out_port, "max_clients": 1},
            },
            timeout=5,
        )
        assert resp.status_code == 201, resp.text
        resp = httpx.post(f"{api}/relay/start", timeout=15)
        assert resp.status_code == 200, resp.text
        return "input.connected"

    def stop_relay(self) -> None:
        httpx.post(f"{self.url}/api/relay/stop", timeout=15)
        httpx.delete(f"{self.url}/api/destinations/{RELAY_DESTINATION}", timeout=5)
        if self._source is not None:
            self._source.close()
            self._source = None


RELAY_DESTINATION = "portal-proxy-test"


def _free_port(host: str = "127.0.0.1") -> int:
    with socket.socket() as s:
        s.bind((host, 0))
        return int(s.getsockname()[1])


@contextmanager
def real_base(
    host: str = "127.0.0.1",
    port: int | None = None,
    extra_env: dict[str, str] | None = None,
) -> Iterator[RealBase]:
    """``host`` and ``port``: where it listens (default: a free 127.0.0.1
    port). Local access tests give each base its own loopback address,
    standing in for its LAN address. ``extra_env``: more environment, e.g.
    the Portal agent's state dir and the Portal's URL (identity endpoint)."""
    port = port or _free_port(host)
    url = f"http://{host}:{port}"
    with tempfile.TemporaryDirectory(prefix="real-base-") as d:
        home = Path(d)
        config = home / ".config" / "sp-rtk-base"
        config.mkdir(parents=True)
        (home / "pypi").mkdir()
        (home / "update").mkdir()
        env = {
            k: v
            for k, v in os.environ.items()
            if not k.startswith(("PYTEST_", "NICEGUI_"))
        }
        env.update(
            HOME=str(home),
            SP_RTK_BASE_HOST=host,
            SP_RTK_BASE_PORT=str(port),
            SP_RTK_BASE_CONFIG=str(config / "config.yaml"),
            SP_RTK_BASE_FAKE_GPS="1",
            SP_RTK_BASE_FAKE_PYPI_DIR=str(home / "pypi"),
            SP_RTK_BASE_UPDATE_DIR=str(home / "update"),
            SP_RTK_BASE_FAKE_HOST_SETUP=str(home / "host-setup.json"),
            SP_RTK_BASE_PORTAL_AGENT_SOCKET=str(home / "no-agent.sock"),
        )
        env.update(extra_env or {})
        log = home / "sp-rtk-base.log"
        with log.open("wb") as out:
            proc = subprocess.Popen(
                [sys.executable, "-m", "sp_rtk_base.main"],
                env=env,
                stdout=out,
                stderr=subprocess.STDOUT,
            )
            try:
                _wait_healthy(url, proc, log)
                yield RealBase(port, url, log)
            finally:
                proc.terminate()
                try:
                    proc.wait(10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(5)


def _wait_healthy(url: str, proc: subprocess.Popen[bytes], log: Path) -> None:
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            break
        try:
            if httpx.get(f"{url}/api/health", timeout=2).status_code < 500:
                return
        except httpx.HTTPError:
            pass
        time.sleep(0.25)
    raise TimeoutError(
        f"sp-rtk-base did not start on {url}:\n"
        + log.read_text(errors="replace")[-4000:]
    )
