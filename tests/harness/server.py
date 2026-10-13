"""Serving an ASGI app over real TCP (uvicorn, on a free 127.0.0.1 port).

httpx's ASGITransport can't carry websockets, so the tunnel, the Session
bar's status channel and the browser tests reach the app this way. The
Portal's lifespan is already running (``running_portal``), so uvicorn
doesn't run it again.
"""

from __future__ import annotations

import asyncio
import socket
import tempfile
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import uvicorn
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


@dataclass(frozen=True)
class TlsFiles:
    cert: str
    key: str


@contextmanager
def localhost_tls() -> Iterator[TlsFiles]:
    """A throwaway self-signed certificate for ``localhost`` (browsers are
    told to ignore that it's untrusted). WebKit keeps ``Secure`` cookies only
    over HTTPS, even on localhost."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False
        )
        .sign(key, hashes.SHA256())
    )
    with tempfile.TemporaryDirectory(prefix="tls-") as d:
        files = TlsFiles(str(Path(d) / "cert.pem"), str(Path(d) / "key.pem"))
        Path(files.cert).write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        Path(files.key).write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        yield files


def free_socket() -> socket.socket:
    """A listening-ready socket on a free 127.0.0.1 port (know the port
    before building the app, e.g. for its public origin)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    return sock


@asynccontextmanager
async def serving(
    app: Any, sock: socket.socket | None = None, *, tls: TlsFiles | None = None
) -> AsyncIterator[int]:
    """Serve ``app`` until the block ends; yields the port. ``tls``: serve
    HTTPS (see ``localhost_tls``)."""
    sock = sock or free_socket()
    port = int(sock.getsockname()[1])
    server = uvicorn.Server(
        uvicorn.Config(
            app,
            lifespan="off",
            log_level="warning",
            ws="websockets-sansio",
            ssl_certfile=tls.cert if tls else None,
            ssl_keyfile=tls.key if tls else None,
        )
    )
    server.install_signal_handlers = lambda: None  # type: ignore[method-assign]
    task = asyncio.create_task(server.serve(sockets=[sock]))
    while not server.started:
        if task.done():
            task.result()
        await asyncio.sleep(0.01)
    try:
        yield port
    finally:
        server.should_exit = True
        await task
