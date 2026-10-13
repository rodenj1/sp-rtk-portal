"""A real SMTP server on 127.0.0.1 that keeps what it receives.

The Portal talks SMTP to it exactly as it talks to the server Authentik uses
(minus STARTTLS and login). ``smtp.outbox`` lists the delivered messages;
``smtp.to(address)`` the ones for one recipient.
"""

from __future__ import annotations

import socket
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from email import message_from_bytes, policy
from email.message import EmailMessage
from typing import Any

from aiosmtpd.controller import Controller


@dataclass(frozen=True)
class Mail:
    sender: str
    to: list[str]
    subject: str
    body: str
    message: EmailMessage


class _Handler:
    def __init__(self, outbox: list[Mail]) -> None:
        self.outbox = outbox

    async def handle_DATA(self, server: Any, session: Any, envelope: Any) -> str:  # noqa: N802
        message = message_from_bytes(envelope.content, policy=policy.default)
        assert isinstance(message, EmailMessage)
        part = message.get_body(preferencelist=("plain",))
        self.outbox.append(
            Mail(
                sender=envelope.mail_from,
                to=list(envelope.rcpt_tos),
                subject=str(message["Subject"]),
                body=part.get_content() if part else "",
                message=message,
            )
        )
        return "250 OK"


class FakeSmtp:
    def __init__(self, port: int) -> None:
        self.host = "127.0.0.1"
        self.port = port
        self.outbox: list[Mail] = []

    def to(self, address: str) -> list[Mail]:
        return [m for m in self.outbox if address.lower() in (t.lower() for t in m.to)]


@contextmanager
def fake_smtp() -> Iterator[FakeSmtp]:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    smtp = FakeSmtp(port)
    controller = Controller(_Handler(smtp.outbox), hostname="127.0.0.1", port=port)
    controller.start()
    try:
        yield smtp
    finally:
        controller.stop()
