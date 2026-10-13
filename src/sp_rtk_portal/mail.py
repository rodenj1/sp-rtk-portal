"""Email the Portal sends itself, through the SMTP server Authentik uses.

(Authentik sends its own flow emails: verification and recovery.) The Portal
sends notifications: Shares now; possible-copy alerts (#98) later.

``await ctx.mailer.send(to, subject, body)`` delivers a plain-text message.
Send after the transaction that made the change has committed: a failed
delivery is logged and never undoes the change.
"""

from __future__ import annotations

import asyncio
import logging
import smtplib
import ssl
from email.message import EmailMessage
from email.utils import make_msgid

from sp_rtk_portal.config import Settings

log = logging.getLogger(__name__)

TIMEOUT_S = 15


class Mailer:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    async def send(self, to: str, subject: str, body: str) -> bool:
        """Deliver one message. ``False``: not sent (logged)."""
        s = self._settings
        if not s.smtp_host:
            log.warning("no SMTP host configured; not emailing %s: %s", to, subject)
            return False
        message = EmailMessage()
        message["From"] = s.smtp_from or s.smtp_username
        message["To"] = to
        message["Subject"] = subject
        message["Message-ID"] = make_msgid(domain="sp-rtk-portal")
        message.set_content(body)
        try:
            await asyncio.to_thread(self._deliver, message)
        except (OSError, smtplib.SMTPException) as e:
            log.warning("emailing %s failed: %s", to, e)
            return False
        return True

    def _deliver(self, message: EmailMessage) -> None:
        s = self._settings
        with smtplib.SMTP(s.smtp_host, s.smtp_port, timeout=TIMEOUT_S) as smtp:
            if s.smtp_starttls:
                smtp.starttls(context=ssl.create_default_context())
            if s.smtp_username:
                smtp.login(s.smtp_username, s.smtp_password)
            smtp.send_message(message)
