"""
Outgoing mail (SMTP) for account e-mails: registration confirmation.

Configured from the environment (see .env.example):

  SMTP_HOST       mail server, e.g. mail.robustidps.ai (empty = mail disabled)
  SMTP_PORT       465 (implicit TLS, default) or 587 (STARTTLS)
  SMTP_USER       login, e.g. noreply@robustidps.ai
  SMTP_PASSWORD   that mailbox's password
  SMTP_FROM       From header; defaults to SMTP_USER
"""

import logging
import os
import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formataddr, make_msgid

logger = logging.getLogger("robustidps.mailer")


class MailError(RuntimeError):
    """The message could not be handed to the mail server."""


def _settings() -> dict:
    user = os.getenv("SMTP_USER", "")
    return {
        "host": os.getenv("SMTP_HOST", ""),
        "port": int(os.getenv("SMTP_PORT", "465")),
        "user": user,
        "password": os.getenv("SMTP_PASSWORD", ""),
        "sender": os.getenv("SMTP_FROM", "") or user,
    }


def mail_configured() -> bool:
    s = _settings()
    return bool(s["host"] and s["sender"])


def send_mail(to: str, subject: str, text: str, html: str | None = None) -> None:
    """Send one message; raise MailError on any failure (the caller decides what to tell the user)."""
    s = _settings()
    if not (s["host"] and s["sender"]):
        raise MailError("SMTP is not configured")
    msg = EmailMessage()
    msg["From"] = formataddr(("RobustIDPS.ai", s["sender"]))
    msg["To"] = to
    msg["Subject"] = subject
    msg["Message-ID"] = make_msgid(domain=s["sender"].rpartition("@")[2] or None)
    msg.set_content(text)
    if html:
        msg.add_alternative(html, subtype="html")
    context = ssl.create_default_context()
    try:
        if s["port"] == 465:
            server = smtplib.SMTP_SSL(s["host"], s["port"], timeout=20, context=context)
        else:
            server = smtplib.SMTP(s["host"], s["port"], timeout=20)
            server.starttls(context=context)
        with server:
            if s["user"]:
                server.login(s["user"], s["password"])
            server.send_message(msg)
    except (OSError, smtplib.SMTPException) as exc:
        logger.error("Mail to %s failed: %s", to, exc)
        raise MailError(str(exc)) from exc
    logger.info("Mail sent to %s: %s", to, subject)
