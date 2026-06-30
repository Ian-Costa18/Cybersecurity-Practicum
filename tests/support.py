"""Reusable, non-fixture test helpers shared across modules.

Fixtures live in ``conftest.py``; the plain constants, types, and functions they
build on live here so test modules can import them directly.
"""

from __future__ import annotations

import socket
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email.message import EmailMessage
from email.parser import BytesParser
from email.policy import default as default_policy

import pyotp
from aiosmtpd.smtp import SMTP, Envelope, Session
from sqlalchemy import select
from sqlalchemy.orm import Session as OrmSession
from sqlalchemy.orm import sessionmaker

from msig_proxy.core.models import User

# The one outbound boundary the suite mocks — see docs/mvp.md.
PYPI_UPLOAD_URL = "https://upload.pypi.org/legacy/"


@dataclass
class SmtpProbe:
    """Handle to the live in-process SMTP server and the mail it received."""

    host: str
    port: int
    messages: list[Envelope] = field(default_factory=list)


class CollectingHandler:
    """aiosmtpd handler that records every delivered envelope."""

    def __init__(self) -> None:
        self.messages: list[Envelope] = []

    # handle_DATA is aiosmtpd's required hook name (not snake_case by our choice).
    async def handle_DATA(self, server: SMTP, session: Session, envelope: Envelope) -> str:
        self.messages.append(envelope)
        return "250 Message accepted for delivery"


def free_port() -> int:
    """Reserve and return an ephemeral local TCP port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def totp_code(secret: str) -> str:
    """A current 6-digit TOTP code for a base32 secret (for driving #16 auth in tests)."""
    return pyotp.TOTP(secret).now()


def totp_code_at(secret: str, offset: int) -> str:
    """A valid TOTP code ``offset`` 30s steps from now for a base32 secret.

    Single-use TOTP (#73) burns the matched ``(user, time-step)``, so a same-user
    repeat *within one window* must present a code from a **different** still-valid
    step. Within ``valid_window=1`` there are three valid steps (t-1, t, t+1); pass
    distinct offsets to drive two same-user actions without waiting out the window.
    """
    return pyotp.TOTP(secret).at(datetime.now(UTC), offset)


def current_totp(session_factory: sessionmaker[OrmSession], username: str) -> str:
    """Look up a user's enrolled TOTP secret in the DB and return a current code.

    Works for both seeded users (``seed_user`` provisions a secret) and enrollees
    (``/enroll`` sets one the test never saw), so HTTP login/approve flows can
    satisfy the second factor without threading the secret through fixtures.
    """
    return current_totp_at(session_factory, username, 0)


def current_totp_at(session_factory: sessionmaker[OrmSession], username: str, offset: int) -> str:
    """Like :func:`current_totp` but for the step ``offset`` 30s steps from now.

    The single-use companion to :func:`current_totp` (#73): when an HTTP test
    re-authenticates the *same* user twice in one window, give the second action a
    distinct-but-still-valid code (e.g. offset ``+1``) so it is not rejected as a
    replay of the first, burned step.
    """
    with session_factory() as session:
        user = session.scalars(select(User).where(User.username == username)).one()
        if user.totp_secret is None:  # pragma: no cover - enrolled users always have one
            raise AssertionError(f"{username} has no totp_secret")
        return pyotp.TOTP(user.totp_secret).at(datetime.now(UTC), offset)


def envelope_as_message(envelope: Envelope) -> EmailMessage:
    """Parse a captured SMTP envelope into an :class:`email.message.EmailMessage`.

    Uses the modern email policy so ``get_content()`` is available.
    """
    content = envelope.content
    if not isinstance(content, (bytes, bytearray)):
        raise TypeError(f"expected envelope content as bytes, got {type(content).__name__}")
    return BytesParser(policy=default_policy).parsebytes(content)
