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

from msig_proxy.core import crypto
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
    """A current 6-digit TOTP code for a *plaintext* base32 secret.

    For callers that hold the plaintext directly (e.g. ``seed_user(...).totp_secret``);
    when only the DB row is in hand, decrypt first via :func:`totp_code_for`.
    """
    return pyotp.TOTP(secret).now()


def totp_code_at(secret: str, offset: int) -> str:
    """A valid TOTP code ``offset`` 30s steps from now for a *plaintext* base32 secret.

    Single-use TOTP (#73) burns the matched ``(user, time-step)``, so a same-user
    repeat *within one window* must present a code from a **different** still-valid
    step. Within ``valid_window=1`` there are three valid steps (t-1, t, t+1); pass
    distinct offsets to drive two same-user actions without waiting out the window.
    """
    return pyotp.TOTP(secret).at(datetime.now(UTC), offset)


def plaintext_totp_secret(user: User, password: str) -> str:
    """Recover a user's base32 TOTP secret from its at-rest wrap (#122).

    Since the secret is AES-256-GCM-wrapped under the password-derived key (bound to
    the user id as AAD), a test that needs a code from a DB row must supply the
    password — exactly what the verifier does at login. Mirrors
    :func:`msig_proxy.auth.credentials._decrypt_totp_secret`.
    """
    assert user.totp_secret is not None and user.totp_salt is not None
    enc_key = crypto.derive_enc_key(password, user.totp_salt)
    return crypto.decrypt_totp_secret(user.totp_secret, enc_key, crypto.totp_aad(user.id))


def totp_code_for(user: User, password: str, offset: int = 0) -> str:
    """A valid TOTP code for a DB ``User`` row, decrypting the wrapped secret first."""
    return pyotp.TOTP(plaintext_totp_secret(user, password)).at(datetime.now(UTC), offset)


def current_totp(session_factory: sessionmaker[OrmSession], username: str, password: str) -> str:
    """Look up a user by name, decrypt their wrapped TOTP secret, return a current code.

    Works for both seeded users (``seed_user`` provisions a secret) and enrollees
    (``/enroll`` sets one the test never saw), so HTTP login/approve flows can satisfy
    the second factor without threading the plaintext through fixtures — but the
    password is required now that the secret is wrapped at rest (#122).
    """
    return current_totp_at(session_factory, username, 0, password)


def current_totp_at(
    session_factory: sessionmaker[OrmSession], username: str, offset: int, password: str
) -> str:
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
        return totp_code_for(user, password, offset)


def envelope_as_message(envelope: Envelope) -> EmailMessage:
    """Parse a captured SMTP envelope into an :class:`email.message.EmailMessage`.

    Uses the modern email policy so ``get_content()`` is available.
    """
    content = envelope.content
    if not isinstance(content, (bytes, bytearray)):
        raise TypeError(f"expected envelope content as bytes, got {type(content).__name__}")
    return BytesParser(policy=default_policy).parsebytes(content)
