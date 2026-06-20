"""Server-side, revocable Proxy Sessions and the signed session cookie.

A Proxy Session is **server-side state** (:class:`msig_proxy.core.models.ProxySession`).
The cookie carries only the session id, HMAC-signed under ``server.secret_key`` so
it cannot be forged or tampered with (``docs/config.md`` §server.secret_key); the
id itself is a 256-bit random token, so resolution requires both a valid signature
*and* a matching live row. Because the row is authoritative, **deleting it revokes
the session immediately** — there is no stateless blob that outlives the record.

Expiry is evaluated **lazily** on resolution (no scheduler in the MVP): an elapsed
session is treated as invalid and its row is cleaned up in passing.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from msig_proxy.core.models import ProxySession, User

# The session cookie name. HttpOnly + Secure + SameSite=Strict are set at issue time.
SESSION_COOKIE = "msig_session"
_SESSION_ID_BYTES = 32  # 256-bit session id


def _aware(value: datetime) -> datetime:
    """Treat a tz-naive timestamp (as SQLite returns) as UTC for comparison."""
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def _signature(session_id: str, secret_key: str) -> str:
    digest = hmac.new(secret_key.encode("utf-8"), session_id.encode("utf-8"), hashlib.sha256)
    return base64.urlsafe_b64encode(digest.digest()).decode("ascii").rstrip("=")


def sign_session_id(session_id: str, secret_key: str) -> str:
    """Return the cookie value: ``<session_id>.<hmac-signature>``."""
    return f"{session_id}.{_signature(session_id, secret_key)}"


def unsign_session_id(cookie_value: str, secret_key: str) -> str | None:
    """Verify the cookie's signature and return the session id, or ``None``.

    A constant-time signature check; the random session id contains no ``.``, so
    splitting on the last one cleanly separates id from signature.
    """
    session_id, separator, signature = cookie_value.rpartition(".")
    if not separator:
        return None
    if not hmac.compare_digest(signature, _signature(session_id, secret_key)):
        return None
    return session_id


def create_session(
    db: Session, user: User, *, lifetime_hours: int, secret_key: str
) -> tuple[ProxySession, str]:
    """Create a Proxy Session row and return it with the signed cookie value."""
    now = datetime.now(UTC)
    session_id = secrets.token_urlsafe(_SESSION_ID_BYTES)
    proxy_session = ProxySession(
        id=session_id,
        user_id=user.id,
        created_at=now,
        expires_at=now + timedelta(hours=lifetime_hours),
    )
    db.add(proxy_session)
    db.flush()
    return proxy_session, sign_session_id(session_id, secret_key)


def resolve_session(db: Session, cookie_value: str, secret_key: str) -> ProxySession | None:
    """Resolve a cookie to a live Proxy Session, or ``None``.

    Returns ``None`` for a bad signature, a missing row (revoked), or an expired
    session — expired rows are deleted lazily here (no scheduler in the MVP).
    """
    session_id = unsign_session_id(cookie_value, secret_key)
    if session_id is None:
        return None
    proxy_session = db.get(ProxySession, session_id)
    if proxy_session is None:
        return None
    if _aware(proxy_session.expires_at) <= datetime.now(UTC):
        db.delete(proxy_session)
        db.flush()
        return None
    return proxy_session


def delete_session(db: Session, session_id: str) -> None:
    """Revoke a session by deleting its row (idempotent)."""
    proxy_session = db.get(ProxySession, session_id)
    if proxy_session is not None:
        db.delete(proxy_session)
        db.flush()


def delete_user_sessions(db: Session, user_id: uuid.UUID) -> int:
    """Revoke **all** of a User's Proxy Sessions (admin deactivate/delete/reset, #17).

    Returns the number revoked. Deleting the rows is immediate revocation — the next
    request finds no matching session and resolves to unauthenticated.
    """
    rows = db.scalars(select(ProxySession).where(ProxySession.user_id == user_id)).all()
    for proxy_session in rows:
        db.delete(proxy_session)
    db.flush()
    return len(rows)
