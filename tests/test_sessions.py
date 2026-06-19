"""Proxy Session lifecycle: signed cookie, server-side record, lazy expiry.

Real DB, real HMAC. Exercises :mod:`msig_proxy.sessions` below the HTTP layer.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.orm import Session

from msig_proxy import sessions
from msig_proxy.db import Base, create_db_engine, create_session_factory
from msig_proxy.models import ProxySession, User
from msig_proxy.seed import seed_user

_SECRET = "test-secret-key-0123456789"


@pytest.fixture
def session() -> Iterator[Session]:
    engine = create_db_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    db = create_session_factory(engine)()
    try:
        yield db
    finally:
        db.close()
        engine.dispose()


def _user(session: Session) -> User:
    return seed_user(
        session, username="alice", email="alice@example.com", password="pw-alice-123"
    ).user


def test_sign_unsign_round_trips() -> None:
    cookie = sessions.sign_session_id("abc123", _SECRET)
    assert sessions.unsign_session_id(cookie, _SECRET) == "abc123"


def test_a_tampered_or_wrongly_keyed_cookie_does_not_verify() -> None:
    cookie = sessions.sign_session_id("abc123", _SECRET)
    assert sessions.unsign_session_id(cookie + "x", _SECRET) is None  # tampered signature
    assert sessions.unsign_session_id(cookie, "a-different-secret-key") is None  # wrong key
    assert sessions.unsign_session_id("no-dot-here", _SECRET) is None  # malformed


def test_create_then_resolve_returns_the_session(session: Session) -> None:
    user = _user(session)
    proxy_session, cookie = sessions.create_session(
        session, user, lifetime_hours=8, secret_key=_SECRET
    )

    resolved = sessions.resolve_session(session, cookie, _SECRET)
    assert resolved is not None
    assert resolved.id == proxy_session.id
    assert resolved.user_id == user.id


def test_deleting_the_record_revokes_resolution(session: Session) -> None:
    user = _user(session)
    proxy_session, cookie = sessions.create_session(
        session, user, lifetime_hours=8, secret_key=_SECRET
    )

    sessions.delete_session(session, proxy_session.id)

    assert sessions.resolve_session(session, cookie, _SECRET) is None


def test_an_expired_session_is_invalid_and_cleaned_up(session: Session) -> None:
    user = _user(session)
    cookie = sessions.sign_session_id("expired-id", _SECRET)
    session.add(
        ProxySession(
            id="expired-id",
            user_id=user.id,
            created_at=datetime.now(UTC) - timedelta(hours=9),
            expires_at=datetime.now(UTC) - timedelta(hours=1),
        )
    )
    session.flush()

    assert sessions.resolve_session(session, cookie, _SECRET) is None
    assert session.get(ProxySession, "expired-id") is None  # lazily deleted in passing
