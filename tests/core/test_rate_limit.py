"""Unit: the framework-free rate-limit primitive (#123; reused by #32).

Drives :mod:`msig_proxy.core.rate_limit` directly — arbitrary string keys, an
injected clock, a real (temp SQLite) session — pinning the seam contract that
the auth guards consume today and the request-creation caps (#32) consume next:
fixed window, backoff penalty with a counting-down ``retry_after``, and
independence across keys and scopes.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy.orm import Session

from msig_proxy.core.db import Base, create_db_engine, create_session_factory
from msig_proxy.core.rate_limit import client_ip, register_attempt

_T0 = datetime(2026, 7, 4, 12, 0, 0, tzinfo=UTC)


@pytest.fixture
def session(tmp_path: Path) -> Iterator[Session]:
    engine = create_db_engine(f"sqlite+pysqlite:///{(tmp_path / 'rl.db').as_posix()}")
    Base.metadata.create_all(engine)
    factory = create_session_factory(engine)
    with factory() as db_session:
        yield db_session
    engine.dispose()


def _attempt(session: Session, *, key: str = "198.51.100.1", scope: str = "auth", **overrides):
    values = {"limit": 3, "window_seconds": 60, "backoff_seconds": 300, "now": _T0}
    values.update(overrides)
    return register_attempt(session, scope=scope, key=key, **values)


def test_attempts_within_the_limit_are_allowed(session: Session) -> None:
    for _ in range(3):
        assert _attempt(session).allowed


def test_the_attempt_exceeding_the_limit_enters_backoff(session: Session) -> None:
    for _ in range(3):
        _attempt(session)

    verdict = _attempt(session)

    assert not verdict.allowed
    assert verdict.retry_after == 300  # the full backoff, verbatim for Retry-After


def test_retry_after_counts_down_while_the_backoff_is_served(session: Session) -> None:
    for _ in range(4):
        _attempt(session)  # the 4th trips the 300s backoff at T0

    later = _attempt(session, now=_T0 + timedelta(seconds=100))

    assert not later.allowed
    assert later.retry_after == 200  # 300s penalty minus the 100s already served


def test_a_fresh_window_opens_after_the_backoff_passes(session: Session) -> None:
    for _ in range(4):
        _attempt(session)

    after = _attempt(session, now=_T0 + timedelta(seconds=301))

    assert after.allowed  # the penalty ended; this attempt starts a new window


def test_an_idle_window_expires_and_the_count_resets(session: Session) -> None:
    for _ in range(3):
        _attempt(session)  # budget fully spent, but no backoff tripped

    next_window = _attempt(session, now=_T0 + timedelta(seconds=61))

    assert next_window.allowed  # a new window, not attempt 4 of the old one


def test_keys_are_counted_independently(session: Session) -> None:
    for _ in range(4):
        _attempt(session, key="198.51.100.1")
    assert not _attempt(session, key="198.51.100.1").allowed

    assert _attempt(session, key="203.0.113.7").allowed  # a different key: untouched budget


def test_scopes_are_counted_independently(session: Session) -> None:
    # The #32 reuse contract: another surface's scope never shares "auth"'s budget.
    for _ in range(4):
        _attempt(session, scope="auth")
    assert not _attempt(session, scope="auth").allowed

    assert _attempt(session, scope="request-creation").allowed


def test_client_ip_ignores_forwarded_for_from_an_untrusted_peer() -> None:
    # A direct attacker's spoofed XFF must not mint a fresh key per request.
    assert client_ip("203.0.113.9", "10.0.0.1", trusted_proxies=[]) == "203.0.113.9"
    assert client_ip("203.0.113.9", "10.0.0.1", trusted_proxies=["192.0.2.1"]) == "203.0.113.9"


def test_client_ip_reads_forwarded_for_behind_a_trusted_proxy() -> None:
    assert client_ip("192.0.2.1", "203.0.113.9", trusted_proxies=["192.0.2.1"]) == "203.0.113.9"


def test_client_ip_walks_past_chained_trusted_hops() -> None:
    # client, then an inner trusted proxy appended by the edge: skip our own hops.
    assert (
        client_ip("192.0.2.1", "203.0.113.9, 192.0.2.2", trusted_proxies=["192.0.2.1", "192.0.2.2"])
        == "203.0.113.9"
    )


def test_client_ip_falls_back_to_the_socket_when_forwarded_for_is_unusable() -> None:
    trusted = ["192.0.2.1"]
    assert client_ip("192.0.2.1", None, trusted) == "192.0.2.1"  # no header
    assert client_ip("192.0.2.1", "192.0.2.1", trusted) == "192.0.2.1"  # only trusted hops
    assert client_ip(None, "203.0.113.9", trusted) == "unknown"  # no socket: shared bucket
