"""Framework-free per-key rate limiting — the shared throttle primitive (#123).

The anti-automation counter behind the auth-endpoint guards (IDENT-5) and, by
design, any later per-key quota (#32 reuses this for request-creation caps —
that is why the counter is keyed by an arbitrary ``(scope, key)`` pair rather
than hardcoding "IP"). It sits in ``core/`` because it is a cross-slice
primitive owned by no slice (``docs/source-layout.md``): the web-edge guards in
:mod:`msig_proxy.auth.guards` call it; nothing here imports FastAPI.

The mechanism is a **fixed window with a backoff penalty**, persisted as one
DB row per ``(scope, key)`` — the same DB-only-state posture as the single-use
TOTP ledger (no Redis, no in-process state; ADR 0013's single worker makes the
DB the one home for counters). Each *attempt* is counted up front, before any
expensive verification runs, so the ``429`` fires before bcrypt burns CPU:

* within a window, attempts increment the row's ``count`` atomically
  (``UPDATE … SET count = count + 1``, not read-modify-write);
* the attempt that exceeds ``limit`` stamps ``blocked_until = now + backoff``
  and is rejected; further attempts are rejected until the stamp passes
  (``retry_after`` counts down — the ``Retry-After`` header value);
* once the backoff (or an idle window) passes, the next attempt starts a
  fresh window.

Counting attempts rather than *failures* is deliberate: it needs no signal
back from the verifier (the guard is self-contained), it caps CPU burned on
the endpoint whether or not credentials are valid, and it cannot be gamed by
an attacker alternating valid and bogus attempts. The cost — successful
authentications spend budget too — is absorbed by generous production
thresholds (see ``auth.rate_limit_*`` in ``docs/config.md``).
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from msig_proxy.core.models import RateLimitCounter
from msig_proxy.core.time import aware


@dataclass(frozen=True)
class Verdict:
    """The limiter's answer for one attempt: pass, or come back later.

    ``retry_after`` is the whole-second countdown a rejected caller should wait
    (the ``Retry-After`` header value); ``0`` when the attempt is allowed.
    """

    allowed: bool
    retry_after: int = 0


def register_attempt(
    session: Session,
    *,
    scope: str,
    key: str,
    limit: int,
    window_seconds: int,
    backoff_seconds: int,
    now: datetime | None = None,
) -> Verdict:
    """Count one attempt against ``(scope, key)`` and say whether it may proceed.

    Check-and-count in one call: the attempt is recorded *and* judged against
    ``limit`` per ``window_seconds``, entering a ``backoff_seconds`` penalty when
    exceeded. ``now`` is injectable for tests; callers own the transaction —
    commit promptly (the auth guards run this on a dedicated short-lived session
    so the count persists even when the request's own transaction rolls back,
    e.g. a vote 401).

    Concurrency mirrors :func:`msig_proxy.auth.credentials._burn_totp_step`: the
    first-attempt insert races on the unique ``(scope, key)`` index inside a
    SAVEPOINT, and the loser falls through to the increment path; the increment
    itself is an atomic ``UPDATE … count + 1``, never read-modify-write.
    """
    now = now or datetime.now(UTC)
    row = session.scalars(
        select(RateLimitCounter).where(
            RateLimitCounter.scope == scope, RateLimitCounter.key == key
        )
    ).one_or_none()

    if row is None:
        savepoint = session.begin_nested()
        try:
            session.add(RateLimitCounter(scope=scope, key=key, window_start=now, count=1))
            session.flush()
            return Verdict(allowed=True)
        except IntegrityError:
            # Lost the first-attempt race: the row exists now — count against it.
            savepoint.rollback()
            row = session.scalars(
                select(RateLimitCounter).where(
                    RateLimitCounter.scope == scope, RateLimitCounter.key == key
                )
            ).one()

    if row.blocked_until is not None:
        if now < aware(row.blocked_until):
            # Serving the penalty: reject with the remaining countdown.
            remaining = (aware(row.blocked_until) - now).total_seconds()
            return Verdict(allowed=False, retry_after=max(1, math.ceil(remaining)))
        return _restart_window(session, row, now)

    if now >= aware(row.window_start) + timedelta(seconds=window_seconds):
        return _restart_window(session, row, now)

    # Atomic increment — the DB owns the arithmetic, not a stale Python copy.
    session.execute(
        update(RateLimitCounter)
        .where(RateLimitCounter.id == row.id)
        .values(count=RateLimitCounter.count + 1)
    )
    session.refresh(row)
    if row.count > limit:
        row.blocked_until = now + timedelta(seconds=backoff_seconds)
        session.flush()
        return Verdict(allowed=False, retry_after=backoff_seconds)
    return Verdict(allowed=True)


def _restart_window(session: Session, row: RateLimitCounter, now: datetime) -> Verdict:
    """Begin a fresh window on ``row`` with this attempt as its first."""
    row.window_start = now
    row.count = 1
    row.blocked_until = None
    session.flush()
    return Verdict(allowed=True)


def client_ip(
    socket_ip: str | None,
    forwarded_for: str | None,
    trusted_proxies: list[str],
) -> str:
    """Resolve the effective client IP for rate-limit keying (PUB-2's trusted boundary).

    ``X-Forwarded-For`` is honored **only** when the TCP peer (``socket_ip``) is a
    declared trusted reverse proxy — otherwise a direct attacker would mint a fresh
    spoofed XFF per request and never accumulate a count. Behind a trusted peer the
    header is walked right-to-left past any further trusted hops, and the first
    address *not* ours is the client (the standard multi-hop XFF reduction). A
    header consisting only of trusted hops, or an absent one, falls back to the
    socket IP; a missing socket address (never the case on a real connection)
    collapses to a shared sentinel bucket rather than an unlimited pass.
    """
    if socket_ip is None:
        return "unknown"
    if not forwarded_for or socket_ip not in trusted_proxies:
        return socket_ip
    for hop in reversed([hop.strip() for hop in forwarded_for.split(",")]):
        if hop and hop not in trusted_proxies:
            return hop
    return socket_ip
