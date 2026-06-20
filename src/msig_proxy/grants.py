"""Service Grant resolution with lazy expiry — the read side of the forward-auth
gate (issue #12).

The grant store is written at the ``approved`` handoff (issue #11,
:func:`msig_proxy.executor.issue_service_grant`) and read here at ``GET /auth``.
Expiry is evaluated **lazily** (no
scheduler in the MVP, ``docs/request-lifecycle.md`` §Service Grant lifecycle): an
``active`` grant whose ``expires_at`` has passed is flipped to ``expired`` the
first time ``/auth`` observes it, emits ``grant.expired``, and is not returned —
so the next request re-gates through the closed (login) path. This mirrors the
lazy session expiry in :mod:`msig_proxy.sessions`.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from msig_proxy import events
from msig_proxy.core.models import GRANT_ACTIVE, GRANT_EXPIRED, ServiceGrant


def _aware(value: datetime) -> datetime:
    """Treat a tz-naive timestamp (as SQLite returns) as UTC for comparison."""
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def resolve_active_grant(
    db: Session, *, user_id: uuid.UUID, service_name: str
) -> ServiceGrant | None:
    """Return a valid (``active``, unexpired) Service Grant for this User + Service, or ``None``.

    Lazy expiry: every ``active`` grant for the pair whose window has elapsed is
    transitioned to ``expired`` here and emits ``grant.expired`` (payload
    ``{"grant_id": ...}``); only a grant still within its window is returned. The
    caller's session scope commits the transition, so the flip persists.
    """
    now = datetime.now(UTC)
    grants = db.scalars(
        select(ServiceGrant).where(
            ServiceGrant.user_id == user_id,
            ServiceGrant.service_name == service_name,
            ServiceGrant.state == GRANT_ACTIVE,
        )
    ).all()

    valid: ServiceGrant | None = None
    for grant in grants:
        if _aware(grant.expires_at) <= now:
            grant.state = GRANT_EXPIRED
            db.flush()
            events.emit(events.Event(events.GRANT_EXPIRED, {"grant_id": str(grant.id)}))
        elif valid is None:
            valid = grant
    return valid
