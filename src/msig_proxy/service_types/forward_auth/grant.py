"""Service Grant issuance: the forward-auth ``approved`` handoff (issue #5, ADR 0007).

The side-effecting primitive a forward-auth ``approved`` request hands off to:
mint (or resume) the Service Grant scoped to the Requester + Service. The grant is
read back at ``GET /auth`` by the sibling ``resolve`` module.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from msig_proxy.core import events
from msig_proxy.core.config import AppConfig
from msig_proxy.core.models import GRANT_ACTIVE, ApprovalRequest, ProxySession, ServiceGrant


def _aware(value: datetime) -> datetime:
    """Treat a tz-naive timestamp (as SQLite returns) as UTC for comparison."""
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def _requester_session_end(
    session: Session, requester_id: uuid.UUID, now: datetime
) -> datetime | None:
    """The end of the Requester's longest-lived still-active Proxy Session, or ``None``.

    Used to bind a ``grant_expiry_hours = 0`` grant to "the Requester's Proxy Session"
    (``docs/config.md`` §services, ``docs/web-proxy.md`` §Service Grant Expiry). A
    forward-auth Requester reaches quorum while logged in, so they normally have one;
    ``None`` means none is live (e.g. it expired mid-wait), and the caller falls back.
    """
    ends = [
        _aware(row.expires_at)
        for row in session.scalars(
            select(ProxySession).where(ProxySession.user_id == requester_id)
        ).all()
    ]
    live = [end for end in ends if end > now]
    return max(live) if live else None


def _grant_expires_at(session: Session, config: AppConfig, request: ApprovalRequest) -> datetime:
    """Resolve a grant's ``expires_at`` from the service's ``grant_expiry_hours`` (#78).

    A non-zero value is a fixed window from now. ``0`` means the grant **expires with
    the Requester's Proxy Session** (``docs/config.md`` §services): bind ``expires_at``
    to that session's end, not to an independent fresh window. With no live session to
    bind to, fall back to a window of the configured session lifetime so the grant is
    not born already-expired.
    """
    service = config.services.get(request.service_name)
    grant_expiry_hours = service.grant_expiry_hours if service is not None else 8
    now = datetime.now(UTC)
    if grant_expiry_hours != 0:
        return now + timedelta(hours=grant_expiry_hours)
    session_end = _requester_session_end(session, request.requester_id, now)
    if session_end is not None:
        return session_end
    return now + timedelta(hours=config.auth.session_expiry_hours)


def issue_service_grant(
    session: Session, config: AppConfig, request: ApprovalRequest
) -> ServiceGrant:
    """Issue (or resume) the forward-auth Service Grant for an approved request.

    The forward-auth handoff (ADR 0007): create an ``active`` grant scoped to the
    Requester + Service with ``expires_at`` from the service's ``grant_expiry_hours``
    (the ``0 → session-bound`` rule lives in :func:`_grant_expires_at`), complete the
    bidirectional link, and emit ``grant.activated``. Idempotent on
    ``approval_request_id`` (unique), so a redelivered ``request.approved`` returns
    the existing grant rather than minting a second one.
    """
    existing = session.scalars(
        select(ServiceGrant).where(ServiceGrant.approval_request_id == request.id)
    ).first()
    if existing is not None:
        return existing

    now = datetime.now(UTC)
    grant = ServiceGrant(
        approval_request_id=request.id,
        user_id=request.requester_id,
        service_name=request.service_name,
        state=GRANT_ACTIVE,
        created_at=now,
        expires_at=_grant_expires_at(session, config, request),
    )
    session.add(grant)
    session.flush()  # allocate grant.id for the forward link
    request.service_grant_id = grant.id  # complete the bidirectional link
    session.flush()

    events.emit(
        events.Event(
            events.GRANT_ACTIVATED,
            {
                "grant_id": str(grant.id),
                "approval_request_id": str(request.id),
                "expires_at": grant.expires_at.isoformat(),
            },
        ),
        session=session,  # lend the open transition so a subscriber sees the flushed grant
    )
    return grant
