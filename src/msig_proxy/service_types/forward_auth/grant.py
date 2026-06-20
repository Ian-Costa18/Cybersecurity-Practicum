"""Service Grant issuance: the forward-auth ``approved`` handoff (issue #5, ADR 0007).

The side-effecting primitive a forward-auth ``approved`` request hands off to:
mint (or resume) the Service Grant scoped to the Requester + Service. The grant is
read back at ``GET /auth`` by the sibling ``resolve`` module.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from msig_proxy.core import events
from msig_proxy.core.config import AppConfig
from msig_proxy.core.models import GRANT_ACTIVE, ApprovalRequest, ServiceGrant


def issue_service_grant(
    session: Session, config: AppConfig, request: ApprovalRequest
) -> ServiceGrant:
    """Issue (or resume) the forward-auth Service Grant for an approved request.

    The forward-auth handoff (ADR 0007): create an ``active`` grant scoped to the
    Requester + Service with ``expires_at`` from ``grant_expiry_hours``, complete
    the bidirectional link, and emit ``grant.activated``. Idempotent on
    ``approval_request_id`` (unique), so a redelivered ``request.approved`` returns
    the existing grant rather than minting a second one.
    """
    existing = session.scalars(
        select(ServiceGrant).where(ServiceGrant.approval_request_id == request.id)
    ).first()
    if existing is not None:
        return existing

    service = config.services.get(request.service_name)
    grant_expiry_hours = service.grant_expiry_hours if service is not None else 8
    # grant_expiry_hours == 0 means "expires with the Proxy Session" (docs/config.md);
    # binding to the requester's exact session end is the /auth slice (#12), so the
    # window here approximates it with the configured session lifetime.
    if grant_expiry_hours == 0:
        grant_expiry_hours = config.auth.session_expiry_hours

    now = datetime.now(UTC)
    grant = ServiceGrant(
        approval_request_id=request.id,
        user_id=request.requester_id,
        service_name=request.service_name,
        state=GRANT_ACTIVE,
        created_at=now,
        expires_at=now + timedelta(hours=grant_expiry_hours),
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
