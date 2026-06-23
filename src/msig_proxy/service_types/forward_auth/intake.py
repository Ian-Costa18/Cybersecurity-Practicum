"""Forward-auth intake: find-or-create the ``pending`` access request for a User+Service.

The forward-auth analogue of one-time intake. It snapshots the eligible-approver
set and quorum at creation (ADR 0008, :mod:`msig_proxy.approvals.snapshot`) exactly
as the publish path does, but with **no artifact, no action, and no hash binding** —
a forward-auth request grants access rather than executing against held bytes.

Operates on a session and flushes (does not commit) — the caller's session scope
owns the commit.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from msig_proxy.approvals import snapshot
from msig_proxy.core.config import ServiceConfig
from msig_proxy.core.models import (
    FORWARD_AUTH,
    PENDING,
    ApprovalRequest,
    User,
)


def request_forward_auth_access(
    session: Session,
    *,
    requester: User,
    service_name: str,
    service: ServiceConfig,
) -> tuple[ApprovalRequest, bool]:
    """Find-or-create the ``pending`` forward-auth Approval Request for this User+Service.

    Idempotent per (User, Service): a Requester who returns while a request is
    still ``pending`` resumes the same one (``docs/web-proxy.md`` §Resuming). The
    boolean is ``True`` only when a new request was created, so the caller emits
    ``request.created`` exactly once.
    """
    existing = session.scalars(
        select(ApprovalRequest).where(
            ApprovalRequest.requester_id == requester.id,
            ApprovalRequest.service_name == service_name,
            ApprovalRequest.service_type == FORWARD_AUTH,
            ApprovalRequest.state == PENDING,
        )
    ).first()
    if existing is not None:
        return existing, False

    approvers = snapshot.resolve_approvers(session, service.approvers)
    request = ApprovalRequest(
        requester_id=requester.id,
        service_name=service_name,
        service_type=FORWARD_AUTH,
        action=None,
        quorum=service.quorum,
        # No artifact_sha256 / package fields — forward-auth holds no payload.
    )
    snapshot.persist_request_with_snapshot(session, request, approvers)
    return request, True
