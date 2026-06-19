"""Upload intake: turn an authenticated artifact upload into a ``pending`` Approval
Request.

This is the one-time entry point's core, below the HTTP layer
(``docs/web-proxy.md`` §One-Time Flow). It performs, in one transaction-staged
unit, the steps issue #3 owns:

1. **Hash Binding** — SHA-256 the exact uploaded bytes and record it on the
   request (``docs/constraints.md`` §6); approvers approve *this* digest.
2. **Snapshot** — freeze the eligible-approver set and quorum from the service
   config onto the request at creation (ADR 0008), immune to later config edits.
3. **Stage** — hold the bytes so the Executor can re-verify the hash before
   publishing and destroy them at a terminal outcome.

Voting, notification, and execution are later slices; this only creates the
record. It operates on a session and flushes (does not commit) — the caller's
session scope owns the commit.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from msig_proxy import crypto
from msig_proxy.config import ServiceConfig
from msig_proxy.models import ApprovalRequest, ApprovalRequestApprover, StagedArtifact, User


class UnknownApproverError(Exception):
    """A service lists an approver username with no corresponding User account.

    A configuration/provisioning fault: the snapshot would silently omit an
    intended approver (weakening quorum), so creation fails loudly instead.
    """


def _resolve_approvers(session: Session, usernames: list[str]) -> list[User]:
    """Map configured approver usernames to User rows, preserving config order.

    Raises :class:`UnknownApproverError` naming every username with no account,
    rather than snapshotting a smaller-than-configured set.
    """
    found = {
        user.username: user
        for user in session.scalars(select(User).where(User.username.in_(usernames)))
    }
    missing = [name for name in usernames if name not in found]
    if missing:
        raise UnknownApproverError(f"no User account for configured approver(s): {missing}")
    return [found[name] for name in usernames]


def create_publish_request(
    session: Session,
    *,
    requester: User,
    service_name: str,
    service: ServiceConfig,
    package_name: str,
    package_version: str,
    filename: str,
    content: bytes,
) -> ApprovalRequest:
    """Create a ``pending`` one-time Approval Request bound to ``content``'s hash.

    Snapshots the service's approver set and quorum onto the request (ADR 0008)
    and stages the bytes. Returns the flushed :class:`ApprovalRequest` (its ``id``
    is allocated); the caller commits.
    """
    approvers = _resolve_approvers(session, service.approvers)
    digest = crypto.sha256_hex(content)

    request = ApprovalRequest(
        requester_id=requester.id,
        service_name=service_name,
        action=service.action or "",
        quorum=service.quorum,
        artifact_sha256=digest,
        package_name=package_name,
        package_version=package_version,
    )
    session.add(request)
    session.flush()  # allocate request.id for the snapshot + staged-artifact links

    session.add_all(
        ApprovalRequestApprover(approval_request_id=request.id, user_id=approver.id)
        for approver in approvers
    )
    session.add(
        StagedArtifact(
            approval_request_id=request.id,
            filename=filename,
            content=content,
            sha256=digest,
        )
    )
    session.flush()
    return request
