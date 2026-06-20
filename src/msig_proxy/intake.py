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

import fnmatch
import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from msig_proxy import crypto
from msig_proxy.config import ServiceConfig, is_wildcard
from msig_proxy.core.models import (
    FORWARD_AUTH,
    PENDING,
    ApprovalRequest,
    ApprovalRequestApprover,
    StagedArtifact,
    User,
)


class UnknownApproverError(Exception):
    """A service lists a literal approver username with no corresponding User account.

    A configuration/provisioning fault: the snapshot would silently omit an
    intended approver (weakening quorum), so creation fails loudly instead. Only
    *literal* entries raise — a glob is allowed to match zero users.
    """


def _resolve_approvers(session: Session, patterns: list[str]) -> list[User]:
    """Expand configured approver patterns to distinct User rows at snapshot time.

    Each entry is a literal username or a glob (``*`` = all users, ``admin_*`` =
    that prefix; fnmatch semantics, see :func:`msig_proxy.config.is_wildcard`).
    Literals must resolve — a missing one raises :class:`UnknownApproverError`
    rather than silently shrinking the eligible set — while a glob may match zero
    users (a forward-looking rule like "any admin" is valid before the first admin
    exists). Matches are de-duplicated and returned in first-seen order, since the
    snapshot keys on distinct user ids (ADR 0008).
    """
    users = session.scalars(select(User)).all()
    by_name = {user.username: user for user in users}

    resolved: dict[uuid.UUID, User] = {}
    missing: list[str] = []
    for pattern in patterns:
        if is_wildcard(pattern):
            for user in users:
                if fnmatch.fnmatchcase(user.username, pattern):
                    resolved.setdefault(user.id, user)
        elif pattern in by_name:
            resolved.setdefault(by_name[pattern].id, by_name[pattern])
        else:
            missing.append(pattern)

    if missing:
        raise UnknownApproverError(f"no User account for configured approver(s): {missing}")
    return list(resolved.values())


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
        service_type=service.type,
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


def request_forward_auth_access(
    session: Session,
    *,
    requester: User,
    service_name: str,
    service: ServiceConfig,
) -> tuple[ApprovalRequest, bool]:
    """Find-or-create the ``pending`` forward-auth Approval Request for this User+Service.

    The forward-auth analogue of :func:`create_publish_request`: it snapshots the
    eligible-approver set and quorum at creation (ADR 0008) exactly as the publish
    path does, but with **no artifact, no action, and no hash binding** — a
    forward-auth request grants access rather than executing against held bytes.

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

    approvers = _resolve_approvers(session, service.approvers)
    request = ApprovalRequest(
        requester_id=requester.id,
        service_name=service_name,
        service_type=FORWARD_AUTH,
        action=None,
        quorum=service.quorum,
        # No artifact_sha256 / package fields — forward-auth holds no payload.
    )
    session.add(request)
    session.flush()  # allocate request.id for the snapshot links

    session.add_all(
        ApprovalRequestApprover(approval_request_id=request.id, user_id=approver.id)
        for approver in approvers
    )
    session.flush()
    return request, True
