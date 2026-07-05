"""One-time intake: turn an authenticated artifact upload into a ``pending`` request.

The one-time entry point's core, below the HTTP layer (``docs/web-proxy.md``
§One-Time Flow). It performs, in one transaction-staged unit, the steps issue #3
owns:

1. **Hash Binding** — SHA-256 the exact uploaded bytes and record it on the
   request (``docs/constraints.md`` §6); approvers approve *this* digest.
2. **Snapshot** — freeze the eligible-approver set and quorum from the service
   config onto the request at creation (ADR 0008, :mod:`msig_proxy.approvals.snapshot`),
   immune to later config edits.
3. **Stage** — hold the bytes (``one_time/artifact``) so the publish primitive can
   re-verify the hash before publishing and destroy them at a terminal outcome.

Voting, notification, and execution are later slices; this only creates the
record. It operates on a session and flushes (does not commit) — the caller's
session scope owns the commit.
"""

from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from msig_proxy.approvals import snapshot
from msig_proxy.core import crypto
from msig_proxy.core.config import ServiceConfig
from msig_proxy.core.models import (
    ApprovalRequest,
    StagedArtifact,
    User,
)


def staged_artifact_count(session: Session, service_name: str) -> int:
    """How many artifacts are currently staged (held) for ``service_name``.

    The upload edge reads this against ``service.max_staged_artifacts`` to enforce
    the per-service artifact-count cap (DOS-1 storage-exhaustion leg, #126). A
    :class:`StagedArtifact` is dropped at its request's terminal outcome, so a live
    row is one artifact's bytes still on disk — the count *is* the current storage
    footprint, not a lifetime total."""
    return (
        session.scalar(
            select(func.count())
            .select_from(StagedArtifact)
            .join(ApprovalRequest, ApprovalRequest.id == StagedArtifact.approval_request_id)
            .where(ApprovalRequest.service_name == service_name)
        )
        or 0
    )


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
    approvers = snapshot.resolve_approvers(session, service.approvers)
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
    snapshot.persist_request_with_snapshot(session, request, approvers)

    # One-time layers artifact staging on top of the shared persist (request.id is
    # allocated above): hold the bytes so publish can re-verify the hash and destroy
    # them at a terminal outcome.
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
