"""The Executor: on ``approved``, re-verify the artifact hash and publish (or refuse).

This closes the thesis end-to-end (issue #5). When an Approval Request reaches a
terminal state, :func:`finalize` runs the handoff:

* ``approved`` (one-time publish) → **re-verify** the held artifact's SHA-256
  against the hash the Approvers signed over (Hash Binding, ``docs/constraints.md``
  §6); on a match, publish to the PyPI boundary; on a mismatch, refuse — the
  publish never reaches PyPI (the integrity oracle). Either way, notify the
  outcome.
* ``denied`` → notify the denial. Nothing is published (the quorum oracle: a
  no-quorum / denied request never reaches the boundary).

The PyPI upload is the **one mocked seam** in the test suite; the captured request
is the assertion oracle (``docs/mvp.md``). The call is a sync :class:`httpx.Client`
POST so it runs in the same threadpool as the DB work (ADR 0011).

Scope (Phase 0): execution is run synchronously off the approving transition and
records no separate Action aggregate — the ``queued → running → succeeded/failed``
lifecycle, retry budget, transactional outbox, and held-artifact destruction
(``docs/request-lifecycle.md`` §Action) are later slices. Hash re-verification and
the two adversarial oracles are landed here.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from msig_proxy import crypto, events, notifications
from msig_proxy.config import AppConfig, ServiceConfig
from msig_proxy.models import (
    APPROVED,
    DENIED,
    FORWARD_AUTH,
    GRANT_ACTIVE,
    ApprovalRequest,
    ServiceGrant,
    StagedArtifact,
)

# The one outbound boundary the suite mocks (``docs/mvp.md``; ``tests/support.py``).
PYPI_UPLOAD_URL = "https://upload.pypi.org/legacy/"
# Twine/PyPI's fixed Basic-Auth username for token uploads (a public sentinel,
# not a secret — naming it without "token" keeps it clear of the secret scanner).
_TWINE_USERNAME = "__token__"


@dataclass(frozen=True)
class ExecutionResult:
    """Outcome of an attempted publish."""

    published: bool
    reason: str | None = None  # human-readable failure reason when not published


def publish_to_pypi(
    *, token: str, name: str, version: str, filename: str, content: bytes
) -> ExecutionResult:
    """POST the artifact to the (mocked) PyPI legacy upload endpoint.

    Mirrors a Twine ``file_upload`` so the boundary is realistic. A 2xx is a
    publish; any other status (or a transport error) is a failure.
    """
    data = {
        ":action": "file_upload",
        "protocol_version": "1",
        "name": name,
        "version": version,
    }
    files = {"content": (filename, content, "application/octet-stream")}
    try:
        with httpx.Client(timeout=30) as client:
            response = client.post(
                PYPI_UPLOAD_URL, data=data, files=files, auth=(_TWINE_USERNAME, token)
            )
    except httpx.HTTPError as exc:
        return ExecutionResult(published=False, reason=f"PyPI upload errored: {exc}")
    if response.is_success:
        return ExecutionResult(published=True)
    return ExecutionResult(
        published=False, reason=f"PyPI rejected the upload (HTTP {response.status_code})"
    )


def execute_publish(
    session: Session, *, request: ApprovalRequest, service: ServiceConfig | None
) -> ExecutionResult:
    """Re-verify the held artifact against the bound hash, then publish on a match.

    The re-verification is the integrity guarantee: a payload mutated in storage
    after approval no longer matches ``artifact_sha256`` and is refused **before**
    any call to PyPI.
    """
    staged = session.get(StagedArtifact, request.id)
    if staged is None:
        return ExecutionResult(published=False, reason="no staged artifact to publish")

    if crypto.sha256_hex(staged.content) != request.artifact_sha256:
        # Hash Binding violated — the bytes changed after the Approvers signed off.
        return ExecutionResult(
            published=False,
            reason="artifact hash mismatch — the payload changed after approval",
        )

    if service is None:
        return ExecutionResult(published=False, reason="service no longer configured")

    # Publish metadata is nullable on the model (forward-auth carries none); a
    # one-time request always has it, so its absence here is a malformed request.
    name, version = request.package_name, request.package_version
    if name is None or version is None:
        return ExecutionResult(published=False, reason="request has no package metadata")

    token = (service.credentials or {}).get("pypi_token", "")
    return publish_to_pypi(
        token=token,
        name=name,
        version=version,
        filename=staged.filename,
        content=staged.content,
    )


def _email_config(config: AppConfig):
    return config.notifications.email if config.notifications else None


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
        )
    )
    return grant


def finalize(session: Session, config: AppConfig, request: ApprovalRequest) -> None:
    """Run the handoff for a request that just reached a terminal state.

    Called after the vote that closed the request committed its transition. Safe
    to call only for ``approved`` / ``denied``; other states are ignored. The
    handoff forks on service type (ADR 0007): forward-auth issues a Service Grant,
    one-time re-verifies the hash and publishes.
    """
    email = _email_config(config)

    if request.state == DENIED:
        notifications.notify_outcome(
            session,
            email,
            request,
            subject=f"Request denied: {request.service_name}",
            body="Your request was denied by an approver.",
        )
        return

    if request.state != APPROVED:
        return

    if request.service_type == FORWARD_AUTH:
        issue_service_grant(session, config, request)
        return

    service = config.services.get(request.service_name)
    result = execute_publish(session, request=request, service=service)

    if result.published:
        notifications.notify_outcome(
            session,
            email,
            request,
            subject=f"Published: {request.package_name} {request.package_version}",
            body="Your request was approved and the package was published successfully.",
        )
    else:
        notifications.notify_outcome(
            session,
            email,
            request,
            subject=f"Execution failed: {request.package_name} {request.package_version}",
            body=f"Your request was approved, but execution failed: {result.reason}",
        )
