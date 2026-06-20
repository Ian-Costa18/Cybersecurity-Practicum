"""The Executor boundary: the post-approval *primitives* a handler invokes.

This module owns the side-effecting operations that a terminal Approval Request
hands off to (issue #5) — but **not** the dispatch that chooses between them. That
dispatch (which service type runs which primitive, on which terminal state) lives
in :mod:`msig_proxy.post_approval`, the ``PostApprovalHandler`` layer that calls
into here. This module is therefore importable by the handlers without a cycle.

The primitives:

* :func:`execute_publish` (one-time ``approved``) → **re-verify** the held
  artifact's SHA-256 against the hash the Approvers signed over (Hash Binding,
  ``docs/constraints.md`` §6); on a match, publish to the PyPI boundary; on a
  mismatch, refuse — the publish never reaches PyPI (the integrity oracle).
* :func:`publish_to_pypi` → the system's single outbound boundary. A sync
  :class:`httpx.Client` POST to the service's configured ``endpoint`` so it runs
  in the same threadpool as the DB work (ADR 0011).
* :func:`issue_service_grant` (forward-auth ``approved``) → mint the Service Grant.
* :func:`destroy_staged_artifact` → drop the held artifact at a terminal outcome and
  emit ``artifact.destroyed`` (#68, ``docs/request-lifecycle.md`` §163).

Scope: execution runs synchronously off the approving transition and records no
separate Action aggregate — the ``queued → running → succeeded/failed`` lifecycle,
retry budget, and transactional outbox (``docs/request-lifecycle.md`` §Action) are
not yet implemented. Held-artifact destruction is wired on the non-handoff terminals
(denial); the approved/handoff path will call it once the Action lifecycle lands.
Hash re-verification and the two adversarial oracles are implemented.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from msig_proxy.core import crypto, events
from msig_proxy.core.config import AppConfig, ServiceConfig
from msig_proxy.core.models import (
    GRANT_ACTIVE,
    ApprovalRequest,
    ServiceGrant,
    StagedArtifact,
)

# Twine/PyPI's fixed Basic-Auth username for token uploads (a public sentinel,
# not a secret — naming it without "token" keeps it clear of the secret scanner).
_TWINE_USERNAME = "__token__"


@dataclass(frozen=True)
class ExecutionResult:
    """Outcome of an attempted publish."""

    published: bool
    reason: str | None = None  # human-readable failure reason when not published


def _rejection_reason(status_code: int) -> str:
    """Human-readable reason for a non-2xx PyPI response, by failure class.

    Distinguishes the failure modes a Requester can act on: authentication
    (a bad/expired token), a version conflict (the version already exists on the
    index — immutable, so re-uploading won't help), other client errors (a
    malformed upload), and server-side errors (transient, worth retrying once the
    Action retry budget lands; see ``docs/request-lifecycle.md`` §Action).
    """
    if status_code in (401, 403):
        return (
            f"PyPI rejected the upload: authentication failed (HTTP {status_code}) "
            "— check the publish token"
        )
    if status_code == 409:
        return "PyPI rejected the upload: this version already exists (HTTP 409)"
    if 400 <= status_code < 500:
        return f"PyPI rejected the upload: invalid request (HTTP {status_code})"
    if status_code >= 500:
        return f"PyPI upload failed: the index returned a server error (HTTP {status_code})"
    return f"PyPI rejected the upload (HTTP {status_code})"


def publish_to_pypi(
    *, url: str, token: str, name: str, version: str, filename: str, content: bytes
) -> ExecutionResult:
    """POST the artifact to the (mocked) PyPI legacy upload endpoint at ``url``.

    Mirrors a Twine ``file_upload`` so the boundary is realistic. A 2xx is a
    publish; any other status (or a transport error) is a failure, surfaced with a
    reason classified by failure mode (auth / version-conflict / other-4xx / 5xx).
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
            response = client.post(url, data=data, files=files, auth=(_TWINE_USERNAME, token))
    except httpx.HTTPError as exc:
        return ExecutionResult(
            published=False, reason=f"PyPI upload could not reach the index: {exc}"
        )
    if response.is_success:
        return ExecutionResult(published=True)
    return ExecutionResult(published=False, reason=_rejection_reason(response.status_code))


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

    if not service.endpoint:
        # A one-time service always has an endpoint (defaulted in config validation);
        # its absence here means a malformed/forward-auth service reached the publish path.
        return ExecutionResult(published=False, reason="service has no publish endpoint configured")

    token = (service.credentials or {}).get("pypi_token", "")
    return publish_to_pypi(
        url=service.endpoint,
        token=token,
        name=name,
        version=version,
        filename=staged.filename,
        content=staged.content,
    )


def destroy_staged_artifact(
    session: Session, request: ApprovalRequest, *, action_id: str | None = None
) -> bool:
    """Destroy the held artifact for a request at a terminal outcome.

    A one-time Service stages the uploaded artifact at request creation; it must not
    outlive the request (``docs/request-lifecycle.md`` §163). This deletes the held
    row and emits ``artifact.destroyed``; forward-auth requests stage nothing, so
    there is nothing to delete and no event fires.

    Idempotent: a request whose artifact is already gone (e.g. a redelivered
    terminal transition) is a no-op that returns ``False`` and emits no event.
    Returns ``True`` when bytes were actually destroyed. ``action_id`` is carried
    into the event payload on the approved/handoff path (``None`` on the
    non-handoff terminals — denial, cancellation).
    """
    staged = session.get(StagedArtifact, request.id)
    if staged is None:
        return False

    session.delete(staged)
    session.flush()

    events.emit(
        events.Event(
            events.ARTIFACT_DESTROYED,
            {
                "approval_request_id": str(request.id),
                "action_id": action_id,
                "terminal_state": request.state,
            },
        )
    )
    return True


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
