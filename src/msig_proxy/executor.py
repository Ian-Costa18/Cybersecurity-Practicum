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

import httpx
from sqlalchemy.orm import Session

from msig_proxy import crypto, notifications
from msig_proxy.config import AppConfig, ServiceConfig
from msig_proxy.models import APPROVED, DENIED, ApprovalRequest, StagedArtifact

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


def finalize(session: Session, config: AppConfig, request: ApprovalRequest) -> None:
    """Run the handoff for a request that just reached a terminal state.

    Called after the vote that closed the request committed its transition. Safe
    to call only for ``approved`` / ``denied``; other states are ignored.
    """
    email = _email_config(config)

    if request.state == DENIED:
        notifications.notify_outcome(
            session,
            email,
            request,
            subject=f"Request denied: {request.package_name} {request.package_version}",
            body="Your request was denied by an approver and will not be published.",
        )
        return

    if request.state != APPROVED:
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
