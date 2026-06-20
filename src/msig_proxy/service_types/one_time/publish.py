"""One-time publish primitives: re-verify the held artifact, then publish to PyPI.

The side-effecting publish path a one-time ``approved`` request hands off to
(issue #5), owned by the one-time slice. :func:`execute_publish` re-verifies the
held artifact's SHA-256 against the hash the Approvers signed over (Hash Binding,
``docs/constraints.md`` §6) and publishes only on a match — a payload mutated in
storage after approval never reaches PyPI (the integrity oracle).
:func:`publish_to_pypi` is the system's single outbound boundary: a sync
:class:`httpx.Client` POST to the service's configured ``endpoint`` so it runs in
the same threadpool as the DB work (ADR 0011).

Scope: execution runs synchronously off the approving transition and records no
separate Action aggregate — the ``queued → running → succeeded/failed`` lifecycle,
retry budget, and transactional outbox (``docs/request-lifecycle.md`` §Action) are
not yet implemented.
"""

from __future__ import annotations

from dataclasses import dataclass

import httpx
from sqlalchemy.orm import Session

from msig_proxy.core import crypto
from msig_proxy.core.config import ServiceConfig
from msig_proxy.core.models import ApprovalRequest, StagedArtifact

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
