"""The one-time PyPI upload entry point: ``POST /pypi/legacy/``.

A proxy-local route emulating the PyPI legacy upload API (``docs/web-proxy.md``
§One-Time Entry Point) so Twine needs no changes beyond its repository URL. It
authenticates the Requester by API token, binds the artifact by hash, and creates
a ``pending`` Approval Request — then returns immediately so the Requester can
walk away (the one-time async contract). No voting, execution, or notification
email yet (issue #3); the publish boundary is never touched.
"""

from __future__ import annotations

import os

from fastapi import APIRouter, Depends, File, Form, HTTPException, Response, UploadFile, status
from sqlalchemy.orm import Session

from msig_proxy.auth.guards import throttle_auth_attempts, throttle_request_creation
from msig_proxy.core import events
from msig_proxy.core.config import AppConfig
from msig_proxy.core.events import EventBus
from msig_proxy.core.models import User
from msig_proxy.deps import get_config, get_event_bus, get_session
from msig_proxy.service_types.one_time.intake import create_publish_request, staged_artifact_count

# The PyPI legacy API multiplexes verbs on a `:action` form field; Twine sends
# `file_upload` for a publish. We only serve uploads, so anything else is refused.
_FILE_UPLOAD = "file_upload"

router = APIRouter()


def _spooled_size(upload: UploadFile) -> int:
    """Bytes held on ``upload``'s multipart spool, measured without reading them
    into memory (seek-to-end / tell). Starlette streams a *file* part to a
    SpooledTemporaryFile with no size cap of its own — its ``max_part_size`` guards
    only non-file fields — so this is where the storage cap (#126) is measured."""
    spool = upload.file
    spool.seek(0, os.SEEK_END)
    size = spool.tell()
    spool.seek(0)
    return size


# Route-dependency order matters: the per-IP throttle (#123, IDENT-5) is judged
# before the token is resolved, so a token-guessing flood is refused (429) without
# burning lookups; then throttle_request_creation resolves the Requester (via
# authenticate_requester) and meters request creation *per requester* (#32, DOS-1
# flooding legs), so one leaked-but-valid token cannot flood the queue either.
@router.post("/pypi/legacy/", dependencies=[Depends(throttle_auth_attempts)])
def upload(
    requester: User = Depends(throttle_request_creation),
    config: AppConfig = Depends(get_config),
    session: Session = Depends(get_session),
    bus: EventBus = Depends(get_event_bus),
    action: str = Form(default=_FILE_UPLOAD, alias=":action"),
    name: str = Form(...),
    version: str = Form(...),
    content: UploadFile = File(...),
) -> Response:
    """Accept a Twine ``file_upload``, hold it pending approval, acknowledge at once.

    Sync ``def`` so the DB work runs in the threadpool (ADR 0011); the artifact
    bytes are read off the already-parsed multipart spool synchronously.
    """
    if action != _FILE_UPLOAD:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"unsupported :action {action!r}; this endpoint only serves {_FILE_UPLOAD}",
        )

    service_name, service = config.pypi_service()

    # Storage cap (DOS-1 storage-exhaustion leg, #126): refuse an oversized upload
    # before reading it into memory or staging it, so one leaked requester
    # credential cannot exhaust storage with uncapped multi-GB uploads. Size comes
    # off the already-parsed multipart spool (seek-to-end/tell) rather than the
    # client's Content-Length, so a lying header cannot slip past.
    upload_bytes = _spooled_size(content)
    if upload_bytes > service.max_upload_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail=(
                f"upload of {upload_bytes} bytes exceeds the "
                f"{service.max_upload_bytes}-byte limit for {service_name!r}"
            ),
        )

    # Count cap (same leg): refuse once the per-service staging store is full, so a
    # flood of in-limit uploads cannot exhaust storage by count either.
    if staged_artifact_count(session, service_name) >= service.max_staged_artifacts:
        raise HTTPException(
            status_code=status.HTTP_507_INSUFFICIENT_STORAGE,
            detail=(
                f"{service_name!r} already holds its maximum of "
                f"{service.max_staged_artifacts} pending artifacts"
            ),
        )

    content.file.seek(0)  # the multipart parser leaves the spool ready, but be explicit
    raw = content.file.read()

    request = create_publish_request(
        session,
        requester=requester,
        service_name=service_name,
        service=service,
        package_name=name,
        package_version=version,
        filename=content.filename or f"{name}-{version}",
        content=raw,
    )

    # Announce the new request so approvers are pulled to the approve/deny page.
    # The forward-auth path emits this from login.py (#10); the one-time path is
    # wired here so solicitation covers *both* service types (#13). Emit only — the
    # notification subscriber solicits the snapshot approvers off this event (#65).
    bus.emit(
        events.RequestCreated(
            approval_request_id=request.id,
            service_name=service_name,
            requester_id=requester.id,
        )
    )

    # PyPI's legacy API replies 200 with an empty body on success; Twine checks
    # only the status code, then exits. The artifact is now held pending approval.
    # The request id (not secret — security is in the approver re-auth) is returned
    # so the derivable approval route can be found without a DB lookup.
    return Response(
        status_code=status.HTTP_200_OK,
        media_type="text/plain",
        headers={"X-Approval-Request-Id": str(request.id)},
    )
