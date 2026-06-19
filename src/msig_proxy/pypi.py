"""The one-time PyPI upload entry point: ``POST /pypi/legacy/``.

A proxy-local route emulating the PyPI legacy upload API (``docs/web-proxy.md``
§One-Time Entry Point) so Twine needs no changes beyond its repository URL. It
authenticates the Requester by API token, binds the artifact by hash, and creates
a ``pending`` Approval Request — then returns immediately so the Requester can
walk away (the one-time async contract). No voting, execution, or notification
email yet (issue #3); the publish boundary is never touched.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, File, Form, Response, UploadFile, status
from sqlalchemy.orm import Session

from msig_proxy.auth import authenticate_requester
from msig_proxy.config import AppConfig
from msig_proxy.deps import get_config, get_session
from msig_proxy.intake import create_publish_request
from msig_proxy.models import User

router = APIRouter()


@router.post("/pypi/legacy/")
def upload(
    requester: User = Depends(authenticate_requester),
    config: AppConfig = Depends(get_config),
    session: Session = Depends(get_session),
    name: str = Form(...),
    version: str = Form(...),
    content: UploadFile = File(...),
) -> Response:
    """Accept a Twine upload, hold it pending approval, and acknowledge at once.

    Sync ``def`` so the DB work runs in the threadpool (ADR 0011); the artifact
    bytes are read off the already-parsed multipart spool synchronously.
    """
    service_name, service = config.pypi_service()

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

    # PyPI's legacy API replies 200 with an empty body on success; Twine checks
    # only the status code, then exits. The artifact is now held pending approval.
    # The request id (not secret — security is in the approver re-auth) is returned
    # so the derivable approval route can be found without a DB lookup.
    return Response(
        status_code=status.HTTP_200_OK,
        media_type="text/plain",
        headers={"X-Approval-Request-Id": str(request.id)},
    )
