"""Web-edge auth guards: the FastAPI-wired checks a route opts into.

The ``[web]`` half of the auth slice — the only auth file that imports FastAPI. It
wires the framework-free verifiers in :mod:`.credentials` into request dependencies
and raises the right HTTP status. ``authenticate_requester`` guards the Twine upload
(API token → 401); the per-route session/admin guards are added here too (#67).
"""

from __future__ import annotations

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from sqlalchemy.orm import Session

from msig_proxy.auth.credentials import resolve_api_token
from msig_proxy.core.models import User
from msig_proxy.deps import get_session

_basic = HTTPBasic(auto_error=False)


def _unauthorized() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="invalid API token",
        headers={"WWW-Authenticate": "Basic"},
    )


def authenticate_requester(
    credentials: HTTPBasicCredentials | None = Depends(_basic),
    session: Session = Depends(get_session),
) -> User:
    """``Depends``-wired web edge: resolve the Requester behind a Twine upload or ``401``.

    A thin wrapper over :func:`msig_proxy.auth.credentials.resolve_api_token` — it
    unpacks the Basic-Auth header and raises the ``401`` when resolution fails. The
    framework-free resolver carries the actual rule so it can be exercised without
    the app.
    """
    username = credentials.username if credentials is not None else None
    presented_token = credentials.password if credentials is not None else None
    user = resolve_api_token(session, username, presented_token)
    if user is None:
        raise _unauthorized()
    return user
