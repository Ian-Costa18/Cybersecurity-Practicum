"""Web-edge auth guards: the FastAPI-wired checks a route opts into.

The ``[web]`` half of the auth slice — the only auth file that imports FastAPI. It
wires the framework-free verifiers in :mod:`.credentials` into request dependencies
and raises the right HTTP status. ``authenticate_requester`` guards the Twine upload
(API token → 401); the per-route session/admin guards are added here too (#67).
"""

from __future__ import annotations

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from sqlalchemy.orm import Session

from msig_proxy.auth import sessions
from msig_proxy.auth.credentials import resolve_api_token
from msig_proxy.core.config import AppConfig
from msig_proxy.core.models import User
from msig_proxy.deps import get_config, get_session

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


def current_session_user(
    request: Request,
    session: Session = Depends(get_session),
    config: AppConfig = Depends(get_config),
) -> User | None:
    """Resolve the User behind the Proxy Session cookie, or ``None`` if unauthenticated.

    A revoked or expired session resolves to ``None`` — the row is authoritative,
    so logout / deletion takes effect on the very next request.
    """
    cookie = request.cookies.get(sessions.SESSION_COOKIE)
    if not cookie:
        return None
    proxy_session = sessions.resolve_session(session, cookie, config.server.secret_key)
    if proxy_session is None:
        return None
    return session.get(User, proxy_session.user_id)


def require_session_user(user: User | None = Depends(current_session_user)) -> User:
    """Require an authenticated Proxy Session; raise ``401`` otherwise."""
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="authentication required"
        )
    return user


def require_admin(user: User = Depends(require_session_user)) -> User:
    """Require an authenticated admin (``docs/web-proxy.md`` §Admin Authorization).

    Layered on :func:`require_session_user`: an unauthenticated caller gets ``401``;
    an authenticated non-admin gets ``403``. The full ``/admin/*`` surface is the
    Admin Portal (#17); #15 uses this for the account-creation endpoint only.
    """
    if not user.is_admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="admin required")
    return user
