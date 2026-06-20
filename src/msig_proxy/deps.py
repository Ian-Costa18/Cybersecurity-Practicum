"""Shared FastAPI request dependencies.

These live outside :mod:`msig_proxy.app` so routers (e.g. the PyPI upload route)
can depend on them without importing the app factory — which would import the
routers back, a cycle. The app factory and every router both import from here.
"""

from __future__ import annotations

from collections.abc import Iterator

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from msig_proxy import sessions
from msig_proxy.config import AppConfig
from msig_proxy.core.db import session_scope
from msig_proxy.core.models import User


def get_session(request: Request) -> Iterator[Session]:
    """Request-scoped DB session dependency.

    Declared as a sync generator so FastAPI runs it (and any sync endpoint that
    depends on it) in the threadpool, matching the sync-DB posture in ADR 0011.
    """
    factory = request.app.state.session_factory
    yield from session_scope(factory)


def get_config(request: Request) -> AppConfig:
    """The validated application config wired onto the app at startup."""
    return request.app.state.config


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
