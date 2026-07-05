"""Web-edge auth guards: the FastAPI-wired checks a route opts into.

The ``[web]`` half of the auth slice — the only auth file that imports FastAPI. It
wires the framework-free verifiers in :mod:`.credentials` into request dependencies
and raises the right HTTP status. ``authenticate_requester`` guards the Twine upload
(API token → 401); the per-route session/admin guards are added here too (#67).
"""

from __future__ import annotations

from fastapi import Depends, Form, HTTPException, Request, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from sqlalchemy.orm import Session

from msig_proxy.auth import sessions
from msig_proxy.auth.credentials import resolve_api_token
from msig_proxy.core import rate_limit
from msig_proxy.core.config import AppConfig
from msig_proxy.core.models import DENY, User
from msig_proxy.deps import get_config, get_session

_basic = HTTPBasic(auto_error=False)

# The one throttle scope shared by every credential endpoint (#123): /login,
# /approve/{id}, and /pypi/legacy/ draw on the same per-IP budget, so an attacker
# rotating across surfaces gains nothing.
_AUTH_THROTTLE_SCOPE = "auth"

# #32's per-requester request-creation cap takes its own scope over the same
# counter table (DOS-1 flooding legs). Distinct from the auth scope because it is
# keyed by requester identity, not IP, and metes a different budget.
_REQUEST_CREATION_THROTTLE_SCOPE = "request-creation"


def throttle_auth_attempts(
    request: Request,
    config: AppConfig = Depends(get_config),
) -> None:
    """``Depends``-wired per-IP throttle for a credential endpoint (#123, IDENT-5).

    Counts this attempt against the caller's effective client IP and raises
    ``429 + Retry-After`` once the ``auth.rate_limit_*`` budget is exceeded — a
    per-IP throttle with backoff, deliberately **not** a per-account lockout
    (which would let an attacker lock out honest approvers). Runs before the
    endpoint body, so a rejected flood never reaches bcrypt.

    Declared as a *route* dependency (``dependencies=[Depends(...)]``) on
    ``POST /login`` and ``POST /pypi/legacy/``; the vote route uses
    :func:`throttle_vote_attempts`, which exempts the Deny path.
    """
    _register_throttled_attempt(request, config)


def throttle_vote_attempts(
    request: Request,
    config: AppConfig = Depends(get_config),
    decision: str = Form(default=""),
) -> None:
    """The vote route's throttle: like :func:`throttle_auth_attempts`, but a **Deny
    is never throttled** — the honest "2 a.m. deny" must land even while the IP
    (a shared NAT, say) is over budget, or the limiter would trade IDENT-5 for a
    fresh denial-of-service on the one action that stops an attack. A deny
    neither consumes budget nor is refused; only approve/withdraw attempts count.

    Reads the parsed form's ``decision`` field (defaulted, so a malformed body
    still reaches the endpoint's own validation) — this is why the guard is a
    dependency and not middleware.
    """
    if decision == DENY:
        return
    _register_throttled_attempt(request, config)


def _register_throttled_attempt(request: Request, config: AppConfig) -> None:
    """Count one attempt for this request's client IP; raise the 429 when over budget."""
    auth = config.auth
    ip = rate_limit.client_ip(
        request.client.host if request.client is not None else None,
        request.headers.get("X-Forwarded-For"),
        auth.rate_limit_trusted_proxies,
    )
    _register_limited_attempt(
        request,
        scope=_AUTH_THROTTLE_SCOPE,
        key=ip,
        limit=auth.rate_limit_attempts,
        window_seconds=auth.rate_limit_window_seconds,
        backoff_seconds=auth.rate_limit_backoff_seconds,
        detail="too many authentication attempts; retry later",
    )


def _register_limited_attempt(
    request: Request,
    *,
    scope: str,
    key: str,
    limit: int,
    window_seconds: int,
    backoff_seconds: int,
    detail: str,
) -> None:
    """Count one attempt against ``(scope, key)``; raise the 429 when over budget.

    The count runs on its **own short-lived session, committed immediately** — not
    the request-scoped one — so a rejected attempt's increment survives the request
    transaction's rollback (a vote 401 raises, which rolls the request session back;
    a throttle riding it would forget every failure it counted). Shared by the per-IP
    auth throttle (#123) and the per-requester request-creation throttle (#32).
    """
    session_factory = request.app.state.session_factory
    with session_factory() as session:
        verdict = rate_limit.register_attempt(
            session,
            scope=scope,
            key=key,
            limit=limit,
            window_seconds=window_seconds,
            backoff_seconds=backoff_seconds,
        )
        session.commit()
    if not verdict.allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=detail,
            headers={"Retry-After": str(verdict.retry_after)},
        )


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


def throttle_request_creation(
    request: Request,
    requester: User = Depends(authenticate_requester),
    config: AppConfig = Depends(get_config),
) -> User:
    """Per-requester quota on request *creation* (#32, DOS-1 flooding legs → ①).

    Runs **after** :func:`authenticate_requester` (it depends on it and re-returns
    the resolved Requester, so the route depends on this instead), so only
    *authenticated* creation attempts are counted — an anonymous or bad-token flood
    is already refused by :func:`throttle_auth_attempts` at the per-IP layer. Counts
    one attempt against the requester's **identity** (not IP): the flood rides one
    valid token, so a single compromised seat cannot outrun the cap by rotating
    source addresses. Over the ``auth.request_rate_limit_*`` budget it raises
    ``429 + Retry-After`` before the upload body stages any artifact.
    """
    auth = config.auth
    _register_limited_attempt(
        request,
        scope=_REQUEST_CREATION_THROTTLE_SCOPE,
        key=str(requester.id),
        limit=auth.request_rate_limit_attempts,
        window_seconds=auth.request_rate_limit_window_seconds,
        backoff_seconds=auth.request_rate_limit_backoff_seconds,
        detail="too many publish requests; retry later",
    )
    return requester


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
