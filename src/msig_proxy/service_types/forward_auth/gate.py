"""The forward-auth gate: ``GET /auth`` (issue #12).

The reverse proxy interposes on a protected URL and makes a subrequest here to ask
whether to allow it (``docs/web-proxy.md`` §Forward-Auth Flow steps 2-3, 11). The
proxy answers from the Service Grant store:

* **Open path** — the session User holds a valid Service Grant for the requested
  Service → ``200`` with the configured identity headers injected, so the reverse
  proxy forwards the request to the ``backend``. The shared backend credential is
  never revealed to the Requester; access is mediated by the headers alone.
* **Closed path** — no session, or no valid grant → ``401`` carrying a ``Location``
  to the login page (``/login?service=...&return_to=...``). The reverse proxy is
  responsible for honoring that redirect (stock NGINX ``auth_request`` needs an
  ``error_page 401`` to do so; ``docs/web-proxy.md``).

**Which Service** the subrequest is for is taken from the ``service`` query
parameter — the reverse proxy is configured per protected Service to point its
auth request at ``/auth?service=<service-id>``, symmetric with the ``service``
carried through ``/login``. The original URL for ``return_to`` is reconstructed
from the standard ``X-Forwarded-*`` headers the reverse proxy sets.

Expiry is evaluated lazily here
(:func:`msig_proxy.service_types.forward_auth.resolve.resolve_active_grant`);
there is no scheduler in the MVP.
"""

from __future__ import annotations

from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Request, Response, status
from sqlalchemy.orm import Session

from msig_proxy.auth.guards import current_session_user
from msig_proxy.core.config import AppConfig, HeadersConfig
from msig_proxy.core.events import EventBus
from msig_proxy.core.models import FORWARD_AUTH, User
from msig_proxy.deps import get_config, get_event_bus, get_session
from msig_proxy.service_types.forward_auth import resolve

router = APIRouter()


def _return_to(request: Request) -> str | None:
    """Reconstruct the originally-requested URL from the reverse proxy's
    ``X-Forwarded-*`` headers, or ``None`` if the host header is absent."""
    host = request.headers.get("x-forwarded-host")
    if not host:
        return None
    proto = request.headers.get("x-forwarded-proto", "https")
    uri = request.headers.get("x-forwarded-uri", "/")
    return f"{proto}://{host}{uri}"


def _login_redirect(service: str | None, return_to: str | None) -> Response:
    """A ``401`` carrying the login ``Location`` for the reverse proxy to honor.

    Status is ``401`` (not a 3xx): the proxy denies the subrequest and the reverse
    proxy turns that into a browser redirect to ``Location``.
    """
    params = [
        (key, value) for key, value in (("service", service), ("return_to", return_to)) if value
    ]
    location = "/login" + (f"?{urlencode(params)}" if params else "")
    return Response(status_code=status.HTTP_401_UNAUTHORIZED, headers={"Location": location})


def _identity_headers(user: User, headers: HeadersConfig) -> dict[str, str]:
    """The identity headers injected upstream on a grant (``docs/web-proxy.md``
    §Identity Headers). A header configured ``False`` is suppressed; ``Remote-Groups``
    is omitted entirely when the User's ``groups`` field is null (#79)."""
    injected: dict[str, str] = {}
    if headers.remote_user:
        injected[headers.remote_user] = user.username
    if headers.remote_name:
        injected[headers.remote_name] = user.username  # display name == username in MVP
    if headers.remote_email:
        injected[headers.remote_email] = user.email
    if headers.remote_groups and user.groups:
        injected[headers.remote_groups] = user.groups
    return injected


@router.get("/auth")
def auth_gate(
    request: Request,
    service: str | None = None,
    user: User | None = Depends(current_session_user),
    session: Session = Depends(get_session),
    config: AppConfig = Depends(get_config),
    bus: EventBus = Depends(get_event_bus),
) -> Response:
    """Answer the reverse proxy's forward-auth subrequest (open/closed path).

    ``200`` with identity headers when the session User holds a valid grant for a
    configured ``forward-auth`` Service; ``401`` with a login ``Location``
    otherwise. A grant past ``expires_at`` is observed expired here and re-gates.
    """
    return_to = _return_to(request)
    if user is None or not service:
        return _login_redirect(service, return_to)

    svc = config.services.get(service)
    if svc is None or svc.type != FORWARD_AUTH:
        return _login_redirect(service, return_to)

    grant = resolve.resolve_active_grant(session, bus=bus, user_id=user.id, service_name=service)
    if grant is None:
        return _login_redirect(service, return_to)

    return Response(status_code=status.HTTP_200_OK, headers=_identity_headers(user, svc.headers))
