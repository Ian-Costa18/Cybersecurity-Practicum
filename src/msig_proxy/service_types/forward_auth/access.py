"""The post-login forward-auth access trigger: ``GET /access``.

After interactive login, a Requester is dropped here to create (or resume) the
pending forward-auth Approval Request for the named Service and enter the waiting
room. Splitting this out of ``POST /login`` is the login de-smudge (ADR 0012): it
keeps ``auth/`` free of any ``service_types`` dependency — login only
authenticates, sets the cookie, and redirects here (carrying ``service``).

Guarded by a Proxy Session (the Requester just logged in). Idempotent per
(User, Service): a returning Requester resumes the same pending request, so
``request.created`` — and thus approver solicitation (#13) — fires exactly once.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, status
from fastapi.responses import RedirectResponse, Response
from sqlalchemy.orm import Session

from msig_proxy.auth.guards import require_session_user
from msig_proxy.core import events
from msig_proxy.core.config import AppConfig
from msig_proxy.core.models import FORWARD_AUTH, User
from msig_proxy.deps import get_config, get_session
from msig_proxy.service_types.forward_auth import intake

router = APIRouter()


@router.get("/access")
def access(
    service: str | None = None,
    session: Session = Depends(get_session),
    config: AppConfig = Depends(get_config),
    user: User = Depends(require_session_user),
) -> Response:
    """Create/resume the forward-auth request for ``service`` and enter the waiting room.

    Session-gated. For a configured forward-auth ``service`` it find-or-creates the
    Requester's pending request, emits ``request.created`` on a *new* one only (so
    a resuming Requester does not re-spam approvers), and redirects to the waiting
    room. A missing/unknown/non-forward-auth ``service`` has nothing to solicit, so
    the User is sent to their portal.
    """
    svc = config.services.get(service) if service else None
    if service is None or svc is None or svc.type != FORWARD_AUTH:
        return RedirectResponse("/account", status_code=status.HTTP_303_SEE_OTHER)

    approval, created = intake.request_forward_auth_access(
        session, requester=user, service_name=service, service=svc
    )
    if created:
        # Emit only — the notification subscriber solicits the snapshot approvers off
        # this event (ADR 0005, #65). Emitting on a *new* request only means a
        # resuming Requester does not re-notify approvers.
        events.emit(
            events.Event(
                events.REQUEST_CREATED,
                {
                    "approval_request_id": str(approval.id),
                    "service_name": service,
                    "requester_id": str(user.id),
                },
            ),
            session=session,
        )
    return RedirectResponse(f"/pending/{approval.id}", status_code=status.HTTP_303_SEE_OTHER)
