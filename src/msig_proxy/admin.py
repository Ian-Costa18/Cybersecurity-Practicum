"""Admin account provisioning: ``POST /admin/users`` (issue #15).

The account-creation half of the enrollment flow (``docs/account-management.md``
§Account Provisioning Flow): an admin creates a User from username + email — in
the **enrolled-pending** state (``is_active = False``, no credentials) — and the
proxy emails a single-use, expiring enrollment link. The admin never sees the
enrollee's password or TOTP secret; the enrollee sets those by following the link
(:mod:`msig_proxy.enroll`).

This is the *only* ``/admin/*`` endpoint this slice adds; the full Admin Portal
(user lifecycle, SMTP fallback display) is #17. Admin authorization is enforced by
:func:`msig_proxy.deps.require_admin`.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, Form, HTTPException, status
from fastapi.responses import JSONResponse
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from msig_proxy import crypto, events, notifications
from msig_proxy.config import AppConfig
from msig_proxy.deps import get_config, get_session, require_admin
from msig_proxy.models import EnrollmentToken, User

router = APIRouter()


def _enroll_url(base_url: str, token: str) -> str:
    return f"{base_url.rstrip('/')}/enroll/{token}"


@router.post("/admin/users")
def create_user(
    session: Session = Depends(get_session),
    config: AppConfig = Depends(get_config),
    _admin: User = Depends(require_admin),
    username: str = Form(...),
    email: str = Form(...),
) -> JSONResponse:
    """Create an enrolled-pending User and email them a single-use enrollment link.

    The account exists with no credentials (``is_active = False``, ``enrolled_at``
    null) until the enrollee self-enrolls. Returns ``201`` with the new user id and
    the enrollment URL (the link also doubles as the admin-portal fallback, #17).
    A duplicate username/email is a ``409``.
    """
    user = User(username=username, email=email, is_active=False)
    session.add(user)
    try:
        session.flush()  # surface the unique-constraint violation now
    except IntegrityError as exc:
        session.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="username or email already exists"
        ) from exc

    token = crypto.generate_enrollment_token()
    now = datetime.now(UTC)
    session.add(
        EnrollmentToken(
            user_id=user.id,
            token_hash=crypto.hash_enrollment_token(token),
            expires_at=now + timedelta(hours=config.auth.enrollment_link_expiry_hours),
            created_at=now,
        )
    )
    session.flush()

    enroll_url = _enroll_url(config.server.base_url, token)
    events.emit(
        events.Event(events.ENROLLMENT_ISSUED, {"user_id": str(user.id), "email": user.email})
    )
    notifications.notify_enrollment_issued(config, user=user, enroll_url=enroll_url)

    return JSONResponse(
        status_code=status.HTTP_201_CREATED,
        content={"user_id": str(user.id), "enrollment_url": enroll_url},
    )
