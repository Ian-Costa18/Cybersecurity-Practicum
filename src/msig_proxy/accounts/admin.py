"""The Admin Portal — administering *other* Users (issues #15, #17).

Gated entirely on ``deps.require_admin`` (Proxy Session + ``is_admin``; 401 anon,
403 non-admin — ``docs/web-proxy.md`` §Admin Authorization). The admin manages
accounts but stays **out of the credential path**: they create/reset/deactivate/
delete users and revoke tokens, but never see or set a password, TOTP secret, or
the plaintext of an API token.

Lifecycle (``docs/account-management.md``):

* **deactivate** — ``is_active = false`` (reversible). Revokes the user's Proxy
  Sessions immediately and, because login/vote now gate on ``is_active``, their
  in-flight approval links stop authenticating. The MVP answer to a malicious
  Approver (no per-grant override exists).
* **delete** — irreversible: drop ``encrypted_private_key`` (the signing key can no
  longer be recovered) while **retaining ``public_key``** so the user's past signed
  votes stay verifiable. The row is kept for audit; the account is deactivated.
* **reset** — invalidate password + TOTP and orphan the signing key, then issue a
  fresh enrollment link (a reset is a re-enrollment).
* **enrollment-link** — regenerate a single-use link for an un-enrolled/expired user.
* **revoke token** — revoke (only) one of a user's API tokens.

**SMTP fallback** (``docs/notification-system.md`` §Portal fallback): only the
enrollment-token *hash* is stored, so a past link can't be reconstructed — recovery
is to **regenerate**. The mint endpoints return the fresh link and whether the email
was delivered, so a flaky mail server never strands onboarding; reachability derives
from the persisted record, not from notification delivery.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, JSONResponse
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from msig_proxy.accounts import keys
from msig_proxy.auth import sessions
from msig_proxy.core import crypto, events
from msig_proxy.core.config import AppConfig
from msig_proxy.core.models import ApiToken, EnrollmentToken, User
from msig_proxy.deps import get_config, get_session, require_admin
from msig_proxy.notifications import notifier

router = APIRouter()


def _enroll_url(base_url: str, token: str) -> str:
    return f"{base_url.rstrip('/')}/enroll/{token}"


def _mint_enrollment_link(session: Session, config: AppConfig, user: User) -> tuple[str, bool]:
    """Create a fresh single-use enrollment token for ``user`` and email the link.

    Shared by create / reset / regenerate. Returns ``(enroll_url, email_delivered)``
    — the URL is the SMTP-down fallback (recoverable even when delivery fails).
    """
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
    delivered = notifier.notify_enrollment_issued(config, user=user, enroll_url=enroll_url)
    return enroll_url, delivered


def _require_user(session: Session, user_id: uuid.UUID) -> User:
    user = session.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="user not found")
    return user


@router.get("/admin", response_class=HTMLResponse)
def admin_portal(
    request: Request,
    session: Session = Depends(get_session),
    _admin: User = Depends(require_admin),
) -> HTMLResponse:
    """List every User with status + admin flag (the portal home)."""
    users = session.scalars(select(User).order_by(User.username)).all()
    rows = "".join(
        "<tr>"
        f"<td>{u.username}</td><td>{u.email}</td>"
        f"<td>{'admin' if u.is_admin else 'user'}</td>"
        f"<td>{'active' if u.is_active else 'inactive'}</td>"
        f"<td>{'enrolled' if u.enrolled_at is not None else 'pending'}</td>"
        "</tr>"
        for u in users
    )
    return HTMLResponse(
        "<!doctype html><title>Admin</title><h1>Users</h1>"
        "<table><tr><th>Username</th><th>Email</th><th>Role</th>"
        f"<th>Status</th><th>Enrollment</th></tr>{rows}</table>"
    )


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
    null) until the enrollee self-enrolls. Returns ``201`` with the new user id, the
    enrollment URL, and whether the email was delivered (the portal fallback). A
    duplicate username/email is a ``409``.
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

    enroll_url, delivered = _mint_enrollment_link(session, config, user)
    return JSONResponse(
        status_code=status.HTTP_201_CREATED,
        content={
            "user_id": str(user.id),
            "enrollment_url": enroll_url,
            "email_delivered": delivered,
        },
    )


@router.post("/admin/users/{user_id}/deactivate")
def deactivate_user(
    user_id: uuid.UUID,
    session: Session = Depends(get_session),
    _admin: User = Depends(require_admin),
) -> JSONResponse:
    """Deactivate a User (reversible) and revoke their Proxy Sessions immediately.

    With ``is_active`` now gating login and vote, deactivation also stops the user's
    in-flight approval links from authenticating.
    """
    user = _require_user(session, user_id)
    user.is_active = False
    revoked = sessions.delete_user_sessions(session, user.id)
    return JSONResponse({"user_id": str(user.id), "is_active": False, "sessions_revoked": revoked})


@router.delete("/admin/users/{user_id}")
def delete_user(
    user_id: uuid.UUID,
    session: Session = Depends(get_session),
    _admin: User = Depends(require_admin),
) -> JSONResponse:
    """Irreversibly delete a User: drop the encrypted private key, keep the public key.

    The row is retained so the user's past signed votes remain verifiable against the
    public key; the account is deactivated and its sessions revoked.
    """
    user = _require_user(session, user_id)
    keys.retire_active_key(session, user)  # drop the private half, retain public_key for audit
    user.is_active = False
    sessions.delete_user_sessions(session, user.id)
    return JSONResponse({"user_id": str(user.id), "deleted": True})


@router.post("/admin/users/{user_id}/reset")
def reset_user(
    user_id: uuid.UUID,
    session: Session = Depends(get_session),
    config: AppConfig = Depends(get_config),
    _admin: User = Depends(require_admin),
) -> JSONResponse:
    """Reset a User's credentials and issue a fresh enrollment link (a re-enrollment).

    Invalidates the password + TOTP and orphans the signing key (drop the encrypted
    private key, keep the public key for audit), returns the account to the
    enrolled-pending state, and revokes existing sessions.
    """
    user = _require_user(session, user_id)
    user.password_hash = None
    user.totp_secret = None
    keys.retire_active_key(session, user)  # retire the old key; re-enrollment inserts a fresh one
    user.enrolled_at = None
    sessions.delete_user_sessions(session, user.id)
    enroll_url, delivered = _mint_enrollment_link(session, config, user)
    return JSONResponse(
        {"user_id": str(user.id), "enrollment_url": enroll_url, "email_delivered": delivered}
    )


@router.post("/admin/users/{user_id}/enrollment-link")
def regenerate_enrollment_link(
    user_id: uuid.UUID,
    session: Session = Depends(get_session),
    config: AppConfig = Depends(get_config),
    _admin: User = Depends(require_admin),
) -> JSONResponse:
    """Regenerate a single-use enrollment link for an un-enrolled / expired User."""
    user = _require_user(session, user_id)
    enroll_url, delivered = _mint_enrollment_link(session, config, user)
    return JSONResponse(
        {"user_id": str(user.id), "enrollment_url": enroll_url, "email_delivered": delivered}
    )


@router.delete("/admin/users/{user_id}/tokens/{token_id}")
def revoke_user_token(
    user_id: uuid.UUID,
    token_id: uuid.UUID,
    session: Session = Depends(get_session),
    _admin: User = Depends(require_admin),
) -> JSONResponse:
    """Revoke one of a User's API tokens (revoke only — admins never create or view).

    Idempotent: revoking an already-revoked token leaves its original ``revoked_at``.
    """
    token = session.get(ApiToken, token_id)
    if token is None or token.user_id != user_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="token not found")
    if token.revoked_at is None:
        token.revoked_at = datetime.now(UTC)
        session.flush()
    return JSONResponse({"token_id": str(token_id), "revoked": True})
