"""The Admin Portal — administering *other* Users (issues #15, #17).

Gated entirely on ``auth.guards.require_admin`` (Proxy Session + ``is_admin``; 401 anon,
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

from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, JSONResponse
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from msig_proxy.accounts import keys, tokens
from msig_proxy.accounts.enrollment_links import mint_enrollment_link, void_open_enrollment_links
from msig_proxy.auth import sessions
from msig_proxy.auth.guards import require_admin
from msig_proxy.core import events
from msig_proxy.core.config import AppConfig
from msig_proxy.core.events import EventBus
from msig_proxy.core.models import PENDING, ApiToken, ApprovalRequest, User
from msig_proxy.core.urls import approval_link
from msig_proxy.deps import get_config, get_event_bus, get_session
from msig_proxy.notifications import notifier

router = APIRouter()


def _require_user(session: Session, user_id: uuid.UUID) -> User:
    user = session.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="user not found")
    return user


def _pending_approval_links(session: Session, config: AppConfig) -> str:
    """The Admin-Portal fallback view of pending Approval Requests + their links (#82).

    The operator-mediated degraded path (``docs/notification-system.md`` §Portal
    fallback, ``docs/mvp-prd.md`` story 5): when an Approval Link email cannot be
    delivered, an admin recovers the link here and hands it out of band. Gated on
    ``notifications.email.fallback_to_portal`` — returns empty markup when the flag is
    off (or no email block is configured), so the section simply does not render. The
    links derive from the persisted Approval Request, not from any notification, so
    they are recoverable even when the original send was dropped.
    """
    email = config.notifications.email if config.notifications else None
    if email is None or not email.fallback_to_portal:
        return ""
    pending = session.scalars(
        select(ApprovalRequest)
        .where(ApprovalRequest.state == PENDING)
        .order_by(ApprovalRequest.created_at)
    ).all()
    rows = "".join(
        "<tr>"
        f"<td>{r.service_name}</td>"
        f"<td>{_requester_name(session, r.requester_id)}</td>"
        f'<td><a href="{approval_link(config.server.base_url, r.id)}">'
        f"{approval_link(config.server.base_url, r.id)}</a></td>"
        "</tr>"
        for r in pending
    )
    return (
        "<h2>Pending Approval Requests</h2>"
        "<p>Approval links (email fallback — distribute to approvers out-of-band).</p>"
        "<table><tr><th>Service</th><th>Requester</th><th>Approval link</th></tr>"
        f"{rows}</table>"
    )


def _requester_name(session: Session, requester_id: uuid.UUID) -> str:
    user = session.get(User, requester_id)
    return user.username if user is not None else str(requester_id)


@router.get("/admin", response_class=HTMLResponse)
def admin_portal(
    request: Request,
    session: Session = Depends(get_session),
    config: AppConfig = Depends(get_config),
    _admin: User = Depends(require_admin),
) -> HTMLResponse:
    """List every User with status/admin/groups, plus the pending Approval-Link fallback.

    The Approval-Link section renders only when ``notifications.email.fallback_to_portal``
    is set (#82); otherwise the page is just the user table.
    """
    users = session.scalars(select(User).order_by(User.username)).all()
    rows = "".join(
        "<tr>"
        f"<td>{u.username}</td><td>{u.email}</td>"
        f"<td>{'admin' if u.is_admin else 'user'}</td>"
        f"<td>{'active' if u.is_active else 'inactive'}</td>"
        f"<td>{'enrolled' if u.enrolled_at is not None else 'pending'}</td>"
        f"<td>{u.groups or ''}</td>"
        "</tr>"
        for u in users
    )
    return HTMLResponse(
        "<!doctype html><title>Admin</title><h1>Users</h1>"
        "<table><tr><th>Username</th><th>Email</th><th>Role</th>"
        f"<th>Status</th><th>Enrollment</th><th>Groups</th></tr>{rows}</table>"
        f"{_pending_approval_links(session, config)}"
    )


@router.patch("/admin/users/{user_id}")
def edit_user(
    user_id: uuid.UUID,
    session: Session = Depends(get_session),
    bus: EventBus = Depends(get_event_bus),
    admin: User = Depends(require_admin),
    groups: str | None = Form(default=None),
    email: str | None = Form(default=None),
) -> JSONResponse:
    """Edit a User's non-credential fields without resetting credentials (#79).

    The documented Edit-user capability (``docs/account-management.md`` §Admin Portal
    Capabilities, ``docs/web-proxy.md`` ``PATCH /admin/users/{id}``): update
    ``groups`` (injected as ``Remote-Groups``) and ``email``. PATCH semantics — a
    field omitted from the form is left unchanged (an empty form value is treated as
    omitted, since FastAPI coerces it to the field default). Credentials (password,
    TOTP, signing key) are untouched, so this never forces a re-enrollment. A
    duplicate email is a ``409``.

    Re-pointing an approver's group membership or contact address is a roster mutation
    with no victim to notify — the quiet leg of the IDENT-1 enroll-forward takeover
    (#125). When a field actually changes, emits ``account.groups_changed`` attributed
    to the acting admin, which lands an audit row (#121) and fires the admin-action
    alarm to every admin. A no-op PATCH (no field supplied or no value changed) emits
    nothing.
    """
    user = _require_user(session, user_id)
    changed: list[str] = []
    if groups is not None and groups != user.groups:
        user.groups = groups
        changed.append("groups")
    if email is not None and email != user.email:
        user.email = email
        changed.append("email")
    try:
        session.flush()
    except IntegrityError as exc:
        session.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="email already exists"
        ) from exc
    if changed:
        bus.emit(
            events.AccountEdited(
                user_id=user.id,
                email=user.email,
                changes=", ".join(changed),
                actor_id=admin.id,
            )
        )
    return JSONResponse({"user_id": str(user.id), "groups": user.groups, "email": user.email})


@router.post("/admin/users")
def create_user(
    session: Session = Depends(get_session),
    config: AppConfig = Depends(get_config),
    bus: EventBus = Depends(get_event_bus),
    admin: User = Depends(require_admin),
    username: str = Form(...),
    email: str = Form(...),
    groups: str | None = Form(default=None),
) -> JSONResponse:
    """Create an enrolled-pending User and email them a single-use enrollment link.

    The account exists with no credentials (``is_active = False``, ``enrolled_at``
    null) until the enrollee self-enrolls. ``groups`` is optional free text injected
    later as ``Remote-Groups`` on forward-auth success (#79); an empty value is
    stored as null. Returns ``201`` with the new user id, the enrollment URL, and
    whether the email was delivered (the portal fallback). A duplicate
    username/email is a ``409``.
    """
    user = User(username=username, email=email, is_active=False, groups=groups or None)
    session.add(user)
    try:
        session.flush()  # surface the unique-constraint violation now
    except IntegrityError as exc:
        session.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="username or email already exists"
        ) from exc

    enroll_url, delivered = mint_enrollment_link(session, config, user, bus=bus, actor_id=admin.id)
    return JSONResponse(
        status_code=status.HTTP_201_CREATED,
        content={
            "user_id": str(user.id),
            "enrollment_url": enroll_url,
            "email_delivered": delivered,
        },
    )


@router.post("/admin/users/{user_id}/activate")
def activate_user(
    user_id: uuid.UUID,
    session: Session = Depends(get_session),
    bus: EventBus = Depends(get_event_bus),
    admin: User = Depends(require_admin),
) -> JSONResponse:
    """Activate an enrolled account — the IDENT-2 pending-confirmation gate (#128).

    Enrollment never activates a seat: completing ``/enroll/{token}`` lands the
    account in **pending-confirmation** (enrolled, ``is_active`` false — it cannot
    log in or vote). This endpoint is the admin's out-of-band confirmation step:
    only after verifying with the intended human that *they* enrolled does the
    admin flip the seat live. It also serves as the documented re-activation of a
    deactivated account (``docs/account-management.md`` §Admin Portal Capabilities).

    Refuses (``409``) an account that has not completed enrollment — pre-activating
    an un-enrolled account would let the next enrollment complete straight into an
    active seat, silently bypassing the confirmation gate.

    Emits ``account.activated`` attributed to the acting admin (#121). No
    notification is sent — the admin has just confirmed with the human out-of-band.
    """
    user = _require_user(session, user_id)
    if user.enrolled_at is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="account has not completed enrollment",
        )
    user.is_active = True
    bus.emit(events.AccountActivated(user_id=user.id, email=user.email, actor_id=admin.id))
    return JSONResponse({"user_id": str(user.id), "is_active": True})


@router.post("/admin/users/{user_id}/deactivate")
def deactivate_user(
    user_id: uuid.UUID,
    session: Session = Depends(get_session),
    config: AppConfig = Depends(get_config),
    bus: EventBus = Depends(get_event_bus),
    admin: User = Depends(require_admin),
) -> JSONResponse:
    """Deactivate a User (reversible) and revoke their Proxy Sessions immediately.

    With ``is_active`` now gating login and vote, deactivation also stops the user's
    in-flight approval links from authenticating. Outstanding enrollment links are
    voided too — a completed enrollment only lands in pending-confirmation now (#128),
    but a live link would still let its holder set the deactivated account's
    credentials, TOTP, and signing key. Emits ``account.deactivated``
    (attributed to the acting admin, #121) and sends the affected User the
    informational notice (#80, ``docs/account-management.md`` §Account Events).
    """
    user = _require_user(session, user_id)
    user.is_active = False
    void_open_enrollment_links(session, user)
    revoked = sessions.delete_user_sessions(session, user.id)
    bus.emit(events.AccountDeactivated(user_id=user.id, email=user.email, actor_id=admin.id))
    notifier.notify_account_deactivated(config, user=user)
    return JSONResponse({"user_id": str(user.id), "is_active": False, "sessions_revoked": revoked})


@router.delete("/admin/users/{user_id}")
def delete_user(
    user_id: uuid.UUID,
    session: Session = Depends(get_session),
    config: AppConfig = Depends(get_config),
    bus: EventBus = Depends(get_event_bus),
    admin: User = Depends(require_admin),
) -> JSONResponse:
    """Irreversibly delete a User: drop the encrypted private key, keep the public key.

    The row is retained so the user's past signed votes remain verifiable against the
    public key; the account is deactivated and its sessions revoked. Outstanding
    enrollment links are voided — because the row survives, a live link would
    otherwise re-enroll the "deleted" account, setting fresh credentials and keys on
    it (even though it would only reach pending-confirmation, #128). Emits
    ``account.deleted`` (attributed to the acting admin, #121) and sends the affected
    User the informational notice (#80, ``docs/account-management.md`` §Account Events).
    """
    user = _require_user(session, user_id)
    keys.retire_active_key(session, user)  # drop the private half, retain public_key for audit
    user.is_active = False
    void_open_enrollment_links(session, user)
    sessions.delete_user_sessions(session, user.id)
    bus.emit(events.AccountDeleted(user_id=user.id, email=user.email, actor_id=admin.id))
    notifier.notify_account_deleted(config, user=user)
    return JSONResponse({"user_id": str(user.id), "deleted": True})


@router.post("/admin/users/{user_id}/reset")
def reset_user(
    user_id: uuid.UUID,
    session: Session = Depends(get_session),
    config: AppConfig = Depends(get_config),
    bus: EventBus = Depends(get_event_bus),
    admin: User = Depends(require_admin),
) -> JSONResponse:
    """Reset a User's credentials and issue a fresh enrollment link (a re-enrollment).

    Invalidates the password + TOTP and orphans the signing key (drop the encrypted
    private key, keep the public key for audit), returns the account to the
    enrolled-pending state, and revokes existing sessions.
    """
    user = _require_user(session, user_id)
    user.password_hash = None
    user.totp_secret = None
    user.totp_salt = None  # drop the wrapped TOTP with its salt (#122); re-enroll mints both
    keys.retire_active_key(session, user)  # retire the old key; re-enrollment inserts a fresh one
    user.enrolled_at = None
    sessions.delete_user_sessions(session, user.id)
    # A reset emits account.credentials_reset (distinct from enrollment_issued) and
    # delivers the reset-flavored fresh-link mail (#80), attributed to the acting admin.
    enroll_url, delivered = mint_enrollment_link(
        session, config, user, bus=bus, reset=True, actor_id=admin.id
    )
    return JSONResponse(
        {"user_id": str(user.id), "enrollment_url": enroll_url, "email_delivered": delivered}
    )


@router.post("/admin/users/{user_id}/enrollment-link")
def regenerate_enrollment_link(
    user_id: uuid.UUID,
    session: Session = Depends(get_session),
    config: AppConfig = Depends(get_config),
    bus: EventBus = Depends(get_event_bus),
    admin: User = Depends(require_admin),
) -> JSONResponse:
    """Regenerate a single-use enrollment link for an un-enrolled / expired User."""
    user = _require_user(session, user_id)
    enroll_url, delivered = mint_enrollment_link(session, config, user, bus=bus, actor_id=admin.id)
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
    tokens.revoke(session, token)
    return JSONResponse({"token_id": str(token_id), "revoked": True})
