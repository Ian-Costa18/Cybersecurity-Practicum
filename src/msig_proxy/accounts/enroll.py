"""Self-enrollment: ``GET/POST /enroll/{token}`` (issue #15).

The enrollee half of the account-provisioning flow (``docs/account-management.md``
§Account Provisioning Flow). Following the single-use link, the enrollee sets their
own password; the proxy **generates the Ed25519 keypair at enrollment** (private
key encrypted AES-256-GCM under a key derived from the new password, mirroring
:mod:`msig_proxy.seed`), provisions a TOTP secret, marks the account enrolled and
active, and atomically consumes the link. The admin never sees these secrets.

TOTP is **set** here, not **enforced** — login/vote enforcement is #16. The enrolled
TOTP secret is displayed once on success for the enrollee to add to their app.

The pages are intentionally minimal inline HTML; richer templating arrives with the
portals (#17/#18).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, cast

from fastapi import APIRouter, Depends, Form, HTTPException, status
from fastapi.responses import HTMLResponse
from sqlalchemy import CursorResult, select, update
from sqlalchemy.orm import Session

from msig_proxy.accounts import keys
from msig_proxy.core import crypto
from msig_proxy.core.config import AppConfig
from msig_proxy.core.models import EnrollmentToken, User
from msig_proxy.core.time import aware
from msig_proxy.deps import get_config, get_session

router = APIRouter()


def _valid_token(session: Session, token: str) -> EnrollmentToken:
    """Resolve an unexpired, unconsumed enrollment token, or raise ``400``.

    Consumption is *not* done here (that is the atomic check-and-set at POST); this
    is the read-side validation shared by the GET form and the POST guard.
    """
    record = session.scalars(
        select(EnrollmentToken).where(
            EnrollmentToken.token_hash == crypto.hash_enrollment_token(token)
        )
    ).one_or_none()
    if record is None or record.consumed_at is not None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="invalid or used link")
    if aware(record.expires_at) <= datetime.now(UTC):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="enrollment link expired"
        )
    return record


@router.get("/enroll/{token}", response_class=HTMLResponse)
def enroll_form(token: str, session: Session = Depends(get_session)) -> HTMLResponse:
    """Render the set-password form for a valid link (else ``400``)."""
    _valid_token(session, token)
    return HTMLResponse(
        "<!doctype html><title>Set up your account</title>"
        "<h1>Set up your account</h1>"
        f'<form method="post" action="/enroll/{token}">'
        '<label>Password <input type="password" name="password" required></label>'
        '<button type="submit">Enroll</button>'
        "</form>"
    )


@router.post("/enroll/{token}", response_class=HTMLResponse)
def enroll_submit(
    token: str,
    session: Session = Depends(get_session),
    config: AppConfig = Depends(get_config),
    password: str = Form(...),
) -> HTMLResponse:
    """Set the password, generate the keypair + TOTP secret, and consume the link.

    Enforces the configured ``auth.password_min_length`` (the documented security
    control, ``docs/account-management.md`` §Authentication Factors) — this single
    enrollment seam covers both first enrollment and a credentials reset, since a
    reset issues a fresh enrollment link the user follows back here. The bcrypt
    72-byte upper cap is enforced separately in the crypto layer.

    The link is consumed by an atomic ``UPDATE ... WHERE consumed_at IS NULL`` so two
    concurrent submissions cannot both enroll; the loser gets ``400``.
    """
    record = _valid_token(session, token)

    min_length = config.auth.password_min_length
    if len(password) < min_length:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"password must be at least {min_length} characters",
        )

    now = datetime.now(UTC)
    consumed = cast(
        "CursorResult[Any]",
        session.execute(
            update(EnrollmentToken)
            .where(EnrollmentToken.id == record.id, EnrollmentToken.consumed_at.is_(None))
            .values(consumed_at=now)
        ),
    )
    if consumed.rowcount == 0:  # lost the race — already consumed
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="invalid or used link")

    user = session.get(User, record.user_id)
    if user is None:  # pragma: no cover - FK guarantees the row
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="user not found")

    # The active key pair is generated at enrollment; its private half is wrapped
    # under PBKDF2(password) inside keys.create_active_key (#53). On a re-enrollment
    # (after an admin reset retired the prior key) this inserts a fresh active key
    # while the retired one stays for audit.
    try:
        password_hash = crypto.hash_password(password)
        keys.create_active_key(session, user, password)
    except ValueError as exc:  # password past bcrypt's 72-byte cap
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    # The TOTP secret is wrapped at rest exactly like the signing key (#122):
    # AES-256-GCM under PBKDF2(password), bound to this user's id as AAD. The
    # plaintext is shown once here for the enrollee to scan, then only the ciphertext
    # is stored; enc_key is transient (invariant 2) and discarded.
    totp_secret = crypto.generate_totp_secret()
    totp_salt = crypto.new_salt()
    enc_key = crypto.derive_enc_key(password, totp_salt)
    user.password_hash = password_hash
    user.totp_secret = crypto.encrypt_totp_secret(totp_secret, enc_key, crypto.totp_aad(user.id))
    user.totp_salt = totp_salt
    del enc_key
    user.enrolled_at = now
    user.is_active = True
    session.flush()

    return HTMLResponse(
        "<!doctype html><title>Enrolled</title><h1>Enrollment complete</h1>"
        f"<p>You can now sign in as <b>{user.username}</b>.</p>"
        "<p>Add this TOTP secret to your authenticator app "
        f"(shown once): <code>{totp_secret}</code></p>"
    )
