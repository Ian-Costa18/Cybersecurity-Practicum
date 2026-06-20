"""The User Portal — ``/account`` self-service for any enrolled User (issue #18).

Distinct from the Admin Portal: gated on a **Proxy Session only** (``require_session_user``;
no ``is_admin``), and organized by **capability**, since one User is simultaneously a
Requester and an Approver (``docs/web-proxy.md`` §User Portal). Every action is scoped
to the authenticated caller — a User can only see/cancel/revoke *their own* things.

Viewing needs only a session. **Casting, changing, or withdrawing a Vote always
requires fresh password + TOTP re-auth** (a Vote is cryptographically signed), so the
portal *surfaces* the User's approvals and their current vote but routes any vote
*action* out to the existing ``POST /approve/{id}`` flow — it adds no vote endpoint.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Form, HTTPException, status
from fastapi.responses import HTMLResponse, JSONResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from msig_proxy.approvals import votes
from msig_proxy.auth.guards import require_session_user
from msig_proxy.core import crypto, events
from msig_proxy.core.config import AppConfig
from msig_proxy.core.models import (
    CANCELLED,
    PENDING,
    ApiToken,
    ApprovalRequest,
    ApprovalRequestApprover,
    User,
)
from msig_proxy.deps import get_config, get_session
from msig_proxy.service_types import dispatch

router = APIRouter()


@router.get("/account", response_class=HTMLResponse)
def account_home(user: User = Depends(require_session_user)) -> HTMLResponse:
    """The portal home (session-gated; no re-auth to view)."""
    return HTMLResponse(
        f"<!doctype html><title>Account</title><h1>{user.username}</h1>"
        "<ul>"
        "<li><a href='/account/requests'>My requests</a></li>"
        "<li><a href='/account/approvals'>Requests I can approve</a></li>"
        "<li>API tokens (create / revoke)</li>"
        "</ul>"
    )


# --- API tokens -------------------------------------------------------------


@router.post("/account/tokens")
def create_token(
    session: Session = Depends(get_session),
    user: User = Depends(require_session_user),
    label: str = Form(...),
) -> JSONResponse:
    """Create a labeled API token for the caller; return the plaintext **once**.

    Only the SHA-256 hash is stored — the plaintext is never retrievable afterward.
    """
    token = crypto.generate_api_token()
    row = ApiToken(user_id=user.id, label=label, token_hash=crypto.hash_api_token(token))
    session.add(row)
    session.flush()
    return JSONResponse(
        status_code=status.HTTP_201_CREATED,
        content={"token_id": str(row.id), "label": label, "api_token": token},
    )


@router.get("/account/tokens")
def list_tokens(
    session: Session = Depends(get_session),
    user: User = Depends(require_session_user),
) -> JSONResponse:
    """List the caller's tokens (metadata only — never the plaintext or hash)."""
    rows = session.scalars(
        select(ApiToken).where(ApiToken.user_id == user.id).order_by(ApiToken.created_at)
    ).all()
    return JSONResponse(
        [
            {"token_id": str(t.id), "label": t.label, "revoked": t.revoked_at is not None}
            for t in rows
        ]
    )


@router.delete("/account/tokens/{token_id}")
def revoke_token(
    token_id: uuid.UUID,
    session: Session = Depends(get_session),
    user: User = Depends(require_session_user),
) -> JSONResponse:
    """Revoke one of the **caller's own** tokens (404 if it isn't theirs)."""
    token = session.get(ApiToken, token_id)
    if token is None or token.user_id != user.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="token not found")
    if token.revoked_at is None:
        token.revoked_at = datetime.now(UTC)
        session.flush()
    return JSONResponse({"token_id": str(token_id), "revoked": True})


# --- own requests + self-cancel --------------------------------------------


@router.get("/account/requests")
def list_requests(
    session: Session = Depends(get_session),
    user: User = Depends(require_session_user),
) -> JSONResponse:
    """List the caller's own Approval Requests with their current status."""
    rows = session.scalars(
        select(ApprovalRequest)
        .where(ApprovalRequest.requester_id == user.id)
        .order_by(ApprovalRequest.created_at)
    ).all()
    return JSONResponse(
        [{"id": str(r.id), "service_name": r.service_name, "state": r.state} for r in rows]
    )


@router.post("/account/requests/{request_id}/cancel")
def cancel_request(
    request_id: uuid.UUID,
    session: Session = Depends(get_session),
    user: User = Depends(require_session_user),
    config: AppConfig = Depends(get_config),
) -> JSONResponse:
    """Cancel one of the caller's own still-``pending`` requests (``request.cancelled``).

    Requester-only and pending-only: cancelling someone else's request is a ``404``;
    cancelling a request that already reached a terminal state is a ``409``.
    """
    request = session.get(ApprovalRequest, request_id)
    if request is None or request.requester_id != user.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="request not found")
    if request.state != PENDING:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"request is {request.state}; only a pending request can be cancelled",
        )
    request.state = CANCELLED
    session.flush()
    events.emit(events.Event(events.REQUEST_CANCELLED, {"approval_request_id": str(request.id)}))
    # Cancellation is a non-handoff terminal: no Executor handoff fires, so the held
    # artifact (if any — forward-auth stages none) is destroyed by the request's
    # post-approval handler, which emits artifact.destroyed (docs/request-lifecycle.md
    # §163). Routing through finalize keeps every terminal's cleanup behind one seam.
    dispatch.finalize(session, config, request)
    return JSONResponse({"id": str(request.id), "state": CANCELLED})


# --- requests the caller may approve ---------------------------------------


@router.get("/account/approvals")
def list_approvals(
    session: Session = Depends(get_session),
    user: User = Depends(require_session_user),
) -> JSONResponse:
    """List still-``pending`` requests the caller is an eligible Approver for, with
    the caller's current effective Vote. Acting on one links out to ``/approve/{id}``
    (a Vote needs fresh password + TOTP re-auth — there is no one-click here)."""
    request_ids = session.scalars(
        select(ApprovalRequestApprover.approval_request_id).where(
            ApprovalRequestApprover.user_id == user.id
        )
    ).all()
    out: list[dict[str, str | None]] = []
    for request_id in request_ids:
        request = session.get(ApprovalRequest, request_id)
        if request is None or request.state != PENDING:
            continue
        effective = votes.effective_votes(votes.votes_for(session, request_id))
        out.append(
            {
                "id": str(request.id),
                "service_name": request.service_name,
                "your_vote": effective.get(user.id),
                "approve_url": f"/approve/{request.id}",
            }
        )
    return JSONResponse(out)
