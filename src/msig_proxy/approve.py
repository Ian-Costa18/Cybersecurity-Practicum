"""The approve/deny page and vote submission — the only human UI in Phase 0.

``GET /approve/{id}`` renders the request summary, an artifact download link, and
the live quorum status, plus a credential form (``docs/approver-authentication.md``
§Approve/Deny Page). ``POST /approve/{id}`` re-authenticates the approver *fresh*
on every vote — a stolen Proxy Session carries no password, so it cannot vote
(``CONTEXT.md`` §Approval Link) — and records a signed Vote via
:mod:`msig_proxy.voting`. ``GET /approve/{id}/artifact`` serves the staged bytes so
an approver can inspect exactly what they sign over (Hash Binding).

Phase 0 authenticates with password only; TOTP is the Phase 2 second factor
(``docs/mvp.md``). Approver sessions are stateless: there is no login cookie, so the
decision POST carries the password and the key is discarded immediately after
signing — never held across requests.
"""

from __future__ import annotations

import uuid
from pathlib import Path

from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.orm import Session

from msig_proxy import crypto, voting
from msig_proxy.deps import get_session
from msig_proxy.models import APPROVED, DENIED, VOTE_WITHDRAW, ApprovalRequest, StagedArtifact, User

router = APIRouter()
_templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))

# The result banner for each terminal transition; partial-quorum, withdraw, and
# no-op outcomes are handled in :func:`_result_banner`.
_TERMINAL_BANNERS = {
    APPROVED: (
        "Approval recorded — quorum reached",
        "The request is approved and hands off to execution.",
    ),
    DENIED: ("Request denied", "A single denial closes the request permanently."),
}


def _load_request(session: Session, request_id: uuid.UUID) -> ApprovalRequest:
    request = session.get(ApprovalRequest, request_id)
    if request is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="no such approval request"
        )
    return request


def _authenticate_approver(session: Session, username: str, password: str) -> User | None:
    """Fresh password re-authentication for one vote; ``None`` on any mismatch.

    Returns ``None`` for an unknown username, a wrong password, or an over-length
    password (the bcrypt 72-byte cap) — the caller maps all three to one 401 so the
    response does not distinguish them.
    """
    user = session.scalars(select(User).where(User.username == username)).one_or_none()
    if user is None:
        return None
    try:
        verified = crypto.verify_password(password, user.password_hash)
    except ValueError:
        return None
    return user if verified else None


def _render_page(
    request: Request,
    approval: ApprovalRequest,
    session: Session,
    *,
    error: str | None = None,
    status_code: int = status.HTTP_200_OK,
) -> HTMLResponse:
    approvals, quorum = voting.quorum_status(session, approval)
    return _templates.TemplateResponse(
        request=request,
        name="approve.html",
        context={"approval": approval, "approvals": approvals, "quorum": quorum, "error": error},
        status_code=status_code,
    )


@router.get("/approve/{request_id}", response_class=HTMLResponse)
def approve_page(
    request_id: uuid.UUID,
    request: Request,
    session: Session = Depends(get_session),
) -> HTMLResponse:
    """Render the approve/deny page: request summary, artifact link, live quorum."""
    approval = _load_request(session, request_id)
    return _render_page(request, approval, session)


@router.get("/approve/{request_id}/artifact")
def download_artifact(
    request_id: uuid.UUID,
    session: Session = Depends(get_session),
) -> Response:
    """Serve the staged artifact bytes so an approver can inspect what they sign over.

    The link is not secret — security is the per-vote re-authentication, not link
    obscurity (``CONTEXT.md`` §Approval Link). Served as an attachment; the bytes are
    the exact ones whose hash the approvers vote on (Hash Binding).
    """
    staged = session.get(StagedArtifact, request_id)
    if staged is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="no staged artifact for this request"
        )
    return Response(
        content=staged.content,
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{staged.filename}"'},
    )


@router.post("/approve/{request_id}", response_class=HTMLResponse)
def submit_vote(
    request_id: uuid.UUID,
    request: Request,
    session: Session = Depends(get_session),
    username: str = Form(...),
    password: str = Form(...),
    decision: str = Form(...),
) -> HTMLResponse:
    """Re-authenticate fresh, record a signed Vote, and report the outcome.

    Bad credentials re-render the page with a 401; a non-approver, a frozen
    (terminal) request, or an unknown decision re-render with 403/409/400. On success
    the outcome page reports the (possibly new) request state and the live tally.
    """
    approval = _load_request(session, request_id)

    approver = _authenticate_approver(session, username, password)
    if approver is None:
        return _render_page(
            request,
            approval,
            session,
            error="Invalid username or password.",
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    try:
        outcome = voting.cast_vote(
            session, request=approval, approver=approver, password=password, decision=decision
        )
    except voting.NotAnApproverError:
        return _render_page(
            request,
            approval,
            session,
            error="You are not an eligible approver for this request.",
            status_code=status.HTTP_403_FORBIDDEN,
        )
    except voting.VotesFrozenError:
        return _render_page(
            request,
            approval,
            session,
            error=f"This request is {approval.state}; voting is closed.",
            status_code=status.HTTP_409_CONFLICT,
        )
    except voting.UnknownDecisionError:
        return _render_page(
            request,
            approval,
            session,
            error="Choose Approve, Deny, or Withdraw.",
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    heading, message = _result_banner(outcome)
    return _templates.TemplateResponse(
        request=request,
        name="approve_result.html",
        context={
            "outcome": outcome,
            "approval_id": approval.id,
            "heading": heading,
            "message": message,
        },
    )


def _result_banner(outcome: voting.VoteOutcome) -> tuple[str, str]:
    """The heading/message for a recorded (or no-op) vote, by outcome."""
    if outcome.unchanged:
        return ("No change", "Your effective vote already matched; nothing was appended.")
    if outcome.request_state in _TERMINAL_BANNERS:
        return _TERMINAL_BANNERS[outcome.request_state]
    if outcome.decision == VOTE_WITHDRAW:
        return ("Vote withdrawn", "Your endorsement was retracted; the request stays open.")
    return ("Vote recorded — waiting for quorum", "Your approval was recorded and signed.")
