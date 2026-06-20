"""The approve/deny page — an Approver's per-request UI (``docs/approver-authentication.md``).

Approver sessions are **stateless**: every link is a fresh, independent
authentication event scoped to one Approval Request. ``GET /approve/{id}`` renders
the request summary, an artifact download link for inspection, and the live quorum
status; ``POST /approve/{id}`` re-authenticates the Approver (username + password +
TOTP) and records a single signed Vote via :mod:`msig_proxy.votes`. ``GET
/approve/{id}/artifact`` serves the held bytes so an Approver can inspect exactly
the artifact whose hash they are signing over.

The request id is not a secret (security rests on the per-vote re-authentication,
not link obscurity, see ``docs/web-proxy.md``); the page and artifact download are
therefore reachable with the link alone, but no vote is recorded without a valid
password.
"""

from __future__ import annotations

import uuid
from pathlib import Path

from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.orm import Session

from msig_proxy import post_approval
from msig_proxy.approvals import votes
from msig_proxy.core.config import AppConfig
from msig_proxy.core.models import APPROVED, DENIED, ApprovalRequest, StagedArtifact, User
from msig_proxy.deps import get_config, get_session

router = APIRouter()

_templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


def _load_request(session: Session, request_id: uuid.UUID) -> ApprovalRequest:
    approval = session.get(ApprovalRequest, request_id)
    if approval is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="approval request not found"
        )
    return approval


def _page(
    http_request: Request,
    approval: ApprovalRequest,
    session: Session,
    *,
    message: str | None = None,
    status_code: int = status.HTTP_200_OK,
) -> HTMLResponse:
    tally = votes.current_tally(approval, votes.votes_for(session, approval.id))
    return _templates.TemplateResponse(
        request=http_request,
        name="approve.html",
        context={
            "approval": approval,
            "tally": tally,
            "message": message,
            "approve_url": f"/approve/{approval.id}",
            "artifact_url": f"/approve/{approval.id}/artifact",
        },
        status_code=status_code,
    )


@router.get("/approve/{request_id}", response_class=HTMLResponse)
def approve_page(
    request_id: uuid.UUID,
    http_request: Request,
    session: Session = Depends(get_session),
) -> HTMLResponse:
    """Render the approve/deny page: summary, artifact link, and live quorum status."""
    approval = _load_request(session, request_id)
    return _page(http_request, approval, session)


@router.post("/approve/{request_id}", response_class=HTMLResponse)
def submit_vote(
    request_id: uuid.UUID,
    http_request: Request,
    session: Session = Depends(get_session),
    config: AppConfig = Depends(get_config),
    username: str = Form(...),
    password: str = Form(...),
    totp: str = Form(default=""),
    decision: str = Form(...),
) -> HTMLResponse:
    """Re-authenticate (password + TOTP) and record one signed Vote, then re-render."""
    approval = _load_request(session, request_id)
    approver = session.scalars(select(User).where(User.username == username)).one_or_none()

    try:
        outcome = votes.cast_vote(
            session,
            request=approval,
            approver=approver,
            password=password,
            totp=totp,
            totp_valid_window=config.auth.totp_window,
            decision=decision,
        )
    except votes.AuthenticationFailed as exc:
        # Generic 401 — a wrong password and an unknown user are indistinguishable.
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid credentials",
            headers={"WWW-Authenticate": "Form"},
        ) from exc
    except votes.NotAnEligibleApprover as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="not an eligible approver"
        ) from exc
    except votes.InvalidDecision as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="invalid decision"
        ) from exc
    except votes.RequestNotPending:
        # Lost the race / link reused after closure: show the frozen page, not an error.
        return _page(
            http_request,
            approval,
            session,
            message="This request is already closed; your vote was not recorded.",
            status_code=status.HTTP_409_CONFLICT,
        )

    if not outcome.recorded:
        message = f"No change — your vote is already {decision!r}."
    else:
        # The vote just closed the request: run the handoff (publish / notify).
        # Best-effort and out-of-band of the decision — a failure here never
        # un-does the recorded approval (``docs/request-lifecycle.md``).
        if outcome.state in (APPROVED, DENIED):
            post_approval.finalize(session, config, approval)
        message = f"Vote recorded ({decision}). This request is now {outcome.state}."
    return _page(http_request, approval, session, message=message)


@router.get("/approve/{request_id}/artifact")
def approve_artifact(
    request_id: uuid.UUID,
    session: Session = Depends(get_session),
) -> Response:
    """Serve the staged artifact bytes so an Approver can inspect what they sign over."""
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
