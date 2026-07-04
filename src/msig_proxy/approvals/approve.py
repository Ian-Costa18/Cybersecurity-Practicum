"""The approve/deny page — an Approver's per-request UI (``docs/approver-authentication.md``).

Approver sessions are **stateless**: every link is a fresh, independent
authentication event scoped to one Approval Request. ``GET /approve/{id}`` renders
the request summary, an artifact download link for inspection, and the live quorum
status — naming the **Endorsing Approvers** and the count still outstanding (#22);
``POST /approve/{id}`` re-authenticates the Approver (username + password + TOTP)
and records a single signed Vote via :mod:`msig_proxy.votes`. ``GET
/approve/{id}/stream`` is a Server-Sent Events projection that keeps that endorser
list live as other Approvers act. ``GET /approve/{id}/artifact`` serves the held
bytes so an Approver can inspect exactly the artifact whose hash they are signing
over.

The request id is not a secret (security rests on the per-vote re-authentication,
not link obscurity, see ``docs/web-proxy.md``); the page, the endorser stream, and
the artifact download are therefore reachable with the link alone — **no
requester-ownership guard** like the waiting room's (``docs/threat-model/00-overview.md`` INFO-1)
— but no vote is recorded without a valid password.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Iterator
from pathlib import Path

from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from msig_proxy.approvals import votes
from msig_proxy.approvals.pending import _POLL_INTERVAL, _event_name, _sse
from msig_proxy.core.config import AppConfig
from msig_proxy.core.events import EventBus
from msig_proxy.core.models import APPROVED, DENIED, PENDING, ApprovalRequest, StagedArtifact, User
from msig_proxy.deps import get_config, get_event_bus, get_session
from msig_proxy.service_types import dispatch

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
    tally = votes.tally_for(session, approval)
    # Name the Endorsing Approvers (effective-approve Users); the JS keeps this list
    # live off the SSE stream. Non-endorsers — deniers, withdrawals, non-actors — are
    # never named, only counted in ``tally.remaining``
    # (#22, docs/threat-model/00-overview.md INFO-1).
    endorsers = [user.username for user in votes.endorsing_approvers(session, approval)]
    return _templates.TemplateResponse(
        request=http_request,
        name="approve.html",
        context={
            "approval": approval,
            "tally": tally,
            "endorsers": endorsers,
            "message": message,
            "approve_url": f"/approve/{approval.id}",
            "stream_url": f"/approve/{approval.id}/stream",
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


def endorser_event_stream(
    session_factory: sessionmaker[Session],
    request_id: uuid.UUID,
    *,
    poll_interval: float = _POLL_INTERVAL,
) -> Iterator[str]:
    """Yield SSE frames naming the Endorsing Approvers as votes land; stop at terminal.

    The approver-facing parallel to the waiting room's
    :func:`msig_proxy.approvals.pending.quorum_event_stream`: same poll-and-diff
    projection (no durable bus in the MVP), same ``approval`` / ``quorum_reached`` /
    ``denied`` event vocabulary, but the payload carries the **endorser identities**
    (effective-approve usernames) on top of count/quorum/remaining/state.

    The change-detection key is the *set* of endorser ids, not the count — a
    withdraw paired with a new approve holds the count constant while the names
    change, and that frame must still be pushed (#22). Opens a short-lived session
    per poll because it outlives the request's dependency scope.
    """
    last: tuple[str, tuple[str, ...], int] | None = None
    while True:
        session = session_factory()
        try:
            approval = session.get(ApprovalRequest, request_id)
            if approval is None:
                return
            tally = votes.tally_for(session, approval)
            endorsers = votes.endorsing_approvers(session, approval)
            endorser_names = [user.username for user in endorsers]
            endorser_ids = tuple(sorted(str(user.id) for user in endorsers))
            state = approval.state
            denial_reason = approval.denial_reason
        finally:
            session.close()

        # Key on the endorser id set (not the count) so a constant-count identity
        # change — withdraw + new approve — still emits a frame.
        snapshot = (state, endorser_ids, tally.quorum)
        if snapshot != last:
            data: dict[str, object] = {
                "endorsers": endorser_names,
                "count": tally.approvals,
                "required": tally.quorum,
                "remaining": tally.remaining,
                "state": state,
            }
            if state == DENIED:
                data["reason"] = denial_reason
            yield _sse(_event_name(state), data)
            last = snapshot
        if state != PENDING:
            return  # terminal: the vote concluded, close the stream
        time.sleep(poll_interval)


@router.get("/approve/{request_id}/stream")
def approve_stream(
    request_id: uuid.UUID,
    http_request: Request,
    session: Session = Depends(get_session),
) -> StreamingResponse:
    """SSE projection naming the Endorsing Approvers (link-scoped, #22).

    Parallels the waiting room stream but is reachable with the approval link alone:
    the approve page itself carries no requester-ownership check, so this stream
    deliberately omits the waiting room's 403-if-not-owner guard
    (``docs/threat-model/00-overview.md`` INFO-1). View-time access needs only the link; *voting*
    still re-authenticates.
    """
    approval = _load_request(session, request_id)
    factory = http_request.app.state.session_factory
    return StreamingResponse(
        endorser_event_stream(factory, approval.id),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache"},
    )


@router.post("/approve/{request_id}", response_class=HTMLResponse)
def submit_vote(
    request_id: uuid.UUID,
    http_request: Request,
    session: Session = Depends(get_session),
    config: AppConfig = Depends(get_config),
    bus: EventBus = Depends(get_event_bus),
    username: str = Form(...),
    password: str = Form(...),
    totp: str = Form(default=""),
    decision: str = Form(...),
    reason: str = Form(default=""),
) -> HTMLResponse:
    """Re-authenticate (password + TOTP) and record one signed Vote, then re-render.

    ``reason`` is the optional free-text denial reason (#87, ``docs/web-proxy.md``
    §Approve/Deny Page Content); it is recorded only when the vote denies the request.
    """
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
            deny_reason=reason or None,
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
            dispatch.finalize(session, config, approval, bus=bus)
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
