"""The forward-auth waiting room: watch quorum build in real time (issue #10).

After a forward-auth Requester's Approval Request is created (or resumed), they
land here. ``GET /pending/{id}`` renders the live quorum status; ``GET
/pending/{id}/stream`` is a Server-Sent Events stream that projects the request's
lifecycle — it pushes an ``approval`` update as votes land and a terminal
``quorum_reached`` / ``denied`` event, then closes.

The page is scoped to the Requester who created the request: a different
authenticated User receives ``403`` (``docs/web-proxy.md`` §Resuming).

The stream is the **quorum-progress-UI projection** of the lifecycle
(``docs/request-lifecycle.md``). With no durable event bus in the MVP it polls the
DB and emits only on change — the spec explicitly allows "SSE or polling over the
vote/closing events." Grant issuance and the browser redirect on quorum are the
next slice (#11/#12); this slice makes "request access and watch the counter" work.
"""

from __future__ import annotations

import json
import time
import uuid
from collections.abc import Iterator
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session, sessionmaker

from msig_proxy import votes
from msig_proxy.deps import get_session, require_session_user
from msig_proxy.models import APPROVED, DENIED, PENDING, ApprovalRequest, User

router = APIRouter()

_jinja = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))

# Default poll cadence for the SSE projection (seconds). Small enough to feel live.
_POLL_INTERVAL = 1.0


def _load_owned_request(session: Session, request_id: uuid.UUID, user: User) -> ApprovalRequest:
    """Load the request, enforcing it exists (404) and belongs to ``user`` (403)."""
    approval = session.get(ApprovalRequest, request_id)
    if approval is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="approval request not found"
        )
    if approval.requester_id != user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="not your request")
    return approval


def _event_name(state: str) -> str:
    """The SSE event name projecting a request state (``docs/web-proxy.md`` §SSE)."""
    if state == APPROVED:
        return "quorum_reached"
    if state == DENIED:
        return "denied"
    return "approval"


def _sse(event: str, data: dict[str, object]) -> str:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


def quorum_event_stream(
    session_factory: sessionmaker[Session],
    request_id: uuid.UUID,
    *,
    poll_interval: float = _POLL_INTERVAL,
) -> Iterator[str]:
    """Yield SSE frames as the request's quorum tally changes; stop at a terminal state.

    Polls the DB (no durable bus in the MVP) and emits only on change. Opens its
    own short-lived session per poll because it outlives the request's dependency
    scope. ``session_factory`` is the app's ``sessionmaker``.
    """
    last: tuple[str, int, int] | None = None
    while True:
        session = session_factory()
        try:
            approval = session.get(ApprovalRequest, request_id)
            if approval is None:
                return
            tally = votes.current_tally(approval, votes.votes_for(session, approval.id))
            state = approval.state
        finally:
            session.close()

        snapshot = (state, tally.approvals, tally.quorum)
        if snapshot != last:
            yield _sse(
                _event_name(state),
                {"count": tally.approvals, "required": tally.quorum, "state": state},
            )
            last = snapshot
        if state != PENDING:
            return  # terminal: the vote concluded, close the stream
        time.sleep(poll_interval)


@router.get("/pending/{request_id}", response_class=HTMLResponse)
def waiting_room(
    request_id: uuid.UUID,
    http_request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(require_session_user),
) -> HTMLResponse:
    """Render the waiting room for the Requester's own forward-auth request."""
    approval = _load_owned_request(session, request_id, user)
    tally = votes.current_tally(approval, votes.votes_for(session, approval.id))
    return _jinja.TemplateResponse(
        request=http_request,
        name="pending.html",
        context={
            "approval": approval,
            "tally": tally,
            "stream_url": f"/pending/{approval.id}/stream",
        },
    )


@router.get("/pending/{request_id}/stream")
def waiting_room_stream(
    request_id: uuid.UUID,
    http_request: Request,
    session: Session = Depends(get_session),
    user: User = Depends(require_session_user),
) -> StreamingResponse:
    """SSE projection of the request's quorum progress (Requester-scoped)."""
    approval = _load_owned_request(session, request_id, user)
    factory = http_request.app.state.session_factory
    return StreamingResponse(
        quorum_event_stream(factory, approval.id),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache"},
    )
