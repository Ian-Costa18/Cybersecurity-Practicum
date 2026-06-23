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
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session, sessionmaker

from msig_proxy.approvals import votes
from msig_proxy.auth.guards import require_session_user
from msig_proxy.core.models import APPROVED, DENIED, FORWARD_AUTH, PENDING, ApprovalRequest, User
from msig_proxy.deps import get_session

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
            tally = votes.tally_for(session, approval)
            state = approval.state
            denial_reason = approval.denial_reason
        finally:
            session.close()

        snapshot = (state, tally.approvals, tally.quorum)
        if snapshot != last:
            data: dict[str, object] = {
                "count": tally.approvals,
                "required": tally.quorum,
                "state": state,
            }
            # The denied frame carries the Approver's optional reason (#87,
            # docs/web-proxy.md §Real-Time Updates / §Denial State).
            if state == DENIED:
                data["reason"] = denial_reason
            yield _sse(_event_name(state), data)
            last = snapshot
        if state != PENDING:
            return  # terminal: the vote concluded, close the stream
        time.sleep(poll_interval)


@router.get("/pending/{request_id}", response_class=HTMLResponse)
def waiting_room(
    request_id: uuid.UUID,
    http_request: Request,
    return_to: str | None = None,
    session: Session = Depends(get_session),
    user: User = Depends(require_session_user),
) -> HTMLResponse:
    """Render the waiting room for the Requester's own forward-auth request.

    ``return_to`` is the originally-requested backend URL, threaded through login →
    ``/access`` → here so the page can send the browser back on quorum (#77,
    ``docs/web-proxy.md`` §Forward-Auth Flow step 10). Absent for a one-time
    requester or a direct visit — the page then just shows the granted state.
    """
    approval = _load_owned_request(session, request_id, user)
    tally = votes.tally_for(session, approval)
    # "Request again" on the denial screen re-enters /access for the same service,
    # which creates a *fresh* Approval Request (the denied one is never reused; #87,
    # docs/web-proxy.md §Denial State). Forward-auth only — a one-time request is
    # re-initiated by re-uploading, not from the waiting room.
    request_again_url: str | None = None
    if approval.service_type == FORWARD_AUTH:
        again_params = {"service": approval.service_name}
        if return_to:
            again_params["return_to"] = return_to
        request_again_url = f"/access?{urlencode(again_params)}"
    return _jinja.TemplateResponse(
        request=http_request,
        name="pending.html",
        context={
            "approval": approval,
            "tally": tally,
            "stream_url": f"/pending/{approval.id}/stream",
            "return_to": return_to,
            "request_again_url": request_again_url,
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
