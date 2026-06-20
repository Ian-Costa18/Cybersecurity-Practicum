"""The held artifact's terminal lifecycle: destroy the staged bytes at an outcome.

A one-time Service stages the uploaded artifact at request creation; it must not
outlive the request (#68, ``docs/request-lifecycle.md`` §163). The held artifact
lives entirely in the one-time slice — forward-auth stages nothing — so its
destruction belongs here, not in a shared layer.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from msig_proxy.core import events
from msig_proxy.core.models import ApprovalRequest, StagedArtifact


def destroy_staged_artifact(
    session: Session, request: ApprovalRequest, *, action_id: str | None = None
) -> bool:
    """Destroy the held artifact for a request at a terminal outcome.

    A one-time Service stages the uploaded artifact at request creation; it must not
    outlive the request (``docs/request-lifecycle.md`` §163). This deletes the held
    row and emits ``artifact.destroyed``; forward-auth requests stage nothing, so
    there is nothing to delete and no event fires.

    Idempotent: a request whose artifact is already gone (e.g. a redelivered
    terminal transition) is a no-op that returns ``False`` and emits no event.
    Returns ``True`` when bytes were actually destroyed. ``action_id`` is carried
    into the event payload on the approved/handoff path (``None`` on the
    non-handoff terminals — denial, cancellation).
    """
    staged = session.get(StagedArtifact, request.id)
    if staged is None:
        return False

    session.delete(staged)
    session.flush()

    events.emit(
        events.Event(
            events.ARTIFACT_DESTROYED,
            {
                "approval_request_id": str(request.id),
                "action_id": action_id,
                "terminal_state": request.state,
            },
        )
    )
    return True
