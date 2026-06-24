"""The one-time Service Handler: terminal handling for a submit-then-publish request.

Approval re-verifies the hash, publishes, and emits the outcome event; denial
destroys the held artifact (it must not outlive the request, #68). The publish and
artifact primitives are siblings in this slice (``publish``/``artifact``); this file
is only the terminal contract the dispatcher reaches without knowing the type.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from msig_proxy.core import events
from msig_proxy.core.config import AppConfig
from msig_proxy.core.models import ApprovalRequest
from msig_proxy.service_types.dispatch import ServiceHandler
from msig_proxy.service_types.one_time import artifact, publish


class OneTimeServiceHandler(ServiceHandler):
    """One-time: approval re-verifies the hash, publishes, and emits the outcome
    event; denial destroys the held artifact (it must not outlive the request, #68)."""

    def on_approved(
        self, session: Session, config: AppConfig, request: ApprovalRequest, *, bus: events.EventBus
    ) -> None:
        service = config.services.get(request.service_name)
        result = publish.execute_publish(session, request=request, service=service)

        # Emit only — the notification subscriber turns these into the outcome email
        # (ADR 0005, #65). The payload carries identifiers; the failure reason rides
        # along so the subscriber needn't re-derive it.
        if result.published:
            bus.emit(
                events.Event(
                    events.ACTION_SUCCEEDED,
                    {"approval_request_id": str(request.id)},
                )
            )
        else:
            bus.emit(
                events.Event(
                    events.ACTION_FAILED,
                    {"approval_request_id": str(request.id), "reason": result.reason},
                )
            )

    def on_denied(
        self, session: Session, config: AppConfig, request: ApprovalRequest, *, bus: events.EventBus
    ) -> None:
        # Non-handoff terminal: no Executor handoff fires, so the held artifact is
        # destroyed here (docs/request-lifecycle.md §163), emitting artifact.destroyed.
        # The approved/handoff path destroys it from the Executor when the Action
        # reaches a terminal state instead.
        # (Cancellation, the other non-handoff terminal, routes through on_cancelled,
        # which mirrors this; the future timed_out terminal will do likewise.)
        # TODO: once the Action aggregate lands, destroy the held artifact on the
        # approved path when the Action reaches succeeded/failed/aborted, passing its
        # action_id into the event.
        artifact.destroy_staged_artifact(session, request, bus=bus)
