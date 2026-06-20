"""Post-approval dispatch: what each service type does at a terminal outcome.

When an Approval Request reaches a terminal state, the proxy hands off to whatever
that service type produces (CONTEXT.md §Post-Approval Object). This module owns the
*producer* side of that handoff — the :class:`PostApprovalHandler`, one per service
type — and the :func:`finalize` dispatcher that routes a terminal request to it.

The split from :mod:`msig_proxy.executor`: the executor holds the side-effecting
*primitives* (publish to PyPI, issue a grant); this module decides *which* primitive
runs for *which* service type on *which* terminal state. Keeping dispatch here, and
primitives there, means the dependency points one way (``post_approval`` → ``executor``)
with no cycle — the handler is never hung off the ``ApprovalRequest`` model, which
stays a pure data leaf (CONTEXT.md §Post-Approval Handler).

A handler owns its service type's *work* on both terminal paths (``on_approved`` /
``on_denied``) and **emits** the matching lifecycle event for that work
(``action.succeeded`` / ``action.failed``); :func:`finalize` emits the shared
``request.denied`` event. Notifications are never called from here — they consume
those events as a best-effort subscriber (ADR 0005, #65). This module only emits.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from sqlalchemy.orm import Session

from msig_proxy import events, executor
from msig_proxy.config import AppConfig
from msig_proxy.models import APPROVED, DENIED, FORWARD_AUTH, ONE_TIME, ApprovalRequest


class PostApprovalHandler(ABC):
    """The producer of a Post-Approval Object for one service type.

    Stateless behavior owning what its service type does at each terminal outcome:
    ``on_approved`` runs the handoff (issue a grant, or re-verify-and-publish);
    ``on_denied`` runs any type-specific cleanup. Both return ``None`` — nothing
    flows back to the dispatcher. Resolved from a request by :func:`handler_for`.
    """

    @abstractmethod
    def on_approved(
        self, session: Session, config: AppConfig, request: ApprovalRequest
    ) -> None:
        """Run the post-approval handoff for an ``approved`` request."""

    @abstractmethod
    def on_denied(
        self, session: Session, config: AppConfig, request: ApprovalRequest
    ) -> None:
        """Run type-specific cleanup for a ``denied`` request (the shared denial
        notification is the dispatcher's job, not the handler's)."""


class ForwardAuthHandler(PostApprovalHandler):
    """Forward-auth: approval issues a Service Grant; denial has nothing to clean up
    (a forward-auth service stages no artifact)."""

    def on_approved(
        self, session: Session, config: AppConfig, request: ApprovalRequest
    ) -> None:
        executor.issue_service_grant(session, config, request)

    def on_denied(
        self, session: Session, config: AppConfig, request: ApprovalRequest
    ) -> None:
        # Nothing to undo: no artifact is staged for a forward-auth request.
        return


class OneTimeHandler(PostApprovalHandler):
    """One-time: approval re-verifies the hash, publishes, and emits the outcome
    event; denial must destroy the held artifact (deferred — see #68)."""

    def on_approved(
        self, session: Session, config: AppConfig, request: ApprovalRequest
    ) -> None:
        service = config.services.get(request.service_name)
        result = executor.execute_publish(session, request=request, service=service)

        # Emit only — the notification subscriber turns these into the outcome email
        # (ADR 0005, #65). The payload carries identifiers; the failure reason rides
        # along so the subscriber needn't re-derive it.
        if result.published:
            events.emit(
                events.Event(
                    events.ACTION_SUCCEEDED,
                    {"approval_request_id": str(request.id)},
                ),
                session=session,
            )
        else:
            events.emit(
                events.Event(
                    events.ACTION_FAILED,
                    {"approval_request_id": str(request.id), "reason": result.reason},
                ),
                session=session,
            )

    def on_denied(
        self, session: Session, config: AppConfig, request: ApprovalRequest
    ) -> None:
        # TODO(#68): destroy the held StagedArtifact on this non-handoff terminal
        # (docs/request-lifecycle.md §163). Deferred with the Action lifecycle.
        return


# One handler instance per service type — they are stateless, so a module-level
# singleton each is fine. New service types register one entry here.
_HANDLERS: dict[str, PostApprovalHandler] = {
    FORWARD_AUTH: ForwardAuthHandler(),
    ONE_TIME: OneTimeHandler(),
}


def handler_for(request: ApprovalRequest) -> PostApprovalHandler:
    """The :class:`PostApprovalHandler` for a request, keyed on its ``service_type``.

    Derived from the discriminator already on the request — not stored, not hung off
    the model. Raises :class:`KeyError` for an unknown service type (an unreachable
    state given config validation, surfaced loudly rather than silently skipped)."""
    return _HANDLERS[request.service_type]


def finalize(session: Session, config: AppConfig, request: ApprovalRequest) -> None:
    """Run the post-approval handoff for a request that just reached a terminal state.

    Called after the vote that closed the request committed its transition. Safe to
    call only for ``approved`` / ``denied``; other states are ignored. Dispatches the
    type-specific work to the request's handler; the shared ``request.denied`` event
    (identical across service types) is emitted here, once. Notifications consume it.
    """
    handler = handler_for(request)

    if request.state == DENIED:
        events.emit(
            events.Event(
                events.REQUEST_DENIED,
                {
                    "approval_request_id": str(request.id),
                    "service_name": request.service_name,
                    "requester_id": str(request.requester_id),
                },
            ),
            session=session,
        )
        handler.on_denied(session, config, request)
        return

    if request.state != APPROVED:
        return

    handler.on_approved(session, config, request)
