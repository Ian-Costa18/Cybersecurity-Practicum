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
``on_denied``) plus any notification specific to that work (the one-time outcome
email). The denial notification is identical across types, so it stays in
:func:`finalize`.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from sqlalchemy.orm import Session

from msig_proxy import executor, notifications
from msig_proxy.config import AppConfig, EmailConfig
from msig_proxy.models import APPROVED, DENIED, FORWARD_AUTH, ONE_TIME, ApprovalRequest


def _email_config(config: AppConfig) -> EmailConfig | None:
    return config.notifications.email if config.notifications else None


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
    """One-time: approval re-verifies the hash, publishes, and notifies the outcome;
    denial destroys the held artifact (it must not outlive the request, #68)."""

    def on_approved(
        self, session: Session, config: AppConfig, request: ApprovalRequest
    ) -> None:
        service = config.services.get(request.service_name)
        result = executor.execute_publish(session, request=request, service=service)

        email = _email_config(config)
        if result.published:
            notifications.notify_outcome(
                session,
                email,
                request,
                subject=f"Published: {request.package_name} {request.package_version}",
                body="Your request was approved and the package was published successfully.",
            )
        else:
            notifications.notify_outcome(
                session,
                email,
                request,
                subject=f"Execution failed: {request.package_name} {request.package_version}",
                body=f"Your request was approved, but execution failed: {result.reason}",
            )

    def on_denied(
        self, session: Session, config: AppConfig, request: ApprovalRequest
    ) -> None:
        # Non-handoff terminal: no Executor handoff fires, so the held artifact is
        # destroyed here (docs/request-lifecycle.md §163), emitting artifact.destroyed.
        # The approved/handoff path destroys it from the Executor when the Action
        # reaches a terminal state instead.
        # TODO(#68): once the Action aggregate lands, destroy the held artifact on the
        # approved path when the Action reaches succeeded/failed/aborted, passing its
        # action_id into the event. The cancelled/timed_out terminals will route here
        # too once those transitions call finalize.
        executor.destroy_staged_artifact(session, request)


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
    type-specific work to the request's handler; the denial notification (identical
    across service types) is sent here, once.
    """
    handler = handler_for(request)

    if request.state == DENIED:
        notifications.notify_outcome(
            session,
            _email_config(config),
            request,
            subject=f"Request denied: {request.service_name}",
            body="Your request was denied by an approver.",
        )
        handler.on_denied(session, config, request)
        return

    if request.state != APPROVED:
        return

    handler.on_approved(session, config, request)
