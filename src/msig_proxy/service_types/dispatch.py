"""Type-blind post-approval dispatch: route a terminal request to its handler.

When an Approval Request reaches a terminal state, the proxy hands off to whatever
that service type produces (CONTEXT.md §Post-Approval Object). Terminal handling is
the **only** point reached without knowing the service type — :func:`finalize` is
called from the generic voting/cancellation path with a request whose type it does
not know — so the dispatched interface is the narrow terminal contract
(:class:`ServiceHandler`) plus a registry keyed on ``service_type``. Intake,
staging, and consumption are *not* dispatched: each type has its own inbound trigger
and lives as sibling files in its slice (see ADR 0012 §Rationale).

A handler owns its service type's *work* on every terminal path (``on_approved`` /
``on_denied`` / ``on_cancelled``) and **emits** the matching lifecycle event for that
work (``action.succeeded`` / ``action.failed``); :func:`finalize` emits the shared
``request.denied`` event. Notifications are never called from here — they consume
those events as a best-effort subscriber (ADR 0005, #65). This module only emits.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from sqlalchemy.orm import Session

from msig_proxy.core import events
from msig_proxy.core.config import AppConfig
from msig_proxy.core.models import (
    APPROVED,
    CANCELLED,
    DENIED,
    FORWARD_AUTH,
    ONE_TIME,
    ApprovalRequest,
)


class ServiceHandler(ABC):
    """The producer of a Post-Approval Object for one service type.

    Stateless behavior owning what its service type does at each terminal outcome:
    ``on_approved`` runs the handoff (issue a grant, or re-verify-and-publish);
    ``on_denied`` runs any type-specific cleanup. Both return ``None`` — nothing
    flows back to the dispatcher. Resolved from a request by :func:`handler_for`.
    """

    @abstractmethod
    def on_approved(self, session: Session, config: AppConfig, request: ApprovalRequest) -> None:
        """Run the post-approval handoff for an ``approved`` request."""

    @abstractmethod
    def on_denied(self, session: Session, config: AppConfig, request: ApprovalRequest) -> None:
        """Run type-specific cleanup for a ``denied`` request (the shared denial
        notification is the dispatcher's job, not the handler's)."""

    def on_cancelled(self, session: Session, config: AppConfig, request: ApprovalRequest) -> None:
        """Run cleanup for a ``cancelled`` request.

        Cancellation is a non-handoff terminal just like denial, so by default it
        mirrors :meth:`on_denied`. It is its own seam — a service type that needs
        cancellation-specific behavior overrides this without disturbing denial.
        (This is the narrow, per-state patch; the principled "a handler models every
        request terminal state" design is tracked in #90.)"""
        self.on_denied(session, config, request)


def handler_for(request: ApprovalRequest) -> ServiceHandler:
    """The :class:`ServiceHandler` for a request, keyed on its ``service_type``.

    Derived from the discriminator already on the request — not stored, not hung off
    the model. Raises :class:`KeyError` for an unknown service type (an unreachable
    state given config validation, surfaced loudly rather than silently skipped)."""
    return _HANDLERS[request.service_type]


def finalize(session: Session, config: AppConfig, request: ApprovalRequest) -> None:
    """Run the post-approval handoff for a request that just reached a terminal state.

    Called after the transition that closed the request committed (a closing vote, or
    a requester cancellation). Safe to call only for ``approved`` / ``denied`` /
    ``cancelled``; other states are ignored. Dispatches the type-specific work to the
    request's handler; the shared ``request.denied`` event (identical across service
    types) is emitted here, once. Notifications consume it.
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

    if request.state == CANCELLED:
        handler.on_cancelled(session, config, request)
        return

    if request.state != APPROVED:
        return

    handler.on_approved(session, config, request)


# The per-type handlers live in their own slices and subclass the contract above.
# They are imported *after* the ABC is defined (not at the top) because each handler
# module imports ServiceHandler from here — importing them earlier would form a
# cycle. New service types register one entry in _HANDLERS.
from msig_proxy.service_types.forward_auth.handler import ForwardAuthServiceHandler  # noqa: E402
from msig_proxy.service_types.one_time.handler import OneTimeServiceHandler  # noqa: E402

# One handler instance per service type — they are stateless, so a module-level
# singleton each is fine.
_HANDLERS: dict[str, ServiceHandler] = {
    FORWARD_AUTH: ForwardAuthServiceHandler(),
    ONE_TIME: OneTimeServiceHandler(),
}
