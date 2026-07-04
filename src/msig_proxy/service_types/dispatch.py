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

from msig_proxy.approvals import integrity
from msig_proxy.core import events
from msig_proxy.core.config import AppConfig
from msig_proxy.core.models import (
    APPROVED,
    CANCELLED,
    DENIED,
    FORWARD_AUTH,
    FROZEN,
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
    def on_approved(
        self, session: Session, config: AppConfig, request: ApprovalRequest, *, bus: events.EventBus
    ) -> None:
        """Run the post-approval handoff for an ``approved`` request, emitting any
        work events on ``bus``."""

    @abstractmethod
    def on_denied(
        self, session: Session, config: AppConfig, request: ApprovalRequest, *, bus: events.EventBus
    ) -> None:
        """Run type-specific cleanup for a ``denied`` request (the shared denial
        notification is the dispatcher's job, not the handler's)."""

    def on_cancelled(
        self, session: Session, config: AppConfig, request: ApprovalRequest, *, bus: events.EventBus
    ) -> None:
        """Run cleanup for a ``cancelled`` request.

        Cancellation is a non-handoff terminal just like denial, so by default it
        mirrors :meth:`on_denied`. It is its own seam — a service type that needs
        cancellation-specific behavior overrides this without disturbing denial.
        (This is the narrow, per-state patch; the principled "a handler models every
        request terminal state" design is tracked in #90.)"""
        self.on_denied(session, config, request, bus=bus)


def handler_for(request: ApprovalRequest) -> ServiceHandler:
    """The :class:`ServiceHandler` for a request, keyed on its ``service_type``.

    Derived from the discriminator already on the request — not stored, not hung off
    the model. Raises :class:`KeyError` for an unknown service type (an unreachable
    state given config validation, surfaced loudly rather than silently skipped)."""
    return _HANDLERS[request.service_type]


def finalize(
    session: Session, config: AppConfig, request: ApprovalRequest, *, bus: events.EventBus
) -> None:
    """Run the post-approval handoff for a request that just reached a terminal state.

    Called after the transition that closed the request committed (a closing vote, or
    a requester cancellation). Safe to call only for ``approved`` / ``denied`` /
    ``cancelled``; other states are ignored. Dispatches the type-specific work to the
    request's handler; the shared ``request.denied`` event (identical across service
    types) is emitted on ``bus``, once. Notifications consume it.
    """
    handler = handler_for(request)

    if request.state == DENIED:
        bus.emit(
            events.RequestDenied(
                approval_request_id=request.id,
                service_name=request.service_name,
                requester_id=request.requester_id,
            )
        )
        handler.on_denied(session, config, request, bus=bus)
        return

    if request.state == CANCELLED:
        handler.on_cancelled(session, config, request, bus=bus)
        return

    if request.state != APPROVED:
        return

    # Execution-time integrity re-check (#121): before acting on an ``approved``
    # request, re-verify that its snapshotted policy (frozen approver keys + quorum)
    # still holds against the live config and its own votes. A HOST-2 database-write
    # attacker who substituted a signing key or weakened the quorum is caught here —
    # the request is frozen for manual review, not published on tampered state
    # (``docs/request-lifecycle.md`` §Execution-time integrity re-check). This runs
    # before any handoff so no service type can act on a compromised request.
    verdict = integrity.verify_request_integrity(session, request, config=config)
    if not verdict.ok:
        request.state = FROZEN
        session.flush()
        bus.emit(
            events.RequestFrozen(
                approval_request_id=request.id,
                service_name=request.service_name,
                requester_id=request.requester_id,
                reason=verdict.reason or "integrity re-check failed",
            )
        )
        return

    # The approval axis settled (``docs/request-lifecycle.md`` §Events): emit the
    # shared ``request.approved`` (identical across service types, like denial) before
    # the type-specific handoff. Notifications route it to the Requester (#81) —
    # distinct from the later ``action.succeeded`` / ``grant.activated`` the handoff
    # emits (``docs/notification-system.md`` §"Two outcome axes").
    bus.emit(
        events.RequestApproved(
            approval_request_id=request.id,
            service_name=request.service_name,
            requester_id=request.requester_id,
        )
    )
    handler.on_approved(session, config, request, bus=bus)


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
