"""A minimal in-process event seam (ADR 0005: the lifecycle emits *blind*).

The lifecycle advances and emits events without knowing who listens; consumers
subscribe. This is **not** a durable bus — the proxy is single-process and
best-effort. The notification system (#13/#65) subscribes here via
:mod:`msig_proxy.notifications.subscriber`; the waiting room projects lifecycle
state by polling the DB (it does not consume this seam).

Subscribers must not raise into the emitter: a handler failure is logged and
swallowed so a notification fault never blocks the lifecycle.

A lifecycle event is emitted *inside* the transition's transaction (the row is
flushed, not yet committed). A subscriber that must read the just-transitioned
state therefore needs the emitter's own session — a separate connection would not
see uncommitted rows. ``emit`` makes that session available through
:func:`active_session` for the duration of delivery; subscribers read it when the
payload's identifiers point at not-yet-committed rows, and fall back to their own
session otherwise (events emitted outside any request scope carry no session).
"""

from __future__ import annotations

import contextvars
import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

_log = logging.getLogger(__name__)

# The session of the transition currently being delivered, if any. Set by ``emit``
# so a subscriber can read flushed-but-uncommitted state from the same transaction.
_active_session: contextvars.ContextVar[Session | None] = contextvars.ContextVar(
    "msig_active_event_session", default=None
)


def active_session() -> Session | None:
    """The emitter's session for the in-flight delivery, or ``None`` outside one."""
    return _active_session.get()

# Event names (subset of ``docs/request-lifecycle.md`` §Event catalog, plus the
# ``account.*`` catalog in ``docs/account-management.md``).
REQUEST_CREATED = "request.created"
REQUEST_CANCELLED = "request.cancelled"
REQUEST_APPROVED = "request.approved"
REQUEST_DENIED = "request.denied"
ACTION_SUCCEEDED = "action.succeeded"
ACTION_FAILED = "action.failed"
GRANT_ACTIVATED = "grant.activated"
GRANT_EXPIRED = "grant.expired"
ARTIFACT_DESTROYED = "artifact.destroyed"
# Account events (``docs/account-management.md`` §Account Events). The affected User
# is the subject; the notification matrix is in ``docs/notification-system.md``.
ENROLLMENT_ISSUED = "account.enrollment_issued"
CREDENTIALS_RESET = "account.credentials_reset"
ACCOUNT_DEACTIVATED = "account.deactivated"
ACCOUNT_DELETED = "account.deleted"


@dataclass(frozen=True)
class Event:
    name: str
    payload: dict[str, Any] = field(default_factory=dict)


_subscribers: list[Callable[[Event], None]] = []


def subscribe(handler: Callable[[Event], None]) -> None:
    """Register a handler to receive every emitted event."""
    _subscribers.append(handler)


def unsubscribe(handler: Callable[[Event], None]) -> None:
    """Remove a previously registered handler (idempotent)."""
    if handler in _subscribers:
        _subscribers.remove(handler)


def clear_subscribers() -> None:
    """Drop all handlers — used to keep tests isolated."""
    _subscribers.clear()


def emit(event: Event, *, session: Session | None = None) -> None:
    """Deliver ``event`` to every subscriber, best-effort (failures are logged).

    ``session`` is the emitting transition's session; when given it is exposed via
    :func:`active_session` so a subscriber can read the flushed transition before it
    commits. Passing it does not couple the emitter to any consumer — the seam stays
    blind; it only lends the open transaction to whoever happens to be listening.
    """
    token = _active_session.set(session)
    try:
        for handler in list(_subscribers):
            try:
                handler(event)
            except Exception:
                _log.warning("event subscriber failed for %s", event.name, exc_info=True)
    finally:
        _active_session.reset(token)
