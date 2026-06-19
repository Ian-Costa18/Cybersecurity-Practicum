"""A minimal in-process event seam (ADR 0005: the lifecycle emits *blind*).

The lifecycle advances and emits events without knowing who listens; consumers
subscribe. This is **not** a durable bus — the proxy is single-process and
best-effort. The notification system (#13) subscribes here; the waiting room
projects lifecycle state by polling the DB (it does not consume this seam).

Subscribers must not raise into the emitter: a handler failure is logged and
swallowed so a notification fault never blocks the lifecycle.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

_log = logging.getLogger(__name__)

# Event names (subset of ``docs/request-lifecycle.md`` §Event catalog, plus the
# ``account.*`` catalog in ``docs/account-management.md``).
REQUEST_CREATED = "request.created"
REQUEST_CANCELLED = "request.cancelled"
GRANT_ACTIVATED = "grant.activated"
GRANT_EXPIRED = "grant.expired"
ENROLLMENT_ISSUED = "account.enrollment_issued"


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


def emit(event: Event) -> None:
    """Deliver ``event`` to every subscriber, best-effort (failures are logged)."""
    for handler in list(_subscribers):
        try:
            handler(event)
        except Exception:
            _log.warning("event subscriber failed for %s", event.name, exc_info=True)
