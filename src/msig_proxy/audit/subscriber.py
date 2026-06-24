"""Audit as the **critical** subscriber to the lifecycle seam (#85, ADR 0005).

Where the notification system is *best-effort* (a dropped message is recoverable),
Audit is the *critical* consumer: it **records every event** the proxy emits, so a
gap in the trail is a detectable fault (``docs/architecture.md`` §"What each box is
responsible for", ``docs/request-lifecycle.md`` §"Consumers and reliability
classes"). This module is the single subscriber that turns every emitted
:class:`~msig_proxy.core.events.Event` into one :class:`~msig_proxy.core.models.AuditLog`
row — the **non-vote** half of the audit trail; the per-Vote Ed25519 signature in
:class:`~msig_proxy.core.models.Vote` is the tamper-evident half.

It records on the **emitter's own session** when a transition is in flight, so the
audit row commits atomically with the transition it records — the strongest
reliability the MVP offers without a transactional outbox. Only when an event is
emitted outside any session scope does it open (and commit) its own session. Both
cases are owned by :func:`msig_proxy.core.events.deliver_with_session` (``commit=True``,
the *critical* class); this module supplies only the recording body. Per
``docs/architecture.md`` the MVP keeps per-record evidence only — there is no hash
chain across rows.
"""

from __future__ import annotations

import dataclasses
import json
from collections.abc import Callable

from sqlalchemy.orm import Session, sessionmaker

from msig_proxy.core import events
from msig_proxy.core.models import AuditLog


def record_event(session: Session, event: events.Event) -> AuditLog:
    """Append one :class:`AuditLog` row for ``event`` and flush it onto ``session``.

    The typed event (ADR 0014) serializes generically — ``event.name`` is its stable
    catalog label and :func:`dataclasses.asdict` dumps its typed fields (``default=str``
    covers UUID/datetime; events carry only identifiers, never secrets). The caller's
    session scope owns the commit when the emitter's session is borrowed.
    """
    entry = AuditLog(
        event_name=event.name,
        payload=json.dumps(dataclasses.asdict(event), sort_keys=True, default=str),
    )
    session.add(entry)
    session.flush()
    return entry


def make_handler(session_factory: sessionmaker[Session]) -> Callable[[events.Event], None]:
    """Build the audit handler bound to a session factory.

    Records on the emitter's bound session when a transition is in flight (atomic with
    it); otherwise opens and commits its own session (events fired outside any session
    scope). The borrow-vs-own choice — and ``commit=True``, since audit is the critical
    consumer whose row must be durable even outside a transition — is owned by
    :func:`events.deliver_with_session`; this handler supplies only the recording body.
    """

    def handler(event: events.Event) -> None:
        events.deliver_with_session(
            lambda session: record_event(session, event),
            session_factory=session_factory,
            commit=True,
        )

    return handler


def register(
    bus: events.EventBus, session_factory: sessionmaker[Session]
) -> Callable[[events.Event], None]:
    """Subscribe the audit handler to the app's event bus; return it (for tests)."""
    handler = make_handler(session_factory)
    bus.subscribe(handler)
    return handler
