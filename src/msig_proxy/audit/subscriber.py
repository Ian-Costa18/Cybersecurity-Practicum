"""Audit as the **critical** subscriber to the lifecycle seam (#85, ADR 0005).

Where the notification system is *best-effort* (a dropped message is recoverable),
Audit is the *critical* consumer: it **records every event** the proxy emits, so a
gap in the trail is a detectable fault (``docs/architecture.md`` §"What each box is
responsible for", ``docs/request-lifecycle.md`` §"Consumers and reliability
classes"). This module is the single subscriber that turns every emitted
:class:`~msig_proxy.core.events.Event` into one :class:`~msig_proxy.core.models.AuditLog`
row — the **non-vote** half of the audit trail; the per-Vote Ed25519 signature in
:class:`~msig_proxy.core.models.Vote` is the tamper-evident half.

It records on the **emitter's own session** when one is lent
(:func:`msig_proxy.core.events.active_session`), so the audit row commits atomically
with the transition it records — the strongest reliability the MVP offers without a
transactional outbox. Only when an event is emitted outside any transaction does it
open (and commit) its own session. Per ``docs/architecture.md`` the MVP keeps
per-record evidence only — there is no hash chain across rows.
"""

from __future__ import annotations

import json
from collections.abc import Callable

from sqlalchemy.orm import Session, sessionmaker

from msig_proxy.core import events
from msig_proxy.core.models import AuditLog


def record_event(session: Session, event: events.Event) -> AuditLog:
    """Append one :class:`AuditLog` row for ``event`` and flush it onto ``session``.

    ``payload`` is serialized to JSON (``default=str`` covers any stray UUID/datetime;
    the events carry only identifiers, never secrets). The caller's session scope owns
    the commit when the emitter's session is borrowed.
    """
    entry = AuditLog(
        event_name=event.name,
        payload=json.dumps(event.payload, sort_keys=True, default=str),
    )
    session.add(entry)
    session.flush()
    return entry


def make_handler(session_factory: sessionmaker[Session]) -> Callable[[events.Event], None]:
    """Build the audit handler bound to a session factory.

    Records on the emitter's lent session when present (atomic with the transition);
    otherwise opens and commits its own session (events fired outside any request
    scope). A borrowed session is never closed or committed here — its owner does that.
    """

    def handler(event: events.Event) -> None:
        active = events.active_session()
        if active is not None:
            record_event(active, event)
            return
        session = session_factory()
        try:
            record_event(session, event)
            session.commit()
        finally:
            session.close()

    return handler


def register(session_factory: sessionmaker[Session]) -> Callable[[events.Event], None]:
    """Subscribe the audit handler to the event seam; return it (for tests)."""
    handler = make_handler(session_factory)
    events.subscribe(handler)
    return handler
