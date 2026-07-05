"""Audit as the **critical** subscriber to the lifecycle seam (#85, ADR 0005).

Where the notification system is *best-effort* (a dropped message is recoverable),
Audit is the *critical* consumer: it **records every event** the proxy emits, so a
gap in the trail is a detectable fault (``docs/architecture.md`` §"What each box is
responsible for", ``docs/request-lifecycle.md`` §"Consumers and reliability
classes"). This module is the single subscriber that turns every emitted
:class:`~msig_proxy.core.events.Event` into one :class:`~msig_proxy.core.models.AuditLog`
row — the **non-vote** half of the audit trail; the per-Vote Ed25519 signature in
:class:`~msig_proxy.core.models.Vote` is the tamper-evident half.

Since #121 each row is **chained**: the writer commits it to its predecessor with an
HMAC-SHA-256 link keyed by an HKDF-derived audit key off ``server.secret_key``
(:func:`msig_proxy.core.crypto.audit_chain_hash`), so whole-row deletion/reordering
is detectable and not just per-record modification — against a HOST-2 database-write
attacker who does not hold the host secret. The chain is verified offline by
:func:`msig_proxy.audit.integrity.verify_audit_chain`.

It records on the **emitter's own session** when a transition is in flight, so the
audit row commits atomically with the transition it records — the strongest
reliability the MVP offers without a transactional outbox. Only when an event is
emitted outside any session scope does it open (and commit) its own session. Both
cases are owned by :func:`msig_proxy.core.events.deliver_with_session` (``commit=True``,
the *critical* class); this module supplies only the recording body.
"""

from __future__ import annotations

import dataclasses
import json
from collections.abc import Callable
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from msig_proxy.core import crypto, events
from msig_proxy.core.models import AuditLog
from msig_proxy.core.time import aware


def _recorded_iso(recorded_at: datetime) -> str:
    """The exact timestamp string committed to the chain — UTC-coerced ISO-8601.

    SQLite returns tz-naive datetimes, so both the write and the offline verify path
    coerce with :func:`msig_proxy.core.time.aware` before formatting, guaranteeing the
    chain hash re-derives byte-for-byte across the round trip.
    """
    return aware(recorded_at).isoformat()


def _actor_str(event: events.Event) -> str | None:
    """The acting principal's id as a string, if the event names one (#121).

    Admin-action events carry an ``actor_id`` (the admin who acted) distinct from the
    subject; system-emitted lifecycle events have none. Read generically so a new
    actor-bearing event is chained without touching this recorder.
    """
    actor_id = getattr(event, "actor_id", None)
    return str(actor_id) if actor_id is not None else None


def record_event(session: Session, event: events.Event, *, audit_key: bytes) -> AuditLog:
    """Append one chained :class:`AuditLog` row for ``event`` and flush it onto ``session``.

    The typed event (ADR 0014) serializes generically — ``event.name`` is its stable
    catalog label and :func:`dataclasses.asdict` dumps its typed fields (``default=str``
    covers UUID/datetime; events carry only identifiers, never secrets). The row is
    linked to the current tail of the chain (``prev_hash`` = the last row's
    ``entry_hash``, or the genesis anchor for the first row) and its own
    ``entry_hash`` is computed over that link plus its content (#121). The caller's
    session scope owns the commit when the emitter's session is borrowed.
    """
    prev_hash = session.scalars(
        select(AuditLog.entry_hash).order_by(AuditLog.id.desc()).limit(1)
    ).first()
    if prev_hash is None:
        prev_hash = crypto.AUDIT_GENESIS

    payload = json.dumps(dataclasses.asdict(event), sort_keys=True, default=str)
    actor_id = _actor_str(event)
    recorded_at = datetime.now(UTC)
    entry_hash = crypto.audit_chain_hash(
        audit_key,
        prev_hash=prev_hash,
        event_name=event.name,
        payload=payload,
        recorded_at=_recorded_iso(recorded_at),
        actor_id=actor_id,
    )

    entry = AuditLog(
        event_name=event.name,
        payload=payload,
        actor_id=getattr(event, "actor_id", None),
        recorded_at=recorded_at,
        prev_hash=prev_hash,
        entry_hash=entry_hash,
    )
    session.add(entry)
    session.flush()
    return entry


def make_handler(
    session_factory: sessionmaker[Session], audit_key: bytes
) -> Callable[[events.Event], None]:
    """Build the audit handler bound to a session factory and the audit-chain key.

    Records on the emitter's bound session when a transition is in flight (atomic with
    it); otherwise opens and commits its own session (events fired outside any session
    scope). The borrow-vs-own choice — and ``commit=True``, since audit is the critical
    consumer whose row must be durable even outside a transition — is owned by
    :func:`events.deliver_with_session`; this handler supplies only the recording body.
    """

    def handler(event: events.Event) -> None:
        events.deliver_with_session(
            lambda session: record_event(session, event, audit_key=audit_key),
            session_factory=session_factory,
            commit=True,
        )

    return handler


def register(
    bus: events.EventBus, session_factory: sessionmaker[Session], audit_key: bytes
) -> Callable[[events.Event], None]:
    """Subscribe the audit handler to the app's event bus; return it (for tests)."""
    handler = make_handler(session_factory, audit_key)
    bus.subscribe(handler)
    return handler
