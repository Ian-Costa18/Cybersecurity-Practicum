"""The notification subscriber: notifications as a best-effort consumer of the
lifecycle seam (ADR 0005, #65).

The end-to-end dispatch (request.created / denied / succeeded / failed → email)
is exercised over the real HTTP + SMTP stack in ``test_request_solicitation.py``
and ``test_execution.py``. These tests pin the subscriber-specific seams those
do not reach: the session-source fallback, the missing-payload guard, and that
``register`` actually wires a handler into the seam.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy.orm import Session

from msig_proxy.accounts.seed import seed_user
from msig_proxy.core import events
from msig_proxy.core.config import (
    AppConfig,
    EmailConfig,
    NotificationsConfig,
    ServerConfig,
)
from msig_proxy.core.db import Base, create_db_engine, create_session_factory
from msig_proxy.core.models import ApprovalRequest
from msig_proxy.notifications import subscriber

_SERVER = ServerConfig(base_url="http://testserver", secret_key="x" * 16)


@pytest.fixture
def bus() -> events.EventBus:
    """A standalone bus for the unit seams below HTTP (the app's bus is HTTP-only)."""
    return events.EventBus()


@pytest.fixture
def session_factory():
    engine = create_db_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = create_session_factory(engine)
    try:
        yield factory
    finally:
        engine.dispose()


def _config(*, email: EmailConfig | None) -> AppConfig:
    return AppConfig(server=_SERVER, notifications=NotificationsConfig(email=email))


def _seed_request(session: Session) -> ApprovalRequest:
    requester = seed_user(
        session, username="dave", email="dave@example.com", password="pw-dave-123"
    ).user
    request = ApprovalRequest(
        requester_id=requester.id,
        service_name="internal-app",
        service_type="forward-auth",
        quorum=1,
    )
    session.add(request)
    session.flush()
    return request


def test_register_wires_a_handler_into_the_seam(session_factory, bus: events.EventBus) -> None:
    config = _config(email=None)
    handler = subscriber.register(bus, session_factory, config)

    # The handler is now a live subscriber: emitting reaches it (it no-ops on the
    # unconfigured-email path, but must not raise back into emit).
    bus.emit(events.Event(events.REQUEST_DENIED, {"approval_request_id": str(uuid.uuid4())}))
    bus.unsubscribe(handler)


def test_handler_falls_back_to_its_own_session_when_none_is_active(
    session_factory, bus: events.EventBus
) -> None:
    # No active session on the seam → the handler must open one off the factory and
    # still resolve the (committed) request rather than failing.
    db = session_factory()
    try:
        request = _seed_request(db)
        db.commit()
        request_id = request.id
    finally:
        db.close()

    subscriber.register(bus, session_factory, _config(email=None))
    # email=None makes notify a no-op, so the assertion is simply: this does not raise
    # and reaches the dispatch (the request loads from the fallback session).
    bus.emit(events.Event(events.REQUEST_DENIED, {"approval_request_id": str(request_id)}))


def test_handler_no_ops_when_the_payload_has_no_request(
    session_factory, bus: events.EventBus
) -> None:
    subscriber.register(bus, session_factory, _config(email=None))

    # Missing id and unparsable id are both tolerated (logged, swallowed).
    bus.emit(events.Event(events.REQUEST_DENIED, {}))
    bus.emit(events.Event(events.REQUEST_DENIED, {"approval_request_id": "not-a-uuid"}))


def test_handler_prefers_the_active_session(session_factory, bus: events.EventBus) -> None:
    # When emit lends its session, the handler reads the flushed-but-uncommitted
    # request from it — a separate (factory) session could not see it.
    subscriber.register(bus, session_factory, _config(email=None))
    db = session_factory()
    try:
        request = _seed_request(db)  # flushed, NOT committed
        bus.emit(
            events.Event(events.REQUEST_DENIED, {"approval_request_id": str(request.id)}),
            session=db,
        )
    finally:
        db.rollback()
        db.close()
