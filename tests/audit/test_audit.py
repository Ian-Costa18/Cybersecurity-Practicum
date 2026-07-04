"""The Audit consumer: records every emitted event (#85).

Audit is the *critical* subscriber (``docs/architecture.md``): one ``audit_log`` row
per emitted event, written on the emitter's session so it commits atomically with the
transition it records. These tests pin the unit seams plus the end-to-end "an admin
action / an approval handoff lands an audit row" path over the real HTTP stack.
"""

from __future__ import annotations

import json
import uuid

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import select

from msig_proxy.accounts.seed import seed_user
from msig_proxy.audit import subscriber as audit
from msig_proxy.auth.sessions import SESSION_COOKIE
from msig_proxy.core import events
from msig_proxy.core.config import AppConfig, ServerConfig
from msig_proxy.core.db import Base, create_db_engine, create_session_factory, session_scope
from msig_proxy.core.models import AuditLog, User
from tests.support import current_totp

_ADMIN_PW = "admin-pw-12345"


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


# --- unit: the recorder + the session-source behavior -----------------------


def test_record_event_appends_a_row(session_factory) -> None:
    db = session_factory()
    try:
        rid, requester = uuid.uuid4(), uuid.uuid4()
        entry = audit.record_event(
            db,
            events.RequestCreated(
                approval_request_id=rid, service_name="svc", requester_id=requester
            ),
        )
        assert entry.event_name == "request.created"
        # asdict dumps the typed fields (the ClassVar name is not a field); ids stringify.
        assert json.loads(entry.payload) == {
            "approval_request_id": str(rid),
            "service_name": "svc",
            "requester_id": str(requester),
        }
    finally:
        db.close()


def test_handler_records_on_the_active_session(session_factory, bus: events.EventBus) -> None:
    # When a transition is bound as the active event session, the audit row is written
    # there — committing atomically with the transition the event records.
    audit.register(bus, session_factory)
    db = session_factory()
    try:
        with events.session_bound(db):
            bus.emit(
                events.RequestApproved(
                    approval_request_id=uuid.uuid4(),
                    service_name="svc",
                    requester_id=uuid.uuid4(),
                )
            )
        rows = db.scalars(select(AuditLog)).all()
        assert [r.event_name for r in rows] == [events.RequestApproved.name]
    finally:
        db.rollback()
        db.close()


def test_handler_falls_back_to_its_own_session_and_commits(
    session_factory, bus: events.EventBus
) -> None:
    # No active session on the seam → the handler opens its own and commits the row.
    audit.register(bus, session_factory)
    bus.emit(events.GrantExpired(grant_id=uuid.uuid4()))

    db = session_factory()
    try:
        rows = db.scalars(select(AuditLog)).all()
        assert [r.event_name for r in rows] == [events.GrantExpired.name]  # committed independently
    finally:
        db.close()


# --- end to end: the wired app records real events --------------------------


@pytest.fixture
def app_config() -> AppConfig:
    return AppConfig(
        server=ServerConfig(
            host="127.0.0.1",
            port=8080,
            base_url="http://testserver",
            secret_key="test-secret-key-0123456789",
        )
    )


async def test_admin_action_lands_an_audit_row(client: httpx.AsyncClient, app: FastAPI) -> None:
    # The app registers the audit subscriber in create_app, so a real admin action
    # (deactivate) records its account.* event with no test-side wiring.
    for session in session_scope(app.state.session_factory):
        seed_user(
            session, username="root", email="root@example.com", password=_ADMIN_PW, is_admin=True
        )
        seed_user(session, username="alice", email="alice@example.com", password="alice-pw-12345")

    login = await client.post(
        "/login",
        data={
            "username": "root",
            "password": _ADMIN_PW,
            "totp": current_totp(app.state.session_factory, "root", _ADMIN_PW),
        },
        follow_redirects=False,
    )
    admin_auth = {"Cookie": f"{SESSION_COOKIE}={login.cookies[SESSION_COOKIE]}"}
    for session in session_scope(app.state.session_factory):
        alice_id = str(session.scalars(select(User.id).where(User.username == "alice")).one())

    resp = await client.post(f"/admin/users/{alice_id}/deactivate", headers=admin_auth)
    assert resp.status_code == 200

    for session in session_scope(app.state.session_factory):
        names = set(session.scalars(select(AuditLog.event_name)).all())
        assert events.AccountDeactivated.name in names  # the deactivation was audited
