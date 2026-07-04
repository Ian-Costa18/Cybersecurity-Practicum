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
from msig_proxy.audit.integrity import verify_audit_chain
from msig_proxy.auth.sessions import SESSION_COOKIE
from msig_proxy.core import crypto, events
from msig_proxy.core.config import AppConfig, ServerConfig
from msig_proxy.core.db import Base, create_db_engine, create_session_factory, session_scope
from msig_proxy.core.models import AuditLog, User
from tests.support import current_totp

_ADMIN_PW = "admin-pw-12345"
_AUDIT_KEY = crypto.derive_audit_key("test-secret-key-0123456789")


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
            audit_key=_AUDIT_KEY,
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
    audit.register(bus, session_factory, _AUDIT_KEY)
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
    audit.register(bus, session_factory, _AUDIT_KEY)
    bus.emit(events.GrantExpired(grant_id=uuid.uuid4()))

    db = session_factory()
    try:
        rows = db.scalars(select(AuditLog)).all()
        assert [r.event_name for r in rows] == [events.GrantExpired.name]  # committed independently
    finally:
        db.close()


# --- adversarial: the tamper-evident hash chain (HOST-2, #121) --------------


def _record_three(db) -> list[AuditLog]:
    """Append three chained rows and return them in append order."""
    for name in ("root@x", "alice@x", "bob@x"):
        audit.record_event(
            db, events.AccountDeactivated(user_id=uuid.uuid4(), email=name), audit_key=_AUDIT_KEY
        )
    return list(db.scalars(select(AuditLog).order_by(AuditLog.id)).all())


def test_chain_verifies_an_intact_trail(session_factory) -> None:
    db = session_factory()
    try:
        _record_three(db)
        assert verify_audit_chain(db, audit_key=_AUDIT_KEY).ok
    finally:
        db.close()


def test_chain_detects_a_modified_row(session_factory) -> None:
    # A HOST-2 attacker rewrites a stored row's payload (e.g. to scrub which account
    # they deactivated). The entry_hash no longer recomputes → the walk flags that row.
    db = session_factory()
    try:
        rows = _record_three(db)
        target = rows[1]
        target.payload = '{"email": "scrubbed", "user_id": "00000000-0000-0000-0000-000000000000"}'
        db.flush()

        verdict = verify_audit_chain(db, audit_key=_AUDIT_KEY)
        assert not verdict.ok
        assert verdict.broken_at == target.id
        assert "modified" in (verdict.reason or "")
    finally:
        db.close()


def test_chain_detects_a_deleted_row(session_factory) -> None:
    # Deleting a whole row (suppressing evidence) is exactly what per-record signing
    # could not catch. The chain does: the successor's prev_hash no longer matches its
    # (now-missing) predecessor's entry_hash.
    db = session_factory()
    try:
        rows = _record_three(db)
        db.delete(rows[1])
        db.flush()

        verdict = verify_audit_chain(db, audit_key=_AUDIT_KEY)
        assert not verdict.ok
        assert verdict.broken_at == rows[2].id
        assert "deleted or reordered" in (verdict.reason or "")
    finally:
        db.close()


def test_chain_forgery_needs_the_host_secret(session_factory) -> None:
    # The whole ④/② boundary: a HOST-2 attacker who rewrites a row AND recomputes its
    # entry_hash under a *guessed* key still fails, because the honest verifier keys on
    # the real HKDF-derived secret. Only HOST-1 (holds server.secret_key) can repair it.
    db = session_factory()
    try:
        rows = _record_three(db)
        forged_key = crypto.derive_audit_key("attacker-guessed-secret-000")
        target = rows[1]
        assert target.prev_hash is not None
        target.payload = '{"email": "attacker", "user_id": "00000000-0000-0000-0000-000000000000"}'
        target.entry_hash = crypto.audit_chain_hash(
            forged_key,
            prev_hash=target.prev_hash,
            event_name=target.event_name,
            payload=target.payload,
            recorded_at=target.recorded_at.isoformat(),
            actor_id=None,
        )
        db.flush()

        assert not verify_audit_chain(db, audit_key=_AUDIT_KEY).ok  # honest key still rejects
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
        # The row attributes the acting admin (root), not just the affected user (#121).
        root_id = session.scalars(select(User.id).where(User.username == "root")).one()
        row = session.scalars(
            select(AuditLog).where(AuditLog.event_name == events.AccountDeactivated.name)
        ).one()
        assert row.actor_id == root_id


async def test_wired_app_chains_audit_rows(client: httpx.AsyncClient, app: FastAPI) -> None:
    # End to end: the app derives the audit key from server.secret_key and chains every
    # row, so the wired trail verifies against the same key an offline auditor derives.
    from msig_proxy.audit.integrity import verify_audit_chain

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
            "totp": current_totp(app.state.session_factory, "root"),
        },
        follow_redirects=False,
    )
    admin_auth = {"Cookie": f"{SESSION_COOKIE}={login.cookies[SESSION_COOKIE]}"}
    for session in session_scope(app.state.session_factory):
        alice_id = str(session.scalars(select(User.id).where(User.username == "alice")).one())
    await client.post(f"/admin/users/{alice_id}/deactivate", headers=admin_auth)

    app_key = crypto.derive_audit_key(app.state.config.server.secret_key)
    for session in session_scope(app.state.session_factory):
        assert verify_audit_chain(session, audit_key=app_key).ok
