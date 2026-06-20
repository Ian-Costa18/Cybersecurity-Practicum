"""The forward-auth gate ``GET /auth`` — closed/open paths, identity headers,
lazy expiry (issue #12).

Real DB, real crypto, real HTTP. Unit-tests the lazy-expiry resolver below the
HTTP layer, then drives the gate over the ASGI surface, ending with the full
forward-auth happy path: login → request → approve to quorum → grant → ``/auth``
``200`` with identity headers.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import select
from sqlalchemy.orm import Session

from msig_proxy.accounts.seed import seed_user
from msig_proxy.approvals import votes
from msig_proxy.auth.sessions import SESSION_COOKIE
from msig_proxy.core import events, models
from msig_proxy.core.config import AppConfig, AuthConfig, HeadersConfig, ServerConfig, ServiceConfig
from msig_proxy.core.db import Base, create_db_engine, create_session_factory, session_scope
from msig_proxy.core.models import (
    APPROVED,
    FORWARD_AUTH,
    GRANT_ACTIVE,
    GRANT_EXPIRED,
    ApprovalRequest,
    ServiceGrant,
    User,
)
from msig_proxy.service_types import dispatch
from msig_proxy.service_types.forward_auth import resolve
from tests.support import totp_code

# TOTP secrets captured at seed time so _login can satisfy the second factor (#16).
_SECRETS: dict[str, str] = {}

_PASSWORD = {name: f"pw-{name}-123" for name in ("alice", "bob", "dave", "eve")}
_SERVICE = ServiceConfig(
    type="forward-auth", quorum=2, approvers=["alice", "bob"], endpoint="http://internal-app:8080"
)
# A second service that renames one identity header and suppresses another.
_CUSTOM_SERVICE = ServiceConfig(
    type="forward-auth",
    quorum=2,
    approvers=["alice", "bob"],
    endpoint="http://custom-app:8080",
    headers=HeadersConfig(remote_user="X-Auth-User", remote_email=False),
)


@pytest.fixture(autouse=True)
def _isolate_event_subscribers() -> Iterator[None]:
    yield
    events.clear_subscribers()


# --- unit: the lazy-expiry resolver ----------------------------------------


@pytest.fixture
def session() -> Iterator[Session]:
    engine = create_db_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    db = create_session_factory(engine)()
    try:
        yield db
    finally:
        db.close()
        engine.dispose()


def _make_grant(
    session: Session, *, user: User, service_name: str, expires_at: datetime
) -> ServiceGrant:
    """A persisted active grant for ``user`` + ``service_name`` with an explicit window."""
    request = ApprovalRequest(
        requester_id=user.id,
        service_name=service_name,
        service_type=FORWARD_AUTH,
        quorum=1,
        state=APPROVED,
    )
    session.add(request)
    session.flush()
    grant = ServiceGrant(
        approval_request_id=request.id,
        user_id=user.id,
        service_name=service_name,
        state=GRANT_ACTIVE,
        expires_at=expires_at,
    )
    session.add(grant)
    session.flush()
    return grant


def test_resolve_returns_an_active_unexpired_grant(session: Session) -> None:
    user = seed_user(session, username="dave", email="dave@example.com", password="pw").user
    grant = _make_grant(
        session,
        user=user,
        service_name="internal-app",
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )

    resolved = resolve.resolve_active_grant(session, user_id=user.id, service_name="internal-app")

    assert resolved is not None and resolved.id == grant.id


def test_resolve_lazily_expires_a_stale_grant_and_emits_event(session: Session) -> None:
    recorded: list[events.Event] = []
    events.subscribe(recorded.append)
    user = seed_user(session, username="dave", email="dave@example.com", password="pw").user
    grant = _make_grant(
        session,
        user=user,
        service_name="internal-app",
        expires_at=datetime.now(UTC) - timedelta(seconds=1),
    )

    resolved = resolve.resolve_active_grant(session, user_id=user.id, service_name="internal-app")

    assert resolved is None  # past its window → not valid
    stored = session.get(ServiceGrant, grant.id)
    assert stored is not None and stored.state == GRANT_EXPIRED  # flipped in place
    assert [e.name for e in recorded] == [events.GRANT_EXPIRED]
    assert recorded[0].payload == {"grant_id": str(grant.id)}


def test_resolve_returns_none_when_there_is_no_grant(session: Session) -> None:
    user = seed_user(session, username="dave", email="dave@example.com", password="pw").user

    assert (
        resolve.resolve_active_grant(session, user_id=user.id, service_name="internal-app") is None
    )


def test_resolve_ignores_a_grant_for_a_different_service(session: Session) -> None:
    user = seed_user(session, username="dave", email="dave@example.com", password="pw").user
    _make_grant(
        session,
        user=user,
        service_name="other-app",
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )

    assert (
        resolve.resolve_active_grant(session, user_id=user.id, service_name="internal-app") is None
    )


# --- HTTP: the gate over the ASGI surface ----------------------------------


@pytest.fixture
def app_config() -> AppConfig:
    return AppConfig(
        server=ServerConfig(
            host="127.0.0.1",
            port=8080,
            base_url="http://testserver",
            secret_key="test-secret-key-0123456789",
        ),
        auth=AuthConfig(session_expiry_hours=8),
        services={"internal-app": _SERVICE, "custom-app": _CUSTOM_SERVICE},
    )


@pytest.fixture
def seeded(app: FastAPI) -> None:
    for session in session_scope(app.state.session_factory):
        for name in _PASSWORD:
            seeded_user = seed_user(
                session, username=name, email=f"{name}@example.com", password=_PASSWORD[name]
            )
            _SECRETS[name] = seeded_user.totp_secret


async def _login(client: httpx.AsyncClient, name: str, **extra: str) -> httpx.Response:
    return await client.post(
        "/login",
        data={
            "username": name,
            "password": _PASSWORD[name],
            "totp": totp_code(_SECRETS[name]),
            **extra,
        },
        follow_redirects=False,
    )


def _auth(response: httpx.Response) -> dict[str, str]:
    return {"Cookie": f"{SESSION_COOKIE}={response.cookies[SESSION_COOKIE]}"}


def _grant_for(app: FastAPI, username: str, service_name: str, *, expires_at: datetime) -> None:
    """Persist an active grant for the named user + service (out-of-band setup)."""
    for session in session_scope(app.state.session_factory):
        user = session.scalars(select(User).where(User.username == username)).one()
        _make_grant(session, user=user, service_name=service_name, expires_at=expires_at)


async def test_auth_without_a_session_returns_401_with_login_location(
    client: httpx.AsyncClient, seeded: None
) -> None:
    response = await client.get(
        "/auth",
        params={"service": "internal-app"},
        headers={
            "X-Forwarded-Host": "internal-app.example.com",
            "X-Forwarded-Uri": "/dashboard",
            "X-Forwarded-Proto": "https",
        },
    )

    assert response.status_code == 401
    location = response.headers["location"]
    assert location.startswith("/login?")
    assert "service=internal-app" in location
    assert "return_to=https%3A%2F%2Finternal-app.example.com%2Fdashboard" in location


async def test_auth_with_a_session_but_no_grant_returns_401(
    client: httpx.AsyncClient, seeded: None
) -> None:
    login = await _login(client, "dave")

    response = await client.get("/auth", params={"service": "internal-app"}, headers=_auth(login))

    assert response.status_code == 401
    assert response.headers["location"].startswith("/login?")


async def test_auth_with_a_valid_grant_returns_200_and_identity_headers(
    client: httpx.AsyncClient, app: FastAPI, seeded: None
) -> None:
    login = await _login(client, "dave")
    _grant_for(app, "dave", "internal-app", expires_at=datetime.now(UTC) + timedelta(hours=1))

    response = await client.get("/auth", params={"service": "internal-app"}, headers=_auth(login))

    assert response.status_code == 200
    assert response.headers["Remote-User"] == "dave"
    assert response.headers["Remote-Name"] == "dave"
    assert response.headers["Remote-Email"] == "dave@example.com"
    assert "Remote-Groups" not in response.headers  # no groups field in the MVP model
    # The mediated-access guarantee: the gate hands the reverse proxy identity only,
    # never a backend/shared credential, and carries no body to the Requester.
    assert response.content == b""
    assert "internal-app:8080" not in response.text  # the backend URL is never echoed


async def test_auth_honors_per_service_header_renames_and_suppression(
    client: httpx.AsyncClient, app: FastAPI, seeded: None
) -> None:
    login = await _login(client, "dave")
    _grant_for(app, "dave", "custom-app", expires_at=datetime.now(UTC) + timedelta(hours=1))

    response = await client.get("/auth", params={"service": "custom-app"}, headers=_auth(login))

    assert response.status_code == 200
    assert response.headers["X-Auth-User"] == "dave"  # renamed
    assert "Remote-User" not in response.headers  # the default name is gone
    assert "Remote-Email" not in response.headers  # suppressed (remote_email=False)


async def test_auth_for_an_unknown_service_returns_401(
    client: httpx.AsyncClient, seeded: None
) -> None:
    login = await _login(client, "dave")

    response = await client.get("/auth", params={"service": "nope"}, headers=_auth(login))

    assert response.status_code == 401


async def test_auth_lazily_expires_a_stale_grant_at_the_gate(
    client: httpx.AsyncClient, app: FastAPI, seeded: None
) -> None:
    recorded: list[events.Event] = []
    events.subscribe(recorded.append)
    login = await _login(client, "dave")
    _grant_for(app, "dave", "internal-app", expires_at=datetime.now(UTC) - timedelta(seconds=1))

    response = await client.get("/auth", params={"service": "internal-app"}, headers=_auth(login))

    assert response.status_code == 401  # re-gated through the closed path
    assert [e.name for e in recorded] == [events.GRANT_EXPIRED]
    # The flip persisted: a second hit finds it already expired (no second event).
    again = await client.get("/auth", params={"service": "internal-app"}, headers=_auth(login))
    assert again.status_code == 401
    assert [e.name for e in recorded] == [events.GRANT_EXPIRED]


async def test_full_forward_auth_happy_path_login_to_authorized(
    client: httpx.AsyncClient, app: FastAPI, seeded: None
) -> None:
    # Login at the forward-auth service creates the pending request and drops the
    # Requester in the waiting room.
    login = await _login(client, "dave", service="internal-app")
    assert login.status_code == 303
    request_id = uuid.UUID(login.headers["location"].rsplit("/", 1)[-1])

    # Approve to quorum and run the handoff (the vote/approve surfaces are covered
    # by test_approve.py / test_service_grant.py; here we just need a real grant).
    for session in session_scope(app.state.session_factory):
        request = session.get(ApprovalRequest, request_id)
        assert request is not None
        for name in ("alice", "bob"):
            approver = session.scalars(select(User).where(User.username == name)).one()
            assert approver.totp_secret is not None
            votes.cast_vote(
                session,
                request=request,
                approver=approver,
                password=_PASSWORD[name],
                totp=totp_code(approver.totp_secret),
                totp_valid_window=1,
                decision=models.APPROVE,
            )
        assert request.state == APPROVED
        dispatch.finalize(session, app.state.config, request)

    # The reverse proxy re-calls /auth; the grant is now found.
    response = await client.get("/auth", params={"service": "internal-app"}, headers=_auth(login))

    assert response.status_code == 200
    assert response.headers["Remote-User"] == "dave"
    assert response.headers["Remote-Email"] == "dave@example.com"
