"""Forward-auth request intake + the live waiting room (issue #10).

Real DB, real HTTP. Covers: the no-artifact forward-auth Approval Request and its
snapshot, the login → request → waiting-room flow, `request.created` emission, the
Requester-scoped waiting room, and the SSE quorum projection reflecting votes.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import select
from sqlalchemy.orm import Session

from msig_proxy import events, intake, models, votes
from msig_proxy.config import AppConfig, ServerConfig, ServiceConfig
from msig_proxy.db import Base, create_db_engine, create_session_factory, session_scope
from msig_proxy.models import ApprovalRequest, ApprovalRequestApprover, User
from msig_proxy.pending import quorum_event_stream
from msig_proxy.seed import seed_user
from msig_proxy.sessions import SESSION_COOKIE

_PASSWORD = {name: f"pw-{name}-123" for name in ("alice", "bob", "dave", "eve")}
_SERVICE = ServiceConfig(
    type="forward-auth", quorum=2, approvers=["alice", "bob"], backend="http://internal-app:8080"
)


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


def _seed_cast(session: Session) -> User:
    for name in ("alice", "bob"):
        seed_user(session, username=name, email=f"{name}@example.com", password=_PASSWORD[name])
    return seed_user(
        session, username="dave", email="dave@example.com", password=_PASSWORD["dave"]
    ).user


# --- intake: forward-auth request (no artifact) ----------------------------


def test_forward_auth_request_is_created_with_no_publish_fields(session: Session) -> None:
    requester = _seed_cast(session)

    request, created = intake.request_forward_auth_access(
        session, requester=requester, service_name="internal-app", service=_SERVICE
    )

    assert created is True
    assert request.service_type == models.FORWARD_AUTH
    assert request.state == models.PENDING
    assert request.action is None  # no action
    assert request.artifact_sha256 is None  # no hash binding
    assert request.package_name is None and request.package_version is None

    snapshot = set(
        session.scalars(
            select(ApprovalRequestApprover.user_id).where(
                ApprovalRequestApprover.approval_request_id == request.id
            )
        )
    )
    approver_ids = {
        session.scalars(select(User.id).where(User.username == n)).one() for n in ("alice", "bob")
    }
    assert snapshot == approver_ids  # approver set snapshotted at creation (ADR 0008)


def test_a_returning_requester_resumes_the_same_pending_request(session: Session) -> None:
    requester = _seed_cast(session)

    first, created_1 = intake.request_forward_auth_access(
        session, requester=requester, service_name="internal-app", service=_SERVICE
    )
    second, created_2 = intake.request_forward_auth_access(
        session, requester=requester, service_name="internal-app", service=_SERVICE
    )

    assert created_1 is True and created_2 is False
    assert first.id == second.id  # idempotent per (User, Service) while pending


# --- the live SSE quorum projection ----------------------------------------


def test_quorum_stream_reflects_votes_as_they_land(tmp_path: Path) -> None:
    # File DB so the generator's per-poll sessions share state with the voting session.
    url = f"sqlite+pysqlite:///{(tmp_path / 'fa.db').as_posix()}"
    engine = create_db_engine(url)
    Base.metadata.create_all(engine)
    factory = create_session_factory(engine)

    with factory() as setup:
        requester = _seed_cast(setup)
        request, _ = intake.request_forward_auth_access(
            setup, requester=requester, service_name="internal-app", service=_SERVICE
        )
        request_id = request.id
        setup.commit()

    def _vote(name: str, decision: str) -> None:
        with factory() as voting:
            approver = voting.scalars(select(User).where(User.username == name)).one()
            request = voting.get(ApprovalRequest, request_id)
            assert request is not None
            votes.cast_vote(
                voting,
                request=request,
                approver=approver,
                password=_PASSWORD[name],
                decision=decision,
            )
            voting.commit()

    stream = quorum_event_stream(factory, request_id, poll_interval=0.01)

    first = next(stream)
    assert '"count": 0' in first and "approval" in first

    _vote("alice", models.APPROVE)
    second = next(stream)
    assert '"count": 1' in second and "approval" in second

    _vote("bob", models.APPROVE)  # reaches quorum 2
    third = next(stream)
    assert "quorum_reached" in third and '"count": 2' in third

    with pytest.raises(StopIteration):  # terminal state closes the stream
        next(stream)

    engine.dispose()


# --- HTTP: login → request → waiting room ----------------------------------


@pytest.fixture
def app_config() -> AppConfig:
    return AppConfig(
        server=ServerConfig(
            host="127.0.0.1",
            port=8080,
            base_url="http://testserver",
            secret_key="test-secret-key-0123456789",
        ),
        services={"internal-app": _SERVICE},
    )


@pytest.fixture
def seeded(app: FastAPI) -> None:
    for session in session_scope(app.state.session_factory):
        for name in _PASSWORD:
            seed_user(session, username=name, email=f"{name}@example.com", password=_PASSWORD[name])


@pytest.fixture(autouse=True)
def _isolate_event_subscribers() -> Iterator[None]:
    yield
    events.clear_subscribers()


def _auth(response: httpx.Response) -> dict[str, str]:
    return {"Cookie": f"{SESSION_COOKIE}={response.cookies[SESSION_COOKIE]}"}


async def _login(client: httpx.AsyncClient, name: str, **extra: str) -> httpx.Response:
    return await client.post(
        "/login",
        data={"username": name, "password": _PASSWORD[name], **extra},
        follow_redirects=False,
    )


async def test_login_to_a_forward_auth_service_creates_request_and_redirects(
    client: httpx.AsyncClient, app: FastAPI, seeded: None
) -> None:
    recorded: list[events.Event] = []
    events.subscribe(recorded.append)

    response = await _login(client, "dave", service="internal-app")

    assert response.status_code == 303
    assert response.headers["location"].startswith("/pending/")
    assert response.cookies.get(SESSION_COOKIE)  # a Proxy Session was issued
    assert [e.name for e in recorded] == [events.REQUEST_CREATED]  # request.created emitted

    for session in session_scope(app.state.session_factory):
        request = session.scalars(select(ApprovalRequest)).one()
        assert request.service_type == models.FORWARD_AUTH
        assert request.artifact_sha256 is None


async def test_waiting_room_shows_live_quorum_status_to_its_requester(
    client: httpx.AsyncClient, app: FastAPI, seeded: None
) -> None:
    login = await _login(client, "dave", service="internal-app")
    pending_url = login.headers["location"]

    page = await client.get(pending_url, headers=_auth(login))

    assert page.status_code == 200
    assert "0 of 2 approvals received" in page.text
    assert f"{pending_url}/stream" in page.text


async def test_waiting_room_is_scoped_to_the_requester(
    client: httpx.AsyncClient, app: FastAPI, seeded: None
) -> None:
    dave_login = await _login(client, "dave", service="internal-app")
    pending_url = dave_login.headers["location"]

    # A different authenticated User cannot view someone else's waiting room.
    eve_login = await client.post("/login", data={"username": "eve", "password": _PASSWORD["eve"]})
    forbidden = await client.get(pending_url, headers=_auth(eve_login))
    assert forbidden.status_code == 403

    # And an unauthenticated viewer is rejected.
    assert (await client.get(pending_url)).status_code == 401


async def test_stream_emits_a_terminal_event_for_a_closed_request(
    client: httpx.AsyncClient, app: FastAPI, seeded: None
) -> None:
    login = await _login(client, "dave", service="internal-app")
    pending_url = login.headers["location"]
    request_id = uuid.UUID(pending_url.rsplit("/", 1)[-1])

    # Drive it to denied so the stream is finite (one event, then it closes).
    for session in session_scope(app.state.session_factory):
        request = session.get(ApprovalRequest, request_id)
        assert request is not None
        approver = session.scalars(select(User).where(User.username == "alice")).one()
        votes.cast_vote(
            session,
            request=request,
            approver=approver,
            password=_PASSWORD["alice"],
            decision=models.DENY,
        )

    stream = await client.get(f"{pending_url}/stream", headers=_auth(login))
    assert stream.status_code == 200
    assert "text/event-stream" in stream.headers["content-type"]
    assert "denied" in stream.text
