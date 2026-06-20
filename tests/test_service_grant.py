"""The forward-auth handoff: a Service Grant is issued on quorum (issue #11).

Real DB, real crypto. Drives a forward-auth request to ``approved`` through the
vote core, then exercises :func:`msig_proxy.executor.finalize` /
:func:`issue_service_grant` below the HTTP layer.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from msig_proxy import events, executor, intake, models, votes
from msig_proxy.config import (
    AppConfig,
    AuthConfig,
    ServerConfig,
    ServiceConfig,
)
from msig_proxy.db import Base, create_db_engine, create_session_factory
from msig_proxy.models import ApprovalRequest, ServiceGrant, User
from msig_proxy.seed import seed_user
from tests.support import totp_code

_PASSWORD = {name: f"pw-{name}-123" for name in ("alice", "bob", "dave")}
_SERVICE = ServiceConfig(
    type="forward-auth",
    quorum=2,
    approvers=["alice", "bob"],
    backend="http://internal-app:8080",
    grant_expiry_hours=8,
)
_CONFIG = AppConfig(
    server=ServerConfig(
        host="127.0.0.1", port=8080, base_url="http://testserver", secret_key="secret-0123456789"
    ),
    auth=AuthConfig(session_expiry_hours=8),
    services={"internal-app": _SERVICE},
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


@pytest.fixture(autouse=True)
def _isolate_event_subscribers() -> Iterator[None]:
    yield
    events.clear_subscribers()


def _approved_forward_auth_request(session: Session) -> ApprovalRequest:
    """Seed approvers + requester, create a forward-auth request, vote it to quorum."""
    for name in ("alice", "bob"):
        seed_user(session, username=name, email=f"{name}@example.com", password=_PASSWORD[name])
    requester = seed_user(
        session, username="dave", email="dave@example.com", password=_PASSWORD["dave"]
    ).user
    request, _ = intake.request_forward_auth_access(
        session, requester=requester, service_name="internal-app", service=_SERVICE
    )
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
    assert request.state == models.APPROVED
    return request


def test_grant_issued_on_approval_scoped_to_requester_and_service(session: Session) -> None:
    request = _approved_forward_auth_request(session)

    executor.finalize(session, _CONFIG, request)

    grant = session.scalars(select(ServiceGrant)).one()
    assert grant.state == models.GRANT_ACTIVE
    assert grant.user_id == request.requester_id  # scoped to the Requester
    assert grant.service_name == "internal-app"  # ...and the Service
    assert grant.expires_at > grant.created_at  # a positive window from grant_expiry_hours


def test_grant_and_request_are_bidirectionally_linked(session: Session) -> None:
    request = _approved_forward_auth_request(session)

    grant = executor.issue_service_grant(session, _CONFIG, request)

    assert grant.approval_request_id == request.id  # grant → request
    assert request.service_grant_id == grant.id  # request → grant


def test_a_redelivered_approval_does_not_mint_a_second_grant(session: Session) -> None:
    request = _approved_forward_auth_request(session)

    first = executor.issue_service_grant(session, _CONFIG, request)
    second = executor.issue_service_grant(session, _CONFIG, request)  # redelivery

    assert first.id == second.id
    assert session.scalars(select(ServiceGrant)).all() == [first]  # exactly one grant


def test_handoff_emits_grant_activated(session: Session) -> None:
    recorded: list[events.Event] = []
    events.subscribe(recorded.append)
    request = _approved_forward_auth_request(session)

    executor.issue_service_grant(session, _CONFIG, request)

    assert [e.name for e in recorded] == [events.GRANT_ACTIVATED]
    assert recorded[0].payload["approval_request_id"] == str(request.id)
