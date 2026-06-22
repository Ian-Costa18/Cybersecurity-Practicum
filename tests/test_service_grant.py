"""The forward-auth handoff: a Service Grant is issued on quorum (issue #11).

Real DB, real crypto. Drives a forward-auth request to ``approved`` through the
vote core, then exercises :func:`msig_proxy.service_types.dispatch.finalize` /
:func:`msig_proxy.issue_service_grant` below the HTTP layer.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from msig_proxy.accounts.seed import seed_user
from msig_proxy.approvals import votes
from msig_proxy.core import events, models
from msig_proxy.core.config import (
    AppConfig,
    AuthConfig,
    EmailConfig,
    NotificationsConfig,
    ServerConfig,
    ServiceConfig,
)
from msig_proxy.core.db import Base, create_db_engine, create_session_factory
from msig_proxy.core.models import ApprovalRequest, ServiceGrant, User
from msig_proxy.notifications import notifier, subscriber
from msig_proxy.service_types import dispatch
from msig_proxy.service_types.forward_auth import intake
from msig_proxy.service_types.forward_auth.grant import issue_service_grant
from tests.support import totp_code

_PASSWORD = {name: f"pw-{name}-123" for name in ("alice", "bob", "dave")}
_SERVICE = ServiceConfig(
    type="forward-auth",
    quorum=2,
    approvers=["alice", "bob"],
    endpoint="http://internal-app:8080",
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

    dispatch.finalize(session, _CONFIG, request)

    grant = session.scalars(select(ServiceGrant)).one()
    assert grant.state == models.GRANT_ACTIVE
    assert grant.user_id == request.requester_id  # scoped to the Requester
    assert grant.service_name == "internal-app"  # ...and the Service
    assert grant.expires_at > grant.created_at  # a positive window from grant_expiry_hours


def test_grant_and_request_are_bidirectionally_linked(session: Session) -> None:
    request = _approved_forward_auth_request(session)

    grant = issue_service_grant(session, _CONFIG, request)

    assert grant.approval_request_id == request.id  # grant → request
    assert request.service_grant_id == grant.id  # request → grant


def test_a_redelivered_approval_does_not_mint_a_second_grant(session: Session) -> None:
    request = _approved_forward_auth_request(session)

    first = issue_service_grant(session, _CONFIG, request)
    second = issue_service_grant(session, _CONFIG, request)  # redelivery

    assert first.id == second.id
    assert session.scalars(select(ServiceGrant)).all() == [first]  # exactly one grant


def test_handoff_emits_grant_activated(session: Session) -> None:
    recorded: list[events.Event] = []
    events.subscribe(recorded.append)
    request = _approved_forward_auth_request(session)

    issue_service_grant(session, _CONFIG, request)

    assert [e.name for e in recorded] == [events.GRANT_ACTIVATED]
    assert recorded[0].payload["approval_request_id"] == str(request.id)


def test_grant_activated_notifies_requester_and_endorsers(
    session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The notification subscriber turns grant.activated into the access-granted
    email — Requester + Endorsing Approvers, the same audience as the other terminal
    outcomes (docs/notification-system.md). Only the SMTP send boundary is captured;
    recipient resolution runs against the real persisted votes."""
    sent: list[tuple[set[str], str]] = []

    def _capture(config: EmailConfig, *, to: list[str], subject: str, body: str) -> bool:
        sent.append((set(to), subject))
        return True

    monkeypatch.setattr(notifier, "send_email", _capture)

    config = AppConfig(
        server=_CONFIG.server,
        auth=_CONFIG.auth,
        services=_CONFIG.services,
        notifications=NotificationsConfig(
            email=EmailConfig(
                enabled=True, smtp_host="localhost", from_address="proxy@example.com", tls=False
            )
        ),
    )
    # The subscriber reads recipients off the emitter's lent session; the factory is
    # only the out-of-request fallback, so a throwaway one is fine here.
    factory = create_session_factory(create_db_engine("sqlite+pysqlite:///:memory:"))
    subscriber.register(factory, config)

    request = _approved_forward_auth_request(session)
    issue_service_grant(session, config, request)

    assert len(sent) == 1
    recipients, subject = sent[0]
    assert "Access granted" in subject
    # dave (requester) + alice, bob (endorsing approvers); de-duplicated.
    assert recipients == {"dave@example.com", "alice@example.com", "bob@example.com"}
