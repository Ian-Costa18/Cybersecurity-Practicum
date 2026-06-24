"""The forward-auth handoff: a Service Grant is issued on quorum (issue #11).

Real DB, real crypto. Drives a forward-auth request to ``approved`` through the
vote core, then exercises :func:`msig_proxy.service_types.dispatch.finalize` /
:func:`msig_proxy.issue_service_grant` below the HTTP layer.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

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
from msig_proxy.core.models import ApprovalRequest, ProxySession, ServiceGrant, User
from msig_proxy.core.time import aware
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


@pytest.fixture
def bus() -> events.EventBus:
    """A standalone bus for these below-HTTP handoff tests; the app's wired bus is
    only reachable through an HTTP request."""
    return events.EventBus()


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


def test_grant_issued_on_approval_scoped_to_requester_and_service(
    session: Session, bus: events.EventBus
) -> None:
    request = _approved_forward_auth_request(session)

    dispatch.finalize(session, _CONFIG, request, bus=bus)

    grant = session.scalars(select(ServiceGrant)).one()
    assert grant.state == models.GRANT_ACTIVE
    assert grant.user_id == request.requester_id  # scoped to the Requester
    assert grant.service_name == "internal-app"  # ...and the Service
    assert grant.expires_at > grant.created_at  # a positive window from grant_expiry_hours


def test_grant_and_request_are_bidirectionally_linked(
    session: Session, bus: events.EventBus
) -> None:
    request = _approved_forward_auth_request(session)

    grant = issue_service_grant(session, _CONFIG, request, bus=bus)

    assert grant.approval_request_id == request.id  # grant → request
    assert request.service_grant_id == grant.id  # request → grant


def _session_bound_config(session_expiry_hours: int = 8) -> AppConfig:
    """A config whose internal-app grant expires with the Proxy Session (hours = 0)."""
    svc = ServiceConfig(
        type="forward-auth",
        quorum=2,
        approvers=["alice", "bob"],
        endpoint="http://internal-app:8080",
        grant_expiry_hours=0,  # 0 = expires with the Requester's Proxy Session
    )
    return AppConfig(
        server=_CONFIG.server,
        auth=AuthConfig(session_expiry_hours=session_expiry_hours),
        services={"internal-app": svc},
    )


def test_session_bound_grant_binds_expiry_to_the_requester_session(
    session: Session, bus: events.EventBus
) -> None:
    # grant_expiry_hours = 0 → expires_at bound to the Requester's actual Proxy Session
    # end, not an independent fresh window (#78, docs/web-proxy.md §Service Grant Expiry).
    request = _approved_forward_auth_request(session)
    session_end = datetime.now(UTC) + timedelta(hours=3)
    session.add(
        ProxySession(id="sess-dave", user_id=request.requester_id, expires_at=session_end)
    )
    session.flush()

    grant = issue_service_grant(session, _session_bound_config(), request, bus=bus)

    assert aware(grant.expires_at) == session_end  # bound to the session, not now+8h


def test_session_bound_grant_falls_back_when_no_session_is_live(
    session: Session, bus: events.EventBus
) -> None:
    # No live session to bind to (e.g. it expired mid-wait): fall back to a fresh
    # window of the configured session lifetime so the grant is not born expired.
    request = _approved_forward_auth_request(session)
    before = datetime.now(UTC)

    grant = issue_service_grant(
        session, _session_bound_config(session_expiry_hours=8), request, bus=bus
    )

    expires = aware(grant.expires_at)
    assert before + timedelta(hours=7) < expires < before + timedelta(hours=9)


def test_per_service_grant_expiry_hours_sets_a_fixed_window(
    session: Session, bus: events.EventBus
) -> None:
    # A non-zero per-service value is honored (not overridden by session_expiry_hours):
    # _SERVICE sets grant_expiry_hours=8 and auth.session_expiry_hours=8 here would be
    # indistinguishable, so use a config whose two values differ.
    config = AppConfig(
        server=_CONFIG.server,
        auth=AuthConfig(session_expiry_hours=99),
        services={
            "internal-app": ServiceConfig(
                type="forward-auth",
                quorum=2,
                approvers=["alice", "bob"],
                endpoint="http://internal-app:8080",
                grant_expiry_hours=2,
            )
        },
    )
    request = _approved_forward_auth_request(session)
    before = datetime.now(UTC)

    grant = issue_service_grant(session, config, request, bus=bus)

    expires = aware(grant.expires_at)
    assert before + timedelta(hours=1) < expires < before + timedelta(hours=3)  # 2h, not 99h


def test_a_redelivered_approval_does_not_mint_a_second_grant(
    session: Session, bus: events.EventBus
) -> None:
    request = _approved_forward_auth_request(session)

    first = issue_service_grant(session, _CONFIG, request, bus=bus)
    second = issue_service_grant(session, _CONFIG, request, bus=bus)  # redelivery

    assert first.id == second.id
    assert session.scalars(select(ServiceGrant)).all() == [first]  # exactly one grant


def test_handoff_emits_grant_activated(
    session: Session, bus: events.EventBus
) -> None:
    recorded: list[events.Event] = []
    bus.subscribe(recorded.append)
    request = _approved_forward_auth_request(session)

    issue_service_grant(session, _CONFIG, request, bus=bus)

    assert [type(e) for e in recorded] == [events.GrantActivated]
    activated = recorded[0]
    assert isinstance(activated, events.GrantActivated)
    assert activated.approval_request_id == request.id


def test_finalize_emits_request_approved_before_the_handoff(
    session: Session, bus: events.EventBus
) -> None:
    # The approval axis settles first: request.approved fires, then the type-specific
    # handoff (grant.activated for forward-auth) — distinct events (#81).
    recorded: list[events.Event] = []
    bus.subscribe(recorded.append)
    request = _approved_forward_auth_request(session)

    dispatch.finalize(session, _CONFIG, request, bus=bus)

    assert [type(e) for e in recorded] == [events.RequestApproved, events.GrantActivated]
    approved = recorded[0]
    assert isinstance(approved, events.RequestApproved)
    assert approved.approval_request_id == request.id
    assert approved.requester_id == request.requester_id


def test_finalize_notifies_requester_of_approval_and_endorsers_of_access(
    session: Session, monkeypatch: pytest.MonkeyPatch, bus: events.EventBus
) -> None:
    # request.approved → Requester only ("Your request was approved"); grant.activated
    # → Requester + Endorsing Approvers ("Access granted"). Two distinct emails (#81,
    # docs/notification-system.md §"Two outcome axes").
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
    factory = create_session_factory(create_db_engine("sqlite+pysqlite:///:memory:"))
    subscriber.register(bus, factory, config)

    request = _approved_forward_auth_request(session)
    # Bind the test transaction as the active event session, as get_session does on the
    # web path, so the subscriber reads recipients from the flushed-but-uncommitted votes.
    with events.session_bound(session):
        dispatch.finalize(session, config, request, bus=bus)

    approved = [s for s in sent if "approved" in s[1].lower()]
    granted = [s for s in sent if "Access granted" in s[1]]
    assert len(approved) == 1 and approved[0][0] == {"dave@example.com"}  # requester only
    assert len(granted) == 1
    assert granted[0][0] == {"dave@example.com", "alice@example.com", "bob@example.com"}


def test_grant_activated_notifies_requester_and_endorsers(
    session: Session, monkeypatch: pytest.MonkeyPatch, bus: events.EventBus
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
    # The subscriber reads recipients off the bound emitter session; the factory is
    # only the out-of-scope fallback, so a throwaway one is fine here.
    factory = create_session_factory(create_db_engine("sqlite+pysqlite:///:memory:"))
    subscriber.register(bus, factory, config)

    request = _approved_forward_auth_request(session)
    # Bind the test transaction as the active event session (as get_session does).
    with events.session_bound(session):
        issue_service_grant(session, config, request, bus=bus)

    assert len(sent) == 1
    recipients, subject = sent[0]
    assert "Access granted" in subject
    # dave (requester) + alice, bob (endorsing approvers); de-duplicated.
    assert recipients == {"dave@example.com", "alice@example.com", "bob@example.com"}
