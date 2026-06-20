"""Phase 1 #8 prefactor: the data model and config can *carry* a forward-auth
request, with no change to the publish path's behavior.

Real DB, real validation. Covers the forward-auth config rules and that an
Approval Request persists with the publish-specific columns null.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from pydantic import ValidationError
from sqlalchemy.orm import Session

from msig_proxy import models
from msig_proxy.config import HeadersConfig, ServiceConfig
from msig_proxy.db import Base, create_db_engine, create_session_factory
from msig_proxy.models import ApprovalRequest
from msig_proxy.seed import seed_user


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


# --- ServiceConfig: forward-auth validation --------------------------------


def test_forward_auth_service_requires_an_endpoint() -> None:
    with pytest.raises(ValidationError, match="forward-auth service requires an 'endpoint'"):
        ServiceConfig(type="forward-auth", quorum=2, approvers=["alice", "bob"])


def test_forward_auth_service_forbids_an_action() -> None:
    with pytest.raises(ValidationError, match="forward-auth service must not set an 'action'"):
        ServiceConfig(
            type="forward-auth",
            quorum=2,
            approvers=["alice", "bob"],
            endpoint="http://internal-app:8080",
            action="publish-to-pypi",
        )


def test_forward_auth_service_parses_endpoint_grant_and_headers() -> None:
    service = ServiceConfig(
        type="forward-auth",
        quorum=2,
        approvers=["alice", "bob"],
        endpoint="http://internal-app:8080",
        grant_expiry_hours=0,
        headers=HeadersConfig(remote_groups=False),
    )

    assert service.endpoint == "http://internal-app:8080"
    assert service.grant_expiry_hours == 0  # 0 = grant expires with the Proxy Session
    assert service.headers.remote_user == "Remote-User"  # Authelia-compatible default
    assert service.headers.remote_groups is False  # explicitly suppressed


def test_headers_default_to_authelia_names() -> None:
    headers = HeadersConfig()
    assert (headers.remote_user, headers.remote_name, headers.remote_email) == (
        "Remote-User",
        "Remote-Name",
        "Remote-Email",
    )


def test_one_time_service_still_requires_an_action() -> None:
    # The existing publish-path rule is unchanged by the prefactor.
    with pytest.raises(ValidationError, match="one-time service requires an 'action'"):
        ServiceConfig(type="one-time", quorum=2, approvers=["alice", "bob"])


# --- ApprovalRequest: a forward-auth request carries no publish fields ------


def test_a_forward_auth_request_persists_with_null_publish_columns(session: Session) -> None:
    requester = seed_user(
        session, username="requester", email="requester@example.com", password="req-pw-123"
    ).user

    request = ApprovalRequest(
        requester_id=requester.id,
        service_name="internal-app",
        service_type=models.FORWARD_AUTH,
        quorum=2,
        # No action, no artifact hash, no package fields — a forward-auth grant.
    )
    session.add(request)
    session.flush()

    stored = session.get(ApprovalRequest, request.id)
    assert stored is not None
    assert stored.service_type == models.FORWARD_AUTH
    assert stored.state == models.PENDING
    assert stored.action is None
    assert stored.artifact_sha256 is None
    assert stored.package_name is None
    assert stored.package_version is None
