"""Post-approval dispatch (#59): the PostApprovalHandler layer and `finalize`.

Real DB, real crypto; the PyPI boundary is the one ``respx`` mock. Exercises the
producer interface — handler resolution, the approved/denied routing, the
configurable publish endpoint, and the classified PyPI failure reasons — below the
HTTP layer.
"""

from __future__ import annotations

from collections.abc import Iterator

import httpx
import pytest
import respx
from sqlalchemy.orm import Session

from msig_proxy import executor, post_approval
from msig_proxy.config import (
    DEFAULT_PYPI_UPLOAD_URL,
    AppConfig,
    ServerConfig,
    ServiceConfig,
)
from msig_proxy.db import Base, create_db_engine, create_session_factory
from msig_proxy.intake import create_publish_request
from msig_proxy.models import (
    APPROVED,
    DENIED,
    FORWARD_AUTH,
    PENDING,
    ApprovalRequest,
    ServiceGrant,
)
from msig_proxy.post_approval import ForwardAuthHandler, OneTimeHandler
from msig_proxy.seed import seed_user

ARTIFACT = b"the exact artifact bytes"
_SERVER = ServerConfig(base_url="https://proxy.example.test", secret_key="x" * 16)


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


def _one_time_service(endpoint: str | None = None) -> ServiceConfig:
    return ServiceConfig(
        type="one-time",
        action="publish-to-pypi",
        quorum=2,
        approvers=["alice", "bob"],
        credentials={"pypi_token": "pypi-token-value"},
        endpoint=endpoint,
    )


def _forward_auth_service() -> ServiceConfig:
    return ServiceConfig(
        type="forward-auth", quorum=2, approvers=["alice", "bob"], endpoint="http://internal:8080"
    )


def _publish_request(session: Session, *, content: bytes = ARTIFACT) -> ApprovalRequest:
    for name in ("alice", "bob"):
        seed_user(session, username=name, email=f"{name}@example.com", password=f"pw-{name}-123")
    requester = seed_user(
        session, username="publisher", email="publisher@example.com", password="pub-pw-123"
    ).user
    return create_publish_request(
        session,
        requester=requester,
        service_name="pypi",
        service=_one_time_service(),
        package_name="foo",
        package_version="1.2.3",
        filename="foo-1.2.3.tar.gz",
        content=content,
    )


def _forward_auth_request(session: Session) -> ApprovalRequest:
    requester = seed_user(
        session, username="requester", email="requester@example.com", password="req-pw-123"
    ).user
    request = ApprovalRequest(
        requester_id=requester.id,
        service_name="internal-app",
        service_type=FORWARD_AUTH,
        quorum=2,
    )
    session.add(request)
    session.flush()
    return request


# --- handler_for: dispatch table over service_type -------------------------


def test_handler_for_maps_each_service_type(session: Session) -> None:
    assert isinstance(post_approval.handler_for(_forward_auth_request(session)), ForwardAuthHandler)
    assert isinstance(post_approval.handler_for(_publish_request(session)), OneTimeHandler)


def test_handler_for_unknown_service_type_raises(session: Session) -> None:
    request = _forward_auth_request(session)
    request.service_type = "carrier-pigeon"
    with pytest.raises(KeyError):
        post_approval.handler_for(request)


# --- the configurable endpoint ---------------------------------------------


def test_one_time_endpoint_defaults_to_pypi() -> None:
    assert _one_time_service().endpoint == DEFAULT_PYPI_UPLOAD_URL


def test_execute_publish_posts_to_the_configured_endpoint(session: Session) -> None:
    request = _publish_request(session)
    request.state = APPROVED
    custom = "https://test.pypi.org/legacy/"

    with respx.mock(assert_all_called=False) as router:
        route = router.post(custom, name="upload").mock(return_value=httpx.Response(200, text="OK"))
        result = executor.execute_publish(
            session, request=request, service=_one_time_service(endpoint=custom)
        )

    assert result.published is True
    assert route.called  # posted to the override, not the PyPI default


# --- classified PyPI failure reasons ---------------------------------------


@pytest.mark.parametrize(
    ("status_code", "needle"),
    [
        (401, "authentication failed"),
        (403, "authentication failed"),
        (409, "already exists"),
        (422, "invalid request"),
        (503, "server error"),
    ],
)
def test_rejection_reason_classifies_failure_modes(status_code: int, needle: str) -> None:
    reason = executor._rejection_reason(status_code)
    assert needle in reason
    assert str(status_code) in reason


# --- finalize: routes terminal states to the handler -----------------------


def test_finalize_one_time_approved_publishes(
    session: Session, mock_pypi: respx.MockRouter
) -> None:
    request = _publish_request(session)
    request.state = APPROVED
    config = AppConfig(server=_SERVER, services={"pypi": _one_time_service()})

    post_approval.finalize(session, config, request)

    assert mock_pypi["pypi_upload"].called  # the one-time handoff reached PyPI


def test_finalize_one_time_approved_publish_rejected_is_handled(
    session: Session, mock_pypi: respx.MockRouter
) -> None:
    # The unhappy approved path: PyPI rejects, so the handler takes the failure
    # branch (the "Execution failed" outcome) rather than raising.
    mock_pypi["pypi_upload"].mock(return_value=httpx.Response(403, text="bad token"))
    request = _publish_request(session)
    request.state = APPROVED
    config = AppConfig(server=_SERVER, services={"pypi": _one_time_service()})

    post_approval.finalize(session, config, request)

    assert mock_pypi["pypi_upload"].called  # it tried, and the rejection was surfaced


def test_finalize_forward_auth_approved_issues_grant(session: Session) -> None:
    request = _forward_auth_request(session)
    request.state = APPROVED
    config = AppConfig(server=_SERVER, services={"internal-app": _forward_auth_service()})

    post_approval.finalize(session, config, request)

    grant = session.query(ServiceGrant).filter_by(approval_request_id=request.id).one_or_none()
    assert grant is not None  # the forward-auth handoff minted a grant


def test_finalize_denied_never_touches_pypi(session: Session, mock_pypi: respx.MockRouter) -> None:
    request = _publish_request(session)
    request.state = DENIED
    config = AppConfig(server=_SERVER, services={"pypi": _one_time_service()})

    post_approval.finalize(session, config, request)

    assert not mock_pypi["pypi_upload"].called  # quorum oracle: denial reaches no boundary


def test_finalize_forward_auth_denied_is_a_clean_no_op(session: Session) -> None:
    # Forward-auth stages no artifact, so denial cleanup does nothing and mints no grant.
    request = _forward_auth_request(session)
    request.state = DENIED
    config = AppConfig(server=_SERVER, services={"internal-app": _forward_auth_service()})

    post_approval.finalize(session, config, request)

    grant = session.query(ServiceGrant).filter_by(approval_request_id=request.id).one_or_none()
    assert grant is None


def test_finalize_ignores_a_non_terminal_state(
    session: Session, mock_pypi: respx.MockRouter
) -> None:
    request = _publish_request(session)
    request.state = PENDING
    config = AppConfig(server=_SERVER, services={"pypi": _one_time_service()})

    post_approval.finalize(session, config, request)

    assert not mock_pypi["pypi_upload"].called  # a still-pending request triggers no handoff
