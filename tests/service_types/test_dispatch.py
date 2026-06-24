"""Post-approval dispatch (#59): the ServiceHandler contract and `finalize`.

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

from msig_proxy.accounts.seed import seed_user
from msig_proxy.core import events
from msig_proxy.core.config import (
    DEFAULT_PYPI_UPLOAD_URL,
    AppConfig,
    ServerConfig,
    ServiceConfig,
)
from msig_proxy.core.db import Base, create_db_engine, create_session_factory
from msig_proxy.core.models import (
    APPROVED,
    DENIED,
    FORWARD_AUTH,
    PENDING,
    ApprovalRequest,
    ServiceGrant,
    StagedArtifact,
)
from msig_proxy.service_types import dispatch
from msig_proxy.service_types.forward_auth.handler import ForwardAuthServiceHandler
from msig_proxy.service_types.one_time import artifact, publish
from msig_proxy.service_types.one_time.handler import OneTimeServiceHandler
from msig_proxy.service_types.one_time.intake import create_publish_request

ARTIFACT = b"the exact artifact bytes"
_SERVER = ServerConfig(base_url="https://proxy.example.test", secret_key="x" * 16)


@pytest.fixture
def bus() -> events.EventBus:
    """A standalone event bus for the below-HTTP tests that drive finalize/handlers
    directly; the app's wired bus is only reachable through an HTTP request."""
    return events.EventBus()


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
    forward_auth_handler = dispatch.handler_for(_forward_auth_request(session))
    assert isinstance(forward_auth_handler, ForwardAuthServiceHandler)
    assert isinstance(dispatch.handler_for(_publish_request(session)), OneTimeServiceHandler)


def test_handler_for_unknown_service_type_raises(session: Session) -> None:
    request = _forward_auth_request(session)
    request.service_type = "carrier-pigeon"
    with pytest.raises(KeyError):
        dispatch.handler_for(request)


# --- the configurable endpoint ---------------------------------------------


def test_one_time_endpoint_defaults_to_pypi() -> None:
    assert _one_time_service().endpoint == DEFAULT_PYPI_UPLOAD_URL


def test_execute_publish_posts_to_the_configured_endpoint(session: Session) -> None:
    request = _publish_request(session)
    request.state = APPROVED
    custom = "https://test.pypi.org/legacy/"

    with respx.mock(assert_all_called=False) as router:
        route = router.post(custom, name="upload").mock(return_value=httpx.Response(200, text="OK"))
        result = publish.execute_publish(
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
    reason = publish._rejection_reason(status_code)
    assert needle in reason
    assert str(status_code) in reason


# --- finalize: routes terminal states to the handler -----------------------


def test_finalize_one_time_approved_publishes(
    session: Session, mock_pypi: respx.MockRouter, bus: events.EventBus
) -> None:
    request = _publish_request(session)
    request.state = APPROVED
    config = AppConfig(server=_SERVER, services={"pypi": _one_time_service()})

    dispatch.finalize(session, config, request, bus=bus)

    assert mock_pypi["pypi_upload"].called  # the one-time handoff reached PyPI


def test_finalize_one_time_approved_publish_rejected_is_handled(
    session: Session, mock_pypi: respx.MockRouter, bus: events.EventBus
) -> None:
    # The unhappy approved path: PyPI rejects, so the handler takes the failure
    # branch (the "Execution failed" outcome) rather than raising.
    mock_pypi["pypi_upload"].mock(return_value=httpx.Response(403, text="bad token"))
    request = _publish_request(session)
    request.state = APPROVED
    config = AppConfig(server=_SERVER, services={"pypi": _one_time_service()})

    dispatch.finalize(session, config, request, bus=bus)

    assert mock_pypi["pypi_upload"].called  # it tried, and the rejection was surfaced


def test_finalize_forward_auth_approved_issues_grant(
    session: Session, bus: events.EventBus
) -> None:
    request = _forward_auth_request(session)
    request.state = APPROVED
    config = AppConfig(server=_SERVER, services={"internal-app": _forward_auth_service()})

    dispatch.finalize(session, config, request, bus=bus)

    grant = session.query(ServiceGrant).filter_by(approval_request_id=request.id).one_or_none()
    assert grant is not None  # the forward-auth handoff minted a grant


def test_finalize_denied_never_touches_pypi(
    session: Session, bus: events.EventBus, mock_pypi: respx.MockRouter
) -> None:
    request = _publish_request(session)
    request.state = DENIED
    config = AppConfig(server=_SERVER, services={"pypi": _one_time_service()})

    dispatch.finalize(session, config, request, bus=bus)

    assert not mock_pypi["pypi_upload"].called  # quorum oracle: denial reaches no boundary


def test_finalize_forward_auth_denied_is_a_clean_no_op(
    session: Session, bus: events.EventBus
) -> None:
    # Forward-auth stages no artifact, so denial cleanup does nothing and mints no grant.
    request = _forward_auth_request(session)
    request.state = DENIED
    config = AppConfig(server=_SERVER, services={"internal-app": _forward_auth_service()})

    dispatch.finalize(session, config, request, bus=bus)

    grant = session.query(ServiceGrant).filter_by(approval_request_id=request.id).one_or_none()
    assert grant is None


def test_finalize_ignores_a_non_terminal_state(
    session: Session, mock_pypi: respx.MockRouter, bus: events.EventBus
) -> None:
    request = _publish_request(session)
    request.state = PENDING
    config = AppConfig(server=_SERVER, services={"pypi": _one_time_service()})

    dispatch.finalize(session, config, request, bus=bus)

    assert not mock_pypi["pypi_upload"].called  # a still-pending request triggers no handoff


# --- held-artifact destruction at a terminal outcome (#68) -----------------


def test_denied_one_time_destroys_the_held_artifact(
    session: Session, bus: events.EventBus
) -> None:
    # The held bytes must not outlive the request: denial is a non-handoff terminal,
    # so the handler destroys the StagedArtifact (no Executor handoff fires here).
    request = _publish_request(session)
    request.state = DENIED
    assert session.get(StagedArtifact, request.id) is not None  # staged at creation
    config = AppConfig(server=_SERVER, services={"pypi": _one_time_service()})

    dispatch.finalize(session, config, request, bus=bus)

    assert session.get(StagedArtifact, request.id) is None  # destroyed at the terminal


def test_denied_one_time_emits_artifact_destroyed(session: Session, bus: events.EventBus) -> None:
    recorded: list[events.Event] = []
    bus.subscribe(recorded.append)
    request = _publish_request(session)
    request.state = DENIED
    config = AppConfig(server=_SERVER, services={"pypi": _one_time_service()})

    dispatch.finalize(session, config, request, bus=bus)

    destroyed = [e for e in recorded if isinstance(e, events.ArtifactDestroyed)]
    assert len(destroyed) == 1
    assert destroyed[0].approval_request_id == request.id
    assert destroyed[0].action_id is None  # no handoff on the denial path
    assert destroyed[0].terminal_state == DENIED


def test_forward_auth_denial_destroys_nothing_and_emits_no_event(
    session: Session, bus: events.EventBus
) -> None:
    # Forward-auth stages no artifact, so there is nothing to destroy and no event.
    recorded: list[events.Event] = []
    bus.subscribe(recorded.append)
    request = _forward_auth_request(session)
    request.state = DENIED
    config = AppConfig(server=_SERVER, services={"internal-app": _forward_auth_service()})

    dispatch.finalize(session, config, request, bus=bus)

    assert not any(isinstance(e, events.ArtifactDestroyed) for e in recorded)


def test_destroy_staged_artifact_is_idempotent(session: Session, bus: events.EventBus) -> None:
    # A redelivered terminal transition (artifact already gone) is a silent no-op:
    # returns False and emits nothing.
    recorded: list[events.Event] = []
    request = _publish_request(session)
    request.state = DENIED

    assert artifact.destroy_staged_artifact(session, request, bus=bus) is True  # first destroys
    bus.subscribe(recorded.append)
    assert artifact.destroy_staged_artifact(session, request, bus=bus) is False  # second no-ops
    assert recorded == []  # no second artifact.destroyed


def test_destroy_staged_artifact_carries_action_id_into_the_event(
    session: Session, bus: events.EventBus
) -> None:
    # The approved/handoff path will pass the Action's id; the primitive threads it
    # into the event payload.
    recorded: list[events.Event] = []
    bus.subscribe(recorded.append)
    request = _publish_request(session)
    request.state = APPROVED

    assert artifact.destroy_staged_artifact(session, request, bus=bus, action_id="act-123") is True

    destroyed = [e for e in recorded if isinstance(e, events.ArtifactDestroyed)]
    assert destroyed[0].action_id == "act-123"
    assert destroyed[0].terminal_state == APPROVED
