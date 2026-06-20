"""The Executor: hash re-verification gates the (mocked) PyPI publish.

Real DB, real crypto; the PyPI boundary is the one ``respx`` mock and its captured
request is the oracle. Exercises :mod:`msig_proxy.executor` below the HTTP layer.
"""

from __future__ import annotations

from collections.abc import Iterator

import httpx
import pytest
import respx
from sqlalchemy.orm import Session

from msig_proxy import executor
from msig_proxy.accounts.seed import seed_user
from msig_proxy.core.config import DEFAULT_PYPI_UPLOAD_URL, ServiceConfig
from msig_proxy.core.db import Base, create_db_engine, create_session_factory
from msig_proxy.core.models import ApprovalRequest, StagedArtifact
from msig_proxy.intake import create_publish_request

ARTIFACT = b"the exact artifact bytes"


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


def _service() -> ServiceConfig:
    return ServiceConfig(
        type="one-time",
        action="publish-to-pypi",
        quorum=2,
        approvers=["alice", "bob"],
        credentials={"pypi_token": "pypi-token-value"},
    )


def _request(session: Session, content: bytes = ARTIFACT) -> ApprovalRequest:
    for name in ("alice", "bob"):  # the service's approvers must resolve at snapshot time
        seed_user(session, username=name, email=f"{name}@example.com", password=f"pw-{name}-123")
    requester = seed_user(
        session, username="publisher", email="publisher@example.com", password="pub-pw-123"
    ).user
    return create_publish_request(
        session,
        requester=requester,
        service_name="pypi",
        service=_service(),
        package_name="foo",
        package_version="1.2.3",
        filename="foo-1.2.3.tar.gz",
        content=content,
    )


def test_publish_to_pypi_posts_a_twine_shaped_upload(mock_pypi: respx.MockRouter) -> None:
    result = executor.publish_to_pypi(
        url=DEFAULT_PYPI_UPLOAD_URL,
        token="pypi-token-value",
        name="foo",
        version="1.2.3",
        filename="foo-1.2.3.tar.gz",
        content=ARTIFACT,
    )

    assert result.published is True
    call = mock_pypi["pypi_upload"].calls.last
    assert call.request.url == DEFAULT_PYPI_UPLOAD_URL
    assert ARTIFACT in call.request.content  # the artifact bytes are in the multipart body


def test_publish_reports_failure_on_a_pypi_rejection(mock_pypi: respx.MockRouter) -> None:
    mock_pypi["pypi_upload"].mock(return_value=httpx.Response(400, text="version exists"))

    result = executor.publish_to_pypi(
        url=DEFAULT_PYPI_UPLOAD_URL,
        token="t",
        name="foo",
        version="1.2.3",
        filename="foo.tar.gz",
        content=ARTIFACT,
    )

    assert result.published is False
    assert "400" in (result.reason or "")


def test_matching_hash_publishes(session: Session, mock_pypi: respx.MockRouter) -> None:
    request = _request(session)

    result = executor.execute_publish(session, request=request, service=_service())

    assert result.published is True
    assert mock_pypi["pypi_upload"].called  # the handoff reached PyPI


def test_a_mutated_artifact_refuses_and_never_calls_pypi(
    session: Session, mock_pypi: respx.MockRouter
) -> None:
    request = _request(session)
    # Substitute the held bytes after approval — one mutated byte breaks the binding.
    staged = session.get(StagedArtifact, request.id)
    assert staged is not None
    staged.content = ARTIFACT + b"!"
    session.flush()

    result = executor.execute_publish(session, request=request, service=_service())

    assert result.published is False
    assert "hash mismatch" in (result.reason or "")
    assert not mock_pypi["pypi_upload"].called  # integrity oracle: PyPI is never touched
