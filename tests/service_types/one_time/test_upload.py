"""End-to-end: a real Twine-shaped upload over HTTP creates a ``pending``,
hash-bound Approval Request with the approver set snapshotted — and bad
credentials are refused.

Real DB, real HTTP, real crypto (``docs/mvp.md`` posture). The PyPI publish
boundary stays untouched (``mock_pypi`` asserts zero calls): issue #3 stops at
request creation, before any voting, execution, or notification.
"""

from __future__ import annotations

import httpx
import pytest
import respx
from fastapi import FastAPI
from sqlalchemy import func, select

from msig_proxy.accounts.seed import seed_user
from msig_proxy.core import crypto, models
from msig_proxy.core.config import AppConfig, ServerConfig, ServiceConfig
from msig_proxy.core.db import session_scope
from msig_proxy.core.models import ApprovalRequest, ApprovalRequestApprover, StagedArtifact, User

ARTIFACT = b"the exact uploaded artifact bytes"


@pytest.fixture
def app_config() -> AppConfig:
    """Override conftest's config to register the one-time PyPI service."""
    return AppConfig(
        server=ServerConfig(
            host="127.0.0.1",
            port=8080,
            base_url="http://testserver",
            secret_key="test-secret-key-0123456789",
        ),
        services={
            "pypi": ServiceConfig(
                type="one-time",
                action="publish-to-pypi",
                quorum=2,
                approvers=["alice", "bob", "carol"],
            )
        },
    )


@pytest.fixture
def requester_token(app: FastAPI) -> str:
    """Seed three approvers + a separate requester; return the requester's API token."""
    token = ""
    for session in session_scope(app.state.session_factory):
        for name in ("alice", "bob", "carol"):
            seed_user(
                session, username=name, email=f"{name}@example.com", password=f"pw-{name}-123"
            )
        token = seed_user(
            session, username="publisher", email="publisher@example.com", password="pub-pw-123"
        ).api_token
    return token


def _twine_form(name: str = "foo", version: str = "1.2.3") -> dict[str, str]:
    """The metadata fields Twine sends alongside the file in a legacy upload."""
    return {
        ":action": "file_upload",
        "protocol_version": "1",
        "metadata_version": "2.1",
        "name": name,
        "version": version,
        "filetype": "sdist",
    }


def _file_part(
    filename: str = "foo-1.2.3.tar.gz", content: bytes = ARTIFACT
) -> dict[str, tuple[str, bytes, str]]:
    # httpx's ``files=`` mapping value is (filename, content, content-type).
    return {"content": (filename, content, "application/octet-stream")}


def _request_count(app: FastAPI) -> int:
    for session in session_scope(app.state.session_factory):
        return session.scalar(select(func.count()).select_from(ApprovalRequest)) or 0
    return 0  # pragma: no cover - session_scope always yields once


async def test_upload_creates_a_pending_hash_bound_request(
    client: httpx.AsyncClient, app: FastAPI, requester_token: str, mock_pypi: respx.MockRouter
) -> None:
    response = await client.post(
        "/pypi/legacy/",
        data=_twine_form(),
        files=_file_part(),
        auth=("__token__", requester_token),
    )

    assert response.status_code == 200  # Twine sees a clean success and exits

    for session in session_scope(app.state.session_factory):
        request = session.scalars(select(ApprovalRequest)).one()
        assert request.state == models.PENDING
        assert request.action == "publish-to-pypi"
        assert request.service_name == "pypi"
        assert request.package_name == "foo"
        assert request.package_version == "1.2.3"
        assert request.quorum == 2  # threshold snapshotted (ADR 0008)
        assert request.artifact_sha256 == crypto.sha256_hex(ARTIFACT)  # Hash Binding (§6)

        requester = session.get(User, request.requester_id)
        assert requester is not None and requester.username == "publisher"

        snapshot = session.scalars(
            select(ApprovalRequestApprover.user_id).where(
                ApprovalRequestApprover.approval_request_id == request.id
            )
        ).all()
        approver_ids = {
            session.scalars(select(User.id).where(User.username == name)).one()
            for name in ("alice", "bob", "carol")
        }
        assert set(snapshot) == approver_ids  # exactly the configured approvers

        staged = session.get(StagedArtifact, request.id)
        assert staged is not None
        assert staged.content == ARTIFACT  # the exact bytes are held for re-verification
        assert staged.sha256 == request.artifact_sha256

    # The acknowledgment carries the (non-secret) request id for the derivable route.
    assert response.headers["X-Approval-Request-Id"]
    # Issue #3 stops before execution: the publish boundary is never invoked.
    assert not mock_pypi["pypi_upload"].called


async def test_rejects_a_non_upload_action(
    client: httpx.AsyncClient, app: FastAPI, requester_token: str
) -> None:
    # The legacy API multiplexes verbs on `:action`; only `file_upload` publishes.
    form = _twine_form() | {":action": "remove_pkg"}
    response = await client.post(
        "/pypi/legacy/", data=form, files=_file_part(), auth=("__token__", requester_token)
    )

    assert response.status_code == 400
    assert _request_count(app) == 0  # a non-upload verb stages nothing


async def test_rejects_a_missing_token(
    client: httpx.AsyncClient, app: FastAPI, requester_token: str
) -> None:
    response = await client.post("/pypi/legacy/", data=_twine_form(), files=_file_part())

    assert response.status_code == 401
    assert _request_count(app) == 0  # nothing is staged for an unauthenticated upload


async def test_rejects_a_bad_token(
    client: httpx.AsyncClient, app: FastAPI, requester_token: str
) -> None:
    response = await client.post(
        "/pypi/legacy/",
        data=_twine_form(),
        files=_file_part(),
        auth=("__token__", "not-a-real-token"),
    )

    assert response.status_code == 401
    assert _request_count(app) == 0


async def test_rejects_the_wrong_basic_username(
    client: httpx.AsyncClient, app: FastAPI, requester_token: str
) -> None:
    # A valid token, but not presented as the `__token__` sentinel Twine uses.
    response = await client.post(
        "/pypi/legacy/",
        data=_twine_form(),
        files=_file_part(),
        auth=("alice", requester_token),
    )

    assert response.status_code == 401
    assert _request_count(app) == 0
