"""Adversarial: the one-time upload edge caps artifact bytes and count (DOS-1
storage-exhaustion leg).

Black-box tier (``docs/threat-model/CONTRIBUTING.md`` §bucket): the attack is
driven through the real ``POST /pypi/legacy/`` HTTP surface and the oracle is the
PyPI mock — an oversized (or over-count) upload is rejected *and nothing is
staged*, so the artifact can never reach the publish boundary. One leaked
requester credential (L2) is the whole precondition; this proves that credential
can no longer exhaust storage with uncapped uploads.

Real DB, real HTTP, real crypto (``docs/mvp.md`` posture); ``mock_pypi`` is the
single mocked boundary and asserts zero calls.
"""

from __future__ import annotations

import httpx
import pytest
import respx
from fastapi import FastAPI
from sqlalchemy import func, select

from msig_proxy.accounts.seed import seed_user
from msig_proxy.core.config import AppConfig, ServerConfig, ServiceConfig
from msig_proxy.core.db import session_scope
from msig_proxy.core.models import ApprovalRequest, StagedArtifact

# A small cap keeps the "oversized" payload cheap to build; the defense is the
# same at 1 KiB as at 100 MiB.
_MAX_UPLOAD_BYTES = 1024
_MAX_STAGED = 2


@pytest.fixture
def app_config() -> AppConfig:
    """A one-time PyPI service with deliberately tiny storage caps."""
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
                max_upload_bytes=_MAX_UPLOAD_BYTES,
                max_staged_artifacts=_MAX_STAGED,
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
    return {
        ":action": "file_upload",
        "protocol_version": "1",
        "metadata_version": "2.1",
        "name": name,
        "version": version,
        "filetype": "sdist",
    }


def _file_part(
    content: bytes, filename: str = "foo-1.2.3.tar.gz"
) -> dict[str, tuple[str, bytes, str]]:
    # httpx's ``files=`` mapping value is (filename, content, content-type).
    return {"content": (filename, content, "application/octet-stream")}


def _staged_counts(app: FastAPI) -> tuple[int, int]:
    """(#ApprovalRequest, #StagedArtifact) currently in the DB."""
    for session in session_scope(app.state.session_factory):
        requests = session.scalar(select(func.count()).select_from(ApprovalRequest)) or 0
        artifacts = session.scalar(select(func.count()).select_from(StagedArtifact)) or 0
        return requests, artifacts
    return 0, 0  # pragma: no cover - session_scope always yields once


async def test_oversized_upload_is_rejected_and_never_reaches_pypi(
    client: httpx.AsyncClient, app: FastAPI, requester_token: str, mock_pypi: respx.MockRouter
) -> None:
    oversized = b"A" * (_MAX_UPLOAD_BYTES + 1)

    response = await client.post(
        "/pypi/legacy/",
        data=_twine_form(),
        files=_file_part(oversized),
        auth=("__token__", requester_token),
    )

    assert response.status_code == 413  # Payload Too Large — refused at the edge
    assert _staged_counts(app) == (0, 0)  # nothing bound, nothing staged
    assert not mock_pypi["pypi_upload"].called  # the publish boundary is never touched


async def test_upload_rejected_once_artifact_count_cap_reached(
    client: httpx.AsyncClient, app: FastAPI, requester_token: str, mock_pypi: respx.MockRouter
) -> None:
    small = b"a wheel's worth of bytes"

    # Fill the per-service staging cap with in-limit uploads.
    for n in range(_MAX_STAGED):
        ok = await client.post(
            "/pypi/legacy/",
            data=_twine_form(version=f"1.0.{n}"),
            files=_file_part(small),
            auth=("__token__", requester_token),
        )
        assert ok.status_code == 200

    # The store is now full; the next upload is refused before staging.
    response = await client.post(
        "/pypi/legacy/",
        data=_twine_form(version="9.9.9"),
        files=_file_part(small),
        auth=("__token__", requester_token),
    )

    assert response.status_code == 507  # Insufficient Storage — the staging store is full
    assert _staged_counts(app) == (_MAX_STAGED, _MAX_STAGED)  # capped, not exceeded
    assert not mock_pypi["pypi_upload"].called  # the publish boundary is never touched
