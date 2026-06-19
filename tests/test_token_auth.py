"""API-token authentication against the normalized ``api_tokens`` table (issue #14).

Real DB, real crypto, real HTTP. The token now resolves against an
:class:`~msig_proxy.models.ApiToken` row (a User may hold many): a revoked token
and any token of a deactivated User are refused, and a second token authenticates
just like the first.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import select

from msig_proxy import crypto, events
from msig_proxy.config import AppConfig, ServerConfig, ServiceConfig
from msig_proxy.db import session_scope
from msig_proxy.models import ApiToken, User
from msig_proxy.seed import seed_user

ARTIFACT = b"the exact uploaded artifact bytes"


@pytest.fixture(autouse=True)
def _isolate_event_subscribers() -> Iterator[None]:
    yield
    events.clear_subscribers()


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
                type="one-time", action="publish-to-pypi", quorum=1, approvers=["publisher"]
            )
        },
    )


@pytest.fixture
def requester_token(app: FastAPI) -> str:
    token = ""
    for session in session_scope(app.state.session_factory):
        token = seed_user(
            session, username="publisher", email="publisher@example.com", password="pub-pw-123"
        ).api_token
    return token


def _twine_form() -> dict[str, str]:
    return {":action": "file_upload", "protocol_version": "1", "name": "foo", "version": "1.2.3"}


async def _upload(client: httpx.AsyncClient, token: str) -> httpx.Response:
    return await client.post(
        "/pypi/legacy/",
        data=_twine_form(),
        files={"content": ("foo-1.2.3.tar.gz", ARTIFACT, "application/octet-stream")},
        auth=("__token__", token),
    )


async def test_a_valid_token_authenticates_via_api_tokens(
    client: httpx.AsyncClient, requester_token: str
) -> None:
    assert (await _upload(client, requester_token)).status_code == 200


async def test_a_revoked_token_is_rejected(
    client: httpx.AsyncClient, app: FastAPI, requester_token: str
) -> None:
    for session in session_scope(app.state.session_factory):
        token = session.scalars(select(ApiToken)).one()
        token.revoked_at = datetime.now(UTC)

    assert (await _upload(client, requester_token)).status_code == 401


async def test_a_token_of_an_inactive_user_is_rejected(
    client: httpx.AsyncClient, app: FastAPI, requester_token: str
) -> None:
    for session in session_scope(app.state.session_factory):
        user = session.scalars(select(User).where(User.username == "publisher")).one()
        user.is_active = False

    # The token itself is still active, but its owner is deactivated.
    assert (await _upload(client, requester_token)).status_code == 401


async def test_a_user_can_hold_multiple_tokens(
    client: httpx.AsyncClient, app: FastAPI, requester_token: str
) -> None:
    second_plaintext = crypto.generate_api_token()
    for session in session_scope(app.state.session_factory):
        user = session.scalars(select(User).where(User.username == "publisher")).one()
        session.add(
            ApiToken(
                user_id=user.id,
                label="CI runner",
                token_hash=crypto.hash_api_token(second_plaintext),
            )
        )

    # Both the seeded token and the second token authenticate independently.
    assert (await _upload(client, requester_token)).status_code == 200
    assert (await _upload(client, second_plaintext)).status_code == 200
    # Revoking one does not affect the other.
    for session in session_scope(app.state.session_factory):
        first = session.scalars(select(ApiToken).where(ApiToken.label == "seed token")).one()
        first.revoked_at = datetime.now(UTC)
    assert (await _upload(client, requester_token)).status_code == 401
    assert (await _upload(client, second_plaintext)).status_code == 200
