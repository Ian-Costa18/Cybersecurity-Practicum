"""End-to-end: the approve/deny page records signed votes over real HTTP and
drives the request to a terminal state — and refuses a vote without fresh
re-authentication.

Real DB, real HTTP, real crypto (``docs/mvp.md`` posture). No PyPI boundary is
touched: issue #4 stops at the approval decision; execution is #5.
"""

from __future__ import annotations

import uuid

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import select

from msig_proxy.accounts.seed import seed_user
from msig_proxy.core import models
from msig_proxy.core.config import ServiceConfig
from msig_proxy.core.db import session_scope
from msig_proxy.core.models import ApprovalRequest, Vote
from msig_proxy.service_types.one_time.intake import create_publish_request
from tests.support import totp_code

ARTIFACT = b"the exact uploaded artifact bytes"
_PASSWORD = {name: f"pw-{name}-123" for name in ("alice", "bob", "carol")}
# TOTP secrets captured at seed time so vote re-auth satisfies the second factor (#16).
_SECRETS: dict[str, str] = {}


def _vote_data(name: str, decision: str, *, password: str | None = None) -> dict[str, str]:
    """Form body for POST /approve: password + a current TOTP, both required (#16)."""
    return {
        "username": name,
        "password": _PASSWORD[name] if password is None else password,
        "totp": totp_code(_SECRETS[name]),
        "decision": decision,
    }


@pytest.fixture
def pending_request_id(app: FastAPI) -> str:
    """Seed three approvers (quorum 2) + a requester and create one pending request."""
    request_id = ""
    for session in session_scope(app.state.session_factory):
        for name in _PASSWORD:
            _SECRETS[name] = seed_user(
                session, username=name, email=f"{name}@example.com", password=_PASSWORD[name]
            ).totp_secret
        requester = seed_user(
            session, username="publisher", email="publisher@example.com", password="pub-pw-123"
        ).user
        service = ServiceConfig(
            type="one-time",
            action="publish-to-pypi",
            quorum=2,
            approvers=list(_PASSWORD),
        )
        request = create_publish_request(
            session,
            requester=requester,
            service_name="pypi",
            service=service,
            package_name="foo",
            package_version="1.2.3",
            filename="foo-1.2.3.tar.gz",
            content=ARTIFACT,
        )
        request_id = str(request.id)
    return request_id


def _state(app: FastAPI, request_id: str) -> str:
    for session in session_scope(app.state.session_factory):
        approval = session.get(ApprovalRequest, uuid.UUID(request_id))
        assert approval is not None
        return approval.state
    return ""  # pragma: no cover


def _vote_count(app: FastAPI, request_id: str) -> int:
    for session in session_scope(app.state.session_factory):
        return len(
            session.scalars(
                select(Vote).where(Vote.approval_request_id == uuid.UUID(request_id))
            ).all()
        )
    return 0  # pragma: no cover


async def test_get_page_renders_summary_and_quorum_status(
    client: httpx.AsyncClient, pending_request_id: str
) -> None:
    response = await client.get(f"/approve/{pending_request_id}")

    assert response.status_code == 200
    body = response.text
    assert "foo" in body and "1.2.3" in body  # request summary
    assert "0 of 2 approvals received" in body  # live quorum status
    assert f"/approve/{pending_request_id}/artifact" in body  # inspection download link


async def test_two_approvals_over_http_reach_quorum(
    client: httpx.AsyncClient, app: FastAPI, pending_request_id: str
) -> None:
    first = await client.post(
        f"/approve/{pending_request_id}",
        data=_vote_data("alice", "approve"),
    )
    assert first.status_code == 200
    assert _state(app, pending_request_id) == models.PENDING  # m-1: no transition

    second = await client.post(
        f"/approve/{pending_request_id}",
        data=_vote_data("bob", "approve"),
    )
    assert second.status_code == 200
    assert _state(app, pending_request_id) == models.APPROVED
    assert _vote_count(app, pending_request_id) == 2


async def test_a_deny_closes_the_request(
    client: httpx.AsyncClient, app: FastAPI, pending_request_id: str
) -> None:
    response = await client.post(
        f"/approve/{pending_request_id}",
        data=_vote_data("alice", "deny"),
    )

    assert response.status_code == 200
    assert _state(app, pending_request_id) == models.DENIED


async def test_a_vote_requires_fresh_reauthentication(
    client: httpx.AsyncClient, app: FastAPI, pending_request_id: str
) -> None:
    response = await client.post(
        f"/approve/{pending_request_id}",
        data=_vote_data("alice", "approve", password="wrong-password"),
    )

    assert response.status_code == 401
    assert _vote_count(app, pending_request_id) == 0  # nothing recorded without a valid password
    assert _state(app, pending_request_id) == models.PENDING


async def test_artifact_download_returns_the_staged_bytes(
    client: httpx.AsyncClient, pending_request_id: str
) -> None:
    response = await client.get(f"/approve/{pending_request_id}/artifact")

    assert response.status_code == 200
    assert response.content == ARTIFACT  # exactly the bytes whose hash is being signed over
    assert "attachment" in response.headers["content-disposition"]


async def test_an_invalid_decision_is_rejected(
    client: httpx.AsyncClient, app: FastAPI, pending_request_id: str
) -> None:
    response = await client.post(
        f"/approve/{pending_request_id}",
        data=_vote_data("alice", "maybe"),
    )

    assert response.status_code == 400
    assert _vote_count(app, pending_request_id) == 0


async def test_voting_on_a_closed_request_shows_the_frozen_page(
    client: httpx.AsyncClient, app: FastAPI, pending_request_id: str
) -> None:
    # Drive the request to denied, then reuse the link to vote again.
    await client.post(
        f"/approve/{pending_request_id}",
        data=_vote_data("alice", "deny"),
    )
    late = await client.post(
        f"/approve/{pending_request_id}",
        data=_vote_data("bob", "approve"),
    )

    assert late.status_code == 409  # the vote is refused, not applied
    assert "closed" in late.text.lower()
    assert _state(app, pending_request_id) == models.DENIED


async def test_unknown_request_returns_404(client: httpx.AsyncClient) -> None:
    response = await client.get(f"/approve/{uuid.uuid4()}")

    assert response.status_code == 404
