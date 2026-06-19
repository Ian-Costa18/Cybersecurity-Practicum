"""End-to-end: the approve/deny page renders the request, the artifact downloads
for inspection, and a vote requires fresh password re-authentication on every POST.

Real DB, real HTTP, real crypto (``docs/mvp.md`` posture). Each vote is signed and
drives the effective-vote quorum / single-deny machine; the PyPI publish boundary is
never touched (issue #4 stops at the approval outcome, before execution).
"""

from __future__ import annotations

import uuid

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import func, select

from msig_proxy import models
from msig_proxy.config import ServiceConfig
from msig_proxy.db import session_scope
from msig_proxy.intake import create_publish_request
from msig_proxy.models import ApprovalRequest, User, Vote
from msig_proxy.seed import seed_user

ARTIFACT = b"the exact uploaded artifact bytes"
FILENAME = "foo-1.2.3.tar.gz"


def _password(name: str) -> str:
    return f"pw-{name}-123"


@pytest.fixture
def seeded(app: FastAPI) -> None:
    """Seed alice/bob/carol approvers plus a separate publisher (the requester)."""
    for session in session_scope(app.state.session_factory):
        for name in ("alice", "bob", "carol"):
            seed_user(
                session, username=name, email=f"{name}@example.com", password=_password(name)
            )
        seed_user(
            session,
            username="publisher",
            email="publisher@example.com",
            password=_password("publisher"),
        )


def _create_request(app: FastAPI, *, quorum: int = 2) -> uuid.UUID:
    """Create a pending, hash-bound request with alice/bob/carol snapshotted."""
    request_id: uuid.UUID | None = None
    for session in session_scope(app.state.session_factory):
        requester = session.scalars(select(User).where(User.username == "publisher")).one()
        service = ServiceConfig(
            type="one-time",
            action="publish-to-pypi",
            quorum=quorum,
            approvers=["alice", "bob", "carol"],
        )
        request = create_publish_request(
            session,
            requester=requester,
            service_name="pypi",
            service=service,
            package_name="foo",
            package_version="1.2.3",
            filename=FILENAME,
            content=ARTIFACT,
        )
        request_id = request.id
    assert request_id is not None
    return request_id


def _state(app: FastAPI, request_id: uuid.UUID) -> str:
    for session in session_scope(app.state.session_factory):
        return session.get(ApprovalRequest, request_id).state
    raise AssertionError("session_scope always yields once")  # pragma: no cover


def _vote_count(app: FastAPI, request_id: uuid.UUID) -> int:
    for session in session_scope(app.state.session_factory):
        return (
            session.scalar(
                select(func.count())
                .select_from(Vote)
                .where(Vote.approval_request_id == request_id)
            )
            or 0
        )
    return 0  # pragma: no cover


def _form(name: str, decision: str) -> dict[str, str]:
    return {"username": name, "password": _password(name), "decision": decision}


# --- the approve/deny page and artifact download ---------------------------


async def test_page_renders_summary_link_and_quorum(
    client: httpx.AsyncClient, app: FastAPI, seeded: None
) -> None:
    request_id = _create_request(app, quorum=2)

    response = await client.get(f"/approve/{request_id}")

    assert response.status_code == 200
    body = response.text
    assert "foo" in body and "1.2.3" in body  # request summary
    assert "0 of 2 approvals received" in body  # live quorum status
    assert f"/approve/{request_id}/artifact" in body  # artifact download link


async def test_artifact_download_returns_the_exact_staged_bytes(
    client: httpx.AsyncClient, app: FastAPI, seeded: None
) -> None:
    request_id = _create_request(app)

    response = await client.get(f"/approve/{request_id}/artifact")

    assert response.status_code == 200
    assert response.content == ARTIFACT  # the bytes whose hash was voted on
    assert FILENAME in response.headers["content-disposition"]


async def test_page_404s_for_an_unknown_request(
    client: httpx.AsyncClient, app: FastAPI, seeded: None
) -> None:
    response = await client.get("/approve/00000000-0000-0000-0000-000000000000")
    assert response.status_code == 404


async def test_artifact_404s_when_nothing_is_staged(
    client: httpx.AsyncClient, app: FastAPI, seeded: None
) -> None:
    response = await client.get("/approve/00000000-0000-0000-0000-000000000000/artifact")
    assert response.status_code == 404


# --- fresh re-authentication on every vote ---------------------------------


async def test_wrong_password_records_no_vote(
    client: httpx.AsyncClient, app: FastAPI, seeded: None
) -> None:
    request_id = _create_request(app)

    response = await client.post(
        f"/approve/{request_id}",
        data={"username": "alice", "password": "not-alices-password", "decision": "approve"},
    )

    assert response.status_code == 401  # a stolen session without the password cannot vote
    assert "Invalid username or password" in response.text
    assert _vote_count(app, request_id) == 0


async def test_unknown_user_is_unauthorized(
    client: httpx.AsyncClient, app: FastAPI, seeded: None
) -> None:
    request_id = _create_request(app)

    response = await client.post(
        f"/approve/{request_id}",
        data={"username": "mallory", "password": "whatever-123", "decision": "approve"},
    )

    assert response.status_code == 401
    assert _vote_count(app, request_id) == 0


async def test_overlong_password_is_unauthorized_not_an_error(
    client: httpx.AsyncClient, app: FastAPI, seeded: None
) -> None:
    request_id = _create_request(app)

    # A password past bcrypt's 72-byte cap must be a clean 401, never a 500.
    response = await client.post(
        f"/approve/{request_id}",
        data={"username": "alice", "password": "x" * 200, "decision": "approve"},
    )

    assert response.status_code == 401
    assert _vote_count(app, request_id) == 0


# --- the approval outcome --------------------------------------------------


async def test_two_distinct_approvals_reach_quorum(
    client: httpx.AsyncClient, app: FastAPI, seeded: None
) -> None:
    request_id = _create_request(app, quorum=2)

    first = await client.post(f"/approve/{request_id}", data=_form("alice", "approve"))
    assert first.status_code == 200
    assert "waiting for quorum" in first.text
    assert _state(app, request_id) == models.PENDING

    second = await client.post(f"/approve/{request_id}", data=_form("bob", "approve"))
    assert second.status_code == 200
    assert "quorum reached" in second.text
    assert _state(app, request_id) == models.APPROVED
    assert _vote_count(app, request_id) == 2


async def test_a_single_deny_closes_the_request(
    client: httpx.AsyncClient, app: FastAPI, seeded: None
) -> None:
    request_id = _create_request(app, quorum=3)

    response = await client.post(f"/approve/{request_id}", data=_form("alice", "deny"))

    assert response.status_code == 200
    assert "Request denied" in response.text
    assert _state(app, request_id) == models.DENIED


async def test_a_non_approver_is_forbidden(
    client: httpx.AsyncClient, app: FastAPI, seeded: None
) -> None:
    request_id = _create_request(app)

    # publisher is the requester, authenticated but not in the snapshotted approver set.
    response = await client.post(f"/approve/{request_id}", data=_form("publisher", "approve"))

    assert response.status_code == 403
    assert _vote_count(app, request_id) == 0


async def test_withdraw_via_the_page_returns_to_neutral(
    client: httpx.AsyncClient, app: FastAPI, seeded: None
) -> None:
    request_id = _create_request(app, quorum=2)
    await client.post(f"/approve/{request_id}", data=_form("alice", "approve"))  # 1 of 2

    response = await client.post(f"/approve/{request_id}", data=_form("alice", "withdraw"))

    assert response.status_code == 200
    assert "Vote withdrawn" in response.text
    assert _state(app, request_id) == models.PENDING
    assert _vote_count(app, request_id) == 2  # the approve is superseded, not deleted


async def test_identical_repeat_via_the_page_is_a_noop(
    client: httpx.AsyncClient, app: FastAPI, seeded: None
) -> None:
    request_id = _create_request(app, quorum=2)
    await client.post(f"/approve/{request_id}", data=_form("alice", "approve"))

    response = await client.post(f"/approve/{request_id}", data=_form("alice", "approve"))

    assert response.status_code == 200
    assert "No change" in response.text
    assert _vote_count(app, request_id) == 1  # nothing appended for an identical repeat


async def test_an_invalid_decision_is_a_bad_request(
    client: httpx.AsyncClient, app: FastAPI, seeded: None
) -> None:
    request_id = _create_request(app)

    response = await client.post(f"/approve/{request_id}", data=_form("alice", "maybe"))

    assert response.status_code == 400
    assert _vote_count(app, request_id) == 0


async def test_voting_on_a_terminal_request_conflicts(
    client: httpx.AsyncClient, app: FastAPI, seeded: None
) -> None:
    request_id = _create_request(app, quorum=1)
    approved = await client.post(f"/approve/{request_id}", data=_form("alice", "approve"))
    assert approved.status_code == 200
    assert _state(app, request_id) == models.APPROVED

    # The vote set freezes at a terminal state; a later vote is refused.
    late = await client.post(f"/approve/{request_id}", data=_form("bob", "approve"))
    assert late.status_code == 409
    assert _vote_count(app, request_id) == 1
