"""The User Portal ``/account`` — own tokens, self-cancel, and approvals (issue #18).

Real DB, real crypto, real HTTP. Viewing needs only a Proxy Session; every action is
scoped to the authenticated caller; a Vote still routes through ``/approve/{id}``.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import select

from msig_proxy import intake
from msig_proxy.accounts.seed import seed_user
from msig_proxy.core import events, models
from msig_proxy.core.config import AppConfig, ServerConfig, ServiceConfig
from msig_proxy.core.db import session_scope
from msig_proxy.core.models import ApiToken, ApprovalRequest, StagedArtifact, User
from msig_proxy.sessions import SESSION_COOKIE
from tests.support import current_totp

_PW = {name: f"pw-{name}-12345" for name in ("alice", "bob")}


@pytest.fixture(autouse=True)
def _isolate_event_subscribers() -> Iterator[None]:
    yield
    events.clear_subscribers()


@pytest.fixture
def app_config() -> AppConfig:
    return AppConfig(
        server=ServerConfig(
            host="127.0.0.1",
            port=8080,
            base_url="http://testserver",
            secret_key="test-secret-key-0123456789",
        )
    )


@pytest.fixture
def seeded(app: FastAPI) -> None:
    for session in session_scope(app.state.session_factory):
        for name in _PW:
            seed_user(session, username=name, email=f"{name}@example.com", password=_PW[name])


async def _auth(client: httpx.AsyncClient, app: FastAPI, name: str) -> dict[str, str]:
    login = await client.post(
        "/login",
        data={
            "username": name,
            "password": _PW[name],
            "totp": current_totp(app.state.session_factory, name),
        },
        follow_redirects=False,
    )
    return {"Cookie": f"{SESSION_COOKIE}={login.cookies[SESSION_COOKIE]}"}


def _pending_publish(app: FastAPI, *, requester: str, approvers: list[str]) -> str:
    """Create a pending one-time request with the given requester + approver set."""
    request_id = ""
    # Let the loop complete so session_scope commits (an early return skips it).
    for session in session_scope(app.state.session_factory):
        req_user = session.scalars(select(User).where(User.username == requester)).one()
        svc = ServiceConfig(
            type="one-time", action="publish-to-pypi", quorum=len(approvers), approvers=approvers
        )
        request = intake.create_publish_request(
            session,
            requester=req_user,
            service_name="pypi",
            service=svc,
            package_name="foo",
            package_version="1.2.3",
            filename="foo.tar.gz",
            content=b"artifact bytes",
        )
        request_id = str(request.id)
    return request_id


# --- gate -------------------------------------------------------------------


async def test_account_home_requires_a_session(
    client: httpx.AsyncClient, app: FastAPI, seeded: None
) -> None:
    assert (await client.get("/account")).status_code == 401  # anonymous

    auth = await _auth(client, app, "alice")
    page = await client.get("/account", headers=auth)
    assert page.status_code == 200
    assert "alice" in page.text


# --- API tokens -------------------------------------------------------------


async def test_create_list_and_revoke_own_tokens(
    client: httpx.AsyncClient, app: FastAPI, seeded: None
) -> None:
    auth = await _auth(client, app, "alice")

    created = await client.post("/account/tokens", data={"label": "CI runner"}, headers=auth)
    assert created.status_code == 201
    body = created.json()
    assert body["api_token"] and body["label"] == "CI runner"  # plaintext shown once
    token_id = body["token_id"]

    listed = await client.get("/account/tokens", headers=auth)
    labels = {t["label"] for t in listed.json()}
    assert "CI runner" in labels and "seed token" in labels  # the seeded one + the new one
    assert all("api_token" not in t for t in listed.json())  # never re-exposed

    revoke = await client.delete(f"/account/tokens/{token_id}", headers=auth)
    assert revoke.status_code == 200
    for session in session_scope(app.state.session_factory):
        token = session.get(ApiToken, uuid.UUID(token_id))
        assert token is not None and token.revoked_at is not None


async def test_cannot_revoke_another_users_token(
    client: httpx.AsyncClient, app: FastAPI, seeded: None
) -> None:
    # Bob's seeded token id.
    for session in session_scope(app.state.session_factory):
        bob = session.scalars(select(User).where(User.username == "bob")).one()
        bob_token_id = str(
            session.scalars(select(ApiToken).where(ApiToken.user_id == bob.id)).one().id
        )

    alice_auth = await _auth(client, app, "alice")
    resp = await client.delete(f"/account/tokens/{bob_token_id}", headers=alice_auth)
    assert resp.status_code == 404  # not the caller's token


# --- own requests + self-cancel --------------------------------------------


async def test_list_own_requests_and_self_cancel(
    client: httpx.AsyncClient, app: FastAPI, seeded: None
) -> None:
    request_id = _pending_publish(app, requester="alice", approvers=["bob"])
    recorded: list[events.Event] = []
    events.subscribe(recorded.append)
    auth = await _auth(client, app, "alice")

    listed = await client.get("/account/requests", headers=auth)
    assert any(r["id"] == request_id and r["state"] == models.PENDING for r in listed.json())

    cancel = await client.post(f"/account/requests/{request_id}/cancel", headers=auth)
    assert cancel.status_code == 200
    assert cancel.json()["state"] == models.CANCELLED
    assert events.REQUEST_CANCELLED in [e.name for e in recorded]

    # Cancelling a non-pending request is rejected.
    again = await client.post(f"/account/requests/{request_id}/cancel", headers=auth)
    assert again.status_code == 409


async def test_self_cancel_destroys_the_held_artifact(
    client: httpx.AsyncClient, app: FastAPI, seeded: None
) -> None:
    # Cancellation is a non-handoff terminal: the held bytes must not outlive the
    # request (docs/request-lifecycle.md §163), so cancel destroys them + emits the event.
    request_id = _pending_publish(app, requester="alice", approvers=["bob"])
    recorded: list[events.Event] = []
    events.subscribe(recorded.append)
    auth = await _auth(client, app, "alice")

    for session in session_scope(app.state.session_factory):
        assert session.get(StagedArtifact, uuid.UUID(request_id)) is not None  # staged

    cancel = await client.post(f"/account/requests/{request_id}/cancel", headers=auth)
    assert cancel.status_code == 200

    for session in session_scope(app.state.session_factory):
        assert session.get(StagedArtifact, uuid.UUID(request_id)) is None  # destroyed
    destroyed = [e for e in recorded if e.name == events.ARTIFACT_DESTROYED]
    assert len(destroyed) == 1
    assert destroyed[0].payload["approval_request_id"] == request_id
    assert destroyed[0].payload["terminal_state"] == models.CANCELLED


async def test_cannot_cancel_another_users_request(
    client: httpx.AsyncClient, app: FastAPI, seeded: None
) -> None:
    request_id = _pending_publish(app, requester="alice", approvers=["bob"])

    bob_auth = await _auth(client, app, "bob")
    resp = await client.post(f"/account/requests/{request_id}/cancel", headers=bob_auth)
    assert resp.status_code == 404  # not bob's request

    for session in session_scope(app.state.session_factory):
        request = session.get(ApprovalRequest, uuid.UUID(request_id))
        assert request is not None and request.state == models.PENDING  # untouched


# --- approvals + vote from the portal --------------------------------------


async def test_approvals_list_and_vote_routes_through_approve(
    client: httpx.AsyncClient, app: FastAPI, seeded: None
) -> None:
    # Bob requests; alice + bob are the eligible approvers (quorum 2, so one vote
    # leaves it pending — no handoff/publish fires).
    request_id = _pending_publish(app, requester="bob", approvers=["alice", "bob"])
    alice_auth = await _auth(client, app, "alice")

    approvals = await client.get("/account/approvals", headers=alice_auth)
    entry = next(a for a in approvals.json() if a["id"] == request_id)
    assert entry["your_vote"] is None  # not yet voted
    assert entry["approve_url"] == f"/approve/{request_id}"  # links out to the signed-vote flow

    # Casting the vote goes through the re-auth flow, not a one-click portal button.
    voted = await client.post(
        entry["approve_url"],
        data={
            "username": "alice",
            "password": _PW["alice"],
            "totp": current_totp(app.state.session_factory, "alice"),
            "decision": "approve",
        },
    )
    assert voted.status_code == 200

    # The portal now reflects the recorded vote (still pending — quorum 2).
    after = await client.get("/account/approvals", headers=alice_auth)
    entry = next(a for a in after.json() if a["id"] == request_id)
    assert entry["your_vote"] == models.APPROVE
