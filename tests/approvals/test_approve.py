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
from msig_proxy.approvals import votes
from msig_proxy.approvals.approve import endorser_event_stream
from msig_proxy.core import models
from msig_proxy.core.config import ServiceConfig
from msig_proxy.core.db import session_scope
from msig_proxy.core.models import ApprovalRequest, User, Vote
from msig_proxy.service_types.one_time.intake import create_publish_request
from tests.support import totp_code, totp_code_at

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


async def test_deny_records_the_optional_reason(
    client: httpx.AsyncClient, app: FastAPI, pending_request_id: str
) -> None:
    # The optional free-text denial reason is captured on the request (#87) for the
    # waiting room's denial screen + the `denied` SSE frame.
    response = await client.post(
        f"/approve/{pending_request_id}",
        data={**_vote_data("alice", "deny"), "reason": "package looks malicious"},
    )

    assert response.status_code == 200
    for session in session_scope(app.state.session_factory):
        approval = session.get(ApprovalRequest, uuid.UUID(pending_request_id))
        assert approval is not None
        assert approval.state == models.DENIED
        assert approval.denial_reason == "package looks malicious"


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


async def test_approve_page_forbids_framing(
    client: httpx.AsyncClient, pending_request_id: str
) -> None:
    # VOTE-3 UI-redress leg (#127): the approve page is where a disguised click becomes a
    # signed, genuine vote. Anti-framing headers must forbid embedding it in an attacker's
    # page so a clickjacking overlay cannot ride a real approval ceremony.
    response = await client.get(f"/approve/{pending_request_id}")

    assert response.status_code == 200
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Content-Security-Policy"] == "frame-ancestors 'none'"


async def test_artifact_download_returns_the_staged_bytes(
    client: httpx.AsyncClient, pending_request_id: str
) -> None:
    response = await client.get(f"/approve/{pending_request_id}/artifact")

    assert response.status_code == 200
    assert response.content == ARTIFACT  # exactly the bytes whose hash is being signed over
    # Served inert (VOTE-5): octet-stream attachment the browser will not re-interpret.
    assert response.headers["content-type"] == "application/octet-stream"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert "attachment" in response.headers["content-disposition"]


async def test_artifact_download_neutralizes_a_hostile_filename(
    client: httpx.AsyncClient, app: FastAPI
) -> None:
    # VOTE-5: the uploaded filename is requester-controlled and echoed on the inspection
    # download. A name carrying a quote/CRLF must not inject response-header syntax, and
    # every artifact response must stay inert (octet-stream + attachment + nosniff) so a
    # browser never re-interprets the bytes as active content.
    hostile = 'evil"\r\nX-Injected: pwned\r\n"; filename="totally-safe.txt'
    request_id = ""
    for session in session_scope(app.state.session_factory):
        requester = seed_user(
            session, username="pub2", email="pub2@example.com", password="pub-pw-123"
        ).user
        seed_user(session, username="appr2", email="appr2@example.com", password="ap-pw-123")
        service = ServiceConfig(
            type="one-time", action="publish-to-pypi", quorum=2, approvers=["*"]
        )
        request = create_publish_request(
            session,
            requester=requester,
            service_name="pypi",
            service=service,
            package_name="foo",
            package_version="1.2.3",
            filename=hostile,
            content=ARTIFACT,
        )
        request_id = str(request.id)

    response = await client.get(f"/approve/{request_id}/artifact")

    assert response.status_code == 200
    assert response.content == ARTIFACT
    # The hostile filename smuggled no new header past the parser.
    assert "x-injected" not in response.headers
    # Inert-download headers hold, and no raw CR/LF/quote survived into the disposition.
    assert response.headers["content-type"] == "application/octet-stream"
    assert response.headers["x-content-type-options"] == "nosniff"
    disposition = response.headers["content-disposition"]
    assert disposition.startswith("attachment")
    # The hostile name was percent-encoded into filename*: no raw CR/LF or quote survived to
    # break out of the header value (the encoded "X-Injected" text is inert — its colon and
    # CRLF are %-escaped, so it cannot form a real header).
    assert "\r" not in disposition and "\n" not in disposition
    assert '"' not in disposition
    assert "filename*=UTF-8''" in disposition


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


# --- live approver visibility (#22) -----------------------------------------


def _cast(app: FastAPI, request_id: str, name: str, decision: str, *, offset: int = 0) -> None:
    """Cast one signed Vote through the seam (offset picks a distinct TOTP step so the
    same Approver can act twice in one window without tripping single-use, #73)."""
    for session in session_scope(app.state.session_factory):
        request = session.get(ApprovalRequest, uuid.UUID(request_id))
        assert request is not None
        approver = session.scalars(select(User).where(User.username == name)).one()
        votes.cast_vote(
            session,
            request=request,
            approver=approver,
            password=_PASSWORD[name],
            totp=totp_code_at(_SECRETS[name], offset),
            totp_valid_window=1,
            decision=decision,
        )


async def test_page_names_endorsers_and_counts_the_rest(
    client: httpx.AsyncClient, app: FastAPI, pending_request_id: str
) -> None:
    # One of two approvals in: the endorser is named, the remainder is a bare count.
    await client.post(f"/approve/{pending_request_id}", data=_vote_data("alice", "approve"))

    page = await client.get(f"/approve/{pending_request_id}")

    assert page.status_code == 200
    body = page.text
    assert "alice" in body  # the Endorsing Approver is named
    assert "waiting on 1 more" in body  # quorum 2, one approval => one remaining
    # Non-endorsers — eligible approvers who have not approved — are never named.
    assert "bob" not in body and "carol" not in body


async def test_withdrawn_approver_is_not_named(
    client: httpx.AsyncClient, app: FastAPI, pending_request_id: str
) -> None:
    _cast(app, pending_request_id, "alice", models.APPROVE, offset=0)
    _cast(app, pending_request_id, "alice", models.WITHDRAW, offset=1)

    page = await client.get(f"/approve/{pending_request_id}")

    assert page.status_code == 200
    # A withdrawal drops the User off the named list (indistinguishable from a non-actor).
    assert "alice" not in page.text
    assert "No approvals yet" in page.text


async def test_stream_is_link_scoped_and_names_endorsers(
    client: httpx.AsyncClient, app: FastAPI, pending_request_id: str
) -> None:
    # Drive to APPROVED so the stream is finite (terminal frame, then it closes).
    await client.post(f"/approve/{pending_request_id}", data=_vote_data("alice", "approve"))
    await client.post(f"/approve/{pending_request_id}", data=_vote_data("bob", "approve"))

    # No session cookie: the stream is reachable with the approval link alone (INFO-1).
    stream = await client.get(f"/approve/{pending_request_id}/stream")

    assert stream.status_code == 200
    assert "text/event-stream" in stream.headers["content-type"]
    assert "quorum_reached" in stream.text
    assert "alice" in stream.text and "bob" in stream.text  # endorser identities ride the frame


def test_stream_emits_on_identity_change_with_constant_count(
    app: FastAPI, pending_request_id: str
) -> None:
    # The change-detection key is the endorser *set*, not the count: a withdraw paired
    # with a new approve holds the count at 1 but must still push a frame (#22).
    request_id = uuid.UUID(pending_request_id)
    _cast(app, pending_request_id, "alice", models.APPROVE, offset=0)  # 1 of 2, pending

    # The generator suspends at each yield with its per-poll session already closed,
    # so two pulls leak nothing; the unreferenced generator is collected at test end.
    gen = endorser_event_stream(app.state.session_factory, request_id, poll_interval=0)
    frame1 = next(gen)
    assert "alice" in frame1

    # Swap the endorser while the count stays 1: alice withdraws, carol approves.
    _cast(app, pending_request_id, "alice", models.WITHDRAW, offset=1)
    _cast(app, pending_request_id, "carol", models.APPROVE, offset=0)

    frame2 = next(gen)
    assert "carol" in frame2  # the new endorser surfaces despite the count holding
    assert "alice" not in frame2  # the withdrawn approver drops off
