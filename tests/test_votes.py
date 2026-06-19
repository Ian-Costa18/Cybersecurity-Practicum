"""The approval core: signed votes, effective-vote quorum, and the single-deny rule.

Real DB, real crypto. Exercises the decision logic in :mod:`msig_proxy.votes`
below the HTTP layer (the page itself is covered in ``test_approve.py``).
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from msig_proxy import crypto, models, votes
from msig_proxy.config import ServiceConfig
from msig_proxy.db import Base, create_db_engine, create_session_factory
from msig_proxy.intake import create_publish_request
from msig_proxy.models import ApprovalRequest, User
from msig_proxy.seed import seed_user

# Passwords are deterministic per username so a vote can re-authenticate later.
_PASSWORD = {name: f"pw-{name}-123" for name in ("alice", "bob", "carol", "dave")}


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


def _user(session: Session, name: str) -> User:
    return session.scalars(select(User).where(User.username == name)).one()


def _user_id(session: Session, name: str) -> uuid.UUID:
    return session.scalars(select(User.id).where(User.username == name)).one()


def _pending_request(session: Session, *, quorum: int, approvers: list[str]) -> ApprovalRequest:
    for name in approvers:
        seed_user(session, username=name, email=f"{name}@example.com", password=_PASSWORD[name])
    requester = seed_user(
        session, username="publisher", email="publisher@example.com", password="pub-pw-123"
    ).user
    service = ServiceConfig(
        type="one-time", action="publish-to-pypi", quorum=quorum, approvers=approvers
    )
    return create_publish_request(
        session,
        requester=requester,
        service_name="pypi",
        service=service,
        package_name="foo",
        package_version="1.2.3",
        filename="foo-1.2.3.tar.gz",
        content=b"the exact artifact bytes",
    )


def _vote(
    session: Session, request: ApprovalRequest, name: str, decision: str
) -> votes.VoteOutcome:
    return votes.cast_vote(
        session,
        request=request,
        approver=_user(session, name),
        password=_PASSWORD[name],
        decision=decision,
    )


def test_quorum_reached_only_at_the_threshold(session: Session) -> None:
    request = _pending_request(session, quorum=2, approvers=["alice", "bob", "carol"])

    # Quorum-bypass oracle: at t = m-1 (one approval), there is NO transition.
    outcome = _vote(session, request, "alice", models.APPROVE)
    assert outcome.state == models.PENDING
    assert outcome.tally.approvals == 1
    assert request.state == models.PENDING

    # The m-th approval — and only it — flips the request to approved.
    outcome = _vote(session, request, "bob", models.APPROVE)
    assert outcome.state == models.APPROVED
    assert request.state == models.APPROVED


def test_a_single_deny_closes_the_request_immediately(session: Session) -> None:
    request = _pending_request(session, quorum=3, approvers=["alice", "bob", "carol"])

    _vote(session, request, "alice", models.APPROVE)
    outcome = _vote(session, request, "bob", models.DENY)

    assert outcome.state == models.DENIED  # one deny, no "quorum of denials"
    assert request.state == models.DENIED


def test_a_flip_to_deny_before_quorum_closes_denied(session: Session) -> None:
    request = _pending_request(session, quorum=3, approvers=["alice", "bob", "carol"])

    _vote(session, request, "alice", models.APPROVE)
    flip = _vote(session, request, "alice", models.DENY)  # supersede own approve

    assert flip.state == models.DENIED
    # The prior approve is retained for audit — supersession appends, never overwrites.
    alice_id = _user_id(session, "alice")
    alice_votes = [
        v.decision for v in votes.votes_for(session, request.id) if v.approver_id == alice_id
    ]
    assert alice_votes == [models.APPROVE, models.DENY]


def test_withdraw_drops_an_approval_below_quorum(session: Session) -> None:
    request = _pending_request(session, quorum=2, approvers=["alice", "bob", "carol"])

    _vote(session, request, "alice", models.APPROVE)
    outcome = _vote(session, request, "alice", models.WITHDRAW)  # retract to neutral

    assert outcome.tally.approvals == 0
    assert outcome.state == models.PENDING
    # bob alone cannot now reach quorum=2.
    outcome = _vote(session, request, "bob", models.APPROVE)
    assert outcome.state == models.PENDING


def test_identical_repeat_is_an_idempotent_noop(session: Session) -> None:
    request = _pending_request(session, quorum=2, approvers=["alice", "bob"])

    _vote(session, request, "alice", models.APPROVE)
    repeat = _vote(session, request, "alice", models.APPROVE)

    assert repeat.recorded is False
    assert len(votes.votes_for(session, request.id)) == 1  # no second row for an identical repeat


def test_vote_is_ed25519_signed_and_verifies_offline(session: Session) -> None:
    request = _pending_request(session, quorum=2, approvers=["alice", "bob"])
    _vote(session, request, "alice", models.APPROVE)

    vote = votes.votes_for(session, request.id)[0]
    alice = _user(session, "alice")

    record = votes.record_for_vote(vote)
    assert crypto.verify_record(
        public_key=alice.public_key, record=record, signature=vote.signature
    )
    assert vote.action_hash == request.artifact_sha256  # the payload approved is the bound hash

    # Tamper detection: a flipped decision no longer verifies under the same signature.
    tampered = {**record, "decision": models.DENY}
    assert not crypto.verify_record(
        public_key=alice.public_key, record=tampered, signature=vote.signature
    )


def test_wrong_password_is_rejected_and_records_nothing(session: Session) -> None:
    request = _pending_request(session, quorum=2, approvers=["alice", "bob"])

    with pytest.raises(votes.AuthenticationFailed):
        votes.cast_vote(
            session,
            request=request,
            approver=_user(session, "alice"),
            password="wrong-password",
            decision=models.APPROVE,
        )
    assert votes.votes_for(session, request.id) == []


def test_an_unknown_user_is_an_authentication_failure(session: Session) -> None:
    request = _pending_request(session, quorum=2, approvers=["alice", "bob"])

    # ``None`` approver (username resolved to nothing) is indistinguishable from a bad password.
    with pytest.raises(votes.AuthenticationFailed):
        votes.cast_vote(
            session, request=request, approver=None, password="whatever", decision=models.APPROVE
        )


def test_a_non_eligible_user_cannot_vote(session: Session) -> None:
    request = _pending_request(session, quorum=2, approvers=["alice", "bob"])
    # A real, authenticatable user who simply is not in this request's approver set.
    seed_user(session, username="dave", email="dave@example.com", password=_PASSWORD["dave"])

    with pytest.raises(votes.NotAnEligibleApprover):
        _vote(session, request, "dave", models.APPROVE)


def test_voting_is_frozen_after_a_terminal_state(session: Session) -> None:
    request = _pending_request(session, quorum=2, approvers=["alice", "bob", "carol"])
    _vote(session, request, "alice", models.APPROVE)
    _vote(session, request, "bob", models.APPROVE)  # -> approved
    assert request.state == models.APPROVED

    with pytest.raises(votes.RequestNotPending):
        _vote(session, request, "carol", models.APPROVE)
