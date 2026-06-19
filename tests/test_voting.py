"""The voting service seam: signed, append-only Votes drive effective-vote quorum
and the single-denial rule out of ``pending`` (ADR 0009, ``docs/request-lifecycle.md``).

Real DB, real crypto. This exercises the logic below the HTTP layer; the
approve/deny page and fresh re-authentication are covered in ``test_approve.py``.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from msig_proxy import crypto, models, voting
from msig_proxy.config import ServiceConfig
from msig_proxy.db import Base, create_db_engine, create_session_factory
from msig_proxy.intake import create_publish_request
from msig_proxy.models import ApprovalRequest, User, Vote
from msig_proxy.seed import seed_user

ARTIFACT = b"the exact artifact bytes the approvers vote on"


def _password(name: str) -> str:
    return f"pw-{name}-123"


@pytest.fixture
def session() -> Iterator[Session]:
    """A real session over a throwaway in-memory SQLite DB (never mocked)."""
    engine = create_db_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    db = create_session_factory(engine)()
    try:
        yield db
    finally:
        db.close()
        engine.dispose()


def _seed_cast(session: Session) -> User:
    """Seed alice/bob/carol approvers + a separate publisher; return the publisher."""
    for name in ("alice", "bob", "carol"):
        seed_user(session, username=name, email=f"{name}@example.com", password=_password(name))
    return seed_user(
        session,
        username="publisher",
        email="publisher@example.com",
        password=_password("publisher"),
    ).user


def _pending_request(session: Session, *, quorum: int) -> ApprovalRequest:
    requester = _seed_cast(session)
    service = ServiceConfig(
        type="one-time",
        action="publish-to-pypi",
        quorum=quorum,
        approvers=["alice", "bob", "carol"],
    )
    return create_publish_request(
        session,
        requester=requester,
        service_name="pypi",
        service=service,
        package_name="foo",
        package_version="1.2.3",
        filename="foo-1.2.3.tar.gz",
        content=ARTIFACT,
    )


def _user(session: Session, name: str) -> User:
    return session.scalars(select(User).where(User.username == name)).one()


def _approve(session: Session, request: ApprovalRequest, name: str) -> voting.VoteOutcome:
    return voting.cast_vote(
        session,
        request=request,
        approver=_user(session, name),
        password=_password(name),
        decision=models.VOTE_APPROVE,
    )


def _vote(
    session: Session, request: ApprovalRequest, name: str, decision: str
) -> voting.VoteOutcome:
    return voting.cast_vote(
        session,
        request=request,
        approver=_user(session, name),
        password=_password(name),
        decision=decision,
    )


# --- quorum and the adversarial t = m-1 oracle ----------------------------


def test_below_quorum_stays_pending(session: Session) -> None:
    # Quorum-bypass oracle: at t = m-1 (two of three) the request must NOT approve.
    request = _pending_request(session, quorum=3)

    _approve(session, request, "alice")
    outcome = _approve(session, request, "bob")

    assert outcome.approvals == 2
    assert outcome.request_state == models.PENDING
    assert session.get(ApprovalRequest, request.id).state == models.PENDING


def test_quorum_reached_transitions_to_approved(session: Session) -> None:
    request = _pending_request(session, quorum=2)

    _approve(session, request, "alice")
    outcome = _approve(session, request, "bob")

    assert outcome.request_state == models.APPROVED
    assert outcome.approvals == 2
    assert session.get(ApprovalRequest, request.id).state == models.APPROVED


def test_distinct_approvers_required_for_quorum(session: Session) -> None:
    # Two distinct approvers, not one approver voting twice, reach a quorum of two.
    request = _pending_request(session, quorum=2)

    _approve(session, request, "alice")
    again = _approve(session, request, "alice")  # identical repeat, a no-op

    assert again.unchanged is True
    assert again.approvals == 1
    assert session.get(ApprovalRequest, request.id).state == models.PENDING


# --- the single-denial rule ------------------------------------------------


def test_single_deny_closes_request_immediately(session: Session) -> None:
    request = _pending_request(session, quorum=3)

    _approve(session, request, "alice")
    outcome = _vote(session, request, "carol", models.VOTE_DENY)

    assert outcome.request_state == models.DENIED
    assert session.get(ApprovalRequest, request.id).state == models.DENIED


def test_deny_dominates_a_quorum_of_approvals(session: Session) -> None:
    # The same-instant case the lifecycle serializes: an effective deny alongside a
    # quorum of effective approvals still closes the request denied (unit of _evaluate).
    effective = {
        "a": Vote(decision=models.VOTE_APPROVE),
        "b": Vote(decision=models.VOTE_APPROVE),
        "c": Vote(decision=models.VOTE_DENY),
    }
    assert voting._evaluate(effective, quorum=2) == models.DENIED


# --- append-only supersession and withdrawal -------------------------------


def test_changed_decision_supersedes_and_is_appended(session: Session) -> None:
    request = _pending_request(session, quorum=3)

    _approve(session, request, "alice")
    outcome = _vote(session, request, "alice", models.VOTE_DENY)  # alice flips to deny

    # Both Votes are retained for audit; the effective (latest) one is the deny.
    history = session.scalars(
        select(Vote).where(Vote.approver_id == _user(session, "alice").id).order_by(Vote.id)
    ).all()
    assert [v.decision for v in history] == [models.VOTE_APPROVE, models.VOTE_DENY]
    effective = voting.effective_votes(session, request.id)
    assert effective[_user(session, "alice").id].decision == models.VOTE_DENY
    assert outcome.request_state == models.DENIED  # the flip-to-deny closes it


def test_identical_repeat_is_a_noop(session: Session) -> None:
    request = _pending_request(session, quorum=3)

    _approve(session, request, "alice")
    outcome = _approve(session, request, "alice")  # same decision again

    assert outcome.unchanged is True
    assert outcome.vote is None
    count = session.scalar(
        select(func.count()).select_from(Vote).where(Vote.approval_request_id == request.id)
    )
    assert count == 1  # nothing appended for an identical repeat


def test_withdraw_returns_an_approver_to_neutral(session: Session) -> None:
    request = _pending_request(session, quorum=2)

    _approve(session, request, "alice")  # 1 of 2
    outcome = _vote(session, request, "alice", models.VOTE_WITHDRAW)

    assert outcome.approvals == 0  # withdraw drops the endorsement
    assert outcome.request_state == models.PENDING
    history = session.scalars(
        select(Vote).where(Vote.approval_request_id == request.id).order_by(Vote.id)
    ).all()
    assert [v.decision for v in history] == [models.VOTE_APPROVE, models.VOTE_WITHDRAW]


# --- the signed audit record ----------------------------------------------


def test_vote_is_signed_and_verifies_offline(session: Session) -> None:
    request = _pending_request(session, quorum=3)
    outcome = _approve(session, request, "alice")
    session.commit()

    alice = _user(session, "alice")
    assert outcome.vote is not None
    assert outcome.vote.key_id == crypto.key_fingerprint(alice.public_key)
    assert outcome.vote.action_hash == request.artifact_sha256  # Hash Binding

    # Reload from a fresh session so the offline check runs against persisted columns
    # (SQLite returns the timestamp naive — verify_vote re-attaches UTC).
    engine = session.get_bind()
    reloaded_session = create_session_factory(engine)()
    try:
        reloaded = reloaded_session.scalars(
            select(Vote).where(Vote.id == outcome.vote.id)
        ).one()
        public_key = reloaded_session.get(User, alice.id).public_key
        assert voting.verify_vote(public_key=public_key, vote=reloaded) is True

        reloaded.decision = models.VOTE_DENY  # tamper with the recorded decision
        assert voting.verify_vote(public_key=public_key, vote=reloaded) is False
    finally:
        reloaded_session.close()


# --- preconditions ---------------------------------------------------------


def test_non_approver_cannot_vote(session: Session) -> None:
    request = _pending_request(session, quorum=2)  # publisher is the requester, not an approver

    with pytest.raises(voting.NotAnApproverError):
        _vote(session, request, "publisher", models.VOTE_APPROVE)


def test_votes_freeze_after_a_terminal_state(session: Session) -> None:
    request = _pending_request(session, quorum=1)
    _approve(session, request, "alice")  # quorum 1 → approved immediately
    assert session.get(ApprovalRequest, request.id).state == models.APPROVED

    with pytest.raises(voting.VotesFrozenError):
        _approve(session, request, "bob")


def test_unknown_decision_is_rejected(session: Session) -> None:
    request = _pending_request(session, quorum=2)

    with pytest.raises(voting.UnknownDecisionError):
        _vote(session, request, "alice", "maybe")
