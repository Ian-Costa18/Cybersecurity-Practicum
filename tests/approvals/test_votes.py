"""The approval core: signed votes, effective-vote quorum, and the single-deny rule.

Real DB, real crypto. Exercises the decision logic in :mod:`msig_proxy.votes`
below the HTTP layer (the page itself is covered in ``test_approve.py``).
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from dataclasses import replace

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from msig_proxy.accounts import keys
from msig_proxy.accounts.seed import seed_user
from msig_proxy.approvals import votes
from msig_proxy.core import crypto, models
from msig_proxy.core.config import ServiceConfig
from msig_proxy.core.db import Base, create_db_engine, create_session_factory
from msig_proxy.core.models import ApprovalRequest, ConsumedTotp, User
from msig_proxy.service_types.one_time.intake import create_publish_request
from tests.support import plaintext_totp_secret, totp_code, totp_code_for

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
    session: Session,
    request: ApprovalRequest,
    name: str,
    decision: str,
    *,
    totp_offset: int = 0,
) -> votes.VoteOutcome:
    approver = _user(session, name)
    assert approver.totp_secret is not None  # seeded users carry a TOTP secret (#16)
    # Single-use TOTP (#73) burns the matched step, so a same-user re-vote in one
    # window must use a distinct still-valid code: ``totp_offset`` selects another
    # step within valid_window=1 (steps t-1/t/t+1) instead of waiting out the window.
    # The secret is wrapped at rest now (#122), so the code is derived by decrypting
    # under the approver's password — the same key the verifier will use.
    return votes.cast_vote(
        session,
        request=request,
        approver=approver,
        password=_PASSWORD[name],
        totp=totp_code_for(approver, _PASSWORD[name], totp_offset),
        totp_valid_window=1,
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


def test_cast_vote_takes_a_row_lock_on_the_request(
    session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Vote application serializes via a row lock (SELECT ... FOR UPDATE) per the spec's
    # named mechanism (#84, docs/request-lifecycle.md §Design notes). On SQLite the
    # lock is a no-op, so assert the locking statement is *issued*, not its effect.
    from sqlalchemy import Select

    request = _pending_request(session, quorum=2, approvers=["alice", "bob"])
    from typing import Any

    captured: list[object] = []
    original = session.execute

    def _spy(statement: Any, *args: Any, **kwargs: Any) -> Any:
        captured.append(statement)
        return original(statement, *args, **kwargs)

    monkeypatch.setattr(session, "execute", _spy)
    _vote(session, request, "alice", models.APPROVE)

    assert any(isinstance(s, Select) and s._for_update_arg is not None for s in captured), (
        "cast_vote must SELECT ... FOR UPDATE the Approval Request row"
    )


def test_a_single_deny_closes_the_request_immediately(session: Session) -> None:
    request = _pending_request(session, quorum=3, approvers=["alice", "bob", "carol"])

    _vote(session, request, "alice", models.APPROVE)
    outcome = _vote(session, request, "bob", models.DENY)

    assert outcome.state == models.DENIED  # one deny, no "quorum of denials"
    assert request.state == models.DENIED


def test_a_flip_to_deny_before_quorum_closes_denied(session: Session) -> None:
    request = _pending_request(session, quorum=3, approvers=["alice", "bob", "carol"])

    _vote(session, request, "alice", models.APPROVE)
    # A distinct still-valid TOTP for the second same-user cast (the first burned t).
    flip = _vote(session, request, "alice", models.DENY, totp_offset=1)  # supersede own approve

    assert flip.state == models.DENIED
    # The prior approve is retained for audit — supersession appends, never overwrites.
    alice_id = _user_id(session, "alice")
    alice_votes = [
        v.decision for v in votes._votes_for(session, request.id) if v.approver_id == alice_id
    ]
    assert alice_votes == [models.APPROVE, models.DENY]


def test_withdraw_drops_an_approval_below_quorum(session: Session) -> None:
    request = _pending_request(session, quorum=2, approvers=["alice", "bob", "carol"])

    _vote(session, request, "alice", models.APPROVE)
    # Distinct still-valid TOTP for the retraction (the approve burned step t).
    outcome = _vote(session, request, "alice", models.WITHDRAW, totp_offset=1)  # retract to neutral

    assert outcome.tally.approvals == 0
    assert outcome.state == models.PENDING
    # bob alone cannot now reach quorum=2.
    outcome = _vote(session, request, "bob", models.APPROVE)
    assert outcome.state == models.PENDING


def test_identical_repeat_is_an_idempotent_noop(session: Session) -> None:
    request = _pending_request(session, quorum=2, approvers=["alice", "bob"])

    _vote(session, request, "alice", models.APPROVE)
    # The identical *decision* is the no-op under test, but it must arrive on a
    # distinct still-valid code: single-use TOTP (#73) burned step t, so reusing the
    # same code would fail auth (a different failure) before the idempotency check.
    repeat = _vote(session, request, "alice", models.APPROVE, totp_offset=1)

    assert repeat.recorded is False
    assert len(votes._votes_for(session, request.id)) == 1  # no second row for an identical repeat


def test_vote_is_ed25519_signed_and_verifies_offline(session: Session) -> None:
    request = _pending_request(session, quorum=2, approvers=["alice", "bob"])
    _vote(session, request, "alice", models.APPROVE)

    vote = votes._votes_for(session, request.id)[0]
    alice = _user(session, "alice")
    alice_key = keys.active_key(session, alice)
    assert alice_key is not None  # an enrolled user has an active signing key (#53)
    assert vote.key_id == alice_key.id  # the vote names the exact key that signed it
    alice_public_key = alice_key.public_key

    record = votes.record_for_vote(vote, quorum=request.quorum)
    assert crypto.verify_record(
        public_key=alice_public_key, message=record.canonical_bytes(), signature=vote.signature
    )
    assert vote.action_hash == request.artifact_sha256  # the payload approved is the bound hash

    # Tamper detection: a flipped decision no longer verifies under the same signature.
    tampered = replace(record, decision=models.DENY)
    assert not crypto.verify_record(
        public_key=alice_public_key, message=tampered.canonical_bytes(), signature=vote.signature
    )


def test_a_reenrolled_users_old_votes_still_verify(session: Session) -> None:
    # The regression #53 exists to prevent: before normalization, re-enrollment
    # overwrote the single key on the User row, so an old vote verified against the
    # WRONG (new) public key. Now each key is its own row; the vote names the exact
    # key that signed it, and retirement keeps that key's public half forever.
    request = _pending_request(session, quorum=2, approvers=["alice", "bob"])
    _vote(session, request, "alice", models.APPROVE)
    vote = votes._votes_for(session, request.id)[0]

    alice = _user(session, "alice")
    old_key = keys.active_key(session, alice)
    assert old_key is not None and vote.key_id == old_key.id

    # Admin reset + re-enrollment: retire the signing key (drop the private half,
    # keep the public), then mint a fresh active key — exactly what admin.reset_user
    # followed by enroll do, and what the partial unique index must permit.
    keys.retire_active_key(session, alice)
    keys.create_active_key(session, alice, "alice-rotated-pw")
    session.flush()
    new_key = keys.active_key(session, alice)
    assert new_key is not None and new_key.id != old_key.id
    assert old_key.revoked_at is not None and old_key.encrypted_private_key is None  # retired

    # The historical vote resolves to the RETIRED key and still verifies against it
    # (the public half outlives retirement)...
    resolved = keys.public_key_for(session, vote.key_id)
    assert resolved is not None and resolved == old_key.public_key
    record = votes.record_for_vote(vote, quorum=request.quorum)
    assert crypto.verify_record(
        public_key=resolved, message=record.canonical_bytes(), signature=vote.signature
    )
    # ...and does NOT verify against the user's NEW key — the silent break #53 fixes.
    assert not crypto.verify_record(
        public_key=new_key.public_key, message=record.canonical_bytes(), signature=vote.signature
    )


def test_vote_record_canonical_bytes_is_stable_and_field_sensitive() -> None:
    base = votes.VoteRecord(
        approver_id=uuid.UUID(int=1),
        key_id=uuid.UUID(int=3),
        approval_request_id=uuid.UUID(int=2),
        timestamp="2026-06-19T12:00:00+00:00",
        action_hash="a" * 64,
        decision=models.APPROVE,
        quorum=2,
    )
    # Deterministic: an equal record serializes to identical bytes, which is why
    # the sign path and the rebuilt verify path provably agree.
    assert base.canonical_bytes() == replace(base).canonical_bytes()
    # Field-sensitive: flipping a field changes the signed bytes (tamper-evident).
    assert base.canonical_bytes() != replace(base, decision=models.DENY).canonical_bytes()
    # The snapshotted quorum is bound too (#121): a lowered threshold breaks the signature.
    assert base.canonical_bytes() != replace(base, quorum=1).canonical_bytes()


def test_wrong_password_is_rejected_and_records_nothing(session: Session) -> None:
    request = _pending_request(session, quorum=2, approvers=["alice", "bob"])

    with pytest.raises(votes.AuthenticationFailed):
        votes.cast_vote(
            session,
            request=request,
            approver=_user(session, "alice"),
            password="wrong-password",
            totp="000000",  # irrelevant — the password check fails first
            totp_valid_window=1,
            decision=models.APPROVE,
        )
    assert votes._votes_for(session, request.id) == []


def test_a_valid_password_with_a_bad_totp_is_rejected(session: Session) -> None:
    # Two factors, no fallback (#16): a correct password but wrong TOTP records nothing.
    request = _pending_request(session, quorum=2, approvers=["alice", "bob"])

    with pytest.raises(votes.AuthenticationFailed):
        votes.cast_vote(
            session,
            request=request,
            approver=_user(session, "alice"),
            password=_PASSWORD["alice"],
            totp="000000",  # not a valid code for alice's secret
            totp_valid_window=1,
            decision=models.APPROVE,
        )
    assert votes._votes_for(session, request.id) == []


def test_an_unknown_user_is_an_authentication_failure(session: Session) -> None:
    request = _pending_request(session, quorum=2, approvers=["alice", "bob"])

    # ``None`` approver (username resolved to nothing) is indistinguishable from a bad password.
    with pytest.raises(votes.AuthenticationFailed):
        votes.cast_vote(
            session,
            request=request,
            approver=None,
            password="whatever",
            totp="000000",
            totp_valid_window=1,
            decision=models.APPROVE,
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


def test_a_reused_totp_code_is_burned_and_rejected(session: Session) -> None:
    # Single-use TOTP (#73, RFC 6238 §5.2): an accepted code is burned per
    # (user, time-step); the *same* code resubmitted in the same window is refused
    # even though the password and code are otherwise valid.
    request = _pending_request(session, quorum=3, approvers=["alice", "bob", "carol"])
    alice = _user(session, "alice")
    assert alice.totp_secret is not None
    secret = plaintext_totp_secret(alice, _PASSWORD["alice"])  # wrapped at rest (#122)
    code = totp_code(secret)
    expected_step = crypto.matched_totp_step(secret, code, valid_window=1)
    assert expected_step is not None

    first = votes.cast_vote(
        session,
        request=request,
        approver=alice,
        password=_PASSWORD["alice"],
        totp=code,
        totp_valid_window=1,
        decision=models.APPROVE,
    )
    assert first.recorded is True

    # The exact (user, step) is now in the burn ledger.
    burned = session.scalars(
        select(ConsumedTotp).where(
            ConsumedTotp.user_id == alice.id, ConsumedTotp.time_step == expected_step
        )
    ).one()
    assert burned.time_step == expected_step

    # Reusing the same code (a flip to deny) is rejected as an auth failure, and no
    # second vote row is appended — the replay achieves nothing.
    with pytest.raises(votes.AuthenticationFailed):
        votes.cast_vote(
            session,
            request=request,
            approver=alice,
            password=_PASSWORD["alice"],
            totp=code,
            totp_valid_window=1,
            decision=models.DENY,
        )
    alice_votes = [v for v in votes._votes_for(session, request.id) if v.approver_id == alice.id]
    assert [v.decision for v in alice_votes] == [models.APPROVE]
    assert request.state == models.PENDING  # the deny replay did not close the request


def test_a_burned_code_cannot_vote_a_different_request(session: Session) -> None:
    # The burn is per (user, time-step), not per request: once a code is redeemed on
    # one request, it cannot be reused to vote a *different* request in the same window.
    request_a = _pending_request(session, quorum=2, approvers=["alice", "bob"])
    alice = _user(session, "alice")
    assert alice.totp_secret is not None
    code = totp_code(plaintext_totp_secret(alice, _PASSWORD["alice"]))  # wrapped at rest (#122)

    votes.cast_vote(
        session,
        request=request_a,
        approver=alice,
        password=_PASSWORD["alice"],
        totp=code,
        totp_valid_window=1,
        decision=models.APPROVE,
    )

    # A second pending request alice is also eligible on.
    service = ServiceConfig(
        type="one-time", action="publish-to-pypi", quorum=2, approvers=["alice", "bob"]
    )
    requester = _user(session, "publisher")
    request_b = create_publish_request(
        session,
        requester=requester,
        service_name="pypi",
        service=service,
        package_name="bar",
        package_version="2.0.0",
        filename="bar-2.0.0.tar.gz",
        content=b"different artifact bytes",
    )

    with pytest.raises(votes.AuthenticationFailed):
        votes.cast_vote(
            session,
            request=request_b,
            approver=alice,
            password=_PASSWORD["alice"],
            totp=code,  # already burned on request_a
            totp_valid_window=1,
            decision=models.APPROVE,
        )
    assert votes._votes_for(session, request_b.id) == []
    # Exactly one burn ledger row for alice — the code was consumed once.
    assert (
        session.scalar(
            select(func.count()).select_from(ConsumedTotp).where(ConsumedTotp.user_id == alice.id)
        )
        == 1
    )
