"""Adversarial: the execution-time integrity re-check (HOST-2, #121).

These are the tests that carry HOST-2 from bucket ② to ①: they *execute* the
database-write forges the ② rating admitted it could not catch — a substituted
signing key and a weakened quorum — and assert the Executor detects them and freezes
the request instead of publishing. Detection tier, at the crypto/DB layer: the oracle
is a tampered database row, verified below the HTTP surface.

Real DB, real crypto (``docs/mvp.md``).
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import select
from sqlalchemy.orm import Session

from msig_proxy.accounts import keys
from msig_proxy.accounts.seed import seed_user
from msig_proxy.approvals import votes
from msig_proxy.approvals.integrity import verify_request_integrity
from msig_proxy.core import crypto, events, models
from msig_proxy.core.config import AppConfig, ServerConfig, ServiceConfig
from msig_proxy.core.db import Base, create_db_engine, create_session_factory
from msig_proxy.core.models import FROZEN, ApprovalRequest, User
from msig_proxy.service_types import dispatch
from msig_proxy.service_types.one_time.intake import create_publish_request
from tests.support import totp_code_for

_PASSWORD = {name: f"pw-{name}-123" for name in ("alice", "bob", "carol")}


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


def _config(*, quorum: int, approvers: list[str]) -> AppConfig:
    """An AppConfig whose ``pypi`` service is the live policy root of trust."""
    return AppConfig(
        server=ServerConfig(base_url="http://testserver", secret_key="test-secret-key-0123456789"),
        services={
            "pypi": ServiceConfig(
                type="one-time", action="publish-to-pypi", quorum=quorum, approvers=approvers
            )
        },
    )


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


def _user(session: Session, name: str) -> User:
    return session.scalars(select(User).where(User.username == name)).one()


def _approve(session: Session, request: ApprovalRequest, name: str) -> None:
    approver = _user(session, name)
    assert approver.totp_secret is not None
    votes.cast_vote(
        session,
        request=request,
        approver=approver,
        password=_PASSWORD[name],
        totp=totp_code_for(approver, _PASSWORD[name]),  # secret wrapped at rest (#122)
        totp_valid_window=1,
        decision=models.APPROVE,
    )


class _Recorder:
    """Collects the events a finalize handoff emits, so the oracle can assert the
    absence of a publish and the presence of the freeze."""

    def __init__(self) -> None:
        self.names: list[str] = []

    def __call__(self, event: events.Event) -> None:
        self.names.append(event.name)


def test_intact_approved_request_passes_the_recheck(session: Session) -> None:
    # Control: an untampered approved request verifies, so the re-check never freezes a
    # legitimate publish.
    request = _pending_request(session, quorum=2, approvers=["alice", "bob"])
    _approve(session, request, "alice")
    _approve(session, request, "bob")
    assert request.state == models.APPROVED

    assert verify_request_integrity(
        session, request, config=_config(quorum=2, approvers=["alice", "bob"])
    ).ok


def test_execution_refuses_a_substituted_signing_key(session: Session) -> None:
    # The headline HOST-2 forge (#121). alice + bob genuinely approve; then an L5
    # attacker overwrites alice's live public key with their own and forges alice's
    # vote signature under it. Against the *live* key the forgery verifies (the ②
    # gap); the frozen snapshot key exposes it, so the re-check fails.
    request = _pending_request(session, quorum=2, approvers=["alice", "bob"])
    _approve(session, request, "alice")
    _approve(session, request, "bob")

    alice = _user(session, "alice")
    alice_key = keys.active_key(session, alice)
    assert alice_key is not None
    frozen_public = alice_key.public_key  # what the snapshot anchored

    attacker_private, attacker_public = crypto.generate_keypair()
    alice_vote = next(v for v in votes._votes_for(session, request.id) if v.approver_id == alice.id)
    forged = votes.record_for_vote(alice_vote, quorum=request.quorum).canonical_bytes()
    alice_vote.signature = Ed25519PrivateKey.from_private_bytes(attacker_private).sign(forged)
    alice_key.public_key = attacker_public  # substitute the live key
    session.flush()

    # The gap made concrete: the forged vote verifies against the substituted live key…
    assert crypto.verify_record(
        public_key=attacker_public, message=forged, signature=alice_vote.signature
    )
    # …but not against the key frozen at creation, which is what the re-check uses.
    assert not crypto.verify_record(
        public_key=frozen_public, message=forged, signature=alice_vote.signature
    )

    verdict = verify_request_integrity(
        session, request, config=_config(quorum=2, approvers=["alice", "bob"])
    )
    assert not verdict.ok
    assert "substituted" in (verdict.reason or "")


def test_finalize_freezes_a_key_substituted_request_and_does_not_publish(session: Session) -> None:
    # Driving the real terminal handoff: a substituted-key request reaches finalize and
    # is frozen — no request.approved, no action.succeeded, no PyPI call.
    request = _pending_request(session, quorum=2, approvers=["alice", "bob"])
    _approve(session, request, "alice")
    _approve(session, request, "bob")

    alice = _user(session, "alice")
    alice_key = keys.active_key(session, alice)
    assert alice_key is not None
    _, attacker_public = crypto.generate_keypair()
    alice_key.public_key = attacker_public
    session.flush()

    recorder = _Recorder()
    bus = events.EventBus()
    bus.subscribe(recorder)
    dispatch.finalize(session, _config(quorum=2, approvers=["alice", "bob"]), request, bus=bus)

    assert request.state == FROZEN
    assert events.RequestFrozen.name in recorder.names
    assert events.RequestApproved.name not in recorder.names
    assert events.ActionSucceeded.name not in recorder.names


def test_execution_freezes_on_a_weakened_quorum(session: Session) -> None:
    # The pre-vote config-field tamper: an L5 attacker lowers the stored quorum from 3
    # to 1 before any vote, so a single genuine approval consistently satisfies the
    # weakened value and every signature verifies. The execution-time compare against
    # the config file — which the attacker cannot reach — catches it.
    request = _pending_request(session, quorum=3, approvers=["alice", "bob", "carol"])
    request.quorum = 1  # the storage-layer weakening
    session.flush()

    _approve(session, request, "alice")  # one approval now "reaches" the forged quorum
    assert request.state == models.APPROVED

    recorder = _Recorder()
    bus = events.EventBus()
    bus.subscribe(recorder)
    dispatch.finalize(
        session, _config(quorum=3, approvers=["alice", "bob", "carol"]), request, bus=bus
    )

    assert request.state == FROZEN
    assert events.RequestFrozen.name in recorder.names
    assert events.ActionSucceeded.name not in recorder.names


def test_post_vote_quorum_tamper_breaks_the_vote_signature(session: Session) -> None:
    # Mechanism 1 (vote-payload binding): once a vote exists, lowering the stored
    # quorum breaks that vote's signature — it was signed over the original threshold.
    request = _pending_request(session, quorum=2, approvers=["alice", "bob"])
    _approve(session, request, "alice")
    _approve(session, request, "bob")
    assert request.state == models.APPROVED

    request.quorum = 1  # tamper AFTER the votes were cast
    session.flush()

    verdict = verify_request_integrity(
        session, request, config=_config(quorum=2, approvers=["alice", "bob"])
    )
    assert not verdict.ok
    # The signature check fires before the config compare — the vote no longer verifies.
    assert "no longer verifies" in (verdict.reason or "")
