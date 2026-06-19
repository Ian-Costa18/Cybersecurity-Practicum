"""The approval core: cast a signed Vote and apply the effective-vote decision rules.

This is the behavior issue #4 owns, below the HTTP layer (``docs/request-lifecycle.md``
§Votes, ADR 0009). A Vote is recorded **append-only**: a changed decision from the
same Approver appends a new signed row that supersedes the prior one; the full
sequence is retained. Quorum and the single-denial rule are computed over
**effective votes** (each Approver's latest decision), never the full history:

* any effective ``deny`` closes the request ``denied`` immediately — *deny dominates*,
  evaluated before quorum, including a flip from a prior ``approve``;
* otherwise, the count of distinct effective ``approve`` reaching the request's
  snapshotted ``quorum`` closes it ``approved``.

Every cast requires fresh password re-authentication (a stolen session cannot
vote): the password verifies the bcrypt login *and* unlocks the Ed25519 key that
signs the record, which is discarded immediately (:func:`msig_proxy.crypto.sign_with_password`).
Votes are accepted only while the request is ``pending``; a terminal request is
frozen. An *identical* repeat of an Approver's current effective decision is an
idempotent no-op (replay defense), not a new row.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from msig_proxy import crypto
from msig_proxy.models import (
    APPROVE,
    APPROVED,
    DENIED,
    DENY,
    PENDING,
    WITHDRAW,
    ApprovalRequest,
    ApprovalRequestApprover,
    User,
    Vote,
)

VALID_DECISIONS = (APPROVE, DENY, WITHDRAW)


class VotingError(Exception):
    """Base class for a refused vote."""


class InvalidDecision(VotingError):
    """The submitted decision is not one of approve / deny / withdraw."""


class RequestNotPending(VotingError):
    """Votes are frozen — the request already reached a terminal state."""


class AuthenticationFailed(VotingError):
    """Fresh password re-authentication failed (unknown user or wrong password)."""


class NotAnEligibleApprover(VotingError):
    """The authenticated user is not in this request's snapshotted approver set."""


@dataclass(frozen=True)
class Tally:
    """The effective-vote count shown on the approve/deny page."""

    approvals: int
    quorum: int
    state: str

    @property
    def remaining(self) -> int:
        return max(self.quorum - self.approvals, 0)


@dataclass(frozen=True)
class VoteOutcome:
    """Result of a cast: the resulting request state, the running tally, and
    whether a new Vote was actually appended (``False`` for an identical-repeat
    no-op)."""

    state: str
    tally: Tally
    recorded: bool


def key_id_for(user: User) -> str:
    """The ``key_id`` recorded in the signed vote: ``{user_id}:{key_version}``.

    Phase 0 collapses keys onto the User row, so the key pair is identified by the
    owning user and its rotation version; this stays stable once keys normalize out
    to their own table in Phase 2.
    """
    return f"{user.id}:{user.key_version}"


def build_vote_record(
    *,
    approver_id: uuid.UUID,
    key_id: str,
    approval_request_id: uuid.UUID,
    timestamp: str,
    action_hash: str,
    decision: str,
) -> dict[str, Any]:
    """The approval record that is Ed25519-signed and reverified offline.

    The shape is fixed by ``docs/approver-authentication.md`` §Signing the Approval
    Record; :func:`msig_proxy.crypto.canonical_json` is the sole serializer, so an
    honest signature always reverifies.
    """
    return {
        "approver_id": approver_id,
        "key_id": key_id,
        "approval_request_id": approval_request_id,
        "timestamp": timestamp,
        "action_hash": action_hash,
        "decision": decision,
    }


def record_for_vote(vote: Vote) -> dict[str, Any]:
    """Reconstruct a stored Vote's signed record from its columns (for verification)."""
    return build_vote_record(
        approver_id=vote.approver_id,
        key_id=vote.key_id,
        approval_request_id=vote.approval_request_id,
        timestamp=vote.signed_at,
        action_hash=vote.action_hash,
        decision=vote.decision,
    )


def votes_for(session: Session, approval_request_id: uuid.UUID) -> list[Vote]:
    """All Votes for a request in append (``id``-ascending) order — full history."""
    return list(
        session.scalars(
            select(Vote).where(Vote.approval_request_id == approval_request_id).order_by(Vote.id)
        ).all()
    )


def effective_votes(votes: list[Vote]) -> dict[uuid.UUID, str]:
    """Map each Approver to their latest (effective) decision.

    Expects ``votes`` in append order; the last decision per Approver wins, which
    is the supersession rule (ADR 0009).
    """
    effective: dict[uuid.UUID, str] = {}
    for vote in votes:
        effective[vote.approver_id] = vote.decision
    return effective


def _approval_count(effective: dict[uuid.UUID, str]) -> int:
    return sum(1 for decision in effective.values() if decision == APPROVE)


def current_tally(request: ApprovalRequest, votes: list[Vote]) -> Tally:
    """The effective approve-count tally for a request given its vote history."""
    return Tally(
        approvals=_approval_count(effective_votes(votes)),
        quorum=request.quorum,
        state=request.state,
    )


def _eligible_approver_ids(session: Session, approval_request_id: uuid.UUID) -> set[uuid.UUID]:
    return set(
        session.scalars(
            select(ApprovalRequestApprover.user_id).where(
                ApprovalRequestApprover.approval_request_id == approval_request_id
            )
        ).all()
    )


def cast_vote(
    session: Session,
    *,
    request: ApprovalRequest,
    approver: User | None,
    password: str,
    totp_code: str,
    decision: str,
) -> VoteOutcome:
    """Authenticate, append a signed Vote, and apply the decision rules atomically.

    ``approver`` may be ``None`` (unknown username) — that is an authentication
    failure, indistinguishable from a wrong password so it leaks nothing. Order:
    validate the decision and that the request is still ``pending``; authenticate
    (password **and** TOTP — a stolen session, lacking the second factor, cannot
    vote, #16); confirm eligibility; then sign + append + transition.
    """
    if decision not in VALID_DECISIONS:
        raise InvalidDecision(f"unknown decision {decision!r}")
    if request.state != PENDING:
        raise RequestNotPending(f"request is {request.state}; voting is closed")

    # Fresh two-factor re-authentication for *every* vote — a stolen session cannot
    # vote. A not-yet-enrolled account (null credentials) authenticates to nobody.
    if (
        approver is None
        or approver.password_hash is None
        or approver.totp_secret is None
        or not crypto.verify_password(password, approver.password_hash)
        or not crypto.verify_totp(approver.totp_secret, totp_code)
    ):
        raise AuthenticationFailed("invalid credentials")

    if approver.id not in _eligible_approver_ids(session, request.id):
        raise NotAnEligibleApprover("not an eligible approver for this request")

    history = votes_for(session, request.id)
    if effective_votes(history).get(approver.id) == decision:
        # Identical repeat of the current effective decision: idempotent no-op.
        return VoteOutcome(
            state=request.state, tally=current_tally(request, history), recorded=False
        )

    # An enrolled approver (password verified above) always has key material; bind
    # the now-nullable columns to locals and guard, so a corrupt half-enrolled row
    # fails auth rather than crashing (and narrows the type for the signing call).
    key_salt, encrypted_private_key = approver.key_salt, approver.encrypted_private_key
    if key_salt is None or encrypted_private_key is None:  # pragma: no cover - enrolled => set
        raise AuthenticationFailed("invalid credentials")
    signed_at = datetime.now(UTC).isoformat()
    key_id = key_id_for(approver)
    # The payload approved: a one-time request's bound artifact hash. ``artifact_sha256``
    # is nullable since the #8 prefactor (a forward-auth request has no artifact); its
    # forward-auth payload-hash semantics arrive with that flow (#10), so default to "".
    action_hash = request.artifact_sha256 or ""
    record = build_vote_record(
        approver_id=approver.id,
        key_id=key_id,
        approval_request_id=request.id,
        timestamp=signed_at,
        action_hash=action_hash,
        decision=decision,
    )
    signature = crypto.sign_with_password(
        password=password,
        key_salt=key_salt,
        encrypted_private_key=encrypted_private_key,
        aad=crypto.key_aad(approver.id, approver.key_version),
        record=record,
    )

    vote = Vote(
        approval_request_id=request.id,
        approver_id=approver.id,
        key_id=key_id,
        decision=decision,
        action_hash=action_hash,
        signed_at=signed_at,
        signature=signature,
    )
    session.add(vote)
    session.flush()  # allocate the append sequence id

    effective = effective_votes([*history, vote])
    if any(value == DENY for value in effective.values()):
        request.state = DENIED  # deny dominates, evaluated before quorum
    elif _approval_count(effective) >= request.quorum:
        request.state = APPROVED
    session.flush()

    return VoteOutcome(
        state=request.state,
        tally=Tally(
            approvals=_approval_count(effective), quorum=request.quorum, state=request.state
        ),
        recorded=True,
    )
