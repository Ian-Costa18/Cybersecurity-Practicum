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
signs the record, which is discarded immediately
(:func:`msig_proxy.core.crypto.sign_with_password`).
Votes are accepted only while the request is ``pending``; a terminal request is
frozen. An *identical* repeat of an Approver's current effective decision is an
idempotent no-op (replay defense), not a new row.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from msig_proxy.accounts import keys
from msig_proxy.auth import credentials
from msig_proxy.core import crypto
from msig_proxy.core.models import (
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


@dataclass(frozen=True)
class VoteRecord:
    """The approval record that is Ed25519-signed and reverified offline.

    The field set is fixed by ``docs/approver-authentication.md`` §Signing the
    Approval Record. :meth:`canonical_bytes` is the single home for "the bytes that
    get signed", so the sign path and the verify path — which rebuilds this record
    from the stored columns via :func:`record_for_vote` — provably agree.
    """

    approver_id: uuid.UUID
    key_id: uuid.UUID
    approval_request_id: uuid.UUID
    timestamp: str
    action_hash: str
    decision: str

    def canonical_bytes(self) -> bytes:
        """The exact bytes signed and verified (``docs/cryptography.md``).

        Fields are enumerated **by name** (not ``asdict``/``fields()``) so adding an
        attribute can never silently change the signed bytes.
        :func:`msig_proxy.core.crypto.canonical_json` stays the sole serializer; this
        only chooses which fields go in.
        """
        return crypto.canonical_json(
            {
                "approver_id": self.approver_id,
                "key_id": self.key_id,
                "approval_request_id": self.approval_request_id,
                "timestamp": self.timestamp,
                "action_hash": self.action_hash,
                "decision": self.decision,
            }
        )


def record_for_vote(vote: Vote) -> VoteRecord:
    """Rebuild a stored Vote's signed record from its columns (for verification)."""
    return VoteRecord(
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
    totp: str,
    totp_valid_window: int,
    decision: str,
    deny_reason: str | None = None,
) -> VoteOutcome:
    """Authenticate, append a signed Vote, and apply the decision rules atomically.

    ``approver`` may be ``None`` (unknown username) — that is an authentication
    failure, indistinguishable from a wrong password so it leaks nothing. Order:
    validate the decision and that the request is still ``pending``; authenticate
    (password **and** TOTP — a stolen session, lacking the second factor, cannot
    vote, #16); confirm eligibility; then sign + append + transition.

    ``deny_reason`` is the optional free text an Approver gives when denying (#87); it
    is recorded on the request at the ``→ denied`` transition (not part of the signed
    Vote record) and surfaced on the waiting room's denial screen. It is ignored for a
    non-deny decision or one that does not close the request.
    """
    if decision not in VALID_DECISIONS:
        raise InvalidDecision(f"unknown decision {decision!r}")

    # Serialize vote application per Approval Request (docs/request-lifecycle.md
    # §Design notes): take a row lock so the read-modify-write below (read effective
    # votes → append → re-tally → transition) cannot interleave with a concurrent
    # vote on the same request. This is the mechanism that makes "deny dominates a
    # same-instant approve" hold on a real RDBMS. ``SELECT ... FOR UPDATE`` on
    # Postgres; silently ignored by SQLite (single-writer), where application is
    # already serial — so the guarantee is portable, evaluated against the same row.
    locked = session.execute(
        select(ApprovalRequest).where(ApprovalRequest.id == request.id).with_for_update()
    ).scalar_one_or_none()
    if locked is not None:
        request = locked

    if request.state != PENDING:
        raise RequestNotPending(f"request is {request.state}; voting is closed")

    # Fresh two-factor re-authentication for *every* vote — a stolen session cannot
    # vote (#16). The leading ``approver is None`` short-circuits an unknown username
    # (authenticating to nobody) and narrows the type for the rest of the cast;
    # ``credentials.verify_credentials`` owns the password + TOTP + enrollment check (#58).
    if approver is None or not credentials.verify_credentials(
        session, approver, password, totp, totp_valid_window=totp_valid_window
    ):
        raise AuthenticationFailed("invalid credentials")

    # Resolve the active signing key (#53) right after authentication, not mid-vote:
    # an enrolled approver (password verified above) always has one, so a corrupt
    # half-enrolled row — no active key, or a live key missing its private half —
    # fails closed here rather than crashing later in the signing call.
    key = keys.active_key(session, approver)
    if (
        key is None
        or key.key_salt is None
        or key.encrypted_private_key is None  # pragma: no cover - enrolled => set
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

    signed_at = datetime.now(UTC).isoformat()
    # The payload approved: a one-time request's bound artifact hash. ``artifact_sha256``
    # is nullable since the #8 prefactor (a forward-auth request has no artifact); its
    # forward-auth payload-hash semantics arrive with that flow (#10), so default to "".
    action_hash = request.artifact_sha256 or ""
    record = VoteRecord(
        approver_id=approver.id,
        key_id=key.id,
        approval_request_id=request.id,
        timestamp=signed_at,
        action_hash=action_hash,
        decision=decision,
    )
    signature = crypto.sign_with_password(
        password=password,
        key_salt=key.key_salt,
        encrypted_private_key=key.encrypted_private_key,
        aad=crypto.key_aad(key.id),
        message=record.canonical_bytes(),
    )

    vote = Vote(
        approval_request_id=request.id,
        approver_id=approver.id,
        key_id=key.id,
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
        request.denial_reason = deny_reason  # surfaced on the denial screen (#87)
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
