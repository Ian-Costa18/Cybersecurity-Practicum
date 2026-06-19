"""Casting and tallying signed Votes — the approval core (issue #4).

Below the HTTP layer (``approve.py`` drives it), this owns the append-only vote
model (ADR 0009) and the transitions out of ``pending`` defined in
``docs/request-lifecycle.md``:

* every decision is recorded as a *new* signed Vote that supersedes the
  approver's prior one — nothing is overwritten or deleted (ADR 0009);
* quorum and the single-deny rule read each approver's **effective** Vote
  (their latest), never the full history;
* reaching ``m`` effective approvals → ``approved``; a single effective
  ``deny`` → ``denied`` immediately, and a deny dominates a coincident approve.

Each Vote is Ed25519-signed transiently: the private key is decrypted from the
approver's password for the signature and discarded (``crypto.sign_with_password``),
so a stolen Proxy Session — which carries no password — cannot vote. The signed
``approval_record`` (``docs/approver-authentication.md``) is reconstructable from
the stored columns and reverifies offline with the approver's retained public key.

Operates on a session and flushes (does not commit); the caller's session scope
owns the commit, which is also the unit that serializes vote application per
Approval Request (``docs/request-lifecycle.md`` §Design notes — a true ``SELECT …
FOR UPDATE`` row lock arrives with the Postgres swap, ADR 0011; under the single
-writer SQLite MVP the transaction already serializes).
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
    APPROVED,
    DENIED,
    PENDING,
    VOTE_APPROVE,
    VOTE_DENY,
    VOTE_WITHDRAW,
    ApprovalRequest,
    ApprovalRequestApprover,
    User,
    Vote,
)

_DECISIONS = (VOTE_APPROVE, VOTE_DENY, VOTE_WITHDRAW)


class NotAnApproverError(Exception):
    """The authenticated user is not in the request's snapshotted eligible set.

    Authentication proves *who* they are; only a designated approver for this
    request may cast a Vote on it (``docs/request-lifecycle.md``).
    """


class VotesFrozenError(Exception):
    """The request has left ``pending``; its votes are frozen (no further votes).

    Votes may only be cast or changed while a request is ``pending`` — once a
    terminal state is reached the handoff (or closure) has happened and the signed
    votes are part of the permanent record (``docs/request-lifecycle.md``).
    """


class UnknownDecisionError(Exception):
    """A decision other than ``approve`` / ``deny`` / ``withdraw`` was submitted."""


@dataclass(frozen=True)
class VoteOutcome:
    """The result of applying a vote: the (possibly new) request state and tally.

    ``unchanged`` is True when the decision matched the approver's existing
    effective Vote — an identical repeat is a no-op, not an appended supersession
    (the reframed replay rule, ADR 0009 / threat-model T8). ``vote`` is the appended
    row, or ``None`` when ``unchanged``.
    """

    request_state: str
    decision: str
    approvals: int
    quorum: int
    unchanged: bool
    vote: Vote | None


def _eligible_ids(session: Session, request_id: uuid.UUID) -> set[uuid.UUID]:
    return set(
        session.scalars(
            select(ApprovalRequestApprover.user_id).where(
                ApprovalRequestApprover.approval_request_id == request_id
            )
        ).all()
    )


def effective_votes(session: Session, request_id: uuid.UUID) -> dict[uuid.UUID, Vote]:
    """Each approver's effective (latest) Vote, keyed by approver id.

    "Latest" is the highest ``id`` — the append sequence — for that approver, so a
    supersession or withdrawal replaces the earlier Vote in the tally without the
    earlier row being deleted (ADR 0009). Iterating in ``id`` order and letting a
    later row overwrite an earlier one leaves exactly the effective Vote per approver.
    """
    votes = session.scalars(
        select(Vote).where(Vote.approval_request_id == request_id).order_by(Vote.id)
    ).all()
    latest: dict[uuid.UUID, Vote] = {}
    for vote in votes:
        latest[vote.approver_id] = vote
    return latest


def _approval_count(effective: dict[uuid.UUID, Vote]) -> int:
    return sum(1 for vote in effective.values() if vote.decision == VOTE_APPROVE)


def quorum_status(session: Session, request: ApprovalRequest) -> tuple[int, int]:
    """``(effective approvals, quorum threshold)`` — the live tally the page shows."""
    return _approval_count(effective_votes(session, request.id)), request.quorum


def _evaluate(effective: dict[uuid.UUID, Vote], quorum: int) -> str:
    """The transition function over effective votes (``docs/request-lifecycle.md``).

    Deny dominates: a single effective ``deny`` closes the request ``denied`` even
    if approvals also reached quorum in the same evaluation. Otherwise ``approved``
    once effective approvals reach the threshold, else still ``pending``.
    """
    if any(vote.decision == VOTE_DENY for vote in effective.values()):
        return DENIED
    if _approval_count(effective) >= quorum:
        return APPROVED
    return PENDING


def vote_record(
    *,
    approver_id: uuid.UUID,
    key_id: str,
    approval_request_id: uuid.UUID,
    timestamp: datetime,
    action_hash: str,
    decision: str,
) -> dict[str, Any]:
    """The canonical ``approval_record`` that is signed (``docs/approver-authentication.md``).

    The single source of truth for the record shape, so the bytes signed at vote
    time and the bytes verified offline are byte-identical. ``crypto.canonical_json``
    renders the ``datetime`` (ISO 8601) and ``UUID`` fields deterministically.
    """
    return {
        "approver_id": approver_id,
        "key_id": key_id,
        "approval_request_id": approval_request_id,
        "timestamp": timestamp,
        "action_hash": action_hash,
        "decision": decision,
    }


def _as_utc(timestamp: datetime) -> datetime:
    """Re-attach UTC to a timestamp read back naive (SQLite drops the tz offset).

    The record is signed with a tz-aware UTC ``datetime``; SQLite stores the
    microseconds but not the offset, so reconstruction for offline verification must
    restore UTC to reproduce the exact ISO string that was signed.
    """
    return timestamp if timestamp.tzinfo is not None else timestamp.replace(tzinfo=UTC)


def verify_vote(*, public_key: bytes, vote: Vote) -> bool:
    """Offline audit check of one stored Vote against the approver's public key.

    Reconstructs the signed record from the Vote's columns and verifies the Ed25519
    signature — no password or approver cooperation needed (``docs/mvp.md`` §Audit
    Trail). Returns ``False`` on any tamper to a recorded field.
    """
    record = vote_record(
        approver_id=vote.approver_id,
        key_id=vote.key_id,
        approval_request_id=vote.approval_request_id,
        timestamp=_as_utc(vote.created_at),
        action_hash=vote.action_hash,
        decision=vote.decision,
    )
    return crypto.verify_record(public_key=public_key, record=record, signature=vote.signature)


def cast_vote(
    session: Session,
    *,
    request: ApprovalRequest,
    approver: User,
    password: str,
    decision: str,
) -> VoteOutcome:
    """Record one approver's signed decision and apply any resulting transition.

    Preconditions, each raised rather than silently no-op'd:

    * ``decision`` is approve/deny/withdraw — else :class:`UnknownDecisionError`;
    * the request is still ``pending`` — else :class:`VotesFrozenError`;
    * ``approver`` is in the request's snapshotted eligible set — else
      :class:`NotAnApproverError`.

    An *identical* repeat of the approver's current effective decision is a no-op
    (``unchanged=True``): nothing is signed or appended (ADR 0009 / T8). A *changed*
    decision appends a new signed Vote that supersedes the prior one. After
    appending, effective votes are recomputed and the request transitions to
    ``denied`` on any effective deny, else ``approved`` once effective approvals
    reach ``quorum`` (:func:`_evaluate`).

    The plaintext key never leaves :func:`crypto.sign_with_password`; this function
    holds only the password (already re-verified fresh by the caller) and the
    resulting signature.
    """
    if decision not in _DECISIONS:
        raise UnknownDecisionError(
            f"unknown decision {decision!r}; expected one of {_DECISIONS}"
        )
    if request.state != PENDING:
        raise VotesFrozenError(
            f"request {request.id} is {request.state!r}; votes are frozen at a terminal state"
        )
    if approver.id not in _eligible_ids(session, request.id):
        raise NotAnApproverError(
            f"user {approver.id} is not an eligible approver for request {request.id}"
        )

    effective = effective_votes(session, request.id)
    current = effective.get(approver.id)
    if current is not None and current.decision == decision:
        # Identical repeat: a no-op, not a supersession (reframed replay rule, T8).
        return VoteOutcome(
            request_state=request.state,
            decision=decision,
            approvals=_approval_count(effective),
            quorum=request.quorum,
            unchanged=True,
            vote=None,
        )

    timestamp = datetime.now(UTC)
    key_id = crypto.key_fingerprint(approver.public_key)
    record = vote_record(
        approver_id=approver.id,
        key_id=key_id,
        approval_request_id=request.id,
        timestamp=timestamp,
        action_hash=request.artifact_sha256,
        decision=decision,
    )
    signature = crypto.sign_with_password(
        password=password,
        key_salt=approver.key_salt,
        encrypted_private_key=approver.encrypted_private_key,
        aad=crypto.key_aad(approver.id, approver.key_version),
        record=record,
    )

    vote = Vote(
        approval_request_id=request.id,
        approver_id=approver.id,
        key_id=key_id,
        decision=decision,
        action_hash=request.artifact_sha256,
        signature=signature,
        created_at=timestamp,
    )
    session.add(vote)
    session.flush()  # assign vote.id so it orders after the approver's prior votes

    effective = effective_votes(session, request.id)
    request.state = _evaluate(effective, request.quorum)
    session.flush()

    return VoteOutcome(
        request_state=request.state,
        decision=decision,
        approvals=_approval_count(effective),
        quorum=request.quorum,
        unchanged=False,
        vote=vote,
    )
