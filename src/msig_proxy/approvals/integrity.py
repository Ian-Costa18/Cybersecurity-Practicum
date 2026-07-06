"""Execution-time integrity re-check for an Approval Request (#121).

The guarantee HOST-2 needs — *a database-write attacker cannot drive a request to a
publish it did not legitimately earn* — is not carried by the Ed25519 vote signatures
alone: the signature check trusts the live ``user_keys.public_key`` and the stored
``request.quorum``, both of which an L5 attacker can rewrite
(``docs/threat-model/HOST-2-database-write-compromise.md`` §"The gap"). This module
closes that gap by re-checking, at the moment of execution, the two things the
signature check assumed:

* **The signing keys are the ones frozen at creation.** Each Vote is verified against
  the ``public_key`` snapshotted onto :class:`ApprovalRequestApprover` at creation
  (ADR 0008), not the live column. Keys are append-only and immutable, so an existing
  ``key_id`` whose live public half no longer matches the frozen one is an
  unambiguous **substitution** — the forge that makes a fabricated Vote verify against
  an attacker-planted key. (A *legitimate* reset mints a **new** ``key_id`` row and
  leaves the frozen one untouched, so it is not flagged.)
* **The snapshotted quorum still matches the policy root of trust.** ``request.quorum``
  is compared against the live service config, whose YAML file a database-write
  attacker cannot reach (that is HOST-1). A lowered quorum — the pre-vote weakening
  where every Vote consistently signs the reduced value — is caught here even though
  each Vote's own signature verifies.

On any failure the Executor freezes the request (``FROZEN``) for manual review rather
than acting on tampered state. Framework-free (`[pure]`): the dispatcher passes a
:class:`~sqlalchemy.orm.Session` and :class:`AppConfig`; this raises nothing and
returns a verdict.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from msig_proxy.accounts import keys
from msig_proxy.approvals import votes
from msig_proxy.core import crypto
from msig_proxy.core.config import AppConfig
from msig_proxy.core.models import ApprovalRequest, ApprovalRequestApprover


@dataclass(frozen=True)
class RequestIntegrity:
    """The verdict of the execution-time re-check (#121).

    ``ok`` is the oracle the Executor gates on; ``reason`` names the tamper for the
    audit trail and the manual-review operator when it freezes.
    """

    ok: bool
    reason: str | None = None


def _frozen_keys(
    session: Session, request_id: uuid.UUID
) -> dict[uuid.UUID, tuple[uuid.UUID | None, bytes | None]]:
    """Map each snapshot approver to their frozen ``(key_id, public_key)`` (#121)."""
    rows = session.scalars(
        select(ApprovalRequestApprover).where(
            ApprovalRequestApprover.approval_request_id == request_id
        )
    ).all()
    return {row.user_id: (row.key_id, row.public_key) for row in rows}


def verify_request_integrity(
    session: Session, request: ApprovalRequest, *, config: AppConfig
) -> RequestIntegrity:
    """Re-check a request's snapshot against its votes and the live policy (#121).

    Returns ``RequestIntegrity(ok=True)`` only when every frozen signing key still
    matches its live counterpart, every Vote verifies against the frozen key under the
    stored quorum, and the snapshotted quorum still equals the configured policy. The
    first failure returns ``ok=False`` with a reason.
    """
    frozen = _frozen_keys(session, request.id)

    # 1. Signing-key substitution: an existing frozen key_id whose live public half
    #    changed. This is the forge the Ed25519 check cannot see, because it verifies
    #    against exactly the substituted key.
    for user_id, (key_id, public_key) in frozen.items():
        if key_id is None or public_key is None:
            continue  # unenrolled at creation — cannot have cast a valid Vote anyway
        live = keys.public_key_for(session, key_id)
        if live != public_key:
            return RequestIntegrity(
                ok=False, reason=f"signing key for approver {user_id} was substituted"
            )

    # 2. Vote signatures against the frozen key + the stored quorum. Catches content
    #    tampering and a post-vote quorum change (the vote signed the original value).
    for vote in votes._votes_for(session, request.id):
        frozen_entry = frozen.get(vote.approver_id)
        anchor = frozen_entry[1] if frozen_entry is not None else None
        anchor = anchor if anchor is not None else keys.public_key_for(session, vote.key_id)
        record = votes.record_for_vote(vote, quorum=request.quorum)
        if anchor is None or not crypto.verify_record(
            public_key=anchor, message=record.canonical_bytes(), signature=vote.signature
        ):
            return RequestIntegrity(
                ok=False, reason=f"vote {vote.id} no longer verifies against the frozen key"
            )

    # 3. Quorum vs the live policy root of trust (the config file, out of L5 reach).
    #    A mismatch is a pre-vote snapshot weakening (or a legitimate mid-flight config
    #    change, which is conservatively frozen for manual review — ADR 0008 has
    #    operators drain pending requests across a policy change).
    service = config.services.get(request.service_name)
    if service is not None and request.quorum != service.quorum:
        return RequestIntegrity(
            ok=False,
            reason=(
                f"snapshotted quorum {request.quorum} diverges from the configured "
                f"policy {service.quorum}"
            ),
        )

    return RequestIntegrity(ok=True)
