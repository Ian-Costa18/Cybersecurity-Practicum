"""ORM models — the persisted identity layer.

Phase 0 collapses the full normalized schema (``docs/account-management.md``'s
separate ``user_keys`` and ``api_tokens`` tables) into a single :class:`User`
row carrying one signing key and one hashed API token. That is the slice the
tracer bullet needs (issue #2); multiple key pairs (password reset / rotation)
and multiple labeled tokens are Phase 2 work and will normalize outward then.

What this model deliberately does **not** store is ``enc_key``: the PBKDF2 output
is transient by invariant (``docs/cryptography.md``). Only ``key_salt`` and the
AES-256-GCM-encrypted private key are persisted; the key is recovered at signing
time from the password via :mod:`msig_proxy.crypto`.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import DateTime, ForeignKey, Integer, LargeBinary, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from msig_proxy.db import Base

# Approval Request lifecycle states (``docs/request-lifecycle.md``). Stored as the
# string value; Phase 0 issue #3 only creates ``pending`` — voting (#4) drives the
# transitions out of it.
PENDING = "pending"
APPROVED = "approved"
DENIED = "denied"
CANCELLED = "cancelled"
TIMED_OUT = "timed_out"

# Vote decisions (``docs/request-lifecycle.md`` §Votes, ADR 0009). ``withdraw``
# retracts a prior endorsement back to neutral without blocking the request.
APPROVE = "approve"
DENY = "deny"
WITHDRAW = "withdraw"

# Service-type discriminator on an Approval Request (ADR 0007). Determines which
# Post-Approval Object the request hands off to: an Action (one-time) or a
# Service Grant (forward-auth). Mirrors ``config.ServiceConfig.type``.
ONE_TIME = "one-time"
FORWARD_AUTH = "forward-auth"


class User(Base):
    """An approver/admin identity with its credentials and one signing key.

    TOTP is intentionally absent — the second factor arrives in Phase 2
    (``docs/mvp.md``). Phase 0 authenticates with password + Ed25519 signing.
    """

    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    username: Mapped[str] = mapped_column(String, unique=True, index=True)
    email: Mapped[str] = mapped_column(String, unique=True, index=True)

    # bcrypt verifier — a login check only, never key material (invariant 1).
    password_hash: Mapped[str] = mapped_column(String)

    # Ed25519 signing key pair. The public half is retained permanently for
    # audit; the private half is stored only AES-256-GCM-encrypted under enc_key.
    public_key: Mapped[bytes] = mapped_column(LargeBinary)
    encrypted_private_key: Mapped[bytes] = mapped_column(LargeBinary)
    key_salt: Mapped[bytes] = mapped_column(LargeBinary)
    # Bound into the GCM AAD (user_id ‖ version); bumps when a key is re-wrapped.
    key_version: Mapped[int] = mapped_column(default=1)

    # SHA-256 of the one API token; the plaintext is shown once at seed time only.
    token_hash: Mapped[str] = mapped_column(String)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )


class ApprovalRequest(Base):
    """The approval-core aggregate (ADR 0007): an m-of-n vote bound to one artifact.

    Phase 0 issue #3 creates it ``pending`` with the eligible-approver set and
    ``quorum`` snapshotted at creation (ADR 0008) and the artifact's SHA-256
    bound (Hash Binding, ``docs/constraints.md`` §6). Voting (#4) drives it out
    of ``pending``; the Post-Approval Action (#5) is the handoff on ``approved``.
    """

    __tablename__ = "approval_requests"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    requester_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), index=True)
    service_name: Mapped[str] = mapped_column(String)
    # The service-type discriminator (ADR 0007): ONE_TIME hands off to an Action,
    # FORWARD_AUTH to a Service Grant. The publish-specific columns below are
    # populated only for ONE_TIME; a FORWARD_AUTH request grants access and carries
    # no artifact/action/package fields (they are nullable, valid-when-ONE_TIME).
    service_type: Mapped[str] = mapped_column(String, default=ONE_TIME)
    # The post-approval action this request will hand off to, e.g. "publish-to-pypi".
    action: Mapped[str | None] = mapped_column(String, nullable=True)
    state: Mapped[str] = mapped_column(String, default=PENDING, index=True)
    # Snapshotted threshold (ADR 0008): #4 evaluates quorum against the snapshot
    # set + this value, never against live config that may have changed mid-vote.
    quorum: Mapped[int] = mapped_column()
    # Hash Binding: SHA-256 (hex) of the exact uploaded artifact. Approvers approve
    # this digest; the Executor re-derives it before publishing (constraints §6).
    # ONE_TIME only — a forward-auth request holds no artifact.
    artifact_sha256: Mapped[str | None] = mapped_column(String, nullable=True)
    package_name: Mapped[str | None] = mapped_column(String, nullable=True)
    package_version: Mapped[str | None] = mapped_column(String, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )


class ApprovalRequestApprover(Base):
    """One member of the eligible-approver set snapshotted onto an Approval Request
    at creation (ADR 0008). The set is frozen here, immune to later config changes;
    #4 evaluates quorum and the single-denial rule against exactly these approvers.
    """

    __tablename__ = "approval_request_approvers"

    approval_request_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("approval_requests.id"), primary_key=True
    )
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), primary_key=True)


class Vote(Base):
    """One signed Vote on an Approval Request — the cryptographic approval record.

    The vote log is **append-only and supersedable** (ADR 0009): a later Vote by
    the same Approver supersedes an earlier one rather than overwriting it, and
    the full sequence is retained for audit. The integer ``id`` is the append
    sequence, so an Approver's *effective* Vote is simply their highest-``id`` row
    (``msig_proxy.votes.effective_votes``); quorum and the single-denial rule read
    only effective votes, never the full history.

    Each row is also the **signed audit record**: ``signature`` is Ed25519 over
    ``canonical_json`` of exactly the fields persisted here (approver, ``key_id``,
    ``approval_request_id``, ``signed_at``, ``action_hash``, ``decision`` — see
    ``docs/approver-authentication.md`` §Signing the Approval Record). It verifies
    offline against the approver's retained ``public_key`` with no password. The
    timestamp is stored as the exact ISO-8601 string that was signed so the record
    reconstructs byte-for-byte (a re-derived datetime could lose the tz and break
    verification); ``created_at`` is the separate, unsigned DB insertion time.
    """

    __tablename__ = "votes"

    # Monotonic append sequence — also the supersession order (latest id wins).
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    approval_request_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("approval_requests.id"), index=True
    )
    approver_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), index=True)
    # Which key pair signed this (Phase 0: ``{user_id}:{key_version}``); links to the
    # public key for offline verification and survives a future key rotation.
    key_id: Mapped[str] = mapped_column(String)
    decision: Mapped[str] = mapped_column(String)  # one of APPROVE / DENY / WITHDRAW
    # The payload approved — the request's bound artifact SHA-256 (Hash Binding).
    action_hash: Mapped[str] = mapped_column(String)
    # The exact ISO-8601 timestamp carried in the signed record (stored verbatim).
    signed_at: Mapped[str] = mapped_column(String)
    # Ed25519 signature over canonical_json of the reconstructable approval record.
    signature: Mapped[bytes] = mapped_column(LargeBinary)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )


class StagedArtifact(Base):
    """The held artifact bytes for a one-time request, staged at creation and
    destroyed at a terminal outcome (``docs/request-lifecycle.md``).

    Kept 1:1 with its Approval Request but in its own row so the bytes can be
    dropped independently at handoff/closure. The Executor (#5) re-hashes
    ``content`` and compares it to the request's bound ``artifact_sha256`` before
    publishing, so a payload substituted in storage cannot ship (Hash Binding).
    """

    __tablename__ = "staged_artifacts"

    approval_request_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("approval_requests.id"), primary_key=True
    )
    filename: Mapped[str] = mapped_column(String)
    content: Mapped[bytes] = mapped_column(LargeBinary)
    # SHA-256 (hex) of ``content`` as staged; equals the request's bound hash at creation.
    sha256: Mapped[str] = mapped_column(String)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )
