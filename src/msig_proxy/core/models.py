"""ORM models — the persisted identity layer.

The schema began with the full normalized design (``docs/account-management.md``'s
separate ``user_keys`` and ``api_tokens`` tables) collapsed into a single
:class:`User` row. Both are now normalized outward: **API tokens** into
:class:`ApiToken` (#14) — a User may hold many labeled, individually-revocable
tokens — and **signing key pairs** into :class:`UserKey` (#53), so a User
accumulates an active key plus the retired keys of past resets/rotations. The
*active* key is derived (the User's :class:`UserKey` with ``revoked_at IS NULL``,
unique per user), not a stored pointer; a :class:`Vote` names the exact key that
signed it by ``key_id`` so historical votes verify regardless of later resets.

What this model deliberately does **not** store is ``enc_key``: the PBKDF2 output
is transient by invariant (``docs/cryptography.md``). Only ``key_salt`` and the
AES-256-GCM-encrypted private key are persisted; the key is recovered at signing
time from the password via :mod:`msig_proxy.crypto`.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Uuid,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from msig_proxy.core.db import Base

# Approval Request lifecycle states (``docs/request-lifecycle.md``). Stored as the
# string value; #3 creates a request ``pending`` and voting (#4) drives the
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

# Service Grant lifecycle states (``docs/request-lifecycle.md`` §Service Grant).
# Time-windowed only; no revocation in the MVP. Expiry is evaluated lazily at /auth.
GRANT_ACTIVE = "active"
GRANT_EXPIRED = "expired"


class User(Base):
    """An approver/admin identity with its login credentials.

    The Ed25519 signing key pair lives in :class:`UserKey` (#53), not on this row.
    This row carries the fields the self-service surfaces need: ``is_admin`` (admin
    is a flag, not a separate account type — ``docs/account-management.md``),
    ``is_active`` (deactivation gate; a deactivated User's sessions and token auth
    are refused), ``totp_secret`` (the second factor, ``docs/account-management.md``
    §Authentication Factors; null until enrollment sets it), and ``enrolled_at``
    (the enrollment state — null marks an account that exists but has not yet set
    its own password/TOTP). The single ``token_hash`` is normalized out to
    :class:`ApiToken` (#14) so a User can hold many labeled, individually-revocable
    tokens.

    The credential columns are **nullable**: an admin-created account exists with
    no credentials until the enrollee self-enrolls (#15) — enrollment sets the
    password, generates the keypair, and stamps ``enrolled_at``. A row with null
    credentials cannot authenticate (login and vote both guard for it).
    """

    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    username: Mapped[str] = mapped_column(String, unique=True, index=True)
    email: Mapped[str] = mapped_column(String, unique=True, index=True)

    # Role + lifecycle flags. Admin is a flag on a regular account (no separate
    # admin type); is_active gates login and token auth (deactivation = immediate
    # cutoff). Defaults keep existing User(...) constructions (seed/tests) valid.
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)

    # Credentials — all null until enrollment sets them (#15). A credential-less
    # account exists (admin-created) but cannot log in or vote.
    # bcrypt verifier — a login check only, never key material (invariant 1).
    password_hash: Mapped[str | None] = mapped_column(String, nullable=True)

    # The Ed25519 signing key pair is normalized out into :class:`UserKey` (#53):
    # the active key is the User's row with ``revoked_at IS NULL``. Resolve it via
    # :func:`msig_proxy.keys.active_key` rather than a column here.

    # TOTP shared secret (the second factor). Null until enrollment sets it.
    totp_secret: Mapped[str | None] = mapped_column(String, nullable=True)
    # Enrollment state: when the account completed self-enrollment (set its own
    # password/TOTP). Null = created but not yet enrolled (the #15 admin-create flow).
    enrolled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )


class UserKey(Base):
    """A User's Ed25519 signing key pair — active or retired (``docs/account-management.md``).

    Normalized out of the original ``User`` key columns (#53) so a User accumulates
    one **active** key plus the **retired** keys of past resets/rotations, and every
    historical :class:`Vote` stays verifiable against the exact key that signed it.

    The active key is **derived, not pointed at**: it is the User's row with
    ``revoked_at IS NULL``, and a partial unique index guarantees at most one per
    user (so there is no ``users.current_key_id`` pointer to drift). A :class:`Vote`
    records this row's ``id`` as its ``key_id``; offline verification resolves the
    public key by that id (:func:`msig_proxy.keys.public_key_for`), never by a
    created/revoked time window.

    A key is **born active** at enrollment with both halves — the ``public_key`` and
    the ``encrypted_private_key`` (AES-256-GCM under PBKDF2(password), bound to this
    row's ``id`` as AAD). It is **retired** on reset/deletion: ``revoked_at`` is
    stamped and the private half (``encrypted_private_key`` + ``key_salt``) is
    dropped, while ``public_key`` is retained permanently for audit. The CHECK
    constraint makes that biconditional structural — a live key always has its
    private half, a retired key never does.
    """

    __tablename__ = "user_keys"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), index=True)
    # Retained permanently — historical votes verify against it even after retirement.
    public_key: Mapped[bytes] = mapped_column(LargeBinary)
    # The private half, AES-256-GCM-encrypted under enc_key. Nullable: dropped at
    # retirement (the public half outlives it). Bound to this row's id as GCM AAD.
    encrypted_private_key: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    key_salt: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )
    # Set when the key is retired (reset/rotation/deletion); null = currently active.
    # Position in the user's keys ordered by created_at *is* the "key version" if
    # ever needed, so no version counter is stored.
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        # The retired ⇔ public-only biconditional, enforced at the storage layer so
        # even a hand-run SQL edit cannot corrupt verifiability: a live key (null
        # revoked_at) has its private half; a retired key has neither private column.
        CheckConstraint(
            "(revoked_at IS NULL AND encrypted_private_key IS NOT NULL AND key_salt IS NOT NULL)"
            " OR (revoked_at IS NOT NULL AND encrypted_private_key IS NULL AND key_salt IS NULL)",
            name="ck_user_keys_private_half_iff_active",
        ),
        # At most one active key per user — the partial unique index that lets the
        # active key be derived from revoked_at rather than tracked by a pointer.
        Index(
            "uq_user_keys_active_per_user",
            "user_id",
            unique=True,
            sqlite_where=text("revoked_at IS NULL"),
            postgresql_where=text("revoked_at IS NULL"),
        ),
    )


class ApiToken(Base):
    """A labeled, individually-revocable API token owned by a User (``docs/account-management.md``).

    Normalized out of the original single ``User.token_hash`` (#14) so a User can
    hold **many** tokens — one per machine/context (``"CI runner"``, ``"work
    laptop"``). Only the SHA-256 ``token_hash`` is stored; the plaintext is shown
    **once** at creation. A token is high-entropy, so the hash is a plain digest,
    not a stretching KDF. Revocation is a timestamp (``revoked_at``); auth also
    refuses any token of an inactive User (``users.is_active`` checked at request
    time), so deactivation contains a leaked token without per-token revocation.
    """

    __tablename__ = "api_tokens"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), index=True)
    label: Mapped[str] = mapped_column(String)
    # SHA-256 (hex) of the token; indexed for the auth-time hash-equality lookup.
    token_hash: Mapped[str] = mapped_column(String, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )
    # Set when the token is revoked; null = currently active.
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class EnrollmentToken(Base):
    """A single-use, expiring enrollment link for a not-yet-enrolled User (#15).

    Admin account-creation (``docs/account-management.md`` §Account Provisioning)
    mints one of these and emails ``/enroll/{token}``; the enrollee follows it to
    set their own password + TOTP, at which point the proxy generates the keypair.
    Only the SHA-256 ``token_hash`` is stored (plain digest — the token is
    high-entropy). ``consumed_at`` is set by an **atomic** check-and-set at
    enrollment (``UPDATE ... WHERE consumed_at IS NULL``) so concurrent clicks
    cannot both enroll; an expired (``expires_at`` passed) or consumed token is
    refused.
    """

    __tablename__ = "enrollment_tokens"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), index=True)
    # SHA-256 (hex) of the emailed token; indexed for the enrollment-time lookup.
    token_hash: Mapped[str] = mapped_column(String, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    # Set when enrollment completes; null = unconsumed (the atomic single-use gate).
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )


class ApprovalRequest(Base):
    """The approval-core aggregate (ADR 0007): an m-of-n vote bound to one artifact.

    Issue #3 creates it ``pending`` with the eligible-approver set and
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

    # Forward pointer to the spawned Post-Approval Object, allocated in the approving
    # transition (ADR 0007 bidirectional link). A plain id (not a FK) to avoid a
    # circular constraint with service_grants; the authoritative link + integrity is
    # the unique ``approval_request_id`` on the Post-Approval Object.
    service_grant_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)

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


class ServiceGrant(Base):
    """A forward-auth Post-Approval Object: bounded interactive access to a Service.

    Created at the ``pending → approved`` handoff for a forward-auth request (the
    structural twin of the one-time Action, ADR 0007). It *persists* — unlike an
    Action it represents ongoing access for a bounded window during which the User
    reaches the Service without a new Approval Request. Time-windowed only;
    no revocation in the MVP (``docs/request-lifecycle.md``). Expiry is evaluated
    lazily at ``/auth`` (next slice).

    ``approval_request_id`` is **unique**: a redelivered ``request.approved`` can
    never mint a second grant. The Approval Request carries the matching forward
    pointer (``service_grant_id``), completing the bidirectional link.
    """

    __tablename__ = "service_grants"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    approval_request_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("approval_requests.id"), unique=True
    )
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), index=True)
    service_name: Mapped[str] = mapped_column(String, index=True)
    state: Mapped[str] = mapped_column(String, default=GRANT_ACTIVE)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class ProxySession(Base):
    """A server-side, revocable browser session for an authenticated User.

    The entry credential the forward-auth flow gates on (``docs/web-proxy.md``).
    Distinct from the API-token path: this is **server-side state**, so the cookie
    carries only the signed ``id`` (not a stateless blob) and *deleting this row
    revokes access immediately* on the next request.

    ``id`` is a high-entropy random token (the session id); the cookie value is
    that id HMAC-signed under ``server.secret_key`` (see :mod:`msig_proxy.sessions`).
    Expiry is evaluated lazily on resolution — no scheduler watches the clock.
    """

    __tablename__ = "proxy_sessions"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


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
    # The :class:`UserKey` that signed this (#53): its ``id`` resolves the public
    # key for offline verification and survives later resets/rotations. A plain id,
    # not a FK (like ``service_grant_id``) — keys are append-only and never deleted.
    key_id: Mapped[uuid.UUID] = mapped_column(Uuid)
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
