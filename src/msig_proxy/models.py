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

from sqlalchemy import DateTime, LargeBinary, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from msig_proxy.db import Base


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
