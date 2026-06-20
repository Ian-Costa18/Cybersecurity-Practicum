"""The signing-key lifecycle: the single home for every ``user_keys`` operation.

Key pairs were normalized out of the User row (#53) into :class:`~msig_proxy.core.models.UserKey`.
This module concentrates every operation on that table so the invariants live in
one readable place instead of being re-derived by each caller (``seed`` / ``enroll``
construct keys, ``votes`` signs with the active one, ``admin`` retires them):

* **At most one active key per user.** :func:`active_key` resolves it by
  ``revoked_at IS NULL``; the partial unique index (``models.UserKey``) enforces
  uniqueness, so "which key is live" is a derived fact, never a stored pointer.
* **Retire, never destroy.** :func:`retire_active_key` is the *only* place that
  stamps ``revoked_at`` and drops the private half, so the retired ⇔ public-only
  biconditional cannot be violated by a caller (the CHECK constraint backs it).
* **A vote names its key.** Signing reads the active key's ``id`` as ``key_id``;
  verification resolves the public key by that id via :func:`public_key_for` — a
  direct lookup, never a created/revoked time-window inference.

The actual key handling (PBKDF2 derive, AES-GCM wrap, Ed25519 sign) stays in
:mod:`msig_proxy.crypto`; this module owns only the *table* and its lifecycle.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from msig_proxy import crypto
from msig_proxy.core.models import User, UserKey


def active_key(session: Session, user: User) -> UserKey | None:
    """The user's currently-active signing key, or ``None`` if they have none.

    Derived from ``revoked_at IS NULL`` (unique per user). ``None`` is a valid
    state: a never-enrolled account, or a reset account between retirement and
    re-enrollment.
    """
    return session.scalars(
        select(UserKey).where(UserKey.user_id == user.id, UserKey.revoked_at.is_(None))
    ).one_or_none()


def create_active_key(session: Session, user: User, password: str) -> UserKey:
    """Generate a fresh key pair, wrap the private half, and insert it as active.

    Mirrors what enrollment and seeding both need: a new Ed25519 pair, the private
    half AES-256-GCM-encrypted under PBKDF2(password) and bound to the new row's id
    as AAD. The caller must ensure the user has no other active key (enrollment and
    re-enrollment-after-reset both satisfy this); the partial unique index is the
    backstop. Raises :class:`ValueError` if the password exceeds bcrypt's 72-byte
    cap (surfaced by :func:`crypto.derive_enc_key`).
    """
    key_id = uuid.uuid4()
    private_raw, public_raw = crypto.generate_keypair()
    key_salt = crypto.new_salt()
    enc_key = crypto.derive_enc_key(password, key_salt)
    encrypted_private_key = crypto.encrypt_private_key(private_raw, enc_key, crypto.key_aad(key_id))
    del private_raw, enc_key

    key = UserKey(
        id=key_id,
        user_id=user.id,
        public_key=public_raw,
        encrypted_private_key=encrypted_private_key,
        key_salt=key_salt,
    )
    session.add(key)
    session.flush()
    return key


def retire_active_key(session: Session, user: User) -> UserKey | None:
    """Retire the user's active key, returning it (or ``None`` if none was active).

    The single writer of the retire transition: stamp ``revoked_at``, drop the
    private half (``encrypted_private_key`` + ``key_salt``), keep ``public_key`` so
    the key's historical votes stay verifiable. Idempotent — a no-op when there is
    no active key (already retired, or never enrolled).
    """
    key = active_key(session, user)
    if key is None:
        return None
    key.revoked_at = datetime.now(UTC)
    key.encrypted_private_key = None
    key.key_salt = None
    session.flush()
    return key


def public_key_for(session: Session, key_id: uuid.UUID) -> bytes | None:
    """Resolve the public key a :class:`~msig_proxy.core.models.Vote` was signed under.

    A direct lookup by the vote's ``key_id`` (a :class:`UserKey` id), so an old vote
    verifies against the exact key that signed it regardless of later resets.
    ``None`` if no such key exists.
    """
    key = session.get(UserKey, key_id)
    return None if key is None else key.public_key
