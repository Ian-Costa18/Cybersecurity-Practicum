"""Seeding path: create a fully-credentialed User without an enrollment UI.

Enrollment (the self-service set-password-and-scan-TOTP flow) is Phase 2; until
then this is how the first approvers come into existence. :func:`seed_user`
performs the same key-material construction enrollment will
(``docs/account-management.md`` §Account Provisioning Flow), minus TOTP, and
returns the API-token plaintext **once** — it is never retrievable afterward.

Run as a CLI to bootstrap a database (password via ``MSIG_SEED_PASSWORD`` or prompt)::

    uv run python -m msig_proxy.seed --username alice --email alice@example.com
"""

from __future__ import annotations

import argparse
import getpass
import os
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy.orm import Session

from msig_proxy import crypto
from msig_proxy.config import Settings
from msig_proxy.db import create_db_engine, create_session_factory, session_scope
from msig_proxy.models import ApiToken, User

_INITIAL_KEY_VERSION = 1


@dataclass(frozen=True)
class SeededUser:
    """The result of seeding. ``api_token`` is the one-time plaintext — show it
    to the operator now; only its hash is stored."""

    user: User
    api_token: str


def seed_user(session: Session, *, username: str, email: str, password: str) -> SeededUser:
    """Create a User with a bcrypt verifier, an encrypted Ed25519 key, and one
    hashed API token, then flush it onto ``session``.

    The password is validated (≤72 bytes) by the crypto layer. The plaintext
    private key and ``enc_key`` exist only transiently here and are dropped
    before returning; the returned ``api_token`` plaintext is the only secret
    that leaves this function.
    """
    user_id = uuid.uuid4()
    aad = crypto.key_aad(user_id, _INITIAL_KEY_VERSION)

    private_raw, public_raw = crypto.generate_keypair()
    key_salt = crypto.new_salt()
    enc_key = crypto.derive_enc_key(password, key_salt)
    encrypted_private_key = crypto.encrypt_private_key(private_raw, enc_key, aad)
    del private_raw, enc_key

    api_token = crypto.generate_api_token()
    user = User(
        id=user_id,
        username=username,
        email=email,
        password_hash=crypto.hash_password(password),
        public_key=public_raw,
        encrypted_private_key=encrypted_private_key,
        key_salt=key_salt,
        key_version=_INITIAL_KEY_VERSION,
        # A seeded account is fully credentialed at creation, so it is already
        # enrolled (the admin-create-then-self-enroll flow is #15).
        enrolled_at=datetime.now(UTC),
    )
    session.add(user)
    session.flush()
    # Tokens are normalized into api_tokens (#14): seed the User's first token.
    session.add(
        ApiToken(user_id=user.id, label="seed token", token_hash=crypto.hash_api_token(api_token))
    )
    session.flush()
    return SeededUser(user=user, api_token=api_token)


def main(argv: list[str] | None = None) -> int:
    """CLI entry point: seed one User and print its one-time API token."""
    parser = argparse.ArgumentParser(description="Seed a User into the proxy database.")
    parser.add_argument("--username", required=True)
    parser.add_argument("--email", required=True)
    args = parser.parse_args(argv)

    password = os.environ.get("MSIG_SEED_PASSWORD") or getpass.getpass("Password: ")

    factory = create_session_factory(create_db_engine(Settings().database_url))
    for session in session_scope(factory):
        seeded = seed_user(session, username=args.username, email=args.email, password=password)
        print(f"Seeded user {seeded.user.username} ({seeded.user.id}).")
        print(f"API token (shown once, store it now): {seeded.api_token}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
