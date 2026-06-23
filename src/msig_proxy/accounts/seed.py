"""Seeding path: create a fully-credentialed User without an enrollment UI.

Enrollment (the self-service set-password-and-scan-TOTP flow, #15) is the normal
way approvers come into existence; seeding bootstraps the first ones before any
admin or enrollment path exists. :func:`seed_user` performs the same key-material
construction enrollment does (``docs/account-management.md`` §Account Provisioning
Flow), including the TOTP secret, and returns the API-token plaintext **once** —
it is never retrievable afterward.

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

from msig_proxy.accounts import keys
from msig_proxy.core import crypto
from msig_proxy.core.config import Settings
from msig_proxy.core.db import create_db_engine, create_session_factory, session_scope
from msig_proxy.core.models import ApiToken, User


@dataclass(frozen=True)
class SeededUser:
    """The result of seeding. ``api_token`` is the one-time plaintext — show it
    to the operator now; only its hash is stored. ``totp_secret`` is the enrolled
    second factor (a real enrollee scans it; a seeded account gets one directly so
    it can satisfy TOTP enforcement, #16)."""

    user: User
    api_token: str
    totp_secret: str


def seed_user(
    session: Session,
    *,
    username: str,
    email: str,
    password: str,
    is_admin: bool = False,
    groups: str | None = None,
) -> SeededUser:
    """Create a User with a bcrypt verifier, an active :class:`UserKey`, and one
    hashed API token, then flush them onto ``session``.

    The password is validated (≤72 bytes) by the crypto layer. The key pair is
    constructed by :func:`msig_proxy.accounts.keys.create_active_key` (the plaintext private
    key and ``enc_key`` exist only transiently inside it); the returned ``api_token``
    plaintext is the only secret that leaves this function. ``is_admin`` bootstraps
    the first admin (#15) — ``POST /admin/users`` needs an existing admin, which no
    enrollment can create.
    """
    api_token = crypto.generate_api_token()
    totp_secret = crypto.generate_totp_secret()
    user = User(
        id=uuid.uuid4(),
        username=username,
        email=email,
        is_admin=is_admin,
        password_hash=crypto.hash_password(password),
        # A seeded account is fully credentialed at creation, so it is already
        # enrolled (the admin-create-then-self-enroll flow is #15) and carries the
        # second factor TOTP enforcement (#16) checks at login/vote.
        totp_secret=totp_secret,
        groups=groups,
        enrolled_at=datetime.now(UTC),
    )
    session.add(user)
    session.flush()
    # The signing key pair is normalized into user_keys (#53): insert the active key.
    keys.create_active_key(session, user, password)
    # Tokens are normalized into api_tokens (#14): seed the User's first token.
    session.add(
        ApiToken(user_id=user.id, label="seed token", token_hash=crypto.hash_api_token(api_token))
    )
    session.flush()
    return SeededUser(user=user, api_token=api_token, totp_secret=totp_secret)


def main(argv: list[str] | None = None) -> int:
    """CLI entry point: seed one User and print its one-time API token."""
    parser = argparse.ArgumentParser(description="Seed a User into the proxy database.")
    parser.add_argument("--username", required=True)
    parser.add_argument("--email", required=True)
    parser.add_argument("--admin", action="store_true", help="seed an admin (bootstraps #15)")
    args = parser.parse_args(argv)

    password = os.environ.get("MSIG_SEED_PASSWORD") or getpass.getpass("Password: ")

    factory = create_session_factory(create_db_engine(Settings().database_url))
    for session in session_scope(factory):
        seeded = seed_user(
            session,
            username=args.username,
            email=args.email,
            password=password,
            is_admin=args.admin,
        )
        print(f"Seeded user {seeded.user.username} ({seeded.user.id}).")
        print(f"API token (shown once, store it now): {seeded.api_token}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
