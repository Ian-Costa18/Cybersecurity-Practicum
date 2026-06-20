"""The seeding path: create a fully-credentialed User without an enrollment UI,
emitting the API-token plaintext exactly once (``docs/account-management.md``).

Real DB, real crypto. The seeded user is the bootstrap approver that later
slices (upload, votes) build on.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from msig_proxy import crypto, keys, seed
from msig_proxy.core.db import Base, create_db_engine, create_session_factory
from msig_proxy.core.models import ApiToken, User, UserKey
from msig_proxy.seed import seed_user


def _token_hash_for(session: Session, user_id: object) -> str:
    """The single seeded token's hash for a user (tokens are normalized out, #14)."""
    return session.scalars(select(ApiToken).where(ApiToken.user_id == user_id)).one().token_hash


@pytest.fixture
def session() -> Iterator[Session]:
    """A real session over a throwaway in-memory SQLite DB (never mocked)."""
    engine = create_db_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    db = create_session_factory(engine)()
    try:
        yield db
    finally:
        db.close()
        engine.dispose()


def test_seed_user_persists_all_required_credentials(session: Session) -> None:
    seeded = seed_user(session, username="alice", email="alice@example.com", password="hunter2pw")

    stored = session.get(User, seeded.user.id)
    assert stored is not None
    assert stored.username == "alice"
    assert stored.email == "alice@example.com"
    assert stored.password_hash  # bcrypt verifier
    key = keys.active_key(session, stored)  # the signing key normalized into user_keys (#53)
    assert key is not None
    assert key.public_key is not None and len(key.public_key) == 32  # raw Ed25519 public key
    assert key.encrypted_private_key  # iv ‖ ciphertext ‖ tag
    assert key.key_salt is not None and len(key.key_salt) == 16  # 128-bit PBKDF2 salt
    assert key.revoked_at is None  # born active
    assert _token_hash_for(session, stored.id)  # one hashed API token (api_tokens, #14)
    assert stored.enrolled_at is not None  # a seeded account is already enrolled
    assert stored.is_active is True and stored.is_admin is False  # lifecycle/role defaults


def test_seed_user_password_verifies(session: Session) -> None:
    seeded = seed_user(session, username="bob", email="bob@example.com", password="correctpw")
    pw_hash = seeded.user.password_hash
    assert pw_hash is not None  # credentials are now nullable; a seeded user always has one
    assert crypto.verify_password("correctpw", pw_hash) is True
    assert crypto.verify_password("wrongpw", pw_hash) is False


def test_seeded_user_can_sign_and_be_verified_offline(session: Session) -> None:
    seeded = seed_user(session, username="carol", email="carol@example.com", password="signingpw")
    key = keys.active_key(session, seeded.user)
    assert key is not None
    key_salt, encrypted_private_key, public_key = (
        key.key_salt,
        key.encrypted_private_key,
        key.public_key,
    )
    assert key_salt is not None and encrypted_private_key is not None and public_key is not None
    message = crypto.canonical_json({"approval_request_id": "req-1", "decision": "approve"})

    signature = crypto.sign_with_password(
        password="signingpw",
        key_salt=key_salt,
        encrypted_private_key=encrypted_private_key,
        aad=crypto.key_aad(key.id),
        message=message,
    )

    assert crypto.verify_record(public_key=public_key, message=message, signature=signature)


def test_api_token_is_emitted_once_and_only_its_hash_is_stored(session: Session) -> None:
    seeded = seed_user(session, username="dave", email="dave@example.com", password="tokenpw1")

    # The plaintext is returned once at seed time...
    assert seeded.api_token
    # ...and only its SHA-256 hash is persisted (in api_tokens now); no plaintext.
    stored_hash = _token_hash_for(session, seeded.user.id)
    assert stored_hash == crypto.hash_api_token(seeded.api_token)
    assert seeded.api_token != stored_hash
    assert "api_token" not in ApiToken.__table__.columns  # only the hash is a column
    assert "token_hash" not in User.__table__.columns  # normalized out of users (#14)


def test_enc_key_is_never_persisted_on_the_user(session: Session) -> None:
    # Invariant 2: the PBKDF2 output is transient. Only the salt is stored, and
    # no stored column equals (or contains) the derived enc_key.
    seeded = seed_user(session, username="erin", email="erin@example.com", password="invariantpw")
    assert "enc_key" not in User.__table__.columns
    assert "enc_key" not in UserKey.__table__.columns

    key = keys.active_key(session, seeded.user)
    assert key is not None
    key_salt = key.key_salt
    encrypted_private_key = key.encrypted_private_key
    assert key_salt is not None and encrypted_private_key is not None
    enc_key = crypto.derive_enc_key("invariantpw", key_salt)
    assert enc_key != encrypted_private_key
    assert enc_key not in encrypted_private_key
    assert enc_key != key_salt


def test_usernames_are_unique(session: Session) -> None:
    # seed_user flushes, so the duplicate is rejected on the second call.
    seed_user(session, username="frank", email="frank@example.com", password="firstpw12")
    with pytest.raises(IntegrityError):
        seed_user(session, username="frank", email="other@example.com", password="secondpw1")


def test_cli_seeds_a_user_and_prints_the_token_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # The CLI bootstraps against the real Settings DB; stand up the schema first
    # (the seeding path provisions accounts, it doesn't run migrations).
    url = f"sqlite+pysqlite:///{(tmp_path / 'seed.db').as_posix()}"
    setup_engine = create_db_engine(url)
    Base.metadata.create_all(setup_engine)
    setup_engine.dispose()

    monkeypatch.setenv("MSIG_DATABASE_URL", url)
    monkeypatch.setenv("MSIG_SEED_PASSWORD", "clipassword")

    assert seed.main(["--username", "grace", "--email", "grace@example.com"]) == 0

    out = capsys.readouterr().out
    assert "API token (shown once" in out  # the one-time plaintext is surfaced

    engine = create_db_engine(url)
    try:
        db = create_session_factory(engine)()
        stored = db.scalars(select(User).where(User.username == "grace")).one()
        assert stored.password_hash is not None
        assert crypto.verify_password("clipassword", stored.password_hash)
        db.close()
    finally:
        engine.dispose()
