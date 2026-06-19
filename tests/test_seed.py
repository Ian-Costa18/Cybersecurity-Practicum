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

from msig_proxy import crypto, seed
from msig_proxy.db import Base, create_db_engine, create_session_factory
from msig_proxy.models import User
from msig_proxy.seed import seed_user


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
    assert len(stored.public_key) == 32  # raw Ed25519 public key
    assert stored.encrypted_private_key  # iv ‖ ciphertext ‖ tag
    assert len(stored.key_salt) == 16  # 128-bit PBKDF2 salt
    assert stored.token_hash  # one hashed API token
    assert stored.key_version == 1


def test_seed_user_password_verifies(session: Session) -> None:
    seeded = seed_user(session, username="bob", email="bob@example.com", password="correctpw")
    assert crypto.verify_password("correctpw", seeded.user.password_hash) is True
    assert crypto.verify_password("wrongpw", seeded.user.password_hash) is False


def test_seeded_user_can_sign_and_be_verified_offline(session: Session) -> None:
    seeded = seed_user(session, username="carol", email="carol@example.com", password="signingpw")
    user = seeded.user
    record = {"approval_request_id": "req-1", "decision": "approve"}

    signature = crypto.sign_with_password(
        password="signingpw",
        key_salt=user.key_salt,
        encrypted_private_key=user.encrypted_private_key,
        aad=crypto.key_aad(user.id, user.key_version),
        record=record,
    )

    assert crypto.verify_record(public_key=user.public_key, record=record, signature=signature)


def test_api_token_is_emitted_once_and_only_its_hash_is_stored(session: Session) -> None:
    seeded = seed_user(session, username="dave", email="dave@example.com", password="tokenpw1")

    # The plaintext is returned once at seed time...
    assert seeded.api_token
    # ...and only its SHA-256 hash is persisted; the row carries no plaintext.
    assert seeded.user.token_hash == crypto.hash_api_token(seeded.api_token)
    assert seeded.api_token != seeded.user.token_hash
    assert "api_token" not in User.__table__.columns


def test_enc_key_is_never_persisted_on_the_user(session: Session) -> None:
    # Invariant 2: the PBKDF2 output is transient. Only the salt is stored, and
    # no stored column equals (or contains) the derived enc_key.
    seeded = seed_user(session, username="erin", email="erin@example.com", password="invariantpw")
    assert "enc_key" not in User.__table__.columns

    enc_key = crypto.derive_enc_key("invariantpw", seeded.user.key_salt)
    assert enc_key != seeded.user.encrypted_private_key
    assert enc_key not in seeded.user.encrypted_private_key
    assert enc_key != seeded.user.key_salt


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
        assert crypto.verify_password("clipassword", stored.password_hash)
        db.close()
    finally:
        engine.dispose()
