"""The signing-key lifecycle module (``msig_proxy.keys``, #53).

Real DB, real crypto. Covers the lifecycle helpers (active resolution, creation,
retirement, public-key resolution) and proves the two structural guarantees the
schema relies on actually fire: at most one active key per user (partial unique
index) and the retired ⇔ public-only biconditional (CHECK constraint).
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator

import pytest
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from msig_proxy import keys
from msig_proxy.core.db import Base, create_db_engine, create_session_factory
from msig_proxy.core.models import User, UserKey
from msig_proxy.seed import seed_user


@pytest.fixture
def session() -> Iterator[Session]:
    engine = create_db_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    db = create_session_factory(engine)()
    try:
        yield db
    finally:
        db.close()
        engine.dispose()


def _alice(session: Session) -> User:
    seeded = seed_user(session, username="alice", email="alice@example.com", password="alice-pw-1")
    return seeded.user


def test_seeded_user_has_one_active_key(session: Session) -> None:
    alice = _alice(session)
    key = keys.active_key(session, alice)
    assert key is not None
    assert key.revoked_at is None
    assert key.encrypted_private_key is not None and key.key_salt is not None


def test_revoke_retires_the_active_key_and_is_idempotent(session: Session) -> None:
    alice = _alice(session)
    original = keys.active_key(session, alice)
    assert original is not None

    retired = keys.retire_active_key(session, alice)
    assert retired is not None and retired.id == original.id
    assert retired.revoked_at is not None  # stamped
    assert retired.encrypted_private_key is None and retired.key_salt is None  # private dropped
    assert retired.public_key is not None  # public half retained for audit
    assert keys.active_key(session, alice) is None  # no signable key remains

    # Idempotent: revoking again when nothing is active is a no-op returning None.
    assert keys.retire_active_key(session, alice) is None


def test_create_active_key_after_revoke_rotates(session: Session) -> None:
    alice = _alice(session)
    old = keys.active_key(session, alice)
    assert old is not None

    keys.retire_active_key(session, alice)
    new = keys.create_active_key(session, alice, "alice-rotated-pw")

    assert new.id != old.id
    assert keys.active_key(session, alice) == new  # the new key is now the active one


def test_public_key_for_resolves_known_and_unknown(session: Session) -> None:
    alice = _alice(session)
    key = keys.active_key(session, alice)
    assert key is not None
    assert keys.public_key_for(session, key.id) == key.public_key
    assert keys.public_key_for(session, uuid.uuid4()) is None  # no such key


def test_partial_unique_index_forbids_two_active_keys(session: Session) -> None:
    # The DB-level guarantee that lets "active" be derived from revoked_at: a user
    # cannot hold two un-revoked keys at once.
    alice = _alice(session)  # already has one active key
    session.add(
        UserKey(
            user_id=alice.id,
            public_key=b"\x01" * 32,
            encrypted_private_key=b"\x02" * 48,
            key_salt=b"\x03" * 16,
        )
    )
    with pytest.raises(IntegrityError):
        session.flush()


def test_check_constraint_forbids_an_active_key_without_its_private_half(session: Session) -> None:
    # The retired ⇔ public-only biconditional at the storage layer: a live key
    # (null revoked_at) must carry its private half.
    alice = _alice(session)
    keys.retire_active_key(session, alice)  # free the active slot first
    session.add(
        UserKey(
            user_id=alice.id,
            public_key=b"\x01" * 32,
            encrypted_private_key=None,
            key_salt=None,
        )
    )
    with pytest.raises(IntegrityError):
        session.flush()
