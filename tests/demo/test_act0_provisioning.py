"""Backing check for the demo's Act 0 (#143, epic #142).

The demo notebook (``demo/notebooks/publish_demo.py``) claims to stand up a 3-of-3
publishing service whose three co-owners are **real, credentialed, ciphertext-at-rest
rows** — one shown coming to life via a live enrollment, two born enrolled (Mode-B).
These tests are the honest backing for that claim: they run the exact provisioning the
notebook runs, against a throwaway in-memory database, and assert the resulting rows are
what the on-screen crypto beat says they are — a readable ``UserKey.public_key`` next to a
ciphertext ``encrypted_private_key`` and a ciphertext ``User.totp_secret``, decryptable
only under the (throwaway, demo-only) password.

Real DB, real crypto — nothing here is mocked (``docs/mvp.md`` posture).
"""

from __future__ import annotations

from collections.abc import Iterator

import demo_lib
import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from sqlalchemy import select
from sqlalchemy.orm import Session

from msig_proxy.accounts import keys
from msig_proxy.core import crypto
from msig_proxy.core.config import load_config
from msig_proxy.core.db import Base, create_db_engine, create_session_factory
from msig_proxy.core.models import User


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


def _user(session: Session, username: str) -> User:
    return session.scalars(select(User).where(User.username == username)).one()


# --- Tracer: the team exists and can vote ---------------------------------


def test_provisions_three_co_owners_who_can_vote(session: Session) -> None:
    demo_lib.provision_demo_team(session)

    co_owners = [p for p in demo_lib.DEMO_TEAM if not p.is_admin]
    assert len(co_owners) == 3  # a 3-of-3 service needs exactly three co-owners
    for person in co_owners:
        user = _user(session, person.username)
        # "Can vote" = credentialed + enrolled + holding an active signing key.
        assert user.is_active is True
        assert user.enrolled_at is not None
        assert user.password_hash is not None
        assert keys.active_key(session, user) is not None


# --- The shown co-owner: readable public key, ciphertext private key -------


def test_shown_enrollment_public_key_is_readable_private_key_is_ciphertext(
    session: Session,
) -> None:
    provisioning = demo_lib.provision_demo_team(session)
    shown = provisioning.shown_person
    assert shown.provisioning == "shown"  # ada is seeded live, not born Mode-B

    state = demo_lib.read_credential_state(session, shown.username, password=shown.password)

    # The public half is stored readable — it loads as a real Ed25519 public key, and
    # the demo can print it in the clear (nothing secret about a public key).
    assert state.public_key_is_valid is True
    Ed25519PublicKey.from_public_bytes(state.public_key)  # no exception = valid 32-byte key

    # The private half is stored as AES-256-GCM ciphertext, not the raw key: the blob
    # is longer than the 32-byte key (iv‖ciphertext‖tag) and is not the plaintext.
    assert state.private_key_at_rest_is_ciphertext is True
    assert state.encrypted_private_key is not None
    assert state.key_salt is not None
    recovered = crypto.decrypt_private_key(
        state.encrypted_private_key,
        crypto.derive_enc_key(shown.password, state.key_salt),
        crypto.key_aad(state.key_id),
    )
    assert len(recovered) == 32  # a raw Ed25519 private key
    assert recovered not in state.encrypted_private_key  # the stored blob is not the key


def test_shown_co_owner_can_cast_a_signed_vote(session: Session) -> None:
    # "Three co-owners exist and can vote" — prove it for the *shown* co-owner the same
    # cryptographic way as the Mode-B pair: decrypt-and-sign under the demo password,
    # verify against the readable public key. (The Mode-B pair is covered separately.)
    provisioning = demo_lib.provision_demo_team(session)
    shown = provisioning.shown_person

    state = demo_lib.read_credential_state(session, shown.username, password=shown.password)
    assert state.encrypted_private_key is not None and state.key_salt is not None

    message = crypto.canonical_json({"decision": "approve", "who": shown.username})
    signature = crypto.sign_with_password(
        password=shown.password,
        key_salt=state.key_salt,
        encrypted_private_key=state.encrypted_private_key,
        aad=crypto.key_aad(state.key_id),
        message=message,
    )
    assert crypto.verify_record(public_key=state.public_key, message=message, signature=signature)


def test_shown_enrollment_totp_secret_is_ciphertext_bound_to_the_password(
    session: Session,
) -> None:
    provisioning = demo_lib.provision_demo_team(session)
    shown = provisioning.shown_person
    user = _user(session, shown.username)

    state = demo_lib.read_credential_state(session, shown.username, password=shown.password)

    # The second factor is wrapped at rest (#122): a database read yields ciphertext,
    # not the base32 TOTP secret. The plaintext the demo seeded is not in the blob.
    assert state.totp_at_rest_is_ciphertext is True
    assert state.totp_secret_ciphertext is not None
    assert state.totp_salt is not None
    assert provisioning.shown.totp_secret.encode("ascii") not in state.totp_secret_ciphertext

    # It decrypts back to that exact plaintext only under the right password...
    enc_key = crypto.derive_enc_key(shown.password, state.totp_salt)
    recovered = crypto.decrypt_totp_secret(
        state.totp_secret_ciphertext, enc_key, crypto.totp_aad(user.id)
    )
    assert recovered == provisioning.shown.totp_secret

    # ...and a wrong password cannot open it (GCM tag failure, no plaintext released).
    wrong_key = crypto.derive_enc_key("not-the-demo-password", state.totp_salt)
    with pytest.raises(InvalidTag):
        crypto.decrypt_totp_secret(
            state.totp_secret_ciphertext, wrong_key, crypto.totp_aad(user.id)
        )


# --- The Mode-B co-owners: born enrolled, and they can really sign ---------


def test_mode_b_co_owners_are_born_enrolled_and_can_sign(session: Session) -> None:
    demo_lib.provision_demo_team(session)

    born_enrolled = [p for p in demo_lib.CO_OWNERS if p.provisioning == "mode-b"]
    assert len(born_enrolled) == 2  # the two born-enrolled co-owners

    for person in born_enrolled:
        user = _user(session, person.username)
        assert user.is_active is True and user.enrolled_at is not None  # born enrolled

        # Their private key decrypts under the demo password and produces a signature
        # that verifies against the readable public key — i.e. they can cast a real
        # Ed25519-signed vote, not just "exist".
        state = demo_lib.read_credential_state(session, person.username, password=person.password)
        assert state.public_key_is_valid is True
        assert state.private_key_at_rest_is_ciphertext is True
        assert state.totp_at_rest_is_ciphertext is True
        assert state.encrypted_private_key is not None and state.key_salt is not None

        message = crypto.canonical_json({"decision": "approve", "who": person.username})
        signature = crypto.sign_with_password(
            password=person.password,
            key_salt=state.key_salt,
            encrypted_private_key=state.encrypted_private_key,
            aad=crypto.key_aad(state.key_id),
            message=message,
        )
        assert crypto.verify_record(
            public_key=state.public_key, message=message, signature=signature
        )


# --- The checked-in seed bundle: marked demo-only, consistent with the cast -


def test_committed_seed_bundle_is_marked_demo_only() -> None:
    # The planted credential file must exist and announce itself as throwaway, so it is
    # never mistaken for real credential material sitting in the tree.
    assert demo_lib.DEMO_USERS_YAML.exists()
    text = demo_lib.DEMO_USERS_YAML.read_text(encoding="utf-8")
    assert demo_lib.DEMO_ONLY_MARKER in text


def test_committed_seed_bundle_matches_the_planted_passwords(session: Session) -> None:
    # provision_demo_team reads the committed bundle (not a fresh regeneration), so this
    # guards against drift between demo_lib.DEMO_TEAM's throwaway passwords and the
    # checked-in ciphertext: each born-enrolled user's stored hash must verify its
    # password, and its wrapped TOTP must open under it.
    provisioning = demo_lib.provision_demo_team(session)
    assert provisioning.mode_b_from_file is True  # the committed file was the source

    for person in demo_lib.DEMO_TEAM:
        if person.provisioning != "mode-b":
            continue
        user = _user(session, person.username)
        assert user.password_hash is not None
        assert crypto.verify_password(person.password, user.password_hash)
        assert user.totp_secret is not None and user.totp_salt is not None
        # Opens under the planted password => the committed bundle belongs to this cast.
        crypto.decrypt_totp_secret(
            user.totp_secret,
            crypto.derive_enc_key(person.password, user.totp_salt),
            crypto.totp_aad(user.id),
        )


def test_committed_demo_config_stands_up_the_3_of_3_service() -> None:
    # "Admin stands up a 3-of-3 service" must be real config the proxy would accept,
    # not just narration: the committed demo config loads, and its service matches the
    # cast (quorum 3 over exactly the three co-owners the notebook provisions).
    config = load_config(demo_lib.DEMO_CONFIG_YAML)
    service = config.services[demo_lib.SERVICE_NAME]
    assert service.quorum == len(demo_lib.CO_OWNERS) == 3
    assert service.approvers == [p.username for p in demo_lib.CO_OWNERS]
    # And demo_lib's narrated descriptor agrees with the committed config.
    assert demo_lib.demo_service_config().approvers == service.approvers
