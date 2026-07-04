"""Declarative create-if-absent provisioning (#100).

Real DB, real crypto. Covers both modes, the additive-only reconciliation
(create-if-absent; never touch an existing user), the users-file loader (env
expansion + validation), and the full ``hash-credentials`` → ``users.yaml`` →
provision round-trip that proves a Mode-B user can actually approve.
"""

from __future__ import annotations

import base64
from collections.abc import Iterator
from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from msig_proxy.accounts import keys, provision
from msig_proxy.accounts.hash_credentials import build_credential_bundle, render_yaml_entry
from msig_proxy.accounts.provision import (
    PRE_CREDENTIALED,
    KeyBundle,
    ProvisionOutcome,
    UserSpec,
    load_user_specs,
    provision_users,
)
from msig_proxy.accounts.seed import seed_user
from msig_proxy.core import crypto, events
from msig_proxy.core.config import AppConfig, ConfigError, ServerConfig
from msig_proxy.core.db import Base, create_db_engine, create_session_factory
from msig_proxy.core.events import Event, EventBus
from msig_proxy.core.models import EnrollmentToken, User, UserKey


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


@pytest.fixture
def config() -> AppConfig:
    """A valid app config with no email block (so Mode-A minting is a silent no-op send)."""
    return AppConfig(
        server=ServerConfig(
            host="127.0.0.1",
            port=8080,
            base_url="http://testserver",
            secret_key="test-secret-key-0123456789",
        )
    )


@pytest.fixture
def bus() -> EventBus:
    return EventBus()


def _user(session: Session, username: str) -> User:
    return session.scalars(select(User).where(User.username == username)).one()


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


# --- Mode A: identity-only + enrollment link ------------------------------


def test_identity_only_creates_inactive_uncredentialed_user_with_link(
    session: Session, config: AppConfig, bus: EventBus
) -> None:
    recorded: list[Event] = []
    bus.subscribe(recorded.append)

    outcomes = provision_users(
        session,
        config,
        [UserSpec(username="alice", email="alice@example.com", groups="developers")],
        bus=bus,
    )

    assert outcomes == [ProvisionOutcome("alice", created=True, mode="identity-only")]
    alice = _user(session, "alice")
    assert alice.is_active is False  # created inactive, no credentials
    assert alice.enrolled_at is None
    assert alice.password_hash is None
    assert alice.totp_secret is None
    assert alice.groups == "developers"
    assert keys.active_key(session, alice) is None  # no signing key yet
    # a single-use enrollment token was minted, and the event fired for the audit trail
    assert session.scalars(select(EnrollmentToken).where(EnrollmentToken.user_id == alice.id)).one()
    assert [type(e) for e in recorded] == [events.EnrollmentIssued]


# --- Mode B: pre-credentialed bundle --------------------------------------


def test_pre_credentialed_creates_enrolled_user_that_can_sign(
    session: Session, config: AppConfig, bus: EventBus, tmp_path: Path
) -> None:
    bundle = build_credential_bundle(
        username="admin",
        email="admin@example.com",
        password="adminpassword",
        is_admin=True,
        groups="ops",
    )
    users_file = tmp_path / "users.yaml"
    users_file.write_text(render_yaml_entry(bundle), encoding="utf-8")

    outcomes = provision_users(session, config, load_user_specs(users_file), bus=bus)

    assert outcomes == [ProvisionOutcome("admin", created=True, mode=PRE_CREDENTIALED)]
    admin = _user(session, "admin")
    assert admin.is_admin is True
    assert admin.is_active is True and admin.enrolled_at is not None  # born enrolled
    assert admin.groups == "ops"
    pw_hash = admin.password_hash
    assert pw_hash is not None
    assert crypto.verify_password("adminpassword", pw_hash)
    # The User.id from the bundle is honored so the TOTP wrap's AAD binding holds...
    assert admin.id == bundle.user_id
    # ...and the second factor is stored wrapped (#122), decrypting to the plaintext
    # only under the password — a database read yields ciphertext, not a TOTP secret.
    enc_totp, totp_salt = admin.totp_secret, admin.totp_salt
    assert enc_totp is not None and totp_salt is not None
    assert bundle.totp_secret.encode("ascii") not in enc_totp
    assert (
        crypto.decrypt_totp_secret(
            enc_totp, crypto.derive_enc_key("adminpassword", totp_salt), crypto.totp_aad(admin.id)
        )
        == bundle.totp_secret
    )

    key = keys.active_key(session, admin)
    assert key is not None
    assert key.id == bundle.key_id  # AAD binding preserved
    key_salt, encrypted_private_key = key.key_salt, key.encrypted_private_key
    assert key_salt is not None and encrypted_private_key is not None
    message = crypto.canonical_json({"decision": "approve"})
    signature = crypto.sign_with_password(
        password="adminpassword",
        key_salt=key_salt,
        encrypted_private_key=encrypted_private_key,
        aad=crypto.key_aad(key.id),
        message=message,
    )
    assert crypto.verify_record(public_key=key.public_key, message=message, signature=signature)


# --- Reconciliation: additive only, never touch an existing user ----------


def test_existing_pending_user_is_a_noop(
    session: Session, config: AppConfig, bus: EventBus
) -> None:
    # First boot creates alice (identity-only, pending).
    provision_users(
        session, config, [UserSpec(username="alice", email="alice@example.com")], bus=bus
    )
    first_token_count = len(session.scalars(select(EnrollmentToken)).all())

    recorded: list[Event] = []
    bus.subscribe(recorded.append)
    # Second boot: same username, now even a Mode-B bundle — must be a clean no-op.
    bundle = build_credential_bundle(
        username="alice", email="changed@example.com", password="differentpw1"
    )
    outcomes = provision_users(
        session,
        config,
        [
            UserSpec(
                id=bundle.user_id,
                username="alice",
                email="changed@example.com",
                password_hash=bundle.password_hash,
                encrypted_totp_secret=_b64(bundle.encrypted_totp_secret),
                totp_salt=_b64(bundle.totp_salt),
                key=KeyBundle(
                    key_id=bundle.key_id,
                    public_key=_b64(bundle.public_key),
                    encrypted_private_key=_b64(bundle.encrypted_private_key),
                    key_salt=_b64(bundle.key_salt),
                ),
            )
        ],
        bus=bus,
    )

    assert outcomes == [ProvisionOutcome("alice", created=False, mode=None)]
    alice = _user(session, "alice")
    assert alice.email == "alice@example.com"  # original, untouched
    assert alice.password_hash is None  # never credentialed
    assert keys.active_key(session, alice) is None  # never resurrected into Mode B
    assert len(session.scalars(select(EnrollmentToken)).all()) == first_token_count  # no re-issue
    assert recorded == []  # no event on a skip


def test_existing_enrolled_user_is_a_noop(
    session: Session, config: AppConfig, bus: EventBus
) -> None:
    seed_user(session, username="bob", email="bob@example.com", password="bobspassword")
    # An identity-only spec for an already-enrolled user must not re-issue a link.
    outcomes = provision_users(
        session,
        config,
        [UserSpec(username="bob", email="bob@example.com")],
        bus=bus,
    )
    assert outcomes == [ProvisionOutcome("bob", created=False, mode=None)]
    # no enrollment link minted for the already-enrolled bob
    assert session.scalars(select(EnrollmentToken)).all() == []


def test_partial_batch_creates_only_the_absent_user(
    session: Session, config: AppConfig, bus: EventBus
) -> None:
    seed_user(session, username="bob", email="bob@example.com", password="bobspassword")
    outcomes = provision_users(
        session,
        config,
        [
            UserSpec(username="bob", email="bob@example.com"),
            UserSpec(username="carol", email="carol@example.com"),
        ],
        bus=bus,
    )
    assert outcomes == [
        ProvisionOutcome("bob", created=False, mode=None),
        ProvisionOutcome("carol", created=True, mode="identity-only"),
    ]


# --- The users-file loader ------------------------------------------------


def test_missing_users_file_is_a_clean_noop(tmp_path: Path) -> None:
    assert load_user_specs(tmp_path / "absent.yaml") == []


def test_load_user_specs_expands_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    # ``$ENV{}`` expansion runs on any users-file field (#122 removed the plaintext
    # totp field, but the mechanism still lets an operator source a value from the
    # environment — e.g. keep the bcrypt hash in a secret store, not the committed file).
    monkeypatch.setenv("ADMIN_PW_HASH", "$2b$12$abcdefghijklmnopqrstuv")
    bundle = build_credential_bundle(
        username="admin", email="admin@example.com", password="adminpassword"
    )
    users_file = tmp_path / "users.yaml"
    text = render_yaml_entry(bundle).replace(
        f"password_hash: {bundle.password_hash}", "password_hash: $ENV{ADMIN_PW_HASH}"
    )
    users_file.write_text(text, encoding="utf-8")

    [spec] = load_user_specs(users_file)
    assert spec.password_hash == "$2b$12$abcdefghijklmnopqrstuv"  # expanded from the environment


def test_load_user_specs_rejects_a_partial_bundle(tmp_path: Path) -> None:
    users_file = tmp_path / "users.yaml"
    # password_hash without the matching id + encrypted_totp_secret + totp_salt + key
    # is a config error (the all-or-none Mode-B rule, #122).
    users_file.write_text(
        "users:\n  - username: x\n    email: x@example.com\n    password_hash: '$2b$12$abc'\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError):
        load_user_specs(users_file)


def test_load_user_specs_rejects_malformed_yaml(tmp_path: Path) -> None:
    users_file = tmp_path / "users.yaml"
    users_file.write_text("users: [oops\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_user_specs(users_file)


def test_load_user_specs_rejects_unknown_keys(tmp_path: Path) -> None:
    # A typo in this credential-bearing file must fail loudly, not silently drop the
    # field (e.g. 'passwordhash' would otherwise leave a Mode-B admin uncredentialed).
    users_file = tmp_path / "users.yaml"
    users_file.write_text(
        "users:\n  - username: x\n    email: x@example.com\n    passwordhash: oops\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError):
        load_user_specs(users_file)


def test_duplicate_email_is_a_clear_config_error(
    session: Session, config: AppConfig, bus: EventBus
) -> None:
    seed_user(session, username="bob", email="shared@example.com", password="bobspassword")
    # A new username reusing an existing email (email is independently unique) must
    # surface a domain-meaningful ConfigError, not a raw IntegrityError.
    with pytest.raises(ConfigError, match="already belongs to another account"):
        provision_users(
            session,
            config,
            [UserSpec(username="carol", email="shared@example.com")],
            bus=bus,
        )


# --- The CLI / entrypoint -------------------------------------------------


def test_cli_provisions_against_settings_db(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # The entrypoint path: stand up the schema (the provision step provisions
    # accounts, it does not run migrations), then drive provision.main over a config
    # file + users file resolved from MSIG_* settings.
    url = f"sqlite+pysqlite:///{(tmp_path / 'provision.db').as_posix()}"
    setup_engine = create_db_engine(url)
    Base.metadata.create_all(setup_engine)
    setup_engine.dispose()

    config_file = tmp_path / "config.yaml"
    config_file.write_text(
        "server:\n  base_url: http://testserver\n  secret_key: test-secret-key-0123456789\n",
        encoding="utf-8",
    )
    bundle = build_credential_bundle(
        username="admin", email="admin@example.com", password="adminpassword", is_admin=True
    )
    users_file = tmp_path / "users.yaml"
    users_file.write_text(render_yaml_entry(bundle), encoding="utf-8")

    monkeypatch.setenv("MSIG_DATABASE_URL", url)
    monkeypatch.setenv("MSIG_CONFIG_FILE", str(config_file))
    monkeypatch.setenv("MSIG_USERS_FILE", str(users_file))

    assert provision.main([]) == 0
    assert "created (pre-credentialed)" in capsys.readouterr().out

    engine = create_db_engine(url)
    try:
        db = create_session_factory(engine)()
        admin = db.scalars(select(User).where(User.username == "admin")).one()
        assert admin.is_admin and admin.enrolled_at is not None
        assert db.scalars(select(UserKey).where(UserKey.user_id == admin.id)).one().id == (
            bundle.key_id
        )
        db.close()
    finally:
        engine.dispose()

    # Second run is an idempotent no-op.
    assert provision.main([]) == 0
    assert "already existed" in capsys.readouterr().out
