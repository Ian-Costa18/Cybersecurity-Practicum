"""The Alembic initial migration applies cleanly to a fresh database."""

from __future__ import annotations

from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text

REPO_ROOT = Path(__file__).resolve().parents[1]


def _alembic_config() -> Config:
    config = Config(str(REPO_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(REPO_ROOT / "migrations"))
    return config


def test_upgrade_head_applies_cleanly(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    db_path = tmp_path / "migrated.db"
    url = f"sqlite+pysqlite:///{db_path.as_posix()}"
    monkeypatch.setenv("MSIG_DATABASE_URL", url)

    command.upgrade(_alembic_config(), "head")

    engine = create_engine(url)
    try:
        with engine.connect() as connection:
            tables = inspect(connection).get_table_names()
            assert "alembic_version" in tables
            assert "users" in tables  # the Phase 0 identity table (#2)
            assert "approval_requests" in tables  # the intake aggregate (#3)
            assert "approval_request_approvers" in tables  # the snapshotted approver set
            assert "staged_artifacts" in tables  # the held artifact bytes
            assert "votes" in tables  # the append-only signed vote log (#4)
            assert "proxy_sessions" in tables  # server-side revocable sessions (#9)
            assert "service_grants" in tables  # forward-auth post-approval object (#11)
            assert "api_tokens" in tables  # normalized multi-token table (#14)
            assert "enrollment_tokens" in tables  # single-use enrollment links (#15)
            assert "user_keys" in tables  # normalized signing key pairs (#53)
            assert "consumed_totps" in tables  # single-use TOTP burn ledger (#73)
            assert "audit_log" in tables  # records every emitted event (#85)
            columns = {col["name"] for col in inspect(connection).get_columns("approval_requests")}
            assert "service_type" in columns  # the forward-auth discriminator (#8)
            assert "service_grant_id" in columns  # the forward pointer (#11)
            assert "denial_reason" in columns  # the optional denial reason (#87)
            user_cols = {c["name"]: c for c in inspect(connection).get_columns("users")}
            assert {
                "is_admin",
                "is_active",
                "totp_secret",
                "groups",  # forward-auth Remote-Groups source (#79)
                "enrolled_at",
            } <= user_cols.keys()  # (#14)
            assert "token_hash" not in user_cols  # normalized out to api_tokens (#14)
            assert user_cols["password_hash"]["nullable"]  # credentials nullable until enroll (#15)
            assert "public_key" not in user_cols  # normalized out to user_keys (#53)
            assert "key_version" not in user_cols  # the key-pair columns left the users row (#53)
            key_cols = {c["name"] for c in inspect(connection).get_columns("user_keys")}
            assert {"public_key", "encrypted_private_key", "key_salt", "revoked_at"} <= key_cols
            revision = connection.execute(
                text("SELECT version_num FROM alembic_version")
            ).scalar_one()
    finally:
        engine.dispose()
    assert revision == "0014"


def test_downgrade_to_base_then_back_up(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    url = f"sqlite+pysqlite:///{(tmp_path / 'cycle.db').as_posix()}"
    monkeypatch.setenv("MSIG_DATABASE_URL", url)
    config = _alembic_config()

    command.upgrade(config, "head")
    command.downgrade(config, "base")

    engine = create_engine(url)
    try:
        with engine.connect() as connection:
            tables = inspect(connection).get_table_names()
            assert "users" not in tables  # downgrade drops it
            assert "approval_requests" not in tables  # ...and the intake tables
    finally:
        engine.dispose()

    command.upgrade(config, "head")  # idempotent round-trip must not raise

    engine = create_engine(url)
    try:
        with engine.connect() as connection:
            tables = inspect(connection).get_table_names()
            assert "users" in tables  # and recreates it
            assert "approval_requests" in tables
    finally:
        engine.dispose()
