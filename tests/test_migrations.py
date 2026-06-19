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
            assert "users" in tables  # the Phase 0 identity table
            revision = connection.execute(
                text("SELECT version_num FROM alembic_version")
            ).scalar_one()
    finally:
        engine.dispose()
    assert revision == "0002"


def test_downgrade_to_base_then_back_up(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    url = f"sqlite+pysqlite:///{(tmp_path / 'cycle.db').as_posix()}"
    monkeypatch.setenv("MSIG_DATABASE_URL", url)
    config = _alembic_config()

    command.upgrade(config, "head")
    command.downgrade(config, "base")

    engine = create_engine(url)
    try:
        with engine.connect() as connection:
            assert "users" not in inspect(connection).get_table_names()  # downgrade drops it
    finally:
        engine.dispose()

    command.upgrade(config, "head")  # idempotent round-trip must not raise

    engine = create_engine(url)
    try:
        with engine.connect() as connection:
            assert "users" in inspect(connection).get_table_names()  # and recreates it
    finally:
        engine.dispose()
