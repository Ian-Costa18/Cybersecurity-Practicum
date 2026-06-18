"""Config loads and validates at startup, and fails loudly on bad input."""

from __future__ import annotations

from pathlib import Path

import pytest

from msig_proxy.config import ConfigError, Settings, load_config

VALID_CONFIG = """\
server:
  host: 127.0.0.1
  port: 9000
  base_url: http://localhost:9000
  secret_key: a-sufficiently-long-secret
"""


def _write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "config.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def test_valid_config_loads(tmp_path: Path) -> None:
    config = load_config(_write(tmp_path, VALID_CONFIG))

    assert config.server.host == "127.0.0.1"
    assert config.server.port == 9000
    assert config.server.base_url == "http://localhost:9000"


def test_missing_required_field_fails_loudly(tmp_path: Path) -> None:
    text = "server:\n  base_url: http://localhost:9000\n"  # no secret_key
    with pytest.raises(ConfigError):
        load_config(_write(tmp_path, text))


def test_secret_key_below_minimum_length_is_rejected(tmp_path: Path) -> None:
    text = "server:\n  base_url: http://localhost:9000\n  secret_key: tooshort\n"
    with pytest.raises(ConfigError):
        load_config(_write(tmp_path, text))


def test_missing_file_fails_loudly(tmp_path: Path) -> None:
    with pytest.raises(ConfigError):
        load_config(tmp_path / "does-not-exist.yaml")


def test_env_var_substitution(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MSIG_TEST_SECRET", "secret-from-the-environment")
    text = "server:\n  base_url: http://localhost:9000\n  secret_key: $ENV{MSIG_TEST_SECRET}\n"

    config = load_config(_write(tmp_path, text))

    assert config.server.secret_key == "secret-from-the-environment"


def test_env_var_substitution_missing_var_fails_loudly(tmp_path: Path) -> None:
    text = "server:\n  base_url: http://localhost:9000\n  secret_key: $ENV{MSIG_DEFINITELY_UNSET}\n"
    with pytest.raises(ConfigError):
        load_config(_write(tmp_path, text))


def test_settings_read_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MSIG_DATABASE_URL", "sqlite+pysqlite:///./from-env.db")

    settings = Settings()

    assert settings.database_url == "sqlite+pysqlite:///./from-env.db"
