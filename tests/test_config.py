"""Config loads and validates at startup, and fails loudly on bad input."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from msig_proxy.config import (
    AppConfig,
    ConfigError,
    ServerConfig,
    ServiceConfig,
    Settings,
    load_config,
)

VALID_CONFIG = """\
server:
  host: 127.0.0.1
  port: 9000
  base_url: http://localhost:9000
  secret_key: a-sufficiently-long-secret
"""


def _server() -> ServerConfig:
    return ServerConfig(base_url="http://testserver", secret_key="a-sufficiently-long-secret")


def _pypi_service(quorum: int = 2, approvers: list[str] | None = None) -> ServiceConfig:
    return ServiceConfig(
        type="one-time",
        action="publish-to-pypi",
        quorum=quorum,
        approvers=approvers or ["alice", "bob", "carol"],
    )


def _write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "config.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def test_valid_config_loads(tmp_path: Path) -> None:
    config = load_config(_write(tmp_path, VALID_CONFIG))

    assert config.server.host == "127.0.0.1"
    assert config.server.port == 9000
    assert config.server.base_url == "http://localhost:9000"


def test_auth_defaults_apply_when_the_block_is_omitted(tmp_path: Path) -> None:
    # VALID_CONFIG has no `auth` block, so every auth field falls to its default.
    config = load_config(_write(tmp_path, VALID_CONFIG))

    assert config.auth.totp_window == 1  # documented default (~±90s clock skew)
    assert config.auth.session_expiry_hours == 8


def test_totp_window_is_read_from_the_auth_block(tmp_path: Path) -> None:
    text = VALID_CONFIG + "auth:\n  totp_window: 3\n"
    config = load_config(_write(tmp_path, text))

    assert config.auth.totp_window == 3


def test_negative_totp_window_is_rejected(tmp_path: Path) -> None:
    text = VALID_CONFIG + "auth:\n  totp_window: -1\n"
    with pytest.raises(ConfigError):
        load_config(_write(tmp_path, text))


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


# --- services config (ADR 0004 ACL, ADR 0008 snapshot source) -------------


def test_quorum_cannot_exceed_the_configured_approvers() -> None:
    with pytest.raises(ValidationError, match="quorum"):
        _pypi_service(quorum=4, approvers=["alice", "bob", "carol"])  # 4-of-3 is impossible


def test_wildcard_approver_relaxes_the_static_quorum_check() -> None:
    # A glob's expansion size is unknown until snapshot time, so quorum may exceed
    # the literal entry count without a validation error ("*" can satisfy any quorum).
    service = _pypi_service(quorum=5, approvers=["*"])
    assert service.quorum == 5
    assert service.approvers == ["*"]


def test_one_time_service_requires_an_action() -> None:
    with pytest.raises(ValidationError, match="action"):
        ServiceConfig(type="one-time", quorum=1, approvers=["alice"])  # no action to hand off to


def test_pypi_service_resolves_the_single_one_time_service() -> None:
    config = AppConfig(server=_server(), services={"pypi": _pypi_service()})

    name, service = config.pypi_service()

    assert name == "pypi"
    assert service.quorum == 2
    assert service.approvers == ["alice", "bob", "carol"]


def test_pypi_service_requires_exactly_one_when_none_configured() -> None:
    config = AppConfig(server=_server())  # health surface needs no services
    with pytest.raises(ConfigError, match="found 0"):
        config.pypi_service()


def test_pypi_service_is_ambiguous_when_two_are_configured() -> None:
    config = AppConfig(
        server=_server(),
        services={"pypi": _pypi_service(), "pypi-mirror": _pypi_service()},
    )
    with pytest.raises(ConfigError, match="found 2"):
        config.pypi_service()
