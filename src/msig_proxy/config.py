"""Typed configuration, validated at startup.

Two layers, deliberately kept separate (see ADR 0011):

* :class:`Settings` — deploy/process-level settings read from the environment
  via ``pydantic-settings`` (the ``MSIG_`` prefix). This is where the database
  lives and where the config file is found.
* :class:`AppConfig` — the application config file (YAML), describing the
  ``server`` block today and growing to cover ``auth``/``notifications``/
  ``services`` in later phases. Secrets are referenced with ``$ENV{VAR}``
  substitution (``docs/config.md``) so they never sit in the file in plaintext.

Both fail loudly: a missing required field or an unset ``$ENV{VAR}`` reference
raises before the app accepts a request.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, ValidationError
from pydantic_settings import BaseSettings, SettingsConfigDict


class ConfigError(Exception):
    """Raised when configuration is missing, malformed, or references an unset env var."""


class Settings(BaseSettings):
    """Deploy-level settings read from the environment (prefix ``MSIG_``)."""

    model_config = SettingsConfigDict(env_prefix="MSIG_", env_file=".env", extra="ignore")

    # Sync SQLAlchemy URL. SQLite for the MVP; the seam swaps to Postgres later (ADR 0011).
    database_url: str = "sqlite+pysqlite:///./msig_proxy.db"
    # Path to the application config file (the YAML parsed into AppConfig).
    config_file: Path = Path("config.yaml")
    # Deployment environment name (e.g. "dev", "prod"). Informational for now.
    env: str = "dev"


class ServerConfig(BaseModel):
    """The ``server`` block of the config file (see ``docs/config.md``)."""

    host: str = "0.0.0.0"  # noqa: S104 - documented default bind for the proxy
    port: int = 8080
    base_url: str = Field(min_length=1)
    secret_key: str = Field(min_length=16)


class AppConfig(BaseModel):
    """The parsed, validated application config file."""

    server: ServerConfig


_ENV_REF = re.compile(r"\$ENV\{([^}]+)\}")


def _expand_env(value: Any) -> Any:
    """Recursively replace ``$ENV{VAR}`` references; raise if a referenced var is unset."""
    if isinstance(value, str):

        def _replace(match: re.Match[str]) -> str:
            name = match.group(1)
            try:
                return os.environ[name]
            except KeyError as exc:
                raise ConfigError(
                    f"config references environment variable ${{ENV}}{{{name}}} which is not set"
                ) from exc

        return _ENV_REF.sub(_replace, value)
    if isinstance(value, dict):
        return {key: _expand_env(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_expand_env(item) for item in value]
    return value


def load_config(path: Path | str) -> AppConfig:
    """Read, env-expand, and validate the application config file.

    Raises :class:`ConfigError` on a missing file, malformed YAML, an unset
    ``$ENV{VAR}`` reference, or a value that fails schema validation.
    """
    config_path = Path(path)
    try:
        text = config_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"could not read config file {config_path}: {exc}") from exc

    try:
        raw = yaml.safe_load(text) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"config file {config_path} is not valid YAML: {exc}") from exc

    expanded = _expand_env(raw)
    try:
        return AppConfig.model_validate(expanded)
    except ValidationError as exc:
        raise ConfigError(f"config file {config_path} failed validation:\n{exc}") from exc
