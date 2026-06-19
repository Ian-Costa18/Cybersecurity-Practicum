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
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field, ValidationError, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# The one-time action the PyPI upload route hands off after quorum. Named here
# because the config layer validates it; intake/executor import it from here.
PUBLISH_TO_PYPI = "publish-to-pypi"


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


_WILDCARD_CHARS = re.compile(r"[*?\[]")


def is_wildcard(approver: str) -> bool:
    """True if an ``approvers`` entry is a glob pattern rather than a literal username.

    Glob entries (``*`` = every user, ``admin_*`` = every username with that prefix;
    fnmatch metacharacters ``*``/``?``/``[…]``) are expanded against the live user
    set when the eligible-approver set is snapshotted at request creation (ADR 0008).
    """
    return bool(_WILDCARD_CHARS.search(approver))


class HeadersConfig(BaseModel):
    """Identity headers injected into the upstream request on forward-auth success
    (``docs/config.md`` §services.*.headers). Defaults match Authelia's names for
    drop-in compatibility; set a field to ``false`` to suppress that header.

    Each field is a header *name* (string) or ``False`` to omit it entirely. No
    header is injected by this slice — it is a prefactor that only *carries* the
    config; the ``/auth`` gate that consumes it lands in Phase 1 #12.
    """

    remote_user: str | Literal[False] = "Remote-User"
    remote_name: str | Literal[False] = "Remote-Name"
    remote_email: str | Literal[False] = "Remote-Email"
    remote_groups: str | Literal[False] = "Remote-Groups"


class ServiceConfig(BaseModel):
    """One protected service's ACL (``docs/CONTEXT.md``, ADR 0004): who may approve,
    how many must (``quorum``), the service ``type``, and the type-specific tail —
    for ``one-time`` the ``action`` executed after quorum, for ``forward-auth`` the
    ``backend`` to forward to plus grant lifetime and identity headers. The
    eligible-approver set and ``quorum`` are snapshotted onto each Approval Request
    at creation (ADR 0008)."""

    type: Literal["one-time", "forward-auth"]
    # The post-approval action for one-time services (e.g. "publish-to-pypi");
    # absent for forward-auth, which grants access rather than executing an action.
    action: str | None = None
    quorum: int = Field(ge=1)
    # Literal usernames and/or glob patterns: "*" = all users, "admin_*" = prefix
    # (see is_wildcard). Patterns expand against the live user set at snapshot time.
    approvers: list[str] = Field(min_length=1)
    # Action credentials (e.g. ``{"pypi_token": "..."}``) the Executor needs to
    # perform the post-approval operation. Secrets — referenced via ``$ENV{...}``
    # in the file (``docs/config.md``). Absent for forward-auth.
    credentials: dict[str, str] | None = None

    # --- forward-auth tail (``docs/config.md``) ----------------------------
    # The protected upstream a granted request is forwarded to. Required for
    # forward-auth, forbidden for one-time (mirrors the one-time ``action`` rule).
    backend: str | None = None
    # Lifetime of the Service Grant issued on approval, in hours. ``0`` = the grant
    # expires with the Requester's Proxy Session. Forward-auth only.
    grant_expiry_hours: int = Field(default=8, ge=0)
    # Which identity headers to inject upstream and what to name them.
    headers: HeadersConfig = Field(default_factory=HeadersConfig)

    @model_validator(mode="after")
    def _validate(self) -> ServiceConfig:
        # The static quorum<=approvers check only holds when every entry is a
        # literal; a glob's expansion size is unknown until the creation-time
        # snapshot (ADR 0008), so skip it when any pattern is present.
        all_literal = not any(is_wildcard(approver) for approver in self.approvers)
        if all_literal and self.quorum > len(self.approvers):
            raise ValueError(
                f"quorum {self.quorum} exceeds the {len(self.approvers)} configured approvers"
            )
        if self.type == "one-time" and not self.action:
            raise ValueError("a one-time service requires an 'action'")
        if self.type == "forward-auth":
            if not self.backend:
                raise ValueError("a forward-auth service requires a 'backend'")
            if self.action:
                raise ValueError("a forward-auth service must not set an 'action'")
        return self


class AuthConfig(BaseModel):
    """The ``auth`` block (``docs/config.md``). Phase 1 needs only the Proxy
    Session lifetime; the enrollment-link lifetime arrives with admin-created
    accounts (#15). Password-policy / TOTP-window fields land with later Phase 2
    slices and will extend this model then."""

    # Lifetime of a Proxy Session, in hours. Governs every Proxy Session.
    session_expiry_hours: int = Field(default=8, ge=0)
    # Lifetime of an emailed enrollment link, in hours (``docs/account-management.md``).
    enrollment_link_expiry_hours: int = Field(default=24, ge=1)


class EmailConfig(BaseModel):
    """The ``notifications.email`` block — SMTP delivery (``docs/config.md``).

    The notification system is a best-effort subscriber (ADR 0005); a delivery
    failure never blocks the lifecycle. ``smtp_user``/``smtp_password`` are
    optional so a local, no-auth dev SMTP server (the test harness's in-process
    aiosmtpd) works without credentials; ``tls`` is opt-out for the same reason.
    """

    enabled: bool = True
    smtp_host: str = Field(min_length=1)
    smtp_port: int = 587
    smtp_user: str | None = None
    smtp_password: str | None = None
    from_address: str = Field(min_length=1)
    tls: bool = True
    fallback_to_portal: bool = True


class NotificationsConfig(BaseModel):
    """The ``notifications`` block. Email is the only MVP delivery backend."""

    email: EmailConfig | None = None


class AppConfig(BaseModel):
    """The parsed, validated application config file."""

    server: ServerConfig
    auth: AuthConfig = Field(default_factory=AuthConfig)
    notifications: NotificationsConfig = Field(default_factory=NotificationsConfig)
    # Protected services keyed by name (the PyPI service, plus forward-auth
    # services in later phases). Empty is valid: the health surface needs none.
    services: dict[str, ServiceConfig] = Field(default_factory=dict)

    def pypi_service(self) -> tuple[str, ServiceConfig]:
        """Resolve the single ``one-time`` PyPI publish service the upload route serves.

        Returns ``(name, config)``. Raises :class:`ConfigError` if none — or more
        than one — is configured, so a misconfiguration fails loudly at upload
        rather than silently mis-routing the artifact.
        """
        matches = [
            (name, svc)
            for name, svc in self.services.items()
            if svc.type == "one-time" and svc.action == PUBLISH_TO_PYPI
        ]
        if len(matches) != 1:
            raise ConfigError(
                f"expected exactly one one-time '{PUBLISH_TO_PYPI}' service, found {len(matches)}"
            )
        return matches[0]


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
