"""Declarative, create-if-absent user provisioning (#100).

An operator declares the users who should exist in a credential-bearing
``users.yaml``; this step **creates any that don't yet exist**, idempotently, on
every boot. It is a *bootstrap* concern like migrations — **not** part of the
side-effect-free app factory (``docs/source-layout.md``; the factory does zero DB
writes so tests build an app per case). The container entrypoint runs it after
``alembic upgrade head`` and before ``exec uvicorn``; local ``uvicorn`` bootstraps
the same way by running this command. It resolves the **first-admin paradox** (no
admin exists to create the first admin) by treating the config as the trusted
authority — equivalent to an admin's "Create user".

Two modes per declared user (``docs/account-management.md`` §Account Provisioning Flow):

* **(A) identity-only** — created inactive with no credentials, and issued an
  enrollment link (the #15 self-enroll flow) via :func:`account.enrollment_issued`.
  Default; preferred for general approvers. No password in the file.
* **(B) pre-credentialed** — created **already enrolled** from an offline bundle
  produced by ``hash-credentials`` (:mod:`msig_proxy.accounts.hash_credentials`). No
  SMTP, no click — for the first admin, CI, and no-Mailpit demos.

**Reconciliation (MVP — additive only):** the match key is ``username``;
create-if-absent only. A username present in the DB in *any* state (pending,
enrolled, deactivated) is a **no-op** — never resurrected, mutated, or re-issued a
link. No deletion/deactivation of users dropped from the file, no field
reconciliation of existing users. Safe no-op on every boot once everyone exists.
"""

from __future__ import annotations

import argparse
import base64
import logging
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, ValidationError, model_validator
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from msig_proxy.accounts.enrollment_links import mint_enrollment_link
from msig_proxy.audit import subscriber as audit_subscriber
from msig_proxy.core import events
from msig_proxy.core.config import AppConfig, ConfigError, Settings, expand_env, load_config
from msig_proxy.core.db import create_db_engine, create_session_factory, session_scope
from msig_proxy.core.events import EventBus
from msig_proxy.core.models import User, UserKey

_log = logging.getLogger(__name__)

# Provisioning modes, also reported in each outcome (see :class:`ProvisionOutcome`).
IDENTITY_ONLY = "identity-only"
PRE_CREDENTIALED = "pre-credentialed"


class KeyBundle(BaseModel):
    """The active signing key carried by a pre-credentialed (Mode B) user.

    Byte fields are base64 in the file; ``key_id`` becomes the inserted
    ``UserKey.id`` and **must** equal the id the private key was AAD-bound to at
    generation, or the first signature throws ``InvalidTag`` (``docs/cryptography.md``).
    """

    # Reject unknown keys: this is credential-bearing input, so a typo must fail
    # loudly rather than silently drop a field (``docs/constraints.md`` §10).
    model_config = ConfigDict(extra="forbid")

    key_id: uuid.UUID
    public_key: str
    encrypted_private_key: str
    key_salt: str


class UserSpec(BaseModel):
    """One declared user. Identity-only (Mode A) carries no credential fields;
    pre-credentialed (Mode B) carries ``id`` + ``password_hash`` +
    ``encrypted_totp_secret`` + ``totp_salt`` + ``key`` together (an all-or-none rule
    — a partial bundle is a config error). The wrapped second factor (#122) replaces
    the former plaintext ``totp_secret``: the file now carries only ciphertext, and
    ``id`` is the ``User.id`` the TOTP wrap was AAD-bound to (it **must** be inserted
    verbatim or the first login fails the GCM tag)."""

    # Same fail-loud posture as :class:`KeyBundle`: an unrecognized key (e.g. a
    # misspelled ``password_hash`` that would silently downgrade a Mode-B admin to a
    # credential-less Mode-A user) is rejected, not ignored.
    model_config = ConfigDict(extra="forbid")

    id: uuid.UUID | None = None
    username: str
    email: str
    is_admin: bool = False
    groups: str | None = None
    password_hash: str | None = None
    encrypted_totp_secret: str | None = None
    totp_salt: str | None = None
    key: KeyBundle | None = None

    @model_validator(mode="after")
    def _credentials_all_or_none(self) -> UserSpec:
        fields = (
            ("id", self.id),
            ("password_hash", self.password_hash),
            ("encrypted_totp_secret", self.encrypted_totp_secret),
            ("totp_salt", self.totp_salt),
            ("key", self.key),
        )
        present = [name for name, value in fields if value is not None]
        if present and len(present) != len(fields):
            missing = {name for name, _ in fields} - set(present)
            raise ValueError(
                f"user {self.username!r}: a pre-credentialed entry needs id, password_hash, "
                f"encrypted_totp_secret, totp_salt, and key together; missing {sorted(missing)}. "
                "Omit all of them for an identity-only (enrollment-link) user."
            )
        return self


class UsersFile(BaseModel):
    """The parsed ``users.yaml`` document. ``users`` is optional/empty-valid so a
    file with no entries (or a missing file, handled by the loader) is a clean no-op."""

    model_config = ConfigDict(extra="forbid")

    users: list[UserSpec] = []


@dataclass(frozen=True)
class ProvisionOutcome:
    """What happened for one declared user: ``created`` with the ``mode`` used, or a
    no-op (``created=False``, ``mode=None``) because the username already existed."""

    username: str
    created: bool
    mode: str | None


def load_user_specs(path: Path | str) -> list[UserSpec]:
    """Read, ``$ENV{}``-expand, and validate ``users.yaml`` into :class:`UserSpec`s.

    A **missing file is a clean no-op** (returns ``[]``) so a stack that declares no
    users still boots. ``$ENV{VAR}`` references are expanded (the same substitution
    config uses, ``docs/config.md``) so any field can be sourced from the environment.
    Since #122 the Mode-B bundle carries no plaintext secret at all — the second
    factor is wrapped (``encrypted_totp_secret`` + ``totp_salt``) like the signing
    key — so a committed ``users.yaml`` leaks nothing a database read would not.
    Raises :class:`ConfigError` on malformed YAML or a spec that fails validation.
    """
    users_path = Path(path)
    if not users_path.exists():
        _log.info("users file %s not found; skipping provisioning", users_path)
        return []
    try:
        raw = yaml.safe_load(users_path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"users file {users_path} is not valid YAML: {exc}") from exc
    try:
        return UsersFile.model_validate(expand_env(raw)).users
    except ValidationError as exc:
        raise ConfigError(f"users file {users_path} failed validation:\n{exc}") from exc


def _create_identity_only(
    session: Session, config: AppConfig, spec: UserSpec, *, bus: EventBus
) -> None:
    """Mode A: create the user inactive/credential-less and issue an enrollment link.

    Mirrors the Admin Portal "Create user" (``accounts.admin.create_user``): the row
    exists with no credentials until the enrollee self-enrolls, and
    :func:`mint_enrollment_link` emits ``account.enrollment_issued`` so the link is
    delivered (SMTP → portal fallback).
    """
    user = User(
        username=spec.username,
        email=spec.email,
        is_admin=spec.is_admin,
        is_active=False,
        groups=spec.groups or None,
    )
    session.add(user)
    session.flush()
    mint_enrollment_link(session, config, user, bus=bus)


def _create_pre_credentialed(session: Session, spec: UserSpec, bundle: KeyBundle) -> None:
    """Mode B: insert the user **already enrolled** plus its active signing key.

    Inserts ``User(..., enrolled_at=now, is_active=True)`` and the ``UserKey`` from
    the bundle, decoding the base64 byte fields. ``User.id`` is set to the bundle's
    ``id`` and ``UserKey.id`` to its ``key_id`` so both AES-GCM AAD bindings hold —
    the wrapped TOTP secret decrypts at the first login (#122) and the wrapped
    private key at the first ``sign_with_password``. The validator has already
    guaranteed the whole bundle is present, so ``spec.id`` /
    ``spec.encrypted_totp_secret`` / ``spec.totp_salt`` are non-null here — the guard
    below only re-narrows their types (and is never hit in practice).
    """
    if spec.id is None or spec.encrypted_totp_secret is None or spec.totp_salt is None:
        raise ConfigError(  # pragma: no cover - the all-or-none validator guarantees this
            f"user {spec.username!r}: incomplete pre-credentialed bundle"
        )
    user = User(
        id=spec.id,
        username=spec.username,
        email=spec.email,
        is_admin=spec.is_admin,
        is_active=True,
        password_hash=spec.password_hash,
        totp_secret=base64.b64decode(spec.encrypted_totp_secret),
        totp_salt=base64.b64decode(spec.totp_salt),
        groups=spec.groups or None,
        enrolled_at=datetime.now(UTC),
    )
    session.add(user)
    session.flush()
    session.add(
        UserKey(
            id=bundle.key_id,
            user_id=user.id,
            public_key=base64.b64decode(bundle.public_key),
            encrypted_private_key=base64.b64decode(bundle.encrypted_private_key),
            key_salt=base64.b64decode(bundle.key_salt),
        )
    )
    session.flush()


def provision_users(
    session: Session, config: AppConfig, specs: list[UserSpec], *, bus: EventBus
) -> list[ProvisionOutcome]:
    """Create every declared user that does not yet exist; no-op for those that do.

    Idempotent and additive (``docs/account-management.md`` §Reconciliation): matched
    by ``username``, an existing row in any state is left untouched. Flushes each
    creation onto ``session``; the caller owns the commit (the CLI :func:`main` wraps
    a :func:`session_scope`).

    The match key is ``username``, but ``email`` is independently unique, so a declared
    new user whose email already belongs to a *different* account is a misconfiguration.
    Rather than surface a raw ``IntegrityError`` at container boot, it is translated to
    a :class:`ConfigError` with a domain-meaningful message (fail loudly, like the
    config validators) — the caller's transaction is then rolled back by
    :func:`session_scope`.
    """
    outcomes: list[ProvisionOutcome] = []
    for spec in specs:
        existing = session.scalars(select(User).where(User.username == spec.username)).one_or_none()
        if existing is not None:
            outcomes.append(ProvisionOutcome(spec.username, created=False, mode=None))
            continue
        try:
            # A present ``key`` means a full Mode-B bundle (the validator enforces
            # all-or-none), and narrows it from ``KeyBundle | None`` for the insert.
            if spec.key is not None:
                _create_pre_credentialed(session, spec, spec.key)
                mode = PRE_CREDENTIALED
            else:
                _create_identity_only(session, config, spec, bus=bus)
                mode = IDENTITY_ONLY
        except IntegrityError as exc:
            raise ConfigError(
                f"users file: cannot create user {spec.username!r} — its email "
                f"{spec.email!r} (or username) already belongs to another account"
            ) from exc
        outcomes.append(ProvisionOutcome(spec.username, created=True, mode=mode))
    return outcomes


def main(argv: list[str] | None = None) -> int:
    """CLI/entrypoint: provision users from ``MSIG_USERS_FILE`` after migrations.

    Loads deploy :class:`Settings` (for ``database_url`` + ``users_file``) and the
    application config (for the enrollment-link base URL, expiry, and SMTP), then
    creates any absent users in one transaction. Wires a fresh :class:`EventBus` with
    the **audit** subscriber so a config-driven ``account.enrollment_issued`` is
    recorded the same as an admin-driven one (the enrollment email itself is sent by
    :func:`mint_enrollment_link`). Prints a one-line-per-user summary.
    """
    argparse.ArgumentParser(
        description="Provision declared users from the users file (create-if-absent)."
    ).parse_args(argv)

    settings = Settings()
    config = load_config(settings.config_file)
    specs = load_user_specs(settings.users_file)

    engine = create_db_engine(settings.database_url)
    factory = create_session_factory(engine)
    bus = EventBus()
    audit_subscriber.register(bus, factory)  # record account.* events, as app wiring does

    try:
        for session in session_scope(factory):
            # Bind the provisioning transaction as the active event session so the audit
            # subscriber records account.* events on it (atomic with the transition),
            # exactly as the request dependency does on the web path (#102).
            with events.session_bound(session):
                outcomes = provision_users(session, config, specs, bus=bus)
    finally:
        engine.dispose()

    created = sum(1 for o in outcomes if o.created)
    for outcome in outcomes:
        status = f"created ({outcome.mode})" if outcome.created else "exists (skipped)"
        print(f"  {outcome.username}: {status}")
    print(f"Provisioned {created} new user(s); {len(outcomes) - created} already existed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
