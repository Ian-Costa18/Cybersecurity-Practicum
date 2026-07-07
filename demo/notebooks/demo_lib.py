"""Demo-support library for the evaluation demo (epic #142; Act 0 = #143).

Framework-free (no ``marimo``, no FastAPI): the marimo notebook
``publish_demo.py`` imports this to drive **Act 0** against a real ``msig_proxy``
database, and the pytest suite (``tests/demo/``) imports it to prove the
provisioning produces real ciphertext-at-rest rows. Keeping the flow logic here —
outside the notebook — is what lets the notebook's render cell be swapped along the
degradation ladder (SVG → mermaid → checklist → runbook) without touching the flow,
and lets the backing check exercise the *exact* code the demo runs.

Act 0 stands up a **3-of-3** publishing service and introduces the team:

* one co-owner (``ada``) is shown **coming to life** via a live enrollment —
  account created → credentials set → Ed25519 keypair generated → private key +
  TOTP secret encrypted at rest (:func:`msig_proxy.accounts.seed.seed_user`, which
  performs the exact key-material construction enrollment does);
* the other two (``grace``, ``charles``) are provisioned **Mode-B** ("born
  enrolled", active) from an offline bundle
  (:func:`msig_proxy.accounts.hash_credentials.build_credential_bundle` →
  :func:`msig_proxy.accounts.provision.provision_users`) and simply appear set up.

╔══════════════════════════════════════════════════════════════════════════════╗
║  THROWAWAY DEMO CREDENTIALS — NOT REAL, NOT SECRET.                           ║
║  The passwords in :data:`DEMO_TEAM` are planted, checked-in, demo-only secrets ║
║  so the recorded demo is reproducible and Act 2's simulated "compromise" uses  ║
║  a *known* stolen credential rather than a real one. No real key material is   ║
║  committed: the private keys and TOTP secrets derived from these passwords are ║
║  AES-256-GCM ciphertext at rest. Never reuse these strings for anything real.  ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

from __future__ import annotations

import base64
import math
import os
import uuid
from dataclasses import dataclass, field
from pathlib import Path

import yaml
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from sqlalchemy import Engine, select
from sqlalchemy.orm import Session, sessionmaker

from msig_proxy.accounts.hash_credentials import CredentialBundle, build_credential_bundle
from msig_proxy.accounts.keys import active_key
from msig_proxy.accounts.provision import KeyBundle, UserSpec, load_user_specs, provision_users
from msig_proxy.accounts.seed import SeededUser, seed_user
from msig_proxy.core import crypto
from msig_proxy.core.config import (
    PUBLISH_TO_PYPI,
    AppConfig,
    ServerConfig,
    ServiceConfig,
)
from msig_proxy.core.db import Base, create_db_engine, create_session_factory
from msig_proxy.core.events import EventBus
from msig_proxy.core.models import DENIED, User

# --- the team --------------------------------------------------------------

# The package the team co-owns and publishes across Acts 0/1/2.
PACKAGE_NAME = "acme-widgets"
# The 3-of-3 one-time publishing service the admin stands up in Act 0.
SERVICE_NAME = "acme-publish"


@dataclass(frozen=True)
class DemoPerson:
    """One character in the demo, with the throwaway credential the demo plants.

    ``provisioning`` is ``"shown"`` for the one co-owner whose enrollment is
    performed live on screen (seeded so the key generation genuinely happens during
    the demo) and ``"mode-b"`` for the born-enrolled co-owners and the admin.
    ``role_note`` records the character's later part (Act 1/2) for the reader; Act 0
    itself is role-agnostic.
    """

    key: str
    username: str
    display_name: str
    email: str
    password: str
    provisioning: str  # "shown" | "mode-b"
    is_admin: bool = False
    groups: str | None = None
    role_note: str = ""

    @property
    def given_name(self) -> str:
        """First token of :attr:`display_name` — the short name used in board prose."""
        return self.display_name.split()[0]


# The cast. Passwords are THROWAWAY, DEMO-ONLY (see the module banner). ``ada`` is the
# co-owner shown enrolling live; ``grace``/``charles`` are born-enrolled (Mode-B); the
# admin stands up the service. Emails use the reserved ``.example`` TLD (RFC 2606).
DEMO_TEAM: tuple[DemoPerson, ...] = (
    DemoPerson(
        key="admin",
        username="admin",
        display_name="Alan Turing (Admin)",
        email="admin@acme.example",
        password="demo-admin-pw-01!",  # noqa: S106 - throwaway demo-only credential
        provisioning="mode-b",
        is_admin=True,
        groups="operators",
        role_note="stands up the 3-of-3 service and introduces the team",
    ),
    DemoPerson(
        key="ada",
        username="ada",
        display_name="Ada Lovelace",
        email="ada@acme.example",
        password="demo-ada-pw-01!",  # noqa: S106 - throwaway demo-only credential
        provisioning="shown",
        groups="release-managers",
        role_note="the enrollment shown on screen; the diligent denier in Act 2",
    ),
    DemoPerson(
        key="grace",
        username="grace",
        display_name="Grace Hopper",
        email="grace@acme.example",
        password="demo-grace-pw-01!",  # noqa: S106 - throwaway demo-only credential
        provisioning="mode-b",
        groups="release-managers",
        role_note="born enrolled; the honest-but-careless rubber-stamp in Act 2",
    ),
    DemoPerson(
        key="charles",
        username="charles",
        display_name="Charles Babbage",
        email="charles@acme.example",
        password="demo-charles-pw-01!",  # noqa: S106 - throwaway demo-only credential
        provisioning="mode-b",
        groups="release-managers",
        role_note="born enrolled; the co-owner whose seat is stolen in Act 2",
    ),
)

# The three co-owners (everyone but the admin) — the eligible-approver set of the
# 3-of-3 service, in board / narrative order.
CO_OWNERS: tuple[DemoPerson, ...] = tuple(p for p in DEMO_TEAM if not p.is_admin)

# The admin/operator who stands up the service (the sole non-co-owner).
ADMIN: DemoPerson = next(p for p in DEMO_TEAM if p.is_admin)

# The quorum the demo service requires: unanimity of the co-owners (3-of-3).
QUORUM: int = len(CO_OWNERS)

# The one co-owner whose enrollment is performed live on screen (seeded), vs. the
# born-enrolled (Mode-B) pair. Derived so the notebook + board never hardcode "ada".
SHOWN_PERSON: DemoPerson = next(p for p in DEMO_TEAM if p.provisioning == "shown")
BORN_ENROLLED: tuple[DemoPerson, ...] = tuple(p for p in CO_OWNERS if p.provisioning == "mode-b")

# --- Act 1/2 role casting (one continuous team; see each DemoPerson.role_note) ---
#
# The narrative parts the same three co-owners play across the two acts, named by cast
# key so `demo_flow` never hardcodes a username. charles is the ordinary publisher in
# Act 1 and the seat stolen in Act 2 (the release seat that legitimately shipped 1.0.0
# is the one impersonated to push malicious 1.0.1). ada is the co-owner shown inspecting
# on camera in Act 1 and the diligent denier in Act 2. grace is a self-driven approver
# in Act 1 and the honest-but-careless rubber-stamp in Act 2.
ACT1_REQUESTER = "charles"  # announces the release + uploads via twine (also self-approves)
ACT1_SHOWN_VOTER = "ada"  # opens the email, inspects the exact artifact, votes on camera
ACT1_SELF_VOTERS: tuple[str, ...] = ("grace", "charles")  # the two votes the notebook self-drives

ACT2_STOLEN_SEAT = "charles"  # the stolen proxy credential (submits + self-approves 1.0.1)
ACT2_CARELESS = "grace"  # the honest-but-careless rubber-stamp (vote 2)
ACT2_DILIGENT = "ada"  # the diligent co-owner who verifies out-of-band and denies


def person(key: str) -> DemoPerson:
    """The :class:`DemoPerson` with cast key ``key`` (e.g. ``"ada"``)."""
    for candidate in DEMO_TEAM:
        if candidate.key == key:
            return candidate
    raise KeyError(f"no demo person with key {key!r}")


def demo_service_config() -> ServiceConfig:
    """The 3-of-3 ``one-time`` PyPI publishing service the admin stands up.

    A real :class:`~msig_proxy.core.config.ServiceConfig` (quorum 3 over the three
    co-owners), so what the board shows is the same shape the proxy validates at
    boot. ``endpoint`` is left to its default here; the live stack points it at the
    local ``pypiserver`` in ``config/config.yaml``.
    """
    return ServiceConfig(
        type="one-time",
        action=PUBLISH_TO_PYPI,
        approvers=[p.username for p in CO_OWNERS],
        quorum=QUORUM,
    )


# --- provisioning ----------------------------------------------------------

# The database the notebook drives when ``MSIG_DATABASE_URL`` is not set (a local
# edit-mode / dry-run default). The live stack sets ``MSIG_DATABASE_URL`` to the
# proxy's shared SQLite file so Act 0 provisions the very rows Acts 1/2 vote on.
DEFAULT_DEMO_DATABASE_URL = "sqlite+pysqlite:///./demo/notebooks/publish_demo.db"

# The committed offline bundle for the born-enrolled co-owners (Act 0 Mode-B).
# Regenerate with: uv run python demo/notebooks/demo_lib.py > demo/seed/users.demo.yaml
DEMO_USERS_YAML = Path(__file__).resolve().parents[1] / "seed" / "users.demo.yaml"

# The committed application config the presenter copies to config/config.yaml; it
# defines the 3-of-3 SERVICE_NAME service the admin stands up in Act 0.
DEMO_CONFIG_YAML = Path(__file__).resolve().parents[1] / "seed" / "config.demo.yaml"

# The marker line at the top of every committed demo credential artifact. The backing
# check asserts it is present, so a file that lost its "throwaway, demo-only" framing
# fails CI rather than sitting in the tree looking like real credential material.
# Kept ASCII so the committed artifact is portable across every console encoding.
DEMO_ONLY_MARKER = "THROWAWAY DEMO CREDENTIALS - NOT REAL"

_DEMO_USERS_YAML_HEADER = f"""\
# ===================== {DEMO_ONLY_MARKER} =====================
# Born-enrolled (Mode-B) bundle for the evaluation demo's co-owners (#143, epic #142).
# GENERATED - do not hand-edit. Regenerate with:
#   uv run python demo/notebooks/demo_lib.py > demo/seed/users.demo.yaml
#
# Every field below is non-reversible (bcrypt hash + AES-256-GCM-wrapped signing key
# and TOTP secret). The only "secret" is the throwaway password in demo_lib.DEMO_TEAM,
# planted on purpose so Act 2's simulated compromise is reproducible. NEVER copy this
# pattern for real accounts, and never reuse these values anywhere real.
"""


def _demo_app_config() -> AppConfig:
    """A minimal valid :class:`AppConfig` for the provisioning calls.

    Only the Mode-A (enrollment-link) path reads it, and the demo provisions no
    Mode-A users, so its values are placeholders — but the type is required by
    :func:`provision_users`.
    """
    return AppConfig(
        server=ServerConfig(
            host="127.0.0.1",
            port=8080,
            base_url="http://localhost:8080",
            secret_key="demo-only-not-a-secret-0000",  # noqa: S106 - throwaway demo-only
        )
    )


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def mode_b_spec(bundle: CredentialBundle) -> UserSpec:
    """Turn an offline :class:`CredentialBundle` into a Mode-B :class:`UserSpec`.

    The in-memory equivalent of pasting ``hash-credentials`` output into
    ``users.yaml``: it carries the id + bcrypt hash + wrapped TOTP + wrapped signing
    key so :func:`provision_users` inserts a born-enrolled user whose AES-GCM AAD
    bindings hold.
    """
    return UserSpec(
        id=bundle.user_id,
        username=bundle.username,
        email=bundle.email,
        is_admin=bundle.is_admin,
        groups=bundle.groups,
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


@dataclass(frozen=True)
class DemoProvisioning:
    """What Act 0 provisioning produced.

    ``shown`` is the live-seeded co-owner's :class:`SeededUser` — it carries the
    one-time API token and the *plaintext* TOTP secret produced live during Act 0 (the
    "credentials live" beat). Acts 1/2 recover any co-owner's current TOTP from the DB
    row + the (known, demo-only) password directly, so no plaintext second factor needs
    to be threaded through here. ``mode_b_from_file`` records whether the born-enrolled
    bundle came from the committed ``users.demo.yaml`` (the planted secrets) or the
    regeneration fallback.
    """

    shown: SeededUser
    shown_person: DemoPerson
    mode_b_from_file: bool


def _exists(session: Session, username: str) -> bool:
    return session.scalars(select(User).where(User.username == username)).one_or_none() is not None


def _build_mode_b_bundle(member: DemoPerson) -> CredentialBundle:
    return build_credential_bundle(
        username=member.username,
        email=member.email,
        password=member.password,
        is_admin=member.is_admin,
        groups=member.groups,
    )


def mode_b_specs() -> tuple[list[UserSpec], bool]:
    """The born-enrolled co-owners' provisioning specs, and whether they came from file.

    Prefers the committed offline bundle (:data:`DEMO_USERS_YAML` — the planted,
    deterministic demo secrets, the same file a presenter could copy to
    ``config/users.yaml``). If that file is missing, regenerates equivalent bundles
    from the cast so the demo still runs, and reports ``False`` so the caller/notebook
    can note the fallback.
    """
    if DEMO_USERS_YAML.exists():
        return load_user_specs(DEMO_USERS_YAML), True
    regenerated = [_build_mode_b_bundle(m) for m in DEMO_TEAM if m.provisioning == "mode-b"]
    return [mode_b_spec(bundle) for bundle in regenerated], False


def provision_demo_team(session: Session) -> DemoProvisioning:
    """Provision the whole demo cast onto ``session`` (create-if-absent).

    The one ``"shown"`` co-owner is seeded live (:func:`seed_user`) so the Ed25519
    keypair generation and the at-rest encryption of the private key + TOTP secret
    genuinely occur during Act 0. The Mode-B people are inserted through the real
    declarative path (:func:`provision_users`) from the committed offline bundle, so
    they are born enrolled and can vote immediately.

    Idempotent enough for the "reset demo" re-run: an already-present username is a
    no-op (``provision_users`` skips it; the seed is guarded), so provisioning twice
    against a not-fully-cleared database does not raise.
    """
    config = _demo_app_config()
    bus = EventBus()

    shown_person = SHOWN_PERSON
    if _exists(session, shown_person.username):
        shown = seed_result_placeholder(session, shown_person)
    else:
        shown = seed_user(
            session,
            username=shown_person.username,
            email=shown_person.email,
            password=shown_person.password,
            is_admin=shown_person.is_admin,
            groups=shown_person.groups,
        )

    specs, from_file = mode_b_specs()
    provision_users(session, config, specs, bus=bus)
    session.flush()
    return DemoProvisioning(shown=shown, shown_person=shown_person, mode_b_from_file=from_file)


def render_demo_users_yaml() -> str:
    """Render the committed born-enrolled bundle (``users.demo.yaml``) from the cast.

    Regenerate the file with::

        uv run python demo/notebooks/demo_lib.py > demo/seed/users.demo.yaml

    Every emitted field is non-reversible (bcrypt hash, AES-256-GCM-wrapped key + TOTP
    secret), so the file is safe to commit; the only "secret" is the throwaway password
    in :data:`DEMO_TEAM`, which is intentionally planted so Act 2's compromise is
    reproducible (see the module banner).
    """
    entries = [
        mode_b_spec(_build_mode_b_bundle(m)).model_dump(mode="json", exclude_none=True)
        for m in DEMO_TEAM
        if m.provisioning == "mode-b"
    ]
    body = yaml.safe_dump({"users": entries}, sort_keys=False)
    return _DEMO_USERS_YAML_HEADER + body


def seed_result_placeholder(session: Session, shown_person: DemoPerson) -> SeededUser:
    """Reconstruct a :class:`SeededUser` view of an already-seeded shown co-owner.

    On a "reset demo" re-run the shown co-owner may already exist; the demo still
    wants their handle. The row already holds a wrapped TOTP secret, which decrypts
    under the (known, demo-only) password, so the plaintext can be recovered rather
    than re-seeded. The ``api_token`` plaintext is not recoverable (only its hash is
    stored), so it is returned empty — Act 1 mints a fresh token when needed.
    """
    user = session.scalars(select(User).where(User.username == shown_person.username)).one()
    if user.totp_secret is None or user.totp_salt is None:  # pragma: no cover - seeded => both set
        raise RuntimeError(f"seeded demo user {shown_person.username!r} is missing its TOTP secret")
    totp_plain = crypto.decrypt_totp_secret(
        user.totp_secret,
        crypto.derive_enc_key(shown_person.password, user.totp_salt),
        crypto.totp_aad(user.id),
    )
    return SeededUser(user=user, api_token="", totp_secret=totp_plain)


# --- credential-at-rest state (the Act 0 crypto beat) ----------------------


@dataclass(frozen=True)
class CredentialState:
    """The at-rest credential state of one enrolled user, read from **real rows**.

    This is what the Act 0 "crypto beat" paints on screen for the shown co-owner —
    and the honest backing for it (``tests/demo/``): a readable
    :attr:`public_key` next to a ciphertext :attr:`encrypted_private_key`
    (``UserKey``) and a ciphertext :attr:`totp_secret_ciphertext` (``User``). The
    ``*_is_ciphertext`` flags are computed by actually decrypting under the supplied
    password — so a green flag means the blob genuinely round-trips, not merely that
    it "looks" encrypted.
    """

    username: str
    is_active: bool
    is_enrolled: bool
    # Signing key (UserKey).
    key_id: uuid.UUID
    public_key: bytes
    public_key_is_valid: bool
    key_salt: bytes | None
    encrypted_private_key: bytes | None
    private_key_at_rest_is_ciphertext: bool
    # Second factor (User.totp_secret), wrapped since #122.
    totp_secret_ciphertext: bytes | None
    totp_salt: bytes | None
    totp_at_rest_is_ciphertext: bool

    @property
    def public_key_hex(self) -> str:
        """The public key rendered as hex — safe to display in the clear."""
        return self.public_key.hex()


def _loads_as_ed25519_public_key(raw: bytes) -> bool:
    """True if ``raw`` is a well-formed Ed25519 public key (32 bytes on the curve)."""
    try:
        Ed25519PublicKey.from_public_bytes(raw)
    except ValueError:
        return False
    return True


def read_credential_state(session: Session, username: str, *, password: str) -> CredentialState:
    """Read the real ``User`` + active ``UserKey`` rows for ``username`` and classify them.

    Proves the at-rest crypto by *doing* it: the private key and TOTP secret are
    decrypted under ``password`` (the throwaway demo password), so
    :attr:`CredentialState.private_key_at_rest_is_ciphertext` and
    :attr:`CredentialState.totp_at_rest_is_ciphertext` are true only when the stored
    blob is genuinely AES-256-GCM ciphertext that round-trips — never a fabricated
    "looks encrypted" check. Raises if the user is not a fully-enrolled account with
    an active key (every provisioned co-owner is).
    """
    user = session.scalars(select(User).where(User.username == username)).one()
    key = active_key(session, user)
    if key is None or key.encrypted_private_key is None or key.key_salt is None:
        raise RuntimeError(f"demo user {username!r} has no active signing key to display")
    if user.totp_secret is None or user.totp_salt is None:
        raise RuntimeError(f"demo user {username!r} has no wrapped TOTP secret to display")

    private_raw = crypto.decrypt_private_key(
        key.encrypted_private_key,
        crypto.derive_enc_key(password, key.key_salt),
        crypto.key_aad(key.id),
    )
    private_at_rest_is_ciphertext = private_raw != key.encrypted_private_key and len(
        key.encrypted_private_key
    ) > len(private_raw)
    totp_plain = crypto.decrypt_totp_secret(
        user.totp_secret,
        crypto.derive_enc_key(password, user.totp_salt),
        crypto.totp_aad(user.id),
    )
    totp_at_rest_is_ciphertext = totp_plain.encode("ascii") not in user.totp_secret

    return CredentialState(
        username=user.username,
        is_active=user.is_active,
        is_enrolled=user.enrolled_at is not None,
        key_id=key.id,
        public_key=key.public_key,
        public_key_is_valid=_loads_as_ed25519_public_key(key.public_key),
        key_salt=key.key_salt,
        encrypted_private_key=key.encrypted_private_key,
        private_key_at_rest_is_ciphertext=private_at_rest_is_ciphertext,
        totp_secret_ciphertext=user.totp_secret,
        totp_salt=user.totp_salt,
        totp_at_rest_is_ciphertext=totp_at_rest_is_ciphertext,
    )


# --- the board scaffold (Maltego-style; reused by Acts 1/2) ----------------
#
# The board is a light-mode link-analysis graph: the cast as actor nodes and the
# services (the Proxy pipeline intake→quorum→executor→audit, Mailpit, pypiserver) as
# service nodes. A `step` state variable selects a :class:`BoardStep`, and the render
# cell paints it. Only :func:`render_board_svg` and its siblings know how to *draw* a
# step — the flow logic advances the step index — so the render backend can be swapped
# down the DEGRADATION LADDER without touching the flow:
#
#   1. custom SVG   (:func:`render_board_svg`)      — the polished default
#   2. mermaid      (:func:`render_board_mermaid`)  — mo.mermaid() if the SVG fights us
#   3. checklist    (:func:`render_capability_checklist`) — capability→test rows only
#   4. runbook      — the notebook's own markdown narration (always present)
#
# Acts 1/2 extend the node-set / step list here and reuse the same renderers.


@dataclass(frozen=True)
class BoardNode:
    """One node on the board. ``kind`` is ``"actor"``, ``"stage"`` (a Proxy pipeline
    stage), or ``"service"`` (an external service). ``x``/``y`` are fixed positions on
    the ``BOARD_WIDTH`` by ``BOARD_HEIGHT`` canvas."""

    id: str
    label: str
    kind: str
    x: float
    y: float


@dataclass(frozen=True)
class BoardStep:
    """One beat of the story. ``active_nodes`` are lit; ``overlays`` maps a node id to a
    small live-data caption (e.g. the shown key's fingerprint) painted under it. The
    notebook may pass extra overlays at render time (real data from the DB rows)."""

    key: str
    title: str
    caption: str
    active_nodes: frozenset[str]
    overlays: dict[str, str] = field(default_factory=dict)
    # ``(hour24, minute)`` of the beat, drawn as a corner clock — Act 2's overnight-vs-morning
    # device (2 a.m. compromise → 9 a.m. wake-up). ``None`` (Act 0/1) draws no clock.
    clock: tuple[int, int] | None = None


BOARD_WIDTH = 1000
BOARD_HEIGHT = 560
# A header band above the graph so the title + caption never ride under the top actor
# node (the graph is drawn translated down by this much; the canvas grows to match).
BOARD_HEADER_H = 44

# Actor nodes are derived from DEMO_TEAM (down the left) so the cast lives in exactly
# one place; the Proxy pipeline runs down the middle and external services on the right.
_ACTOR_X = 150
_ACTOR_TOP = 80
_ACTOR_GAP = 127
BOARD_NODES: tuple[BoardNode, ...] = (
    *(
        BoardNode(p.key, p.display_name, "actor", _ACTOR_X, _ACTOR_TOP + i * _ACTOR_GAP)
        for i, p in enumerate(DEMO_TEAM)
    ),
    BoardNode("intake", "Proxy · intake", "stage", 470, 110),
    BoardNode("quorum", "Proxy · quorum", "stage", 470, 240),
    BoardNode("executor", "Proxy · executor", "stage", 470, 370),
    BoardNode("audit", "Proxy · audit", "stage", 470, 490),
    BoardNode("mailpit", "Email", "service", 810, 175),
    BoardNode("pypiserver", "PyPI", "service", 810, 400),
)

# Static relationships; a step lights the subset whose endpoints are both active. The
# actor→pipeline edges are derived from the team so they track any cast change.
BOARD_EDGES: tuple[tuple[str, str], ...] = (
    (ADMIN.key, "intake"),
    *((p.key, "quorum") for p in CO_OWNERS),
    ("intake", "quorum"),
    ("quorum", "executor"),
    ("executor", "audit"),
    ("intake", "mailpit"),
    ("quorum", "mailpit"),
    ("executor", "pypiserver"),
)

# The Act 0 beats whose crypto card / lock badge feature the shown co-owner's real key.
ADA_KEYPAIR_BEAT = "ada-keypair"
ADA_SEALED_BEAT = "ada-sealed"

ACT0_STEPS: tuple[BoardStep, ...] = (
    BoardStep(
        key="standup",
        title=f"Publishing {PACKAGE_NAME} takes all {QUORUM} owners' approval",
        caption=(
            f"{ADMIN.given_name} sets up the release service — no single account, "
            "stolen or not, can ship a release alone."
        ),
        active_nodes=frozenset({ADMIN.key, "intake", "quorum", "executor", "audit", "pypiserver"}),
        overlays={"quorum": f"{QUORUM} of {QUORUM} must approve"},
    ),
    BoardStep(
        key="ada-account",
        title=f"{SHOWN_PERSON.given_name} joins the team",
        caption="A new co-owner comes aboard — her account is created on the service.",
        active_nodes=frozenset({SHOWN_PERSON.key, "intake"}),
    ),
    BoardStep(
        key=ADA_KEYPAIR_BEAT,
        title=f"{SHOWN_PERSON.given_name} gets a personal signing key",
        caption="A brand-new key pair is generated for her — the public half is safe to share.",
        active_nodes=frozenset({SHOWN_PERSON.key, "quorum"}),
    ),
    BoardStep(
        key=ADA_SEALED_BEAT,
        title=f"{SHOWN_PERSON.given_name}'s private key is locked away",
        caption=(
            "Her private key is sealed under her password — only she can unlock it, "
            "and only to approve a release."
        ),
        active_nodes=frozenset({SHOWN_PERSON.key, "quorum"}),
    ),
    BoardStep(
        key="already-enrolled",
        title=f"{' & '.join(p.given_name for p in BORN_ENROLLED)} are already set up",
        caption="The other two co-owners were enrolled earlier — accounts and keys ready to go.",
        active_nodes=frozenset({p.key for p in BORN_ENROLLED} | {"quorum"}),
    ),
    BoardStep(
        key="team-ready",
        title="Three owners, each able to approve a release",
        caption="The service is ready: from here on, every release needs all three of them.",
        active_nodes=frozenset({p.key for p in DEMO_TEAM} | {"quorum", "audit"}),
    ),
)

ACT1_STEPS: tuple[BoardStep, ...] = (
    BoardStep(
        key="act1-announce",
        title=f"{person(ACT1_REQUESTER).given_name} tells the team a release is coming",
        caption=f'"Team — I\'m publishing {PACKAGE_NAME} 1.0.0 today. Please review and approve."',
        active_nodes=frozenset({ACT1_REQUESTER, "mailpit"}),
    ),
    BoardStep(
        key="act1-self-cancel",
        title="A stray file slips in — caught and corrected",
        caption=(
            f"{person(ACT1_REQUESTER).given_name} spots a leftover debug file and cancels the "
            "upload before anyone reviews it."
        ),
        active_nodes=frozenset({ACT1_REQUESTER, "intake"}),
    ),
    BoardStep(
        key="act1-submit",
        title="Version 1.0.0 is uploaded and fingerprinted",
        caption="Every owner gets an email to review the exact release being proposed.",
        active_nodes=frozenset({ACT1_REQUESTER, "intake", "quorum", "mailpit"}),
    ),
    BoardStep(
        key="act1-inspect-vote",
        title=f"{person(ACT1_SHOWN_VOTER).given_name} inspects the exact release and approves",
        caption="She downloads the exact files she is approving, signs in again, and approves.",
        active_nodes=frozenset({ACT1_SHOWN_VOTER, "mailpit", "quorum"}),
    ),
    BoardStep(
        key="act1-self-votes",
        title="The other two owners approve",
        caption=f"With all {QUORUM} approvals in, the release is cleared to publish.",
        active_nodes=frozenset({ACT1_SHOWN_VOTER, *ACT1_SELF_VOTERS, "quorum"}),
    ),
    BoardStep(
        key="act1-publish",
        title="Approved — the release publishes to PyPI",
        caption="The service re-checks the fingerprint, publishes to PyPI, and logs the result.",
        active_nodes=frozenset({"quorum", "executor", "audit", "pypiserver", "mailpit"}),
    ),
    BoardStep(
        key="act1-install",
        title=f"pip install {PACKAGE_NAME}==1.0.0 works",
        caption="The release really shipped — anyone can install it.",
        active_nodes=frozenset({"pypiserver"}),
    ),
)

ACT2_STEPS: tuple[BoardStep, ...] = (
    BoardStep(
        key="act2-2am",
        title="2 a.m. — a malicious 1.0.1 from a stolen account",
        caption=(
            f"The attacker has {person(ACT2_STOLEN_SEAT).given_name}'s login, uploads 1.0.1, and "
            "approves it — with no word to the team."
        ),
        active_nodes=frozenset({ACT2_STOLEN_SEAT, "intake", "quorum"}),
        clock=(2, 0),
    ),
    # The careless approval and the freeze are one beat: the second stamp *is* what lands the
    # request at 2/3, and 2/3 is where it stops — a separate "now it's frozen" click added
    # nothing. The clock stays at 2 a.m.; it swings to 9 a.m. on the next beat, when the
    # diligent owner wakes and looks — the whole point being that the release just waited.
    BoardStep(
        key="act2-frozen",
        title=f"A second owner rubber-stamps — stuck at 2 of {QUORUM}",
        caption=(
            f"That is two approvals, but all {QUORUM} are required. Without the third the "
            "release just waits — no one can force it through."
        ),
        active_nodes=frozenset({ACT2_CARELESS, "quorum"}),
        clock=(2, 0),
    ),
    BoardStep(
        key="act2-verify",
        title=(
            f"9 a.m. — {person(ACT2_DILIGENT).given_name} checks directly with "
            f"{person(ACT2_STOLEN_SEAT).given_name}"
        ),
        caption=(
            '"Are you pushing 1.0.1?" — "No, I was asleep." '
            f"The attacker never had {person(ACT2_STOLEN_SEAT).given_name}'s inbox."
        ),
        active_nodes=frozenset({ACT2_DILIGENT, ACT2_STOLEN_SEAT, "mailpit"}),
        clock=(9, 0),
    ),
    BoardStep(
        key="act2-deny",
        title=f"{person(ACT2_DILIGENT).given_name} denies the release — no code review needed",
        caption="One honest question was enough to stop it, and the denial is logged.",
        active_nodes=frozenset({ACT2_DILIGENT, "quorum", "audit"}),
        clock=(9, 0),
    ),
    BoardStep(
        key="act2-blocked",
        title="1.0.1 never reached PyPI",
        caption=f"pip install {PACKAGE_NAME}==1.0.1 fails — users were never exposed.",
        active_nodes=frozenset({"pypiserver"}),
        clock=(9, 0),
    ),
    BoardStep(
        key="act2-reveal",
        title="Only now: what the release would have done",
        caption=(
            "The block held on human judgment alone — the hidden install-time code just "
            "confirms it."
        ),
        active_nodes=frozenset({ACT2_STOLEN_SEAT, "intake"}),
        clock=(9, 0),
    ),
)


def act1_overlays(
    step: BoardStep,
    *,
    artifact_sha256: str | None = None,
    approvals: int | None = None,
    quorum: int | None = None,
    published_version: str | None = None,
    installable: bool | None = None,
) -> dict[str, str]:
    """Live-data overlays (node id → caption) for an Act 1 beat, from **real** values.

    Extracted so this step→overlay mapping is tested flow logic, not glue in the
    notebook: the notebook passes the real hash / tally / published version read back
    from the stack, and only the node the current beat features is painted."""
    overlays: dict[str, str] = {}
    if "intake" in step.active_nodes and artifact_sha256:
        overlays["intake"] = f"sha256:{artifact_sha256[:8]}…"
    if "quorum" in step.active_nodes and approvals is not None and quorum is not None:
        overlays["quorum"] = f"{approvals}/{quorum} approvals"
    if "pypiserver" in step.active_nodes and published_version:
        tag = f"{PACKAGE_NAME} {published_version}"
        overlays["pypiserver"] = f"{tag} ✓ installs" if installable else f"{tag} published"
    return overlays


def act2_overlays(
    step: BoardStep,
    *,
    approvals: int | None = None,
    quorum: int | None = None,
    state: str | None = None,
    blocked_version: str | None = None,
) -> dict[str, str]:
    """Live-data overlays for an Act 2 beat, from **real** values (the frozen tally, the
    DENIED state, the version absent from the index)."""
    overlays: dict[str, str] = {}
    if "quorum" in step.active_nodes:
        if state == DENIED:
            overlays["quorum"] = "DENIED"
        elif approvals is not None and quorum is not None:
            overlays["quorum"] = f"{approvals}/{quorum} — frozen"
    if "pypiserver" in step.active_nodes and blocked_version:
        overlays["pypiserver"] = f"{PACKAGE_NAME} {blocked_version} ✗ absent"
    return overlays


# Act 0 capabilities shown, each traced to a backing test (the §2 checklist idea). Acts
# 1/2 append their rows; the render stays the same.
CAPABILITY_CHECKLIST: tuple[tuple[str, str], ...] = (
    (
        "Admin stands up a 3-of-3 service; three co-owners can vote",
        "tests/demo/test_act0_provisioning.py::test_provisions_three_co_owners_who_can_vote",
    ),
    (
        "Shown enrollment: readable public key, ciphertext private key at rest",
        "tests/demo/test_act0_provisioning.py"
        "::test_shown_enrollment_public_key_is_readable_private_key_is_ciphertext",
    ),
    (
        "Shown enrollment: TOTP secret ciphertext at rest, password-bound",
        "tests/demo/test_act0_provisioning.py"
        "::test_shown_enrollment_totp_secret_is_ciphertext_bound_to_the_password",
    ),
    (
        "Mode-B co-owners born enrolled and able to cast a signed vote",
        "tests/demo/test_act0_provisioning.py::test_mode_b_co_owners_are_born_enrolled_and_can_sign",
    ),
    # --- Act 1 (happy path) ---
    (
        "Team-thread heads-up is a real email to the co-owners",
        "tests/demo/test_act1_happy_path.py::test_team_thread_heads_up_is_a_real_email",
    ),
    (
        "Real twine upload creates a pending, hash-bound request",
        "tests/demo/test_act1_happy_path.py::test_submit_creates_a_hash_bound_request",
    ),
    (
        "Benign self-cancel: requester withdraws a draft, resubmits clean",
        "tests/demo/test_act1_happy_path.py::test_benign_self_cancel_then_clean_resubmit",
    ),
    (
        "Approvers notified; the shown co-owner inspects the exact artifact",
        "tests/demo/test_act1_happy_path.py::test_approvers_notified_and_exact_artifact_downloadable",
    ),
    (
        "Quorum over reauth+signed votes triggers a real publish",
        "tests/demo/test_act1_happy_path.py::test_quorum_publishes_the_release",
    ),
    (
        "Published version installs from the local index",
        "tests/demo/test_act1_happy_path.py::test_published_version_appears_in_the_index",
    ),
    # --- Act 2 (the compromise deny) ---
    (
        "Stolen seat + careless approver freeze at 2/3 — no publish",
        "tests/demo/test_act2_compromise.py::test_stolen_seat_and_careless_stamp_freeze_at_two_thirds",
    ),
    (
        "Out-of-band verification is a real, independent email exchange",
        "tests/demo/test_act2_compromise.py::test_out_of_band_verification_is_real_email",
    ),
    (
        "Diligent deny → DENIED; malicious 1.0.1 never reaches the index",
        "tests/demo/test_act2_compromise.py::test_diligent_deny_blocks_the_malicious_release",
    ),
    (
        "t = m-1 worst case (two compromised seats) still cannot publish",
        "tests/service_types/one_time/test_compromise_boundary.py"
        "::test_m_minus_one_compromised_seats_cannot_publish",
    ),
)


def _esc(text: str) -> str:
    """Escape text for inclusion in SVG/XML character data."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _lock_glyph(cx: float, cy: float) -> str:
    """A small padlock centred at ``(cx, cy)`` — marks a node whose signing key is sealed.

    Drawn as a badge on Act 0's "private key sealed" beat so the viewer literally sees the
    key locked up, rather than only reading that it is encrypted."""
    body_w, body_h = 16.0, 12.0
    x = cx - body_w / 2
    y = cy - body_h / 2 + 2
    return (
        '<g class="lock" aria-label="sealed">'
        f'<path d="M{cx - 5} {y} v-3 a5 5 0 0 1 10 0 v3" '
        'fill="none" stroke="#b9822b" stroke-width="2"/>'
        f'<rect x="{x}" y="{y}" width="{body_w}" height="{body_h}" rx="2.5" '
        'fill="#fdf1d6" stroke="#b9822b" stroke-width="1.5"/>'
        f'<circle cx="{cx}" cy="{y + body_h / 2}" r="1.6" fill="#b9822b"/>'
        "</g>"
    )


def _clock_glyph(cx: float, cy: float, r: float, hour24: int, minute: int) -> str:
    """A small analog clock centred at ``(cx, cy)`` with an AM/PM label beneath it.

    Act 2's time-of-day, drawn in the corner. The hour hand visibly swings from 2 o'clock
    (the overnight compromise) to 9 o'clock (morning, when the diligent owner wakes and
    checks) — so the viewer *sees* that the frozen release simply waited hours for a human
    to look, which is the whole point of the delay."""

    def _hand(angle_deg: float, length: float) -> tuple[float, float]:
        rad = math.radians(angle_deg)
        return cx + length * math.sin(rad), cy - length * math.cos(rad)

    def _tick(t: int) -> str:
        x1, y1 = _hand(t * 30, r - 4)
        x2, y2 = _hand(t * 30, r - 1)
        return f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}"/>'

    hx, hy = _hand((hour24 % 12) * 30.0 + minute * 0.5, r * 0.5)  # hour hand
    mx, my = _hand(minute * 6.0, r * 0.72)  # minute hand
    ticks = "".join(_tick(t) for t in range(12))
    meridiem = "AM" if hour24 < 12 else "PM"
    label = f"{hour24 % 12 or 12} {meridiem}"
    return (
        f'<g class="clock" aria-label="{_esc(label)}">'
        f'<circle class="clock-face" cx="{cx}" cy="{cy}" r="{r}"/>'
        f'<g class="clock-tick">{ticks}</g>'
        f'<line class="clock-hand hour" x1="{cx}" y1="{cy}" x2="{hx:.1f}" y2="{hy:.1f}"/>'
        f'<line class="clock-hand min" x1="{cx}" y1="{cy}" x2="{mx:.1f}" y2="{my:.1f}"/>'
        f'<circle class="clock-pin" cx="{cx}" cy="{cy}" r="2.2"/>'
        f'<text class="clock-label" x="{cx}" y="{cy + r + 15}" text-anchor="middle">'
        f"{_esc(label)}</text>"
        "</g>"
    )


_BOARD_STYLE = (
    ".bg{fill:#f7f8fa}"
    ".title{font:600 20px system-ui,sans-serif;fill:#1a1a2e}"
    ".caption{font:400 14px system-ui,sans-serif;fill:#556}"
    ".edge{stroke:#c7ccd6;stroke-width:2}"
    ".edge.active{stroke:#3b6ea5;stroke-width:3.5}"
    ".node rect{fill:#ffffff;stroke:#c7ccd6;stroke-width:1.5;rx:10}"
    ".node text{font:600 14px system-ui,sans-serif;fill:#2a2a3a;text-anchor:middle}"
    ".node .overlay{font:400 12px ui-monospace,monospace;fill:#3b6ea5}"
    ".node.active rect{stroke:#3b6ea5;stroke-width:3;fill:#eef4fb}"
    ".node.actor rect{rx:22}"
    ".node.service rect{fill:#fbf7ee}"
    ".node.service.active rect{fill:#fdf1d6;stroke:#b9822b}"
    ".clock-face{fill:#ffffff;stroke:#8891a3;stroke-width:1.5}"
    ".clock-tick line{stroke:#b3b9c4;stroke-width:1}"
    ".clock-hand{stroke:#2a2a3a;stroke-linecap:round}"
    ".clock-hand.hour{stroke-width:2.6}"
    ".clock-hand.min{stroke-width:1.8}"
    ".clock-pin{fill:#2a2a3a}"
    ".clock-label{font:600 13px system-ui,sans-serif;fill:#556}"
)


def render_board_svg(
    step: BoardStep,
    *,
    overlays: dict[str, str] | None = None,
    locked_nodes: frozenset[str] | None = None,
    nodes: tuple[BoardNode, ...] = BOARD_NODES,
    edges: tuple[tuple[str, str], ...] = BOARD_EDGES,
) -> str:
    """Render one :class:`BoardStep` as a self-contained, well-formed SVG string.

    The polished default of the degradation ladder. Active nodes/edges are lit; live
    ``overlays`` (node id → caption) are merged over the step's own and painted under
    the node — this is where the notebook writes real data (a key fingerprint, a
    quorum tally) so the choreography is illustrative but never fabricated. ``locked_nodes``
    get a padlock badge (Act 0's "private key sealed" beat), and a step carrying a
    :attr:`BoardStep.clock` time gets a small analog clock in the bottom-right corner (Act
    2's 2 a.m. → 9 a.m. device).

    The graph is drawn inside a group translated down by :data:`BOARD_HEADER_H` so the
    title + caption sit in a clear header band and never collide with the top actor node.
    """
    by_id = {node.id: node for node in nodes}
    merged_overlays = {**step.overlays, **(overlays or {})}
    locked = locked_nodes or frozenset()
    canvas_h = BOARD_HEIGHT + BOARD_HEADER_H

    parts: list[str] = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {BOARD_WIDTH} {canvas_h}" '
        f'width="100%" role="img">',
        f"<style>{_BOARD_STYLE}</style>",
        f'<rect class="bg" x="0" y="0" width="{BOARD_WIDTH}" height="{canvas_h}"/>',
        f'<text class="title" x="28" y="40">{_esc(step.title)}</text>',
        f'<text class="caption" x="28" y="64">{_esc(step.caption)}</text>',
        f'<g transform="translate(0,{BOARD_HEADER_H})">',
    ]

    for src, dst in edges:
        if src not in by_id or dst not in by_id:
            continue
        active = src in step.active_nodes and dst in step.active_nodes
        a, b = by_id[src], by_id[dst]
        cls = "edge active" if active else "edge"
        parts.append(f'<line class="{cls}" x1="{a.x}" y1="{a.y}" x2="{b.x}" y2="{b.y}"/>')

    for node in nodes:
        active = node.id in step.active_nodes
        cls = f"node {node.kind}" + (" active" if active else "")
        half_w, half_h = 92, 26
        parts.append(f'<g class="{cls}">')
        parts.append(
            f'<rect x="{node.x - half_w}" y="{node.y - half_h}" '
            f'width="{half_w * 2}" height="{half_h * 2}" rx="10"/>'
        )
        parts.append(f'<text x="{node.x}" y="{node.y + 5}">{_esc(node.label)}</text>')
        overlay = merged_overlays.get(node.id)
        if overlay:
            parts.append(
                f'<text class="overlay" x="{node.x}" y="{node.y + half_h + 18}" '
                f'text-anchor="middle">{_esc(overlay)}</text>'
            )
        if node.id in locked:
            parts.append(_lock_glyph(node.x + half_w - 12, node.y - half_h + 2))
        parts.append("</g>")

    if step.clock is not None:
        # Bottom-right corner clock: Act 2's overnight-vs-morning device. Drawn last so it
        # sits above the graph, clear of every node (the lower-right of the canvas is empty).
        hour, minute = step.clock
        parts.append(_clock_glyph(BOARD_WIDTH - 95, BOARD_HEIGHT - 62, 30, hour, minute))

    parts.append("</g>")
    parts.append("</svg>")
    return "".join(parts)


def render_board_mermaid(step: BoardStep, *, nodes: tuple[BoardNode, ...] = BOARD_NODES) -> str:
    """Fallback 2 of the degradation ladder: the same step as a mermaid ``graph``.

    For ``mo.mermaid(...)`` if the custom SVG fights the presenter. Active nodes get a
    ``:::active`` class; the flow logic that chose the step is unchanged.
    """
    by_id = {node.id: node for node in nodes}
    lines = ["graph LR", f"  %% {step.title}"]
    for src, dst in BOARD_EDGES:
        if src in by_id and dst in by_id:
            lines.append(f"  {src}[{by_id[src].label}] --> {dst}[{by_id[dst].label}]")
    for node_id in sorted(step.active_nodes):
        if node_id in by_id:
            lines.append(f"  class {node_id} active")
    lines.append("  classDef active fill:#eef4fb,stroke:#3b6ea5,stroke-width:3px;")
    return "\n".join(lines)


def render_capability_checklist(
    completed: set[str] | None = None,
    rows: tuple[tuple[str, str], ...] = CAPABILITY_CHECKLIST,
) -> str:
    """Fallback 3 of the degradation ladder: the capability→test checklist as markdown.

    Each row names the real test that backs the capability, so every claim the demo
    makes traces to a passing test (the evaluation-plan §2 acceptance criterion). Pass
    ``completed`` (a set of test ids) to tick rows the run has exercised.
    """
    completed = completed or set()
    out = ["| ✓ | Capability | Backing test |", "|---|---|---|"]
    for capability, test_id in rows:
        tick = "✅" if test_id in completed else "☐"
        out.append(f"| {tick} | {capability} | `{test_id}` |")
    return "\n".join(out)


def overlays_for_step(step: BoardStep, *, shown_fingerprint: str | None = None) -> dict[str, str]:
    """The live-data overlays (node id → caption) to paint for ``step``.

    Extracted from the notebook so this step→overlay mapping is *tested* flow logic in
    this module rather than glue buried in the excluded notebook. ``shown_fingerprint``
    is the shown co-owner's **real** Ed25519 public-key fingerprint (the notebook reads
    it from the DB row via :func:`read_credential_state`); it is painted on their node
    only once their key exists (the keypair / sealed beats), not while their account is
    merely being created. The already-set-up pair get a tag on their beat. Returns only
    what the current beat lights, so nothing is fabricated for a node the step omits.
    """
    overlays: dict[str, str] = {}
    if step.key in (ADA_KEYPAIR_BEAT, ADA_SEALED_BEAT) and shown_fingerprint:
        overlays[SHOWN_PERSON.key] = f"ed25519:{shown_fingerprint}"
    if {p.key for p in BORN_ENROLLED} & step.active_nodes:
        for member in BORN_ENROLLED:
            overlays[member.key] = "already set up"
    return overlays


def locked_nodes_for_step(step: BoardStep) -> frozenset[str]:
    """Nodes drawn with a padlock badge on ``step`` — the shown co-owner's node once her
    private key is sealed (Act 0's ``ada-sealed`` beat). Tested flow logic so the notebook
    stays a thin drawer."""
    return frozenset({SHOWN_PERSON.key}) if step.key == ADA_SEALED_BEAT else frozenset()


# --- database connection helpers (used by the notebook) --------------------


def demo_engine(database_url: str | None = None) -> Engine:
    """A SQLAlchemy engine for the demo database (``MSIG_DATABASE_URL`` or the default)."""
    url = database_url or os.environ.get("MSIG_DATABASE_URL") or DEFAULT_DEMO_DATABASE_URL
    return create_db_engine(url)


def ensure_schema(engine: Engine) -> None:
    """Create any missing tables (idempotent).

    The live stack's proxy already ran the Alembic migrations, so this is a no-op
    there; in a standalone ``marimo edit`` dry-run it stands the schema up so Act 0
    has somewhere to write.
    """
    Base.metadata.create_all(engine)


def demo_sessionmaker(database_url: str | None = None) -> sessionmaker[Session]:
    """A session factory over the demo database, schema ensured."""
    engine = demo_engine(database_url)
    ensure_schema(engine)
    return create_session_factory(engine)


if __name__ == "__main__":
    # Regenerate the committed born-enrolled bundle:
    #   uv run python demo/notebooks/demo_lib.py > demo/seed/users.demo.yaml
    import sys

    # Write UTF-8 bytes straight to the buffer so the output is identical regardless of
    # the console codepage (Windows cp1252 would otherwise choke on any non-ASCII).
    sys.stdout.buffer.write(render_demo_users_yaml().encode("utf-8"))
