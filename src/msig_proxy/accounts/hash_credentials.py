"""``hash-credentials`` — produce a pre-credentialed (Mode B) provisioning bundle offline.

The declarative provision step (#100, :mod:`msig_proxy.accounts.provision`) can create a
user **already enrolled** from credential material generated *offline* — no SMTP, no
enrollment click — which is what bootstraps the first admin, CI identities, and the
no-Mailpit demos. This module generates that material.

In this system the password is load-bearing twice (``docs/account-management.md``,
``docs/cryptography.md``): it is the bcrypt **login verifier** *and* the PBKDF2 input
that wraps the Ed25519 **signing key**. A bare bcrypt hash would yield a user who can
log in but cannot approve. So a Mode-B bundle carries the **full enrolled set** — and
it is built by :func:`build_credential_bundle` **reusing the exact enrollment crypto**
(:mod:`msig_proxy.core.crypto`, :func:`msig_proxy.accounts.keys.create_active_key`), so
the bytes are identical to what a normal enrollment would store.

Run it as a console script (also exposed in the container image)::

    hash-credentials --username admin --email admin@example.com --admin

It prompts for the password once, prints the ``otpauth://`` URI to scan into an
authenticator app, and emits a paste-ready ``users.yaml`` entry (byte fields base64'd).
Everything in the bundle is non-reversible **except** the TOTP secret (plaintext in the
MVP — see #76 / ``docs/threat-model.md`` T7; it may be ``$ENV{}``-referenced in the file).
"""

from __future__ import annotations

import argparse
import base64
import getpass
import uuid
from dataclasses import dataclass

import pyotp
import yaml

from msig_proxy.core import crypto

# The issuer label shown by authenticator apps for a scanned secret.
TOTP_ISSUER = "Multi-Sig Proxy"


@dataclass(frozen=True)
class CredentialBundle:
    """A complete, already-enrolled credential set for one user (Mode B).

    Mirrors exactly what enrollment persists: a bcrypt ``password_hash``, the
    plaintext ``totp_secret`` (the second factor), and the active signing key
    (``key_id`` + ``public_key`` + the password-wrapped ``encrypted_private_key`` +
    ``key_salt``). The plaintext private key never leaves :func:`build_credential_bundle`.
    """

    username: str
    email: str
    is_admin: bool
    groups: str | None
    password_hash: str
    totp_secret: str
    key_id: uuid.UUID
    public_key: bytes
    encrypted_private_key: bytes
    key_salt: bytes


def build_credential_bundle(
    *,
    username: str,
    email: str,
    password: str,
    is_admin: bool = False,
    groups: str | None = None,
) -> CredentialBundle:
    """Generate a full enrolled bundle for ``username`` from ``password``.

    Reuses the enrollment primitives so the stored bytes are byte-for-byte what the
    self-enroll flow would produce: ``bcrypt(password)``, a fresh base32 TOTP secret,
    a fresh Ed25519 key pair whose private half is ``AES-256-GCM(private,
    PBKDF2(password, key_salt))`` bound to ``key_id`` as AAD. The ``key_id`` is part
    of the bundle because the AAD binding means the inserted ``UserKey.id`` **must
    equal** it or the first ``sign_with_password`` throws ``InvalidTag``. The
    ``public_key`` is emitted (not later derived) because it is derivable only from
    the *plaintext* private key, which is never stored. Raises :class:`ValueError` if
    the password exceeds bcrypt's 72-byte cap (surfaced by the crypto layer).
    """
    password_hash = crypto.hash_password(password)
    totp_secret = crypto.generate_totp_secret()
    key_id = uuid.uuid4()
    private_raw, public_raw = crypto.generate_keypair()
    key_salt = crypto.new_salt()
    enc_key = crypto.derive_enc_key(password, key_salt)
    encrypted_private_key = crypto.encrypt_private_key(private_raw, enc_key, crypto.key_aad(key_id))
    del private_raw, enc_key

    return CredentialBundle(
        username=username,
        email=email,
        is_admin=is_admin,
        groups=groups,
        password_hash=password_hash,
        totp_secret=totp_secret,
        key_id=key_id,
        public_key=public_raw,
        encrypted_private_key=encrypted_private_key,
        key_salt=key_salt,
    )


def otpauth_uri(bundle: CredentialBundle) -> str:
    """The ``otpauth://`` provisioning URI for the bundle's TOTP secret.

    The human scans this (or the QR an app renders from it) into their authenticator
    so the second factor works at first login — the Mode-B substitute for the QR a
    self-enrollee would have seen.
    """
    return pyotp.TOTP(bundle.totp_secret).provisioning_uri(
        name=bundle.email, issuer_name=TOTP_ISSUER
    )


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def render_yaml_entry(bundle: CredentialBundle) -> str:
    """Render the bundle as a paste-ready ``users.yaml`` document (byte fields base64'd).

    Emits a complete ``users:`` document with a single entry so the output drops
    straight into a fresh file; to add more users, paste additional entries under the
    same ``users:`` key. The schema matches :mod:`msig_proxy.accounts.provision`'s
    ``UserSpec`` (``docs/config.md`` §users.yaml).
    """
    entry: dict[str, object] = {"username": bundle.username, "email": bundle.email}
    if bundle.is_admin:
        entry["is_admin"] = True
    if bundle.groups:
        entry["groups"] = bundle.groups
    entry["password_hash"] = bundle.password_hash
    entry["totp_secret"] = bundle.totp_secret
    entry["key"] = {
        "key_id": str(bundle.key_id),
        "public_key": _b64(bundle.public_key),
        "encrypted_private_key": _b64(bundle.encrypted_private_key),
        "key_salt": _b64(bundle.key_salt),
    }
    return yaml.safe_dump({"users": [entry]}, sort_keys=False)


def main(argv: list[str] | None = None) -> int:
    """CLI entry point: prompt for a password, print the otpauth URI + a YAML entry."""
    parser = argparse.ArgumentParser(
        description="Generate a pre-credentialed users.yaml entry (offline enrollment)."
    )
    parser.add_argument("--username", required=True)
    parser.add_argument("--email", required=True)
    parser.add_argument("--admin", action="store_true", help="mint an admin (is_admin: true)")
    parser.add_argument("--groups", default=None, help="free-text groups value (e.g. 'a,b')")
    args = parser.parse_args(argv)

    password = getpass.getpass("Password: ")
    bundle = build_credential_bundle(
        username=args.username,
        email=args.email,
        password=password,
        is_admin=args.admin,
        groups=args.groups,
    )

    print("Scan this into your authenticator app (TOTP second factor):")
    print(f"  {otpauth_uri(bundle)}\n")
    print("Paste this into your users.yaml (keep it out of version control):\n")
    print(render_yaml_entry(bundle))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
