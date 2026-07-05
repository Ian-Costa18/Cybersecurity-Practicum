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
**Every field in the emitted entry is non-reversible**: the password is a bcrypt
hash, the signing key is AES-256-GCM-wrapped under it, and since #122 the TOTP secret
is wrapped the same way (``encrypted_totp_secret`` + ``totp_salt``, bound to the
bundle's ``id`` as AAD) — the plaintext second factor never lands in the file. The
generator holds the plaintext just long enough to print the ``otpauth://`` URI for
scanning; provision decrypts it only at login, when the password is present.
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
TOTP_ISSUER = "Multi-Party Proxy"


@dataclass(frozen=True)
class CredentialBundle:
    """A complete, already-enrolled credential set for one user (Mode B).

    Mirrors exactly what enrollment persists: a stable ``user_id`` (the inserted
    ``User.id``, also the TOTP wrap's AAD), a bcrypt ``password_hash``, the
    **wrapped** second factor (``encrypted_totp_secret`` + ``totp_salt``, #122), and
    the active signing key (``key_id`` + ``public_key`` + the password-wrapped
    ``encrypted_private_key`` + ``key_salt``). ``totp_secret`` is the *plaintext*
    base32 secret, kept for the ``otpauth://`` URI only — it is **not** rendered into
    the YAML. Neither plaintext secret (private key, TOTP) leaves
    :func:`build_credential_bundle`.
    """

    username: str
    email: str
    is_admin: bool
    groups: str | None
    user_id: uuid.UUID
    password_hash: str
    totp_secret: str
    encrypted_totp_secret: bytes
    totp_salt: bytes
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
    self-enroll flow would produce: ``bcrypt(password)``, a fresh base32 TOTP secret
    wrapped ``AES-256-GCM(secret, PBKDF2(password, totp_salt))`` bound to ``user_id``
    as AAD (#122), and a fresh Ed25519 key pair whose private half is
    ``AES-256-GCM(private, PBKDF2(password, key_salt))`` bound to ``key_id`` as AAD.
    Both AADs are part of the bundle because the bindings mean the inserted
    ``User.id`` and ``UserKey.id`` **must equal** them or the first login / first
    ``sign_with_password`` throws ``InvalidTag`` — the same reason ``key_id`` was
    already carried. The ``public_key`` is emitted (not later derived) because it is
    derivable only from the *plaintext* private key, which is never stored. Raises
    :class:`ValueError` if the password exceeds bcrypt's 72-byte cap (surfaced by the
    crypto layer).
    """
    password_hash = crypto.hash_password(password)
    user_id = uuid.uuid4()
    totp_secret = crypto.generate_totp_secret()
    totp_salt = crypto.new_salt()
    totp_enc_key = crypto.derive_enc_key(password, totp_salt)
    encrypted_totp_secret = crypto.encrypt_totp_secret(
        totp_secret, totp_enc_key, crypto.totp_aad(user_id)
    )
    key_id = uuid.uuid4()
    private_raw, public_raw = crypto.generate_keypair()
    key_salt = crypto.new_salt()
    enc_key = crypto.derive_enc_key(password, key_salt)
    encrypted_private_key = crypto.encrypt_private_key(private_raw, enc_key, crypto.key_aad(key_id))
    del private_raw, enc_key, totp_enc_key

    return CredentialBundle(
        username=username,
        email=email,
        is_admin=is_admin,
        groups=groups,
        user_id=user_id,
        password_hash=password_hash,
        totp_secret=totp_secret,
        encrypted_totp_secret=encrypted_totp_secret,
        totp_salt=totp_salt,
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
    entry: dict[str, object] = {
        "id": str(bundle.user_id),
        "username": bundle.username,
        "email": bundle.email,
    }
    if bundle.is_admin:
        entry["is_admin"] = True
    if bundle.groups:
        entry["groups"] = bundle.groups
    entry["password_hash"] = bundle.password_hash
    # The wrapped second factor (#122) — ciphertext, safe to commit; the plaintext
    # base32 secret is never rendered (it lives only in the printed otpauth:// URI).
    entry["encrypted_totp_secret"] = _b64(bundle.encrypted_totp_secret)
    entry["totp_salt"] = _b64(bundle.totp_salt)
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
