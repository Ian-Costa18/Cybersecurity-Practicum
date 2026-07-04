"""The cryptographic foundation the vote and audit paths rest on.

This module is the single home for the five primitives in ``docs/cryptography.md``
and the one composed operation that ties them together: given a password, derive
``enc_key``, decrypt the Ed25519 private key, sign a record, and discard the key.
Parameters and roles follow `ADR 0003 <docs/adr/0003-cryptographic-primitive-selection.md>`_.

The module is deliberately shaped so the four load-bearing invariants are
*structural*, not conventions a caller must remember:

1. **bcrypt output is never key material.** Password verification
   (:func:`hash_password` / :func:`verify_password`) and key derivation
   (:func:`derive_enc_key`) are separate functions; bcrypt's output is a verifier
   string that is never handed to AES. Key material comes only from PBKDF2.
2. **The PBKDF2 output (``enc_key``) is never stored.** It is a transient return
   value; nothing here persists it, and the encrypted blob contains only
   ``iv ‖ ciphertext ‖ tag``.
3. **The Ed25519 private key is confined to the signing call.**
   :func:`sign_with_password` decrypts the key into a local, signs, and returns
   only the signature — callers never receive the plaintext key, and it is
   released to GC when the call returns. (Python cannot zero immutable ``bytes``
   in place, so this is confinement, not secure erasure.)
4. **The AES-256-GCM IV is unique per encryption event.**
   :func:`encrypt_private_key` generates a fresh 96-bit IV internally on every
   call; there is no parameter through which a caller could reuse one.

Everything operates on primitive ``bytes`` / ``str`` / ``uuid.UUID`` — never on
ORM or Pydantic objects — so :func:`canonical_json` is the *only* serializer in
the signing path (``docs/cryptography.md`` §Canonical Serialization).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import uuid
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

import bcrypt
import pyotp
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# --- parameters (docs/cryptography.md, ADR 0003) --------------------------
BCRYPT_ROUNDS = 12  # ≈300 ms/hash; re-evaluate as hardware improves
MAX_PASSWORD_BYTES = 72  # bcrypt truncates past this; cap loudly instead
PBKDF2_ITERATIONS = 600_000  # OWASP 2023 / NIST SP 800-132
ENC_KEY_LEN = 32  # 256-bit AES key
SALT_LEN = 16  # 128-bit PBKDF2 salt
IV_LEN = 12  # 96-bit AES-GCM IV
API_TOKEN_BYTES = 32  # 256-bit high-entropy token

_RAW = serialization.Encoding.Raw
_NO_ENCRYPTION = serialization.NoEncryption()


# --- password verification (bcrypt) ---------------------------------------


def _password_bytes(password: str) -> bytes:
    """Encode a password, rejecting anything past bcrypt's 72-byte limit.

    The cap is enforced at every entry so verification and the PBKDF2 key-wrap
    always operate on the *same* bytes (ADR 0003); silent truncation would split
    them.
    """
    encoded = password.encode("utf-8")
    if len(encoded) > MAX_PASSWORD_BYTES:
        raise ValueError(f"password must be at most {MAX_PASSWORD_BYTES} bytes")
    return encoded


def hash_password(password: str) -> str:
    """Return a bcrypt verifier for ``password`` (a login verifier, never a key)."""
    return bcrypt.hashpw(_password_bytes(password), bcrypt.gensalt(rounds=BCRYPT_ROUNDS)).decode(
        "ascii"
    )


def verify_password(password: str, password_hash: str) -> bool:
    """Constant-time check of ``password`` against a stored bcrypt verifier."""
    return bcrypt.checkpw(_password_bytes(password), password_hash.encode("ascii"))


# --- key derivation (PBKDF2-HMAC-SHA-256) ---------------------------------


def new_salt() -> bytes:
    """A fresh 128-bit random salt for a user's key-encryption derivation."""
    return os.urandom(SALT_LEN)


def derive_enc_key(password: str, salt: bytes) -> bytes:
    """Derive the 256-bit ``enc_key`` from a password (transient; never stored)."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=ENC_KEY_LEN,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(_password_bytes(password))


# --- Ed25519 key pairs -----------------------------------------------------


def generate_keypair() -> tuple[bytes, bytes]:
    """Generate an Ed25519 key pair, returned as ``(private_raw, public_raw)``."""
    private = Ed25519PrivateKey.generate()
    private_raw = private.private_bytes(
        encoding=_RAW, format=serialization.PrivateFormat.Raw, encryption_algorithm=_NO_ENCRYPTION
    )
    public_raw = private.public_key().public_bytes(
        encoding=_RAW, format=serialization.PublicFormat.Raw
    )
    return private_raw, public_raw


# --- private-key encryption at rest (AES-256-GCM) -------------------------


def key_aad(key_id: uuid.UUID) -> bytes:
    """Additional authenticated data binding a ciphertext to its ``UserKey.id``.

    Since #53 each key pair is its own row with a globally-unique id, so the AAD is
    that id: GCM authentication fails if the blob is moved onto any other key row,
    making transplant structurally impossible (``docs/cryptography.md``).
    """
    return key_id.bytes


def _aesgcm_seal(plaintext: bytes, enc_key: bytes, aad: bytes) -> bytes:
    """Seal ``plaintext`` under AES-256-GCM, returning ``iv ‖ ciphertext ‖ tag``.

    The single home for the seal so invariant 4 (a fresh 96-bit IV per encryption
    event) is structural: the IV is generated here on every call and there is no
    parameter through which a caller could reuse one. Both the signing-key wrap and
    the TOTP-secret wrap (#122) go through here, so the invariant is enforced once.
    """
    iv = os.urandom(IV_LEN)
    return iv + AESGCM(enc_key).encrypt(iv, plaintext, aad)


def _aesgcm_open(blob: bytes, enc_key: bytes, aad: bytes) -> bytes:
    """Open a blob sealed by :func:`_aesgcm_seal`.

    Raises :class:`cryptography.exceptions.InvalidTag` (without releasing any
    plaintext) if the key, AAD, or ciphertext is wrong.
    """
    iv, ciphertext = blob[:IV_LEN], blob[IV_LEN:]
    return AESGCM(enc_key).decrypt(iv, ciphertext, aad)


def encrypt_private_key(private_key: bytes, enc_key: bytes, aad: bytes) -> bytes:
    """Encrypt a raw Ed25519 private key, returning ``iv ‖ ciphertext ‖ tag``.

    A fresh 96-bit IV is generated on every call (:func:`_aesgcm_seal`) — there is
    no parameter to reuse one, which is invariant 4 made structural.
    """
    return _aesgcm_seal(private_key, enc_key, aad)


def decrypt_private_key(blob: bytes, enc_key: bytes, aad: bytes) -> bytes:
    """Decrypt a blob from :func:`encrypt_private_key`.

    Raises :class:`cryptography.exceptions.InvalidTag` (without releasing any
    plaintext) if the key, AAD, or ciphertext is wrong.
    """
    return _aesgcm_open(blob, enc_key, aad)


# --- API tokens (SHA-256; high-entropy, not stretched) --------------------


def generate_api_token() -> str:
    """A fresh high-entropy API token (URL-safe). Shown once; never stored raw."""
    return secrets.token_urlsafe(API_TOKEN_BYTES)


def hash_api_token(token: str) -> str:
    """Hash an API token for storage.

    A plain SHA-256, not a stretching KDF: the token is already high-entropy, so
    stretching would add cost with no security benefit (``docs/account-management.md``).
    """
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


# --- enrollment links + TOTP secrets (#15) --------------------------------


def generate_enrollment_token() -> str:
    """A fresh high-entropy, single-use enrollment token (URL-safe, goes in the link)."""
    return secrets.token_urlsafe(API_TOKEN_BYTES)


def hash_enrollment_token(token: str) -> str:
    """SHA-256 of an enrollment token for storage (plain digest; high-entropy)."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def generate_totp_secret() -> str:
    """A fresh base32 TOTP shared secret (160-bit), set at enrollment (RFC 6238).

    Base32 is the encoding authenticator apps expect.
    """
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii")


def totp_aad(user_id: uuid.UUID) -> bytes:
    """AAD binding a wrapped TOTP secret to its owning ``User.id`` (#122).

    The TOTP-secret parallel to :func:`key_aad`: GCM authentication fails if the
    blob is moved onto another user's row, so a database-write attacker cannot
    transplant one user's wrapped second factor onto another (``docs/cryptography.md``).
    """
    return user_id.bytes


def encrypt_totp_secret(secret: str, enc_key: bytes, aad: bytes) -> bytes:
    """Wrap a base32 TOTP secret at rest, returning ``iv ‖ ciphertext ‖ tag`` (#122).

    Exactly the signing-key wrap applied to the second factor: AES-256-GCM under the
    password-derived ``enc_key``, bound to the user's id as ``aad``. TOTP is only
    ever checked at a moment the password is present (login, per-vote re-auth), so
    the secret can live wrapped under the same key class as the Ed25519 private key
    rather than in the clear (``docs/threat-model/HOST-3-database-read-compromise.md``).
    A fresh IV is generated per call (:func:`_aesgcm_seal`).
    """
    return _aesgcm_seal(secret.encode("ascii"), enc_key, aad)


def decrypt_totp_secret(blob: bytes, enc_key: bytes, aad: bytes) -> str:
    """Recover a base32 TOTP secret wrapped by :func:`encrypt_totp_secret`.

    Transient, discarded after the TOTP check — the same lifecycle as the decrypted
    signing key. Raises :class:`cryptography.exceptions.InvalidTag` (releasing no
    plaintext) if the ``enc_key`` (wrong password), ``aad`` (wrong user), or
    ciphertext is wrong.
    """
    return _aesgcm_open(blob, enc_key, aad).decode("ascii")


def matched_totp_step(
    secret: str, code: str, *, valid_window: int, now: datetime | None = None
) -> int | None:
    """The absolute 30s time-step ``code`` matches within ±``valid_window``, else ``None``.

    Single-use TOTP (#73, ``docs/approver-authentication.md`` §TOTP Single-Use
    Enforcement) has to *burn the exact step a code matched*, but ``pyotp.verify``
    only returns a bool. This mirrors pyotp's acceptance loop to learn **which**
    30s time-step counter (``unix_time // 30``) accepted the code, so the caller
    can record precisely that ``(user, time-step)`` per RFC 6238 §5.2.

    ``valid_window`` is the clock-skew tolerance (number of steps on either side of
    now, ~90s total at ``1``), supplied from ``auth.totp_window`` config. ``now``
    exists only for testability; it defaults to the current UTC time. A malformed
    or empty ``code`` matches no step and yields ``None`` (never an error). The
    comparison is constant-time so the code is not a timing oracle.
    """
    totp = pyotp.TOTP(secret)
    now = now or datetime.now(UTC)
    base = totp.timecode(now)
    for offset in range(-valid_window, valid_window + 1):
        if hmac.compare_digest(str(code), str(totp.at(now, offset))):
            return base + offset
    return None


def verify_totp(secret: str, code: str, *, valid_window: int) -> bool:
    """Verify a 6-digit TOTP ``code`` against ``secret``.

    ``valid_window`` is the number of 30s time-steps tolerated on either side of
    now (the clock-skew window, ~90s total at ``1``). It is supplied by the caller
    from ``auth.totp_window`` config so the knob is auditable rather than hardcoded
    (``docs/config.md`` §auth, ``docs/account-management.md`` §Authentication
    Factors). A malformed or empty code is simply a non-match (returns ``False``),
    never an error.

    Delegates to :func:`matched_totp_step` so the membership test and the
    step-finder used for single-use burning (#73) provably agree on what counts as
    a match.
    """
    return matched_totp_step(secret, code, valid_window=valid_window) is not None


# --- artifact hashing (SHA-256 Hash Binding) ------------------------------


def sha256_hex(data: bytes) -> str:
    """Hex SHA-256 of raw bytes — the Hash Binding primitive (``docs/constraints.md`` §6).

    Computed over the *exact* uploaded artifact at request creation and recorded
    on the Approval Request; approvers approve this digest, and the Executor
    re-derives it before publishing so a substituted payload cannot ship.
    """
    return hashlib.sha256(data).hexdigest()


# --- canonical serialization ----------------------------------------------


def _json_default(value: Any) -> str:
    """Encode the value types an approval record carries that JSON cannot.

    Kept explicit and total: an unrecognized type raises rather than silently
    producing a non-canonical encoding that would break verification.
    """
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, uuid.UUID):
        return str(value)
    raise TypeError(f"{type(value).__name__} is not canonical-JSON serializable")


def canonical_json(record: Mapping[str, Any]) -> bytes:
    """Serialize a record to canonical JSON: sorted keys, no insignificant
    whitespace, UTF-8. This is the *only* serializer used for signing and
    verification, so an honest signature always reverifies (``docs/cryptography.md``)."""
    return json.dumps(
        record,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=_json_default,
    ).encode("utf-8")


# --- the load-bearing primitive -------------------------------------------


def sign_with_password(
    *,
    password: str,
    key_salt: bytes,
    encrypted_private_key: bytes,
    aad: bytes,
    message: bytes,
) -> bytes:
    """Derive ``enc_key``, decrypt the Ed25519 key, sign ``message``, discard the key.

    ``message`` is the already-canonical record bytes (the caller serializes via
    :func:`canonical_json` — e.g. ``VoteRecord.canonical_bytes()`` — so there is a
    single home for "the bytes that get signed"). Returns the 64-byte signature.
    The plaintext private key (and ``enc_key``) exist only in this call's locals
    and are never returned or stored; they are unbound here and released to GC on
    return. Python cannot zero immutable ``bytes`` in place, so this is confinement,
    not secure erasure — it keeps the key out of every caller and every record.
    """
    enc_key = derive_enc_key(password, key_salt)
    private_raw = decrypt_private_key(encrypted_private_key, enc_key, aad)
    private_key = Ed25519PrivateKey.from_private_bytes(private_raw)
    signature = private_key.sign(message)
    del enc_key, private_raw, private_key
    return signature


def verify_record(*, public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Offline audit check: does ``signature`` match ``message`` under ``public_key``?

    ``message`` is the same canonical record bytes the signer signed (e.g.
    ``VoteRecord.canonical_bytes()``); needs no password. Returns ``False`` on any
    mismatch (a tampered record or a forged signature).
    """
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
    except InvalidSignature:
        return False
    return True
