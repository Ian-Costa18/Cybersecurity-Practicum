"""The cryptographic foundation: primitives, the sign→verify path, and the four
load-bearing invariants from ``docs/cryptography.md``.

Real primitives only — crypto is never mocked (``docs/mvp.md``). Iteration count
is left at the production value; these tests run in well under a second because
each derivation happens once.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta

import pyotp
import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from msig_proxy.core import crypto


def _record() -> dict[str, object]:
    """A representative approval record (``docs/approver-authentication.md``)."""
    return {
        "approver_id": str(uuid.uuid4()),
        "key_id": str(uuid.uuid4()),
        "approval_request_id": str(uuid.uuid4()),
        "timestamp": datetime(2026, 6, 18, 12, 0, tzinfo=UTC),
        "action_hash": "a" * 64,
        "decision": "approve",
    }


# --- password verification (bcrypt) ---------------------------------------


def test_password_hash_round_trips() -> None:
    hashed = crypto.hash_password("correct horse battery")
    assert crypto.verify_password("correct horse battery", hashed) is True
    assert crypto.verify_password("wrong password", hashed) is False


def test_password_hash_is_salted_and_unique_per_call() -> None:
    first = crypto.hash_password("same-password")
    second = crypto.hash_password("same-password")
    assert first != second  # distinct random salts
    assert crypto.verify_password("same-password", first)
    assert crypto.verify_password("same-password", second)


def test_password_over_72_bytes_is_rejected() -> None:
    # bcrypt silently truncates past 72 bytes; the cap is enforced loudly so
    # login verification and the PBKDF2 key-wrap stay on the same bytes (ADR 0003).
    with pytest.raises(ValueError, match="72 bytes"):
        crypto.hash_password("x" * 73)
    with pytest.raises(ValueError, match="72 bytes"):
        crypto.verify_password("x" * 73, crypto.hash_password("x" * 72))


# --- TOTP verification (RFC 6238, configurable clock-skew window) ----------


def test_verify_totp_accepts_the_current_code() -> None:
    secret = crypto.generate_totp_secret()
    code = pyotp.TOTP(secret).now()

    assert crypto.verify_totp(secret, code, valid_window=1)


def test_verify_totp_rejects_a_malformed_code_without_raising() -> None:
    secret = crypto.generate_totp_secret()

    # A non-match is a plain ``False`` (never an exception) regardless of window.
    assert crypto.verify_totp(secret, "", valid_window=1) is False
    assert crypto.verify_totp(secret, "000000", valid_window=0) is False


def test_valid_window_governs_clock_skew_tolerance() -> None:
    # The window is the knob #60 moved into config: it is the number of 30s steps
    # tolerated on either side of now. A code from the previous step verifies only
    # when the window admits it.
    secret = crypto.generate_totp_secret()
    totp = pyotp.TOTP(secret)
    previous_step_code = totp.at(datetime.now(UTC) - timedelta(seconds=30))

    assert crypto.verify_totp(secret, previous_step_code, valid_window=1)
    assert not crypto.verify_totp(secret, previous_step_code, valid_window=0)


def test_matched_totp_step_returns_the_accepted_step_or_none() -> None:
    # Single-use TOTP (#73) needs the *exact* step a code matched to burn it. A
    # current code resolves to now's absolute 30s step counter; non-matches are None.
    secret = crypto.generate_totp_secret()
    totp = pyotp.TOTP(secret)
    now = datetime.now(UTC)
    expected_step = totp.timecode(now)

    step = crypto.matched_totp_step(secret, totp.now(), valid_window=1, now=now)
    assert step == expected_step

    assert crypto.matched_totp_step(secret, "", valid_window=1) is None
    assert crypto.matched_totp_step(secret, "000000", valid_window=0) is None
    assert crypto.matched_totp_step(secret, "123456", valid_window=1) is None


def test_matched_totp_step_resolves_adjacent_steps_within_the_window() -> None:
    # ±1-step tolerance: the previous and next steps resolve to *their own* counter,
    # not now's — so each valid code in the window burns a distinct ledger entry.
    secret = crypto.generate_totp_secret()
    totp = pyotp.TOTP(secret)
    now = datetime.now(UTC)
    base = totp.timecode(now)

    assert crypto.matched_totp_step(secret, totp.at(now, -1), valid_window=1, now=now) == base - 1
    assert crypto.matched_totp_step(secret, totp.at(now, 1), valid_window=1, now=now) == base + 1
    # Outside the window the same code matches nothing.
    assert crypto.matched_totp_step(secret, totp.at(now, 1), valid_window=0, now=now) is None


def test_verify_totp_agrees_with_matched_totp_step() -> None:
    # verify_totp delegates to matched_totp_step, so membership and step-finding
    # provably agree: a code is a match iff it resolves to a step.
    secret = crypto.generate_totp_secret()
    code = pyotp.TOTP(secret).now()

    assert crypto.verify_totp(secret, code, valid_window=1) is (
        crypto.matched_totp_step(secret, code, valid_window=1) is not None
    )
    assert crypto.verify_totp(secret, "000000", valid_window=1) is (
        crypto.matched_totp_step(secret, "000000", valid_window=1) is not None
    )


# --- key derivation (PBKDF2-HMAC-SHA-256) ---------------------------------


def test_enc_key_is_deterministic_for_same_password_and_salt() -> None:
    salt = crypto.new_salt()
    assert crypto.derive_enc_key("pw", salt) == crypto.derive_enc_key("pw", salt)


def test_enc_key_differs_for_different_salt_and_is_256_bits() -> None:
    key = crypto.derive_enc_key("pw", crypto.new_salt())
    other = crypto.derive_enc_key("pw", crypto.new_salt())
    assert key != other
    assert len(key) == 32  # 256-bit AES key


# --- private-key encryption at rest (AES-256-GCM) -------------------------


def test_private_key_encrypt_decrypt_round_trips() -> None:
    private_key, _ = crypto.generate_keypair()
    enc_key = crypto.derive_enc_key("pw", crypto.new_salt())
    aad = crypto.key_aad(uuid.uuid4())

    blob = crypto.encrypt_private_key(private_key, enc_key, aad)
    assert crypto.decrypt_private_key(blob, enc_key, aad) == private_key


def test_decrypt_fails_when_aad_does_not_match() -> None:
    # AAD binds the ciphertext to its UserKey id (#53); a transplanted blob fails.
    private_key, _ = crypto.generate_keypair()
    enc_key = crypto.derive_enc_key("pw", crypto.new_salt())
    blob = crypto.encrypt_private_key(private_key, enc_key, crypto.key_aad(uuid.uuid4()))

    with pytest.raises(InvalidTag):
        crypto.decrypt_private_key(blob, enc_key, crypto.key_aad(uuid.uuid4()))


def test_decrypt_fails_when_ciphertext_is_tampered() -> None:
    private_key, _ = crypto.generate_keypair()
    enc_key = crypto.derive_enc_key("pw", crypto.new_salt())
    aad = crypto.key_aad(uuid.uuid4())
    blob = bytearray(crypto.encrypt_private_key(private_key, enc_key, aad))
    blob[-1] ^= 0x01  # flip a tag bit

    with pytest.raises(InvalidTag):
        crypto.decrypt_private_key(bytes(blob), enc_key, aad)


# --- canonical JSON --------------------------------------------------------


def test_canonical_json_is_order_independent() -> None:
    a = crypto.canonical_json({"b": 1, "a": 2})
    b = crypto.canonical_json({"a": 2, "b": 1})
    assert a == b


def test_canonical_json_has_no_insignificant_whitespace() -> None:
    assert crypto.canonical_json({"a": 1, "b": 2}) == b'{"a":1,"b":2}'


def test_canonical_json_serializes_uuid_and_datetime_stably() -> None:
    key_id = uuid.uuid4()
    record = {
        "key_id": key_id,  # a raw UUID, not pre-stringified
        "timestamp": datetime(2026, 6, 18, 12, 0, tzinfo=UTC),
        "decision": "approve",
    }
    encoded = crypto.canonical_json(record)
    # An explicit, reparseable encoding — not an ORM/Pydantic dump.
    reparsed = json.loads(encoded)
    assert reparsed["decision"] == "approve"
    assert reparsed["key_id"] == str(key_id)
    assert reparsed["timestamp"] == "2026-06-18T12:00:00+00:00"


def test_canonical_json_rejects_unserializable_values() -> None:
    with pytest.raises(TypeError):
        crypto.canonical_json({"bad": object()})


# --- artifact hashing (SHA-256 Hash Binding, docs/constraints.md §6) -------


def test_sha256_hex_matches_a_known_vector() -> None:
    # The empty input has a well-known SHA-256 digest; pinning it proves the
    # helper is plain SHA-256 over raw bytes with no salting or encoding quirks.
    assert crypto.sha256_hex(b"") == (
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )


def test_sha256_hex_is_deterministic_and_byte_sensitive() -> None:
    artifact = b"the exact bytes that were uploaded"
    assert crypto.sha256_hex(artifact) == crypto.sha256_hex(artifact)  # bound to the bytes
    assert len(crypto.sha256_hex(artifact)) == 64  # 256-bit digest, hex-encoded
    assert crypto.sha256_hex(artifact) != crypto.sha256_hex(artifact + b"!")  # one byte flips it


# --- the load-bearing primitive: sign with password, then verify ----------


def test_sign_with_password_then_verify_round_trips() -> None:
    private_key, public_key = crypto.generate_keypair()
    salt = crypto.new_salt()
    enc_key = crypto.derive_enc_key("pw", salt)
    aad = crypto.key_aad(uuid.uuid4())
    blob = crypto.encrypt_private_key(private_key, enc_key, aad)
    record = _record()

    message = crypto.canonical_json(record)
    signature = crypto.sign_with_password(
        password="pw",
        key_salt=salt,
        encrypted_private_key=blob,
        aad=aad,
        message=message,
    )

    assert crypto.verify_record(public_key=public_key, message=message, signature=signature) is True


def test_verify_detects_a_tampered_record() -> None:
    private_key, public_key = crypto.generate_keypair()
    salt = crypto.new_salt()
    enc_key = crypto.derive_enc_key("pw", salt)
    aad = crypto.key_aad(uuid.uuid4())
    blob = crypto.encrypt_private_key(private_key, enc_key, aad)
    record = _record()
    signature = crypto.sign_with_password(
        password="pw",
        key_salt=salt,
        encrypted_private_key=blob,
        aad=aad,
        message=crypto.canonical_json(record),
    )

    mutated = {**record, "decision": "deny"}
    assert (
        crypto.verify_record(
            public_key=public_key, message=crypto.canonical_json(mutated), signature=signature
        )
        is False
    )


def test_sign_with_password_fails_with_wrong_password() -> None:
    private_key, _ = crypto.generate_keypair()
    salt = crypto.new_salt()
    aad = crypto.key_aad(uuid.uuid4())
    blob = crypto.encrypt_private_key(private_key, crypto.derive_enc_key("pw", salt), aad)

    with pytest.raises(InvalidTag):  # wrong password derives a wrong key → decrypt fails
        crypto.sign_with_password(
            password="not-pw",
            key_salt=salt,
            encrypted_private_key=blob,
            aad=aad,
            message=crypto.canonical_json(_record()),
        )


# --- the four invariants (docs/cryptography.md) ---------------------------


def test_invariant_1_bcrypt_output_is_not_aes_key_material() -> None:
    # bcrypt output is a 60-char verifier string, never a 32-byte AES key. The
    # only key material AES-256-GCM ever receives comes from derive_enc_key.
    bcrypt_hash = crypto.hash_password("pw").encode("ascii")
    assert len(bcrypt_hash) != 32
    with pytest.raises(ValueError, match="key must be"):
        AESGCM(bcrypt_hash)  # not a valid AES key length


def test_invariant_2_enc_key_is_never_persisted_on_the_record() -> None:
    # The encrypted blob carries only iv ‖ ciphertext ‖ tag — never the enc_key.
    private_key, _ = crypto.generate_keypair()
    enc_key = crypto.derive_enc_key("pw", crypto.new_salt())
    blob = crypto.encrypt_private_key(private_key, enc_key, crypto.key_aad(uuid.uuid4()))
    assert enc_key not in blob


def test_invariant_3_sign_returns_only_a_signature_not_the_key() -> None:
    # The composed primitive hands back a 64-byte Ed25519 signature and nothing
    # else; the decrypted key is confined to the call and never leaks into the
    # output. (Confinement, not erasure — Python can't zero immutable bytes.)
    private_key, _ = crypto.generate_keypair()
    salt = crypto.new_salt()
    aad = crypto.key_aad(uuid.uuid4())
    blob = crypto.encrypt_private_key(private_key, crypto.derive_enc_key("pw", salt), aad)

    signature = crypto.sign_with_password(
        password="pw",
        key_salt=salt,
        encrypted_private_key=blob,
        aad=aad,
        message=crypto.canonical_json(_record()),
    )
    assert isinstance(signature, bytes)
    assert len(signature) == 64
    assert private_key not in signature  # the raw key never leaks into the output


def test_invariant_4_each_encryption_uses_a_unique_iv() -> None:
    private_key, _ = crypto.generate_keypair()
    enc_key = crypto.derive_enc_key("pw", crypto.new_salt())
    aad = crypto.key_aad(uuid.uuid4())

    first = crypto.encrypt_private_key(private_key, enc_key, aad)
    second = crypto.encrypt_private_key(private_key, enc_key, aad)
    assert first[:12] != second[:12]  # 96-bit IV prefix differs per encryption
    assert first != second
