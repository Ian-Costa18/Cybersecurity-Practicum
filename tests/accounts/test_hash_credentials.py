"""The offline Mode-B bundler (``hash-credentials``, #100).

Real crypto. The contract that matters: a bundle's bytes are *identical* to what a
normal enrollment would store, so a user provisioned from it can both log in
(password verifies) and approve (the wrapped signing key decrypts under the password
and the key_id AAD). The provision round-trip is asserted in ``test_provision.py``;
here we pin the bundle shape, the sign/verify capability, and the renderers/CLI.
"""

from __future__ import annotations

import base64
import uuid

import pyotp
import pytest
import yaml

from msig_proxy.accounts import hash_credentials
from msig_proxy.accounts.hash_credentials import (
    build_credential_bundle,
    otpauth_uri,
    render_yaml_entry,
)
from msig_proxy.core import crypto


def test_build_credential_bundle_has_enrollment_shaped_fields() -> None:
    bundle = build_credential_bundle(
        username="admin", email="admin@example.com", password="adminpassword", is_admin=True
    )
    assert bundle.is_admin is True
    assert crypto.verify_password("adminpassword", bundle.password_hash)  # bcrypt verifier
    assert base64.b32decode(bundle.totp_secret)  # base32 TOTP secret
    assert isinstance(bundle.key_id, uuid.UUID)
    assert len(bundle.public_key) == 32  # raw Ed25519 public key
    assert len(bundle.key_salt) == 16  # 128-bit PBKDF2 salt
    assert bundle.encrypted_private_key  # iv ‖ ciphertext ‖ tag


def test_bundle_private_key_decrypts_and_signs_under_the_password() -> None:
    # The load-bearing property: the wrapped key is recoverable with the password and
    # the key_id AAD, and signs verifiably — exactly the enrollment crypto.
    bundle = build_credential_bundle(
        username="carol", email="carol@example.com", password="signingpw1"
    )
    message = crypto.canonical_json({"decision": "approve"})
    signature = crypto.sign_with_password(
        password="signingpw1",
        key_salt=bundle.key_salt,
        encrypted_private_key=bundle.encrypted_private_key,
        aad=crypto.key_aad(bundle.key_id),
        message=message,
    )
    assert crypto.verify_record(public_key=bundle.public_key, message=message, signature=signature)


def test_bundle_is_unique_per_call() -> None:
    a = build_credential_bundle(username="a", email="a@example.com", password="passwordone")
    b = build_credential_bundle(username="b", email="b@example.com", password="passwordone")
    assert a.key_id != b.key_id
    assert a.totp_secret != b.totp_secret
    assert a.key_salt != b.key_salt


def test_otpauth_uri_carries_secret_and_issuer() -> None:
    bundle = build_credential_bundle(
        username="dana", email="dana@example.com", password="danpassword1"
    )
    uri = otpauth_uri(bundle)
    assert uri.startswith("otpauth://totp/")
    assert f"secret={bundle.totp_secret}" in uri
    assert "Multi-Party%20Proxy" in uri  # url-encoded issuer
    # the URI's secret produces the same codes the stored secret would
    parsed = pyotp.parse_uri(uri)
    assert isinstance(parsed, pyotp.TOTP)
    assert parsed.now() == pyotp.TOTP(bundle.totp_secret).now()


def test_render_yaml_entry_round_trips_to_loadable_schema() -> None:
    bundle = build_credential_bundle(
        username="erin", email="erin@example.com", password="erinpass123", groups="ops,release"
    )
    doc = yaml.safe_load(render_yaml_entry(bundle))
    [entry] = doc["users"]
    assert entry["username"] == "erin"
    assert entry["groups"] == "ops,release"
    assert entry["password_hash"] == bundle.password_hash
    assert entry["totp_secret"] == bundle.totp_secret
    assert base64.b64decode(entry["key"]["public_key"]) == bundle.public_key
    assert uuid.UUID(entry["key"]["key_id"]) == bundle.key_id


def test_render_yaml_entry_omits_admin_and_groups_when_unset() -> None:
    bundle = build_credential_bundle(
        username="frank", email="frank@example.com", password="frankpass12"
    )
    entry = yaml.safe_load(render_yaml_entry(bundle))["users"][0]
    assert "is_admin" not in entry  # default user — not emitted
    assert "groups" not in entry


def test_cli_prints_otpauth_uri_and_yaml(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("getpass.getpass", lambda *_: "clipassword1")
    assert (
        hash_credentials.main(["--username", "grace", "--email", "grace@example.com", "--admin"])
        == 0
    )
    out = capsys.readouterr().out
    assert "otpauth://totp/" in out
    # The YAML block is the tail starting at the first "users:" key.
    entry = yaml.safe_load("users:" + out.split("users:", 1)[1])["users"][0]
    assert entry["username"] == "grace"
    assert entry["is_admin"] is True
    assert crypto.verify_password("clipassword1", entry["password_hash"])
