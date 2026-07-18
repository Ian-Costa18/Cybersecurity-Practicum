---
id: HOST-3
title: "Database Read Compromise"
stride: ["Information Disclosure", "Elevation of Privilege"]
attack: [T1005, T1110.002]
capability: [L4]
delta: introduced
likelihood_baseline: N/A
likelihood_residual: medium
severity_baseline: N/A
severity_residual: high
bucket: 2
related: [HOST-1, HOST-2, CRYPTO-1, CORE-2, CODE-1, DOS-2, IDENT-6]
tests:
  - tests/core/test_crypto.py::test_decrypt_fails_when_aad_does_not_match
  - tests/core/test_crypto.py::test_private_key_encrypt_decrypt_round_trips
  - tests/core/test_crypto.py::test_totp_secret_encrypt_decrypt_round_trips
  - tests/core/test_crypto.py::test_totp_decrypt_fails_when_aad_does_not_match_user
  - tests/accounts/test_seed.py::test_seeded_totp_secret_is_stored_encrypted_not_plaintext
---

# HOST-3 — Database Read Compromise

| | |
|---|---|
| **Category** | Information Disclosure; Elevation of Privilege (deferred — only after an offline crack) |
| **Capability** | L4 — read access to the database (SQL injection, a stolen backup, a read replica, an on-disk snapshot). The write-capable sibling is [HOST-2](HOST-2-database-write-compromise.md); host access that reaches the database is [HOST-1](HOST-1-proxy-host-compromise.md). |
| **What the attacker gains** | A full read of the credential store. Since [#122](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/122) every stored credential falls into one of **two** protection classes: **(1) one-way hashed** — `bcrypt` password hashes (cost ≥ 12) and SHA-256 API-/enrollment-token digests; a read yields useless hashes, not replayable secrets. **(2) Wrapped under a key the reader lacks** — the `encrypted_private_key` blob **and** the `totp_secret` blob, both AES-256-GCM under the user's password-derived key (the private key bound to its `user_keys.id` as AAD, the TOTP secret to its `users.id`); ciphertext without the password. Public keys and all approval records are readable but not forgeable without the private keys. |
| **What they cannot do** | Authenticate, approve, or forge a signature on the strength of the read alone. **There is no plaintext credential at rest** — every usable secret is either a one-way hash or password-wrapped — so account takeover still requires cracking a `bcrypt` hash offline (cost ≥ 12) to derive the key that unwraps a private key (and, since #122, the second-factor TOTP secret). The read publishes nothing by itself. |
| **Current defenses** | AES-256-GCM encryption at rest of **both** password-wrapped credentials — the Ed25519 private key (`test_private_key_encrypt_decrypt_round_trips`, `test_decrypt_fails_when_aad_does_not_match`) and, since #122, the TOTP secret (`test_totp_secret_encrypt_decrypt_round_trips`, `test_totp_decrypt_fails_when_aad_does_not_match_user`); the stored TOTP column holds ciphertext, never the base32 plaintext (`test_seeded_totp_secret_is_stored_encrypted_not_plaintext`). Both are decrypted transiently only at a moment the password is present (login, per-vote re-auth) and discarded — no plaintext key material or secret is ever written to disk (`docs/cryptography.md`, `docs/approver-authentication.md`). `bcrypt` password hashing at cost ≥ 12 with a unique 128-bit per-user salt — offline cracking is expensive and precomputed tables are useless. Token hashing — API and enrollment tokens are stored only as SHA-256 digests; the plaintext is shown or delivered once and never persisted, so a read cannot recover or replay them. |
| **Operator configuration** | Never expose the database port to the internet; bind it to localhost or a private network reachable only by the proxy host. Use a dedicated database user with least-privilege table grants (no superuser). Enable database audit logging and alert on unexpected bulk reads. Store the database on an encrypted volume to raise the cost of offline extraction of the wrapped credentials and hashes — and apply the identical protection to **backups, read replicas, and dev/on-disk snapshots**, which carry the same wrapped keys, wrapped TOTP secrets, and hashes *outside* the live database's ACLs and are a read surface in their own right, not just a live L4 read. Rotate database credentials on any suspected breach, and establish a `bcrypt`-cost escalation policy as hardware improves. |

## The invariant (absorbing the former standalone TOTP-exposure threat)

A credential at rest survives a database read only if it is *one-way hashed* (passwords,
tokens) or *wrapped under a key the reader does not hold* (the private key and the TOTP
secret, both under the password-derived key). The TOTP secret was once the one credential
that was neither — the exposure that had been split out as its own threat and folded in
here. It need not have been: the proxy only checks TOTP at interactive login and per-vote
re-authentication, and both always present the password, so the secret is now wrapped under
the same password-derived key as the private key ([#122](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/122))
rather than stored raw. With that closed, the invariant holds **uniformly** across the
credential store: a bare read escalates toward takeover only by first cracking a `bcrypt`
hash offline.

## ATT&CK mapping

The mapping is two techniques. **T1005 (Data from Local System):** the attacker collects
data — here the entire credential store — from the compromised system. **T1110.002 (Brute
Force: Password Cracking):** offline cracking of the captured `bcrypt` hashes to derive the
password — and with it the key that unwraps the private key (and the TOTP secret) — which is
the step the entire severity ceiling (account takeover → forged quorum) is gated behind.
Online guessing against the live endpoints is [IDENT-5](IDENT-5-no-anti-automation-on-authentication-endpoints.md)'s
surface (parent T1110); HOST-3 owns the offline half.

The former **T1552.001 (Unsecured Credentials: Credentials in Files)** tag is retired with
#122: it mapped only the plaintext `totp_secret`, and there is no longer any credential
readable without cracking something — nothing at rest fits "a usable secret sitting
unprotected in the store."

## Rating rationale

`delta: introduced` — the at-rest credential set (wrapped private keys, wrapped TOTP
secrets, the approval records) exists only because the proxy exists; a maintainer publishing
directly to PyPI has no such store, so both baselines are N/A. Residual likelihood **medium**
(the L4 default): a read via injection, a stolen backup, or a read replica is a routine
breach shape, no deviation claimed. Residual severity **high**, not critical: the ceiling is
account takeover → forged quorum → an unauthorized publish, but it is *gated behind offline
`bcrypt` cracking* — the authentication input is corrupted, yet a real barrier still stands,
which is the "high" rung, not the "publish-at-will" top of the mission ladder. Wrapping the
TOTP secret does not move either rating (the ceiling was already crack-gated); it removes the
one credential that a read handed over for free, which is what promotes the **bucket**.

## Bucket

Bucket ② (argued by design). The property that makes this threat inert — *a database read
yields nothing directly usable* — now **holds**: every credential at rest is one-way hashed
or wrapped under the user's password-derived key, an invariant backed by tested components
(AES-GCM round-trip + AAD binding for both the private key and the TOTP secret, `bcrypt`
one-way, token hashing), with `test_seeded_totp_secret_is_stored_encrypted_not_plaintext`
asserting no plaintext secret survives a read. It is ②, not ①, because there is no single
end-to-end "attacker reads the store and cracks nothing" oracle — the argument is assembled
from per-component tests, not driven as one adversarial script. What remains is offline
`bcrypt` cracking (T1110.002) to unwrap a key; operator controls (network isolation, a
least-privilege DB role, read-access alerting) raise the bar on reaching the store at all,
but they are no longer what stands between a read and account takeover — closing the
plaintext-TOTP gap promoted this from **③ → ②** ([#122](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/122)).
