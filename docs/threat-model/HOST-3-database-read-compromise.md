---
id: HOST-3
title: "Database Read Compromise"
stride: ["Information Disclosure", "Elevation of Privilege"]
attack: [T1005, T1552.001, T1110.002]
capability: [L4]
delta: introduced
likelihood_baseline: N/A
likelihood_residual: medium
severity_baseline: N/A
severity_residual: high
bucket: 3
related: [HOST-1, HOST-2, CRYPTO-1, CORE-2, CODE-1, DOS-2, IDENT-6]
tests:
  - tests/core/test_crypto.py::test_decrypt_fails_when_aad_does_not_match
  - tests/core/test_crypto.py::test_private_key_encrypt_decrypt_round_trips
---

# HOST-3 — Database Read Compromise

| | |
|---|---|
| **Category** | Information Disclosure; Elevation of Privilege (deferred — only after an offline crack) |
| **Capability** | L4 — read access to the database (SQL injection, a stolen backup, a read replica, an on-disk snapshot). The write-capable sibling is [HOST-2](HOST-2-database-write-compromise.md); host access that reaches the database is [HOST-1](HOST-1-proxy-host-compromise.md). |
| **What the attacker gains** | A full read of the credential store. Its rows fall into three protection classes: **(1) one-way hashed** — `bcrypt` password hashes (cost ≥ 12) and SHA-256 API-/enrollment-token digests; a read yields useless hashes, not replayable secrets. **(2) Wrapped under a key the reader lacks** — `encrypted_private_key` blobs (AES-256-GCM under the user's password-derived key); ciphertext without the password. **(3) Stored in the clear — the gap** — `totp_secret` is plaintext today (the exposure once split out as its own threat, since folded in here), so a single read hands the attacker a working second factor for every account. Public keys and all approval records are readable but not forgeable without the private keys. |
| **What they cannot do** | Authenticate, approve, or forge a signature on the strength of the read alone. Every usable secret except the plaintext TOTP is either a one-way hash or password-wrapped, so account takeover still requires cracking a `bcrypt` hash offline (cost ≥ 12) to derive the key that decrypts a private key. The read publishes nothing by itself. |
| **The invariant (absorbing the former standalone TOTP-exposure threat)** | A credential at rest survives a database read only if it is *one-way hashed* (passwords, tokens) or *wrapped under a key the reader does not hold* (the private key, under the password-derived key). The TOTP secret is the one credential that is neither. It need not be: the proxy only checks TOTP at interactive login, and login always presents the password, so the secret can be wrapped under the same password-derived key as the private key ([#122](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/122)) rather than stored raw. Until then it is the sole plaintext credential, and it is what makes a bare read escalate toward full account takeover. |
| **Current defenses** | AES-256-GCM encryption of private keys at rest — the plaintext private key is never stored (`test_private_key_encrypt_decrypt_round_trips`, `test_decrypt_fails_when_aad_does_not_match`). `bcrypt` password hashing at cost ≥ 12 with a unique 128-bit per-user salt — offline cracking is expensive and precomputed tables are useless. Token hashing — API and enrollment tokens are stored only as SHA-256 digests; the plaintext is shown or delivered once and never persisted, so a read cannot recover or replay them. |
| **Operator configuration** | Never expose the database port to the internet; bind it to localhost or a private network reachable only by the proxy host. Use a dedicated database user with least-privilege table grants (no superuser). Enable database audit logging and alert on unexpected bulk reads. Store the database on an encrypted volume to raise the cost of offline extraction of the plaintext TOTP secret until #122 lands. Rotate database credentials on any suspected breach, and establish a `bcrypt`-cost escalation policy as hardware improves. |

The mapping is three techniques. **T1005 (Data from Local System):** the attacker collects data — here the entire credential store — from the compromised system. **T1552.001 (Unsecured Credentials: Credentials in Files):** the plaintext `totp_secret` is a usable credential sitting unprotected in the store. A mild fit — the sub-technique's canonical case is a config file — but the property is identical: a secret readable without cracking anything. **T1110.002 (Brute Force: Password Cracking):** offline cracking of the captured `bcrypt` hashes to derive the password — and with it the key that unwraps the private key — which is the step the entire severity ceiling (account takeover → forged quorum) is gated behind. Online guessing against the live endpoints is [IDENT-5](IDENT-5-no-anti-automation-on-authentication-endpoints.md)'s surface (parent T1110); HOST-3 owns the offline half.

## Rating rationale

`delta: introduced` — the at-rest credential set (encrypted private keys, TOTP secrets, the approval records) exists only because the proxy exists; a maintainer publishing directly to PyPI has no such store, so both baselines are N/A. Residual likelihood **medium** (the L4 default): a read via injection, a stolen backup, or a read replica is a routine breach shape, no deviation claimed. Residual severity **high**, not critical: the ceiling is account takeover → forged quorum → an unauthorized publish, but it is *gated behind offline `bcrypt` cracking* — the authentication input is corrupted, yet a real barrier still stands, which is the "high" rung, not the "publish-at-will" top of the mission ladder.

## Bucket

Bucket ③ (operator-enforced). The property that would make this threat inert — *a database read yields nothing directly usable* — does **not** hold today, because the plaintext TOTP secret is directly usable. What stands between a read and account takeover is therefore operator configuration: network-isolating the database, a least-privilege DB role, and read-access controls. It promotes to **② (argued by design)** once TOTP secrets are wrapped (#122): every credential at rest is then hashed or password-wrapped, an invariant backed by tested components (AES-GCM AAD binding, `bcrypt` one-way, token hashing), though without a single end-to-end "attacker cracks nothing" oracle.

## Planned defenses

- **Encrypt TOTP secrets at rest under the password-derived key** — #122 — closes the sole plaintext-credential gap, makes the credential-at-rest set uniform, and promotes **③ → ②**.
