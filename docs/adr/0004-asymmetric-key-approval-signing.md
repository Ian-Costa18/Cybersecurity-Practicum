# ADR 0004: Asymmetric Key Pairs for Approval Signing

## Status
Accepted

## Context

Approval records must be cryptographically tied to the approver's identity to prevent retroactive forgery and support audit. Two signing schemes were evaluated during design.

### Option A: MFKDF-Style Signing

Derive a transient signing key `K` from the approver's plaintext password and TOTP code at login time. `K` is never stored. Sign the approval record with `K`, then discard it.

- **Advantage:** No signing key artifact is ever persisted on disk.
- **Disadvantage:** Verification requires re-deriving `K`, which requires the approver's original password. Password changes break verification of historical records, requiring all past approval records to be re-signed on every password change.

### Option B: Per-User Asymmetric Key Pairs (Ed25519)

Generate a long-term Ed25519 key pair per approver at enrollment. Store the private key encrypted under a PBKDF2-derived key from the approver's password. Store the public key in plaintext. Sign approval records with the private key at authentication time; discard the private key from memory immediately after.

- **Advantage:** Verification is always possible using the stored public key — no password or approver cooperation required. Password changes only require re-encrypting the private key; the key pair and all past signatures are unaffected. Uses standard, auditable cryptographic primitives.
- **Disadvantage:** An encrypted private key artifact is persisted on the server.

## Decision

**Chosen: Option B (Per-User Asymmetric Key Pairs, Ed25519)**

## Rationale

1. **TOTP inclusion in Option A is illusory against the relevant attacker.** Option A derives `K = PBKDF2(password || totp_code, approval_id)`. However, the TOTP secret is stored in the proxy DB. A DB-level attacker who cracks the password can reconstruct any past TOTP code from the stored secret and the approval timestamp, re-deriving `K`. TOTP inclusion does not meaningfully differentiate Option A from Option B for the relevant threat (DB access + password cracking).

2. **Both schemes reduce to password security at the DB level.** Against a DB-level attacker, both options require cracking the approver's bcrypt password to forge signatures. There is no meaningful practical security difference between them.

3. **Password-change handling is cleaner.** Option A requires re-signing all historical approval records on every password change. Option B requires only re-encrypting the private key — the public key and all past signatures are unaffected.

4. **Audit quality is higher.** Option B enables verification using only the stored public key, without requiring the approver's cooperation or knowledge of any password. Option A requires approver self-verification and knowledge of the password used at the time of each approval.

5. **Standard primitives.** Ed25519 is a well-audited, widely-deployed signing scheme with broad library support. Option A's MFKDF-style scheme required a custom implementation with fewer precedents.

## Implications

- Each approver has an Ed25519 key pair generated at enrollment time.
- The private key is stored as `AES-256-GCM-Encrypt(private_key, PBKDF2(password, key_salt))`.
- The public key and `key_salt` are stored in plaintext.
- On password change: decrypt private key with old `enc_key`, re-encrypt with new `enc_key`. Key pair does not change; all past signatures remain valid.
- At approval time: decrypt private key transiently, sign the approval record, discard private key from memory.
- Audit verification uses the public key only — no approver cooperation required.

## Trade-offs Accepted

- **Encrypted private key persisted on disk.** A full proxy compromise combined with password cracking gives an attacker signing capability. This is the same practical bar as Option A (password cracking required in both cases). The persisted artifact is accepted because the practical security equivalence does not justify Option A's password-change complexity.
