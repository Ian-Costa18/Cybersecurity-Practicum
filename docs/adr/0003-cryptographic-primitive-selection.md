# Cryptographic Primitive Selection

## Status
Accepted

## Context

This decision follows from [ADR 0002](0002-asymmetric-key-approval-signing.md): once approvals are signed with per-approver key pairs stored encrypted at rest, the system needs a concrete primitive for each role. These choices are recorded together because they share one threat model and one set of selection criteria.

The proxy uses five cryptographic primitives, each in exactly one role:

| Role | Primitive chosen | Leading alternative rejected |
|---|---|---|
| Approval-record signing | Ed25519-IETF (RFC 8032) | RSA-PSS-2048, P-256 ECDSA |
| Derive `enc_key` from password | PBKDF2-HMAC-SHA-256, c=600,000 | Argon2id |
| Encrypt Ed25519 private key at rest | AES-256-GCM | AES-128-CBC + HMAC (EtM) |
| Verify approver password at login | bcrypt, cost ≥ 12 | Argon2id, scrypt |
| Artifact hash binding | SHA-256 (FIPS 180-4) | SHA-1, MD5; SHA-512, SHA-3, BLAKE2 |

All five selections share the same evaluation criteria, in priority order:

1. **A correct security property for the role**, ideally with a formal reduction to a well-studied assumption.
2. **FIPS-forward standardization.** The proxy may eventually run in regulated environments; an unapproved primitive creates a later migration cost.
3. **Fit to the threat model.** The realistic offline adversary steals the database and tries to forge approval signatures. They face two sequential barriers — crack bcrypt to learn the password, then run PBKDF2 to derive `enc_key`. The bcrypt step is the binding constraint. This is a low-throughput system (< 100 logins/day), so the marginal value of memory-hardness over a primitive that is already FIPS-approved and battle-tested is low.
4. **Library maturity and constant-time implementations** across Python/Go/Java/OpenSSL.

This ADR records *that* each primitive was chosen and *why* at the decision level. The full formal treatment — algorithm definitions, security theorems, attack analysis, and implementation invariants — lives in [`docs/cryptography.md`](../cryptography.md) and is not duplicated here.

## Decision

### Signing: Ed25519-IETF (RFC 8032)
Over RSA-PSS-2048 and P-256 ECDSA.

- Achieves **SUF-CMA** with a formal proof (Brendel et al. 2021, Thm 4); the IETF `S ∈ {0,…,l−1}` check closes the malleability gap. RSA-PSS and ECDSA reach only EUF-CMA. SUF-CMA is the right property for non-repudiable approval records.
- **Deterministic nonces** eliminate the RNG-dependent failures that have broken ECDSA in practice (PS3 key recovery, Minerva biased-nonce lattice attacks).
- Verifiably-random curve parameters; compact 64-byte signatures; ubiquitous constant-time implementations.
- *Trade-off:* not in FIPS 186-4 (added in FIPS 186-5, 2023). Re-evaluate only if FIPS compliance is required before library support catches up.

### Key derivation: PBKDF2-HMAC-SHA-256, c = 600,000, 128-bit salt, 32-byte output
Over Argon2id.

- **FIPS 140-2/140-3 approved** (NIST SP 800-132); Argon2id is not NIST-approved.
- Memory-hardness is marginal in this threat model: the bcrypt verification step already dominates per-candidate cost, so Argon2id's GPU/ASIC resistance buys little here.
- 600,000 iterations impose a ~1,000× slowdown vs raw SHA-256 — adequate for a low-throughput system layered behind bcrypt.
- *Trade-off:* weaker GPU resistance than Argon2id. If both FIPS and memory-hardness are later required, evaluate scrypt (NIST-approved and memory-hard).

### Encryption at rest: AES-256-GCM
Over AES-128-CBC + HMAC-SHA-256 (Encrypt-then-MAC).

- **AEAD in one primitive under one key**: confidentiality (IND-CPA) and integrity (UF-CMA) both reduce to the single AES-PRP assumption (McGrew & Viega, Thms 1–2). The CBC+HMAC option needs two assumptions composed correctly.
- **No composition footgun.** Correct EtM ordering is a discipline requirement in the CBC option; GCM enforces it structurally — no ciphertext without a tag, no plaintext released on a bad tag.
- No padding (no padding-oracle class), AAD binds ciphertext to `user_id ‖ version` (cross-account transplant fails), and AES-256 gives a 128-bit post-quantum (Grover) margin.
- *Trade-off:* IV reuse is catastrophic for GCM. The implementation must use an RBG-generated 96-bit IV per encryption and must not derive IVs from mutable state that can repeat. See `docs/cryptography.md` for the full invariant list.

### Password verification: bcrypt, cost ≥ 12
Over Argon2id and scrypt.

- **Adaptable cost** is the decisive property bcrypt has and simpler iterated hashes lack: cost is a log₂ exponent that can be raised as hardware improves with no change to the stored format.
- **OWASP now ranks bcrypt as a *legacy fallback*** — its current ordering is Argon2id → scrypt → PBKDF2 (for FIPS) → bcrypt ([OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)) — so bcrypt is not the modern first choice. The selection here is nonetheless defensible on **FIPS-forward** grounds: consistency with the FIPS-approved PBKDF2 already used for key-wrap, anti-bitslicing dynamic S-boxes for GPU friction, 25+ years of deployment with no practical preimage attacks, and unmatched library maturity. (Earlier wording called bcrypt "endorsed by NIST SP 800-63B"; SP 800-63B permits memorized-secret verifiers built on approved hashing but does not single out or endorse bcrypt — corrected here to avoid overstating it.)
- Used as a **verifier only** — its output is never used as key material. Key material comes from PBKDF2 above.
- **72-byte input limit:** bcrypt silently truncates its input at 72 bytes. To keep login verification and the PBKDF2 key-wrap operating on the *same* bytes, passwords are **capped at 72 bytes** at enrollment/reset (see [`docs/account-management.md`](../account-management.md)); pre-hashing before bcrypt was rejected because it would leave bcrypt and PBKDF2 on different representations.
- *Trade-offs:* no memory-hardness (accepted for this threat model); not OWASP's first-ranked choice (accepted for FIPS consistency); no tight formal proof — security rests informally on Blowfish, which is documented and accepted given the deployment record; cost must be re-evaluated as hardware improves.

### Artifact hash binding: SHA-256 (FIPS 180-4)
Over SHA-1 / MD5, and over SHA-512 / SHA-3 / BLAKE2.

- The proxy records the SHA-256 digest of an uploaded artifact in the Approval Request; approvers approve that digest and a mismatch blocks publication. The property this depends on is **collision and second-preimage resistance**.
- SHA-1 and MD5 are rejected: their broken collision resistance would defeat hash binding (an attacker could get one artifact approved and publish another with the same digest).
- SHA-512, SHA-3, and BLAKE2 are unnecessary: SHA-256 is sufficient for this role, ubiquitous, hardware-accelerated, and FIPS-approved. SHA-256 is also already in use as the HMAC hash inside PBKDF2.

## Implications

- The four primitives compose into the login/signing/audit flow defined in [`docs/cryptography.md`](../cryptography.md), which is the authoritative reference for parameters and invariants.
- Cross-cutting invariants that any implementation must uphold: bcrypt output is never used as a key; `enc_key` (PBKDF2 output) is never stored; the Ed25519 private key is discarded immediately after signing; GCM IVs are unique per encryption; GCM plaintext is not released before tag verification.
- If a future requirement changes the threat model (higher-value targets, larger scale, or a hard FIPS-186-5 + memory-hardness mandate), this ADR is the single place to revisit all five choices together rather than separate records.

## Notes

This ADR supersedes four earlier per-primitive ADRs (Ed25519, PBKDF2, AES-256-GCM, bcrypt) that were consolidated here because they shared one threat model and one set of criteria, and because the formal detail they carried is already maintained in `docs/cryptography.md`.
