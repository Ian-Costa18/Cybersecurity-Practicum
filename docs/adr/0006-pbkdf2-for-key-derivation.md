# ADR 0006: PBKDF2-HMAC-SHA-256 over Argon2id for Key Derivation

## Status

Accepted

## Context

The proxy derives a 256-bit symmetric key (enc_key) from each approver's password at login time, using it to decrypt the approver's Ed25519 private key (stored as an AES-256-GCM ciphertext). The key derivation function must:

1. Be slow enough that offline brute-force attacks against a stolen database are costly
2. Produce output indistinguishable from random (suitable as an AES-256 key)
3. Accept a per-user salt to prevent precomputed attacks across accounts

Two candidates were evaluated: **PBKDF2-HMAC-SHA-256** (RFC 8018, NIST SP 800-132) and **Argon2id** (RFC 9106, OWASP first recommendation).

### Option A: Argon2id (RFC 9106)

Argon2id is the hybrid variant of Argon2 — it combines the data-independent memory access of Argon2i (side-channel resistant) with the data-dependent access of Argon2d (GPU/ASIC resistant). It is the OWASP first recommendation for password-based key derivation and password hashing.

- **Hardness model:** Memory-hard + time-hard. Attacker must allocate m KB of memory per candidate, multiplying hardware cost by the memory requirement in addition to time.
- **GPU resistance:** Memory bandwidth is the binding constraint on GPU parallelism; Argon2id's memory requirement effectively caps the number of simultaneous guesses a GPU can run in parallel.
- **ASIC resistance:** Memory-hard functions raise ASIC cost because memory cannot be amortized across guesses (unlike SHA-256, which is fully pipelinable).
- **Standardization:** RFC 9106 (2021), but **not NIST-approved** and not FIPS 140-2/140-3 compliant as of the decision date.
- **OWASP recommendation:** Argon2id with m=64 MB, t=3, p=4 (for general key derivation).

### Option B: PBKDF2-HMAC-SHA-256 (RFC 8018)

PBKDF2 stretches the password via iterated PRF applications:

```
T_i = U_1 ⊕ U_2 ⊕ ... ⊕ U_c
U_1 = HMAC-SHA-256(P, S ‖ INT(i))
U_j = HMAC-SHA-256(P, U_{j-1})
```

- **Hardness model:** Time-hard only. Attacker's cost scales linearly with iteration count c, but each iteration requires only CPU time — not memory. GPUs can parallelize PBKDF2 across password candidates because the SHA-256 state fits in GPU registers.
- **GPU parallelism:** A high-end GPU can evaluate approximately 10^6 PBKDF2-HMAC-SHA-256 candidates per second at c=600,000 in 2023. Memory-hard functions cannot be similarly parallelized.
- **Standardization:** RFC 8018, NIST SP 800-132, FIPS 140-2/140-3 approved. Required for government and healthcare deployments.
- **OWASP:** Second recommendation; parameters of 600,000 iterations for PBKDF2-HMAC-SHA-256 as of 2023 guidance.

## Decision

**Chosen: PBKDF2-HMAC-SHA-256, c = 600,000, salt = 128-bit random, dkLen = 32 bytes (Option B)**

## Rationale

1. **FIPS 140-2/140-3 compliance is a forward-looking requirement.** PBKDF2-HMAC-SHA-256 with HMAC-SHA-256 as the PRF is approved under NIST SP 800-132 and FIPS 140-2. Argon2id is not NIST-approved. A proxy protecting PyPI publishing operations may eventually need to operate in regulated environments (government agencies, healthcare organizations using PyPI for internal tooling). Selecting an unapproved primitive now creates a later migration cost.

2. **The threat model makes memory-hardness marginally beneficial.** The proxy is a low-throughput system: fewer than 100 approver logins per day in any realistic deployment. An offline attacker who steals the database faces two sequential barriers: (a) crack the bcrypt password hash (cost=12, ~300ms per candidate) to obtain the password, then (b) run PBKDF2 to derive enc_key. The bcrypt step is the binding constraint — it is also memory-hard relative to SHA-256 (4 KB S-box state per attempt). An attacker who cracks bcrypt can trivially run PBKDF2 at 600,000 iterations; the bcrypt cost dominates. Memory-hardness in the key derivation layer provides marginal additional benefit given that the password verification layer already imposes a substantial per-candidate cost.

3. **600,000 iterations provide adequate attacker slowdown for this threat model.** At 600,000 iterations, PBKDF2-HMAC-SHA-256 takes approximately 300–600 ms on modern hardware. An offline attacker using a GPU cluster can evaluate roughly 10^6 candidates/second (vs 10^9/second for raw SHA-256), a ~1,000× slowdown. Combined with the bcrypt barrier on password verification, this is adequate for the low-throughput, non-high-value threat model of the MVP.

4. **Library maturity and audit coverage.** PBKDF2 is implemented identically in Python's `hashlib`, Go's `golang.org/x/crypto/pbkdf2`, Java's `PBKDF2WithHmacSHA256`, and OpenSSL. All have been independently audited many times. Argon2id implementations are newer and have seen fewer independent audits in production-grade library code.

## Implications

- The key derivation call is: `PBKDF2(password, key_salt, 600000, SHA-256, 32)`
- `key_salt` is a 128-bit random value generated at enrollment and stored in plaintext per user
- `enc_key` is never stored; it is derived transiently at login and discarded after AES-256-GCM decryption
- On password change: derive old enc_key, decrypt private key, derive new enc_key, re-encrypt private key; the Ed25519 key pair is unchanged

## Trade-offs Accepted

- **Weaker GPU resistance than Argon2id.** A well-resourced offline attacker with GPU access has greater parallelism against PBKDF2 than against Argon2id. This is accepted because the bcrypt step provides the primary offline cracking barrier, FIPS compliance is valued, and the threat model is a low-volume system.
- **If future requirements demand FIPS + memory-hardness:** scrypt is both NIST SP 800-132 approved and memory-hard. It should be evaluated if Argon2id's lack of FIPS approval becomes a blocker and memory-hardness becomes a priority.
