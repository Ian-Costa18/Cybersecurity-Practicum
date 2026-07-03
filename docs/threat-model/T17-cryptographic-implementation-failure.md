---
id: T17
title: "Cryptographic Implementation Failure"
stride: ["Information Disclosure", "Elevation of Privilege"]
attack: []
capability: [L4]
delta: introduced
likelihood_baseline: N/A
likelihood_residual: low
severity_baseline: N/A
severity_residual: high
bucket: 2
related: [T5, T23, T29]
---

# T17 — Cryptographic Implementation Failure

| | |
|---|---|
| **Category** | Information Disclosure, Elevation of Privilege |
| **Capability** | L4 — read access to the stored material a defect would surrender. A latent bug is inert on its own; it becomes an attack only in combination with a position to exploit it. L6 is deliberately not claimed: at host compromise, crypto correctness barely matters — memory scraping recovers keys from a *correct* implementation too, and that consequence class is accepted under [T4](T04-proxy-host-compromise.md). |
| **What the attacker gains** | Whichever guarantee the violated invariant carried (table below). In every case the payoff is approver key material — the ability to produce *validly-signed* forged records without cracking any password: a stored `enc_key` is a direct AES key that bypasses password hashing entirely; a reused IV surrenders the wrapped private key; a persistent plaintext key makes the encryption pointless. |
| **What they cannot do** | Exploit a defect without an independent L4 position — the bug does nothing until someone can read the blobs. Turn recovered keys into an unauthorized publish by themselves: forged signatures still need a vote path, which demands either database write access ([T6](T06-database-write-compromise.md)) or web-edge authentication (password + TOTP). |
| **Current defenses** | The invariants are **structural** in `core/crypto.py`, not conventions a caller must remember, and each load-bearing one has a named pinning test (below). Tests use real primitives only — crypto is never mocked. |
| **Operator configuration** | No runtime configuration can fix a broken implementation. Require a security review of the cryptographic subsystem before deployment, confirm it against [cryptography.md](../cryptography.md), and run static crypto lint (`bandit`). |

**The six invariants and their status.** [cryptography.md §Cross-Cutting Implementation
Invariants](../cryptography.md) names six; this file is their single home (the nonce row
absorbs the former T20).

| Invariant | Violation consequence | Status in the implementation |
|---|---|---|
| bcrypt output is never key material | Collapse of `enc_key` derivation: bcrypt output is not a uniformly random bit string | Structural — password verification and key derivation are separate functions; only PBKDF2 output reaches AES. Pinned by `test_invariant_1` (`tests/core/test_crypto.py`). |
| PBKDF2 output (`enc_key`) is never stored | A stored `enc_key` is a direct AES-256-GCM key; bypasses bcrypt and PBKDF2 entirely | Structural — transient return value; the blob is `iv ‖ ciphertext ‖ tag` and nothing else. Pinned by `test_invariant_2`. |
| Ed25519 private key discarded after signing | A persistent plaintext key makes encrypting it pointless | Structural — the key exists only in `sign_with_password`'s locals and is never returned. Pinned by `test_invariant_3`. Honest caveat: this is *confinement, not secure erasure* — Python cannot zero immutable `bytes` in place. |
| AES-256-GCM IV unique per encryption *(absorbs T20)* | Reuse destroys authentication and XOR of two ciphertexts under one (key, IV) recovers plaintext (SP 800-38D Appendix A) | Structural — `encrypt_private_key` generates a fresh 96-bit random IV internally on every call; there is no parameter through which a caller could reuse one. Pinned by `test_invariant_4`. The random-IV *exhaustion* bound (NIST's conservative 2^32 invocation limit per key) is unreachable at MVP usage — each key encrypts exactly one object, re-encrypted only on password change; it becomes relevant only if a bulk-encryption use ever appears. |
| No plaintext released before tag verification | Undetected ciphertext manipulation | Delegated to the `cryptography` library's AEAD interface — `AESGCM.decrypt` verifies before releasing anything; exercised by `test_decrypt_fails_when_ciphertext_is_tampered`. |
| bcrypt cost re-evaluated as hardware improves | Fixed cost erodes monotonically | Operational — `BCRYPT_ROUNDS = 12` (~300 ms) with a re-evaluation note; no runtime mechanism, by nature a maintenance duty. |

**Boundaries.** vs. [T23](T23-cryptographic-side-channel-leakage.md): T17 owns *the code
deviates from the documented crypto design*; T23 owns *the code matches the design and
physics still leaks* — complements, split on whether the implementation is at fault. vs.
[T5](T05-database-read-compromise.md): T5 rates what a database reader gets when the crypto
*holds*; a T17 defect is precisely what would collapse T5's protection classes (e.g. a
stored `enc_key` removes the offline-cracking gate T5's severity rationale rests on). vs.
[T29](T29-application-layer-vulnerability.md): sibling implementation-bug meta-threats —
T17 owns *our crypto code has a bug*, T29 owns *our web code has a bug*; both share the
same bucket-② ceiling (no oracle demonstrates the absence of unknown bugs).

**ATT&CK mapping.** None — `attack: []` is a considered verdict, not an omission: ATT&CK
catalogs adversary behaviors, and a latent defect in our own code is a weakness, not a
technique. The *exploitation* of what a defect surrenders is the L4 read itself, which is
[T5](T05-database-read-compromise.md)'s mapping (T1005/T1552.001); tagging it here too
would double-count one action.

## Rating rationale

`delta: introduced` — the cryptographic subsystem is a proxy construct; a maintainer
publishing directly to PyPI has no such implementation to get wrong, so both baselines are
N/A. Residual likelihood **low**, a justified deviation below the L4 default (medium):
exploitation requires the *conjunction* of a latent defect surviving the structural shaping
plus the pinned invariant tests, *and* an independent L4 compromise — strictly harder than
[T5](T05-database-read-compromise.md) alone (medium), so it must rate below it. Residual
severity **high**: an authorization input (approver key material) is corrupted, but ≥1
barrier stands — forged signatures still need a vote path (database write, or password +
TOTP at the web edge). No failure in this file alone reaches publish-at-will.

## Bucket

Bucket ② (argued by design) — and ② is this threat's **ceiling by nature**. Each of the
four load-bearing invariants has an executable oracle (`test_invariant_1..4`), but the
threat is the open-ended class "*some* deviation from the documented design exists," and no
test suite can demonstrate the absence of implementation bugs. There is nothing for a
bucket-① oracle to fire against until a specific defect is hypothesized — at which point
either its pinning test already exists, or the defect lies outside the invariant list
entirely. No promotion path, hence no planned-defenses section: the file's former planned
rows (memory-inspection tests, CI persistence checks, review checklists) carried no issue;
the parts that shipped are Current defenses above, and the rest is cut.
