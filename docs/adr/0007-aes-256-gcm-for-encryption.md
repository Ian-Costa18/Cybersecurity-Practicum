# ADR 0007: AES-256-GCM over AES-128-CBC for Private Key Encryption

## Status

Accepted

## Context

Each approver's Ed25519 private key must be encrypted at rest so that a database-only attacker who has not cracked the approver's password cannot recover the private key. The encryption scheme must provide both confidentiality and integrity: an attacker who modifies the stored ciphertext must not be able to produce a valid decryption.

Two candidates were evaluated.

### Option A: AES-128-CBC with HMAC-SHA-256 (Encrypt-then-MAC)

CBC mode provides confidentiality only (IND-CPA). Providing integrity requires composing CBC with a separate MAC. The correct composition order is **Encrypt-then-MAC** (EtM): compute the MAC over the ciphertext, not the plaintext.

- **Confidentiality:** IND-CPA under the AES PRP assumption, for uniformly random IVs
- **Integrity:** HMAC-SHA-256 over the ciphertext provides UF-CMA under SHA-256 assumptions — a separate security argument from the confidentiality argument
- **Key size:** 128-bit key for AES; additional 256-bit key for HMAC → two-key management
- **IV:** 128-bit, random per encryption; included in MAC input
- **Composition risk:** MAC-then-Encrypt (MtE) is insecure and has been exploited in practice (Lucky13 TLS attack, BEAST). The implementation must use EtM, not MtE. This is a correctness requirement that is not enforced by the primitive itself — it requires disciplined use.
- **Padding:** CBC requires deterministic padding (PKCS#7 for block alignment). Padding oracle attacks (Vaudenay 2002, Lucky13 2013) apply when error messages differentiate padding errors from MAC errors. The EtM order avoids this: a MAC failure is returned before any decryption or padding check occurs.
- **Assumptions:** Two independent assumptions (AES PRP for CBC, SHA-256 collision resistance for HMAC), combined by the security of the EtM composition proof.
- **Post-quantum security:** AES-128 provides 64-bit security against Grover's algorithm (Grover halves effective key length to 64 bits from 128 bits). This does not meet the 128-bit post-quantum security threshold.

### Option B: AES-256-GCM

GCM is an Authenticated Encryption with Associated Data (AEAD) mode. It provides both confidentiality and authentication in a single primitive under a single key.

- **Confidentiality (Theorem 1, McGrew & Viega 2004/193):** GCM achieves IND-CPA. Adversary advantage is bounded by Adv^PRP(AES) + q²/2^128 for q queries.
- **Authentication (Theorem 2, McGrew & Viega 2004/193):** GCM achieves UF-CMA via the almost-XOR-universality of GHASH (Lemma 2: GHASH is [l/w+1]·2^{-l}-AXU). Both confidentiality and authentication reduce to the single AES PRP assumption.
- **GHASH:** Y_i = (Y_{i-1} ⊕ X_i) · H in GF(2^128), where H = AES_K(0^128). The almost-XOR-universality bound ensures that the probability any two distinct messages produce the same authentication tag is at most [l/w+1]·2^{-l}.
- **Key size:** 256-bit single key
- **IV:** 96-bit, one unique IV per encryption event; included in stored representation
- **AAD:** Additional authenticated data bound to the ciphertext but not encrypted; modification of AAD causes authentication failure
- **Post-quantum security:** AES-256 provides 128-bit security against Grover's algorithm (256 bits / 2 = 128 bits).
- **FIPS approval:** GCM is approved in NIST SP 800-38D; AES-256 is approved in FIPS 197.

**IV reuse catastrophe (SP 800-38D Appendix A):** If the same IV is used twice under the same key, an attacker who observes both ciphertexts can compute H = GHASH_K and thereafter forge any authentication tag. Additionally, XORing the two CTR-mode ciphertext streams gives the XOR of the two plaintexts, enabling full plaintext recovery given any known plaintext. IV uniqueness is a hard requirement.

## Decision

**Chosen: AES-256-GCM (Option B)**

## Rationale

1. **Single-assumption security proof for both confidentiality and authentication.** McGrew & Viega Theorems 1 and 2 establish IND-CPA and UF-CMA from the single assumption that AES is a secure PRP. Option A requires trusting two independent assumptions (AES PRP and SHA-256 collision resistance) composed correctly — a larger trust surface.

2. **AEAD eliminates composition errors.** Correctly composing CBC with HMAC requires Encrypt-then-MAC; using MAC-then-Encrypt is insecure and has been exploited. GCM computes authentication as a native part of the encryption operation — the API cannot produce a ciphertext without a tag, and the API cannot return plaintext if the tag is invalid. The correct composition is enforced by the primitive, not by the programmer.

3. **128-bit post-quantum security margin.** AES-256 under Grover's algorithm provides 128 bits of post-quantum security. AES-128 provides 64 bits — below the 128-bit post-quantum threshold that the broader industry treats as acceptable for long-lived data.

4. **No padding, no padding oracle.** GCM operates in counter mode, which has no padding. Padding oracle attacks (Lucky13, BEAST, Vaudenay) apply to CBC; they are structurally inapplicable to GCM.

5. **Single key management.** GCM uses one 256-bit key. Option A requires managing two keys (128-bit AES + 256-bit HMAC) or deriving them from a single master key — adding key derivation logic that must itself be implemented correctly.

6. **AAD enables cross-account replay prevention without a separate MAC.** AES-256-GCM authenticates the associated data (user_id ‖ version) in the same operation. A ciphertext encrypted for approver A cannot be substituted for approver B's ciphertext — the AAD mismatch causes authentication failure. Option A would require including this binding in the HMAC input explicitly; GCM includes it by design.

## Implications

- IV: 96-bit, generated per encryption via RBG (NIST SP 800-38D §8.2.2); the construction guarantees uniqueness with probability ≥ 1 − 2^{-32} for up to 2^32 invocations per key
- Tag: 128-bit (full-length per SP 800-38D §5.2.1.2; do not truncate)
- AAD: `user_id ‖ version` (prevents cross-account ciphertext transplant)
- Stored representation: `iv (12 bytes) ‖ ciphertext (32 bytes) ‖ tag (16 bytes)` = 60 bytes total per stored private key
- Plaintext is not returned until tag verification succeeds (enforce in decryption implementation)
- Key rotation: if a key is used for more than 2^32 encryptions, rotate it (in practice, one key per user; rotation is not needed unless the user count exceeds 2^32)

## Trade-offs Accepted

- **IV reuse is catastrophic.** Unlike CBC (where IV reuse causes only IND-CPA failure, not authentication failure), GCM IV reuse enables full authentication forgery and plaintext recovery. The RBG-based IV construction in SP 800-38D §8.2.2 makes IV reuse negligibly probable for the expected invocation count; but the implementation must not use deterministic IV counters that wrap, and must not derive IVs from mutable state that could repeat.
- **ChaCha20-Poly1305 not considered.** ChaCha20-Poly1305 (RFC 8439) is a strong AEAD alternative with superior performance in software implementations without hardware AES acceleration. It was not selected because AES-NI is ubiquitous in server hardware and AES-256-GCM is FIPS-approved. ChaCha20-Poly1305 is not FIPS 140-2 approved.
