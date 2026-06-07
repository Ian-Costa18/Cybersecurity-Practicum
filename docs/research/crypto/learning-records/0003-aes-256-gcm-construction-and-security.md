# AES-256-GCM: Construction and Security Model

The user engaged with NIST SP 800-38D (all 39 pages) and McGrew & Viega IACR ePrint 2004/193
(full paper including security proofs) covering the formal GCM algorithm, GHASH construction,
IV uniqueness requirements, and the concrete security theorems.

**Evidence:** Both sources read in full on 2026-06-06. Lesson 0003 created.

**Key constructions understood:**
- H = AES_K(0^128) — hash subkey derived by encrypting the zero block
- GHASH_H(X): iterative polynomial evaluation Y_i = (Y_{i-1} ⊕ X_i) • H over GF(2^128)
- GCTR: counter mode using AES, starting from ICB = inc_32(J_0) for plaintext
- GCM-AE: C = GCTR(inc_32(J_0), P); S = GHASH(A ‖ pad ‖ C ‖ pad ‖ [len(A)] ‖ [len(C)]); T = GCTR(J_0, S)
- J_0 is the pre-counter block; J_0 encrypts the tag; inc_32(J_0) is the ICB for plaintext — these are always disjoint

**Security model:**
- Single assumption: AES is a secure PRP (pseudorandom permutation)
- Theorem 1 (McGrew & Viega): GCM confidentiality reduces to AES PRP — formal IND-CPA proof
- Theorem 2: GCM authentication reduces to AES PRP — formal UF-CMA proof via GHASH almost-XOR-universality
- Lemma 2: GHASH is [l/w+1]2^{-l}-almost XOR universal — this is the MAC security foundation
- Corollary 1: AES-N-GCM with 96-bit IV, 96-bit tag, < 2^48 invocations → adversary advantage ≤ 2^{-18}
- Contrast with PBKDF2: GCM has a tight formal proof from a single assumption; PBKDF2 does not

**IV uniqueness requirement (SP 800-38D §8):**
- IV must be unique per (K, IV) pair with probability ≥ 1 - 2^{-32}
- IV reuse catastrophe (Appendix A): attacker recovers H from two ciphertexts under same (K, IV), then forges any tag
- Once H is known: authentication is gone and CTR malleability gives full plaintext control
- Approved constructions: deterministic counter (unlimited invocations with 96-bit IV) or RBG-based (≤ 2^32 invocations/key)

**AAD semantics:**
- AAD is authenticated but not encrypted — bound to the ciphertext, transmitted in clear
- Modification of AAD causes GCM-AD to return FAIL
- In the proxy: AAD = user_id ‖ version prevents cross-account ciphertext replay

**Decryption requirement:**
- Plaintext must not be released until tag verification is complete (GCM-AD step 8: if T = T', return P; else FAIL)
- Releasing plaintext before tag check is a critical implementation flaw

**Implications for next lessons:**
- bcrypt (lesson 0004): user password is the input to bcrypt (for login verification); enc_key comes from
  PBKDF2. bcrypt and PBKDF2 serve different roles in the system.
- The ADR for AES-256-GCM choice should cite: FIPS approval, single-assumption security proof, AEAD
  (eliminating the need for separate MAC), and 256-bit key providing 128-bit post-quantum security margin.
