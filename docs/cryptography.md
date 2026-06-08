# Cryptographic Design

This document describes the cryptographic model used by the approval proxy, justifies each primitive choice, and states the formal security properties and implementation invariants that must be upheld. It is written for a reader who can engage with formal security properties; for the decisions behind each choice, see the linked ADRs.

## System-Level Model

The proxy uses four primitives in two distinct roles:

```
Login (verification only):
  password ──bcrypt──► stored_hash  [compare; never used as key material]

Key decryption (at authentication time):
  password ──PBKDF2──► enc_key ──AES-256-GCM.Decrypt──► Ed25519_private_key

Approval signing (transient; key discarded after):
  Ed25519_private_key ──Sign──► σ  (bound to approval_record)

Audit verification (any time):
  Ed25519_public_key ──Verify──► (σ, approval_record)  [no password required]
```

Each primitive has exactly one role. The bcrypt output is never used as key material. The PBKDF2 output is never stored. The Ed25519 private key is never written to disk in plaintext. These are not conventions — they are invariants; violating any one of them collapses the security argument of the entire scheme.

## Primitive Summary

| Primitive | Role | Formal Security Property | Hardness Assumption | Primary Source |
|---|---|---|---|---|
| Ed25519-IETF | Approval record signing | SUF-CMA | ECDLP on Curve25519 | Brendel et al. IEEE S&P 2021 |
| PBKDF2-HMAC-SHA-256 | Deriving enc_key from password | PRF security | HMAC-SHA-256 is a PRF | RFC 8018 §5.2, NIST SP 800-132 |
| AES-256-GCM | Encrypting Ed25519 private keys at rest | IND-CPA + UF-CMA | AES is a secure PRP | McGrew & Viega IACR 2004/193 |
| bcrypt | Approver password verification | ε-secure password function | Blowfish security | Provos & Mazières USENIX FREENIX 1999 |
| SHA-256 | Artifact hash binding | collision resistance + second-preimage resistance | (standard model, no reduction) | FIPS 180-4 |

---

## Ed25519-IETF

### Role

Each approver has an Ed25519 key pair generated at enrollment. The private key signs the approval record at authentication time and is immediately discarded from memory. The public key is stored in plaintext and used for audit verification without any password or approver cooperation. See [ADR 0001](adr/0001-credential-backed-approval.md) and [ADR 0002](adr/0002-asymmetric-key-approval-signing.md).

### Algorithm

Ed25519 is EdDSA instantiated over the twisted Edwards curve birationally equivalent to Curve25519:

- Curve: twisted Edwards with coefficient a = −1 over **F**_p, p = 2^255 − 19
- Group order: l = 2^252 + 27742317777372353535851937790883648493
- Key generation: k ← {0,1}^256; H = SHA-512(k); a = clamp(H[0..255]); A = a·B
- Signing: r = SHA-512(H[256..511] ‖ M) mod l; R = r·B; S = (r + SHA-512(R ‖ A ‖ M)·a) mod l
- Verification (IETF variant): check S ∈ {0,...,l−1}; check 8(S·B) = 8(R + SHA-512(R ‖ A ‖ M)·A)

The nonce r is derived deterministically from the private key and message — there is no per-signature random input.

### Formal Security Property

The Ed25519-IETF variant (RFC 8032, with the S ∈ {0,...,l−1} bounds check in verification) achieves **SUF-CMA** (strong unforgeability under chosen-message attack) under the ECDLP assumption on Curve25519.

The proof chain (Brendel et al. 2021, Theorems 3 and 4):
1. ECDLP on Curve25519 → difficulty of computing discrete logs in the Edwards group
2. ECDLP → IMP-PA security (impersonation under passive attack) of the underlying identification scheme
3. IMP-PA → EUF-CMA via Fiat-Shamir transform (in the random oracle model)
4. EUF-CMA → SUF-CMA for Ed25519-IETF because the S bounds check blocks signature malleability

EUF-CMA (standard unforgeability): an adversary with access to a signing oracle for messages of their choice cannot produce a valid signature on any new message.

SUF-CMA (strong unforgeability): additionally, the adversary cannot produce a *new valid signature* on a *previously signed message*. The Ed25519-IETF bounds check closes the malleability gap that makes the original Ed25519 variant only EUF-CMA.

SUF-CMA is required here because approval records must be non-repudiable: an approver must not be able to produce an alternative signature on the same record to muddy audit.

### Why Ed25519 over RSA-2048 and P-256 ECDSA

See [ADR 0003](adr/0003-cryptographic-primitive-selection.md).

---

## PBKDF2-HMAC-SHA-256

### Role

Derives the 256-bit symmetric key (enc_key) used by AES-256-GCM to encrypt each approver's Ed25519 private key. Computed at login from the approver's plaintext password; the output is never stored. On password change: decrypt private key with old enc_key, re-encrypt with new enc_key. The Ed25519 key pair does not change; all past signatures remain valid.

### Algorithm

From RFC 8018 §5.2:

```
DK = T_1 ‖ T_2 ‖ ... ‖ T_{⌈dkLen/hLen⌉}
T_i = U_1 ⊕ U_2 ⊕ ... ⊕ U_c
U_1 = PRF(P, S ‖ INT(i))
U_j = PRF(P, U_{j-1})  for j = 2,...,c
```

where P is the password, S is the salt, c is the iteration count, and PRF = HMAC-SHA-256.

### Parameters

| Parameter | Value | Source |
|---|---|---|
| PRF | HMAC-SHA-256 | NIST SP 800-132 Table 1 (approved) |
| Iteration count | 600,000 | OWASP 2023; NIST SP 800-132 §5.3 (≥1,000 required) |
| Salt length | 128 bits, random per user | NIST SP 800-132 §5.1 (≥128 bits required) |
| Output length | 256 bits (32 bytes) | Sized to AES-256 key requirement |

### Formal Security Property

PBKDF2 does not have a tight formal proof from a single clean hardness assumption. The security argument rests on:

1. HMAC-SHA-256 is a PRF, which holds under the assumption that SHA-256 is collision-resistant and that the HMAC construction is a PRF under SHA-256 assumptions (Bellare 2006).
2. Iterating the PRF c times multiplies the attacker's per-candidate cost by c — a computational hardening argument, not a cryptographic reduction.

This is a weaker security basis than AES-256-GCM or Ed25519, both of which reduce to a single well-studied assumption. It is the standard basis accepted by NIST and the IETF for this class of primitive.

### Why PBKDF2 over Argon2id

See [ADR 0003](adr/0003-cryptographic-primitive-selection.md).

---

## AES-256-GCM

### Role

Encrypts each approver's Ed25519 private key at rest. The stored representation is:

```
encrypted_key = AES-256-GCM-Encrypt(
    key  = enc_key,            # 256-bit PBKDF2 output
    iv   = 96-bit random,      # unique per encryption event
    aad  = user_id ‖ version,  # authenticated, not encrypted
    pt   = Ed25519_private_key # 256-bit scalar
)
# Stored: iv ‖ ciphertext ‖ 128-bit tag
```

### Algorithm

From NIST SP 800-38D and McGrew & Viega (2004/193):

- **Hash subkey:** H = AES_K(0^128)
- **Pre-counter block:** For 96-bit IV, J_0 = IV ‖ 0^31 ‖ 1
- **Encryption:** C = GCTR(inc_32(J_0), P)
- **Authentication:** S = GHASH_H(A ‖ pad(A) ‖ C ‖ pad(C) ‖ [len(A)]_64 ‖ [len(C)]_64); T = MSB_t(GCTR(J_0, S))
- **GHASH:** Y_i = (Y_{i-1} ⊕ X_i) · H in GF(2^128) mod x^128 + x^7 + x^2 + x + 1

The tag-generation block (J_0) and the first plaintext-encryption block (inc_32(J_0)) are always distinct — they cannot collide within a single encryption.

### Formal Security Property

From McGrew & Viega (2004/193):

- **Theorem 1 (Confidentiality):** GCM achieves IND-CPA. The advantage of any adversary is bounded by: Adv ≤ Adv^PRP(AES) + q²/2^128, where q is the number of queries.
- **Theorem 2 (Authentication):** GCM achieves UF-CMA. Authentication security reduces entirely to AES PRP security via the almost-XOR-universality of GHASH (Lemma 2: GHASH is [l/w + 1]·2^{−l}-AXU for message blocks of length l).
- **Corollary 1 (Concrete):** With 96-bit IV, 128-bit tag, and fewer than 2^48 invocations per key, adversary advantage ≤ 2^{−18}.

Both confidentiality and authentication reduce to a single assumption (AES is a secure PRP), with no additional assumptions.

### Implementation Requirements

These are not optional. Each represents a catastrophic failure mode:

1. **IV uniqueness.** The IV must be unique for every encryption under the same key. IV reuse allows an attacker to compute H = GHASH_K from two ciphertexts under the same (K, IV); once H is known, GCM authentication is destroyed and plaintext XOR gives full plaintext recovery (SP 800-38D Appendix A). Generate IV via RBG (NIST SP 800-38D §8.2.2); rotate the key after 2^32 invocations.

2. **Plaintext not released before tag verification.** GCM-AD must return FAIL before any plaintext is released if the tag does not match (SP 800-38D Algorithm 5, step 8). Releasing plaintext before verification enables padding oracle-style attacks on the authentication.

3. **AAD binds ciphertext to identity.** AAD = user_id ‖ version prevents an attacker from substituting one approver's encrypted private key for another's (cross-account replay). Modification of AAD causes GCM-AD to return FAIL.

4. **128-bit tag.** Use the full 128-bit tag per SP 800-38D §5.2.1.2. Truncated tags reduce authentication security directly.

### Why AES-256-GCM over AES-128-CBC

See [ADR 0003](adr/0003-cryptographic-primitive-selection.md).

---

## bcrypt

### Role

Verifies approver passwords at login. The bcrypt output is a login verifier stored in the database — it is **not key material and must never be used as a key**. Key material comes from PBKDF2.

### Algorithm

From Provos & Mazières (1999), §4–5:

```
EksBlowfishSetup(cost, salt, key):
    state ← InitState()                     # load digits of π into P-array and S-boxes
    state ← ExpandKey(state, salt, key)
    repeat 2^cost:
        state ← ExpandKey(state, 0, salt)
        state ← ExpandKey(state, 0, key)
    return state

bcrypt(cost, salt, pwd):
    state ← EksBlowfishSetup(cost, salt, pwd)
    ctext ← "OrpheanBeholderScryDoubt"     # 192-bit magic constant
    repeat 64: ctext ← EncryptECB(state, ctext)
    return Concatenate(cost, salt, ctext)
```

Output format: `$2a$NN$<22-char base64 salt><31-char base64 hash>` (128-bit salt, 192-bit ctext).

Blowfish round function: F(a,b,c,d) = ((S_1[a] ⊕ S_2[b]) + S_3[c]) ⊕ S_4[d] where S_1–S_4 are 256×32-bit S-boxes (4 KB total state).

### Formal Security Property

From Provos & Mazières §3: F(s,t) is **ε-secure** if, for any randomized boolean circuit attacker A of size |A| against password distribution D with predictability R(D) = max_{s∈D} Pr(s):

1. No partial information about s can be extracted from F(s,t) with advantage > (ε/2)·|A|·R(D)
2. No second preimage can be found with advantage > ε·|A|·R(D)

**There is no formal proof that bcrypt achieves ε-security.** The paper states: *"we cannot formally prove bcrypt ε-secure, any flaw would likely deal a serious blow to the well-studied blowfish encryption algorithm."* The security argument is conditional on Blowfish being a secure cipher — a cipher studied since 1993 with no known practical attacks.

This is a weaker security basis than Ed25519 or AES-256-GCM, which have tight reductions to well-studied hardness assumptions. It is accepted here because bcrypt satisfies the engineering requirements (adaptable cost, large salt, GPU resistance) with broad library support and extensive real-world deployment.

### Parameters

| Parameter | Value | Rationale |
|---|---|---|
| cost | ≥ 12 | Produces ≈ 300ms per hash on modern hardware; re-evaluate as hardware improves |
| Salt | 128 bits, random per user | 2^41-entry precomputed tables have negligible collision probability (§6.2.1) |

### Anti-Bitslicing Property

DES crypt is vulnerable to bitslicing — treating a CPU as N parallel 1-bit processors, which allows N simultaneous password guesses. Bcrypt is immune: the S-boxes (4 KB) are dynamically recomputed from the (password, salt) pair during EksBlowfishSetup and differ for every input. A bitsliced circuit cannot precompute or share S-box state across instances — each simultaneous guess requires independent 4 KB state, eliminating the N× speedup (§6.2.3).

### Why bcrypt over Argon2id

See [ADR 0003](adr/0003-cryptographic-primitive-selection.md).

---

## SHA-256

### Role

Binds an uploaded artifact to its approval. When an artifact is uploaded, the proxy computes its SHA-256 digest and records it in the Approval Request. Approvers approve *that digest* — the recorded value is exactly what they sign over. Before publication, the proxy recomputes the digest of the artifact about to be published and compares it to the approved value; a mismatch blocks publication. This is the hash-binding integrity guarantee that defends against threat T11 (publishing an artifact other than the one approved).

SHA-256 already appears internally as the PRF inside PBKDF2-HMAC-SHA-256; here it is used directly as the artifact digest.

### Formal Security Property

The hash-binding guarantee reduces to two standard properties of SHA-256:

- **Collision resistance:** an adversary cannot find two distinct artifacts *m₁ ≠ m₂* with SHA-256(*m₁*) = SHA-256(*m₂*).
- **Second-preimage resistance:** given an approved artifact *m₁*, an adversary cannot find a distinct *m₂ ≠ m₁* with SHA-256(*m₂*) = SHA-256(*m₁*).

If either property failed, the binding would break: an attacker could get one artifact approved (recording its digest) and then publish a second artifact that hashes to the same value, passing the pre-publication recheck. Both properties are required — collision resistance covers the case where the attacker controls both artifacts (e.g., supplies the artifact under review), and second-preimage resistance covers the case where the approved artifact is fixed and only the published one is substituted.

Unlike Ed25519 and AES-256-GCM, hash functions have no reduction to a separate hardness assumption; collision and second-preimage resistance are taken as standard-model properties of the construction itself, justified by sustained public cryptanalysis.

### Why SHA-256 over SHA-1 / MD5

MD5 and SHA-1 both have demonstrated or practically feasible collision attacks (MD5 collisions are trivial; SHA-1 collisions were demonstrated by SHAttered in 2017). A broken collision property directly defeats hash binding, so neither is acceptable here. SHA-256 has no known collision or second-preimage weakness, is ubiquitous, and is hardware-accelerated (SHA extensions) on modern CPUs. SHA-512, SHA-3, and BLAKE2 would all be equally safe for this role but offer no advantage — the artifact digest is not a performance bottleneck and SHA-256 is the most broadly available FIPS-approved choice.

---

## Cross-Cutting Implementation Invariants

These apply across primitives and must be enforced in any implementation:

| Invariant | Consequence of Violation |
|---|---|
| bcrypt output is never used as key material | Collapse of enc_key derivation security: bcrypt is not designed as a KDF; its output is not a uniformly random bit string |
| PBKDF2 output (enc_key) is never stored | Stored enc_key gives attacker direct AES-256-GCM key; bypasses bcrypt and PBKDF2 entirely |
| Ed25519 private key discarded after signing | Persistent plaintext private key makes AES-256-GCM encryption of the key pointless |
| AES-256-GCM IV is unique per encryption event | IV reuse destroys authentication and enables plaintext recovery (SP 800-38D Appendix A) |
| AES-256-GCM plaintext not released before tag verification | Enables ciphertext manipulation without detection |
| bcrypt cost is re-evaluated as hardware improves | Fixed cost erodes security monotonically; bcrypt's adaptive cost exists for exactly this reason |

---

## Primary Sources

| Source | What it establishes |
|---|---|
| Bernstein et al. — "High-speed high-security signatures" (2011) | Ed25519 algorithm definition, curve parameters, deterministic nonce rationale |
| Brendel, Cremers, Jackson, Zhao — "The Provable Security of Ed25519" (IEEE S&P 2021) | SUF-CMA and EUF-CMA proofs for Ed25519 variants; reduction to ECDLP |
| RFC 8032 — Edwards-Curve Digital Signature Algorithm | Ed25519-IETF specification; S ∈ {0,...,l−1} bounds check that achieves SUF-CMA |
| RFC 8018 — PKCS #5 v2.1 | PBKDF2 formal algorithm definition (§5.2), PRF requirements |
| NIST SP 800-132 | PBKDF2 parameter requirements: ≥128-bit salt, ≥1,000 iterations, approved PRF list |
| NIST SP 800-38D | GCM formal algorithm (Algorithms 4 and 5), IV uniqueness requirement (§8), IV reuse catastrophe (Appendix A) |
| McGrew & Viega — "The Security and Performance of GCM" (IACR 2004/193) | Theorems 1 and 2 (IND-CPA + UF-CMA reductions to AES PRP); GHASH AXU Lemma 2 |
| FIPS 197 | AES specification, key schedule, key size definitions |
| FIPS 180-4 — Secure Hash Standard (SHA-2) | SHA-256 specification; the artifact-digest primitive for hash binding |
| Provos & Mazières — "A Future-Adaptable Password Scheme" (USENIX FREENIX 1999) | bcrypt algorithm, ε-secure password function definition, EksBlowfishSetup, anti-bitslicing argument |
