# ADR 0008: bcrypt over Argon2id and scrypt for Password Verification

## Status

Accepted

## Context

The proxy must verify approver passwords at login without storing the password in recoverable form. The stored value must be computationally expensive to crack offline if the database is stolen. The password hashing function must be distinct from the key derivation function (PBKDF2, [ADR 0006](0006-pbkdf2-for-key-derivation.md)) — the two serve different roles and must not be conflated.

Three candidates were evaluated: bcrypt, Argon2id, and scrypt.

### Option A: Argon2id (RFC 9106)

Argon2id is memory-hard and time-hard. It fills a configurable memory block with pseudorandom data derived from the password and salt, then makes multiple data-dependent passes over it. This means cracking a single candidate requires both time and memory — GPU/ASIC parallelism is constrained by memory bandwidth.

- **Hardness:** Memory-hard (m KB per candidate) + time-hard (t passes) + parallel (p lanes)
- **OWASP first recommendation** for password hashing (2023): m=64 MB, t=3, p=4
- **GPU resistance:** Memory bandwidth bounds simultaneous candidates; a GPU with 40 GB memory and 64 MB per candidate can run at most ~640 simultaneous guesses, versus millions for bcrypt
- **Standardization:** RFC 9106 (2021); not NIST-approved; not FIPS 140-2 compliant
- **Deployment maturity:** Argon2id is relatively newer; library implementations exist but have fewer combined service-years than bcrypt in production

### Option B: scrypt (NIST SP 800-132)

scrypt is memory-hard and time-hard. It uses PBKDF2-SHA-256 internally, followed by a memory-hard mixing step (ROMix) that requires reading and writing a large array in a data-dependent order.

- **Hardness:** Memory-hard (N blocks of 128r bytes) + time-hard (p iterations)
- **Standardization:** NIST SP 800-132 (2010, includes scrypt as an approved KDF)
- **Side-channel concern:** scrypt's data-dependent memory access pattern leaks timing information correlated with the password; Colin Percival (the author) has noted this. Argon2id's first pass is data-independent, specifically to mitigate this.
- **Library support:** Less uniform than bcrypt; some language ecosystems lack a native scrypt implementation with maintained bindings.

### Option C: bcrypt (Provos & Mazières, USENIX FREENIX 1999)

bcrypt is based on Blowfish, a 64-bit block cipher. The key setup (EksBlowfishSetup) performs 2^cost rounds of ExpandKey, which mixes the password and salt into the Blowfish P-array and four 256×32-bit S-boxes (4 KB total). The output is computed by encrypting the magic constant "OrpheanBeholderScryDoubt" 64 times under the derived state.

- **Hardness:** Time-hard; the 4 KB S-box state imposes a partial memory cost per instance (discussed below)
- **Adaptable cost:** The cost parameter is a log₂ exponent — each increment doubles computation. Cost=12 produces approximately 300 ms on a modern server CPU. Cost can be increased as hardware improves without changing the algorithm or stored format.
- **Salt:** 128-bit salt per password; precomputed lookup tables for 2^41 entries have negligible collision probability (§6.2.1, Provos & Mazières)
- **Anti-bitslicing (§6.2.3):** The S-boxes are computed from (password, salt) and differ for every input. Bitslicing — treating a CPU as N parallel 1-bit processors — works only when S-boxes are fixed and can be hardcoded into a boolean circuit. Bcrypt S-boxes are dynamic; a bitsliced circuit must maintain independent 4 KB S-box state per simultaneous guess, eliminating the N× speedup that breaks DES crypt.
- **Anti-GPU:** The same dynamic S-box property applies to GPUs: each simultaneous password candidate requires independent 4 KB state in registers or shared memory. This is not the bandwidth-limited resistance of Argon2id, but it meaningfully limits GPU throughput compared to SHA-256-based schemes.
- **Formal security:** Provos & Mazières §3 define an ε-secure password function and state that bcrypt is designed to meet this definition; they explicitly note that "we cannot formally prove bcrypt ε-secure, any flaw would likely deal a serious blow to the well-studied blowfish encryption algorithm." There is no tight formal security proof — contrast with AES-256-GCM, which has such a proof.
- **Deployment maturity:** bcrypt is the most widely deployed password hash in production. Python's `bcrypt`, Go's `golang.org/x/crypto/bcrypt`, Java's `jBCrypt`, and Node.js's `bcrypt` are all independently maintained and extensively audited. No successful preimage or second-preimage attacks are known against bcrypt in 25+ years of deployment.
- **NIST stance:** Not NIST-approved as a KDF; NIST recommends PBKDF2 or scrypt for key derivation. For password storage (verification only), NIST SP 800-63B recommends a "suitable one-way function" and lists bcrypt as an example (§5.1.1.2).

## Decision

**Chosen: bcrypt, cost ≥ 12 (Option C)**

## Rationale

1. **The threat model is low-throughput.** This is a proxy for a small organization's PyPI publishing workflow, not a consumer authentication service with millions of accounts and high-value targets. The realistic offline threat is an attacker who steals the database and attempts to crack approver passwords to forge approval signatures. The attacker faces two sequential barriers: crack bcrypt (the verifier) to learn the password, then run PBKDF2 to derive enc_key. Bcrypt at cost=12 imposes approximately 300 ms per candidate CPU-side and meaningful GPU friction via the anti-bitslicing property. Argon2id's GPU resistance via memory bandwidth provides marginal additional benefit in this threat model given the bcrypt cost already in place.

2. **Adaptable cost is the critical feature absent from alternatives like MD5-crypt and SHA-based schemes.** The original bcrypt paper identifies adaptable cost as the decisive design criterion — the property that DES crypt and MD5 crypt lack, and whose absence makes those schemes steadily weaker as hardware improves. Bcrypt's cost parameter allows the administrator to double the cracking cost by incrementing a single parameter, with no change to the storage format. This is the primary reason bcrypt was chosen over simpler iterated hash constructions.

3. **Absence of a formal proof is noted and accepted.** Bcrypt does not have a tight formal reduction to a well-studied hardness assumption (unlike Ed25519 → ECDLP, or AES-256-GCM → AES PRP). This is a known limitation. The security argument is: any practical break of bcrypt requires breaking the EksBlowfishSetup key schedule, which is argued (not proven) to reduce to breaking Blowfish — a cipher that has been publicly analyzed for over 30 years with no known practical attacks. For a password verification function (where the formal definition requires second-preimage resistance and partial information hardness, not IND-CPA), this level of security basis is widely accepted in practice and explicitly endorsed by NIST SP 800-63B.

4. **Library maturity and audit coverage are unmatched.** bcrypt implementations in all major language runtimes have been independently reviewed, deployed at scale, and battle-tested for 25+ years. Argon2id implementations are newer and have seen fewer combined service-years in hostile production environments. The risk of a subtle implementation bug in a less-deployed library is real; it is lower for bcrypt.

5. **The bcrypt role is password verification only, not key derivation.** NIST recommends against using bcrypt as a KDF; it is designed as a one-way verifier, not as a source of key material. This ADR governs only the use of bcrypt as a verifier. enc_key is derived by PBKDF2 ([ADR 0006](0006-pbkdf2-for-key-derivation.md)), which is the NIST-approved construction for key derivation from passwords.

## Implications

- bcrypt is called at login to verify the password against the stored hash.
- The stored hash includes the cost, salt, and ctext in the `$2a$NN$...` format; the implementation library handles parsing.
- cost = 12 is the deployment minimum. Re-evaluate annually; increment cost when login latency budget allows.
- The bcrypt output is never used as a cryptographic key, IV seed, or any other role beyond password verification.
- The PBKDF2 call (enc_key derivation) runs separately, in addition to bcrypt, at login time.

## Trade-offs Accepted

- **No memory-hardness.** Argon2id provides stronger GPU/ASIC resistance via memory bandwidth constraints. This is accepted for this threat model; if the proxy is ever deployed at larger scale or with higher-value targets, upgrading to Argon2id should be re-evaluated.
- **No formal security proof.** The security of bcrypt reduces informally to Blowfish security rather than formally to a well-studied hardness assumption. This is documented here and accepted given the widespread deployment evidence and the NIST SP 800-63B endorsement.
- **Cost factor must be actively managed.** Unlike a memory-hard function with a fixed memory parameter that provides absolute GPU resistance, bcrypt's cost must be periodically increased to maintain the same cracking latency as hardware improves. This is an operational requirement.
