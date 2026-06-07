# PBKDF2: Construction and Security Model

The user engaged with RFC 8018 §5.2 (full text) and NIST SP 800-132 (all 18 pages) covering the
formal PBKDF2 algorithm, salt and iteration count requirements, and the security rationale in
Appendix A.

**Evidence:** Both sources read in full on 2026-06-06. User understands the iterate chain
(U_j = PRF(P, U_{j-1})), the belt-and-suspenders XOR design, the NIST salt (≥128 bits) and
iteration count (≥1,000, 600k for OWASP-recommended PBKDF2-HMAC-SHA-256) requirements.

**Key distinctions understood:**
- PBKDF2 is CPU-hard but NOT memory-hard — GPU parallelism across password candidates is feasible
- Argon2id (RFC 9106) is memory-hard and preferred by OWASP, but is NOT NIST/FIPS-approved
- The 600k iteration count aligns with OWASP 2023 guidance for PBKDF2-HMAC-SHA-256
- Password change requires re-encrypting the private key (NIST SP 800-132 §5.4)

**Security model distinction from Ed25519:**
PBKDF2 does not have a tight formal proof from a clean hardness assumption the way Ed25519 does.
Its security is argued from (1) HMAC being a PRF under SHA-256 assumptions and (2) the engineering
argument that iteration count multiplies attacker cost. This is a weaker but widely accepted
security basis.

**Implications:** Next lesson (AES-256-GCM) can assume the user understands what enc_key is,
how it is derived, and why it is 256 bits. The ADR write-up should explicitly state the FIPS
compliance rationale for choosing PBKDF2 over Argon2id.
