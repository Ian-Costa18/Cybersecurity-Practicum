# Cryptography Resources

## Knowledge

### Ed25519
- [Paper: "High-speed high-security signatures" — Bernstein, Duif, Lange, Schwabe, Yang (2011)](https://ed25519.cr.yp.to/ed25519-20110926.pdf)
  The original Ed25519 paper. Use for: formal algorithm definition, curve parameters, performance comparisons vs RSA and P-256 ECDSA, security claims, deterministic nonce rationale.
  Local copy: `references/ed25519-20110926.pdf`

- [Paper: "The Provable Security of Ed25519: Theory and Practice" — Brendel, Cremers, Jackson, Zhao (IEEE S&P 2021)](https://eprint.iacr.org/2020/823.pdf)
  First detailed EUF-CMA and SUF-CMA proofs for Ed25519 variants. Use for: formal security theorems, ECDLP reduction, key clamping subtleties, variant comparison (Original vs IETF vs LibS).
  Local copy: `references/ed25519-SP.pdf`

- [RFC 8032 — Edwards-Curve Digital Signature Algorithm (EdDSA)](https://www.rfc-editor.org/rfc/rfc8032)
  IETF standardisation of EdDSA/Ed25519. The Ed25519-IETF variant (SUF-CMA secure). Use for: implementation-level specification, the S ∈ {0,...,L-1} bounds check that achieves strong unforgeability.

### PBKDF2
- [RFC 8018 — PKCS #5: Password-Based Cryptography Specification v2.1](https://www.rfc-editor.org/rfc/rfc8018)
  Current IETF specification for PBKDF2 (§5.2) and PBKDF1. Use for: formal PBKDF2 construction, PRF requirements, output length, iteration count guidance.
  Local copy: `references/rfc8018.txt`

- [NIST SP 800-132 — Recommendation for Password-Based Key Derivation](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf)
  NIST guidance on password-based KDFs. Use for: minimum iteration count justification (≥1000, with 600k defensible against current hardware), salt length requirements, approved PRF list.
  Local copy: `references/nistspecialpublication800-132.pdf`

### AES-256-GCM
- [NIST SP 800-38D — Recommendation for Block Cipher Modes of Operation: GCM and GMAC](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf)
  Primary specification for GCM. Use for: formal algorithm (Algorithms 4 and 5), IV uniqueness requirement (§8), Appendix A (IV reuse catastrophe), approved tag lengths.
  Local copy: `references/nistspecialpublication800-38d.pdf`

- [McGrew & Viega — "The Security and Performance of the Galois/Counter Mode (GCM) of Operation" (IACR ePrint 2004/193)](https://eprint.iacr.org/2004/193.pdf)
  Original GCM paper. Use for: Theorem 1 (confidentiality reduces to AES PRP), Theorem 2 (authentication reduces to AES PRP), GHASH almost-XOR-universality (Lemma 2), Corollary 1 (concrete security bounds for AES-N-GCM).
  Local copy: `references/gcm-spec-mcgrew-viega.pdf`

- [FIPS 197 — Advanced Encryption Standard (AES)](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf)
  AES specification. Use for: key schedule, round structure, key size requirements (128/192/256 bits).
  Local copy: `references/NIST.FIPS.197-upd1.pdf`

### bcrypt

- [Provos & Mazières — "A Future-Adaptable Password Scheme" (USENIX FREENIX 1999)](https://www.usenix.org/legacy/events/usenix99/provos/provos.pdf)
  Original bcrypt paper. Use for: formal definition of ε-secure password function (§3), EksBlowfishSetup algorithm (§4), bcrypt algorithm/Figure 3 (§5), anti-bitslicing argument, cost parameter semantics, comparison with DES crypt and MD5 crypt (§6).
  Local copy: `references/bcrypt-provos-mazieres-1999.pdf`

## Wisdom (Communities)

- [IACR ePrint Archive](https://eprint.iacr.org)
  Preprint server for cryptography research. Use for: finding primary sources and proofs before journal publication.

- [Crypto StackExchange](https://crypto.stackexchange.com)
  High-signal Q&A for applied and theoretical cryptography. Moderated; answers often cite papers. Use for: clarifying proof details, comparing primitives, checking intuitions.
