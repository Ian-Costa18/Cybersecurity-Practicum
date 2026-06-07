# Mission: Applied Cryptography for the Approval Proxy

## Why

The approval proxy uses several cryptographic primitives (Ed25519, PBKDF2, AES-256-GCM, bcrypt) without documented justification for why each was chosen over its alternatives. The goal is to understand each primitive well enough — from its formal definition and security proof through to its practical tradeoffs — to write a defensible `docs/cryptography.md` and a set of ADRs that can survive a security review.

## Success looks like

- Can state the formal security property each primitive provides (e.g., EUF-CMA for Ed25519, IND-CPA for AES-GCM) and cite the paper that proves it
- Can explain what hardness assumption each proof reduces to and why that assumption is credible
- Can articulate why the chosen primitive was preferred over named alternatives (RSA/P-256 for signing; Argon2id for key derivation; AES-CBC for encryption; scrypt for password hashing)
- Has written `docs/cryptography.md` and supporting ADRs that a cryptographer could read and critique

## Constraints

- Learning is driven by primary sources — original papers and RFCs — not textbook summaries
- Each primitive is researched one at a time, sequentially, before documentation is written
- Scope is limited to four primitives: Ed25519, PBKDF2, AES-256-GCM, bcrypt

## Out of scope

- Threshold signature schemes (FROST, GG20, DKLS) — already covered in prior research, not used in MVP
- Post-quantum alternatives — not relevant to current threat model
- Side-channel implementation details beyond what the original papers discuss
