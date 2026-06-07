# Notes

## User preferences

- Learning is grounded in primary sources (papers, RFCs) — not textbook summaries or Wikipedia
- Each primitive is researched before any documentation is written
- The user wants to understand the formal security properties and proofs, not just the intuition
- The user converts PDFs to markdown/images manually when WebFetch can't parse them

## Session notes

- 2026-06-06: Started with Ed25519. Both source papers read in full (original 2011 Bernstein et al. + 2021 Brendel et al. provable security). Teaching session completed in-chat before lesson was formally created.
- 2026-06-06: PBKDF2. RFC 8018 (full text) + NIST SP 800-132 (all pages) read. Lesson 0002 created. Source files now in references/ (flat directory, no per-primitive subfolders).
- 2026-06-06: AES-256-GCM. NIST SP 800-38D (all 39 pages) + McGrew & Viega IACR 2004/193 (all pages, full proofs) read. Lesson 0003 created.
- 2026-06-06: bcrypt. Provos & Mazières USENIX FREENIX 1999 (all 13 pages) read. Lesson 0004 created. TOTP removed from research scope at user request.
- 2026-06-06: Documentation phase complete. docs/cryptography.md written with formal security properties and implementation invariants for all four primitives. ADRs 0005–0008 written covering Ed25519 over RSA/P-256, PBKDF2 over Argon2id, AES-256-GCM over AES-128-CBC, and bcrypt over Argon2id/scrypt.
