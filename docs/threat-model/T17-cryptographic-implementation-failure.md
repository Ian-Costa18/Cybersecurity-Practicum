---
id: T17
title: "Cryptographic Implementation Failure"
stride: ["Elevation of Privilege", "Information Disclosure"]
capability: [L4, L6]
bucket: TODO  # four-bucket evaluation classification — owned by issue #107
related: []
---

# T17 — Cryptographic Implementation Failure

| | |
|---|---|
| **Category** | Elevation of Privilege, Information Disclosure |
| **Capability** | L4 to L6 (depends on the specific failure) |
| **What the attacker gains** | Depends on which invariant is violated: |
| | **bcrypt output used as key material:** Collapse of enc_key derivation security. |
| | **PBKDF2 output stored:** Stored enc_key gives direct AES-256-GCM key; bypasses all password hashing. |
| | **Ed25519 private key not discarded after signing:** Persistent plaintext private key in memory or DB makes encryption pointless. |
| | **AES-256-GCM IV reuse:** Authentication is destroyed and XOR of ciphertexts gives full plaintext recovery. |
| | **AES-256-GCM plaintext released before tag verification:** Enables ciphertext manipulation without detection. |
| **Current defenses** | These invariants are documented explicitly in [cryptography.md](../cryptography.md) and must be upheld in implementation. The design is sound if implemented correctly. |
| **Planned defenses** | Unit tests asserting that the private key is not in memory after signing (using memory inspection or explicit zeroing). CI checks for any code path that stores `enc_key` in a persistent data structure. Code review checklist for cryptographic invariants. |
| **Operator configuration** | No runtime configuration can fix a broken implementation. Operators should: require a security code review of the cryptographic subsystem before deployment; review the cryptography.md document and confirm implementation matches specification; use cryptographic linting tools (e.g., `bandit` for Python). |
