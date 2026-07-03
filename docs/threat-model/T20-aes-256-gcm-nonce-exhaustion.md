---
id: T20
title: "AES-256-GCM Nonce (IV) Exhaustion (merged into T17)"
merged_into: T17
related: [T17]
---

<!-- TOMBSTONE — merged into T17. ID retired; this file and all references are removed
     in the Phase D renumbering pass (decided 2026-07-02). Do not add content here. -->

# T20 — AES-256-GCM Nonce (IV) Exhaustion

**Merged into [T17 — Cryptographic Implementation Failure](T17-cryptographic-implementation-failure.md).** Reframed by the invariant-vs-instance pass: the real invariant is nonce *uniqueness*, whose dominant failure mode is IV reuse from an implementation bug — one row of T17's invariant table (fresh-IV generation is structural in `encrypt_private_key` and pinned by `test_invariant_4`). The 2^48/2^32 exhaustion bound this file rated is a sub-case, unreachable at MVP usage: each key encrypts exactly one object, re-encrypted only on password change. This ID is retired; the file and its remaining references are removed in the Phase D renumbering pass.
