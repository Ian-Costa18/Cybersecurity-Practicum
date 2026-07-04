---
id: CORE-4
title: "Authorization Repudiation"
stride: ["Repudiation"]
attack: []
capability: [L7]
delta: improved
likelihood_baseline: high
likelihood_residual: low
severity_baseline: medium
severity_residual: low
bucket: 2
related: [CORE-3, HOST-2, HOST-4]
tests:
  - tests/approvals/test_votes.py::test_vote_is_ed25519_signed_and_verifies_offline
---

# CORE-4 — Authorization Repudiation

| | |
|---|---|
| **Category** | Repudiation |
| **Capability** | L7 — a legitimate, enrolled approver (or whoever holds their credentials) who authorized a publish and later denies having done so. No forgery or system compromise required; the attack is a *claim*. |
| **What the attacker gains** | At the direct-publish baseline, nothing binds a publish to a person: whoever held the token published, and "that wasn't me / someone used my account" is unfalsifiable — there is no signed record of who authorized what. Under the proxy, the same denial is what this threat rates: an approver disowns their vote after the fact, hoping the record cannot prove authorship. |
| **What they cannot do** | Deny a vote they cast and have the record agree with them: every Vote is an Ed25519 signature over the approval record, made with a key derived only through the approver's own password ceremony, and it verifies offline against their retained public key with no password and no trust in the proxy process (`tests/approvals/test_votes.py::test_vote_is_ed25519_signed_and_verifies_offline`). The plausible denial the baseline hands out for free becomes a claim against a cryptographic record. |
| **Current defenses** | Per-vote Ed25519 signatures, offline-verifiable (tested, above); public keys retained permanently — even after account deletion — so historical votes stay verifiable; the append-only vote model ([ADR 0009](../adr/0009-append-only-vote-model.md)) keeps the full signed sequence, so a supersession cannot silently rewrite history. |
| **Operator configuration** | Keep an independent record of enrollment-time public keys outside the database ([HOST-2](HOST-2-database-write-compromise.md)'s operator row) — it is what lets the signature answer a repudiation dispute even against a database-write insider. Mirror the audit trail to an external append-only store ([HOST-4](HOST-4-database-repudiation-attack.md)) so "the record was deleted" cannot substitute for "I never voted." |

## Delta story

The missing improved half of Repudiation: the catalog carries the *introduced* side —
[HOST-4](HOST-4-database-repudiation-attack.md), where an attacker suppresses the trail the
proxy created — and this entry records what that trail buys. Baseline likelihood **high**:
denial is free where no evidence exists, and a shared or borrowed credential makes it
routine. Baseline severity **medium** on the mission ladder's evidence-loss rung —
accountability failure moves no publish decision, but it dissolves responsibility for one
that happened. Residual likelihood **low**: a repudiation attempt now has to defeat an
offline-verifiable signature attributable to the approver's own key ceremony. Residual
severity **low**: the failed denial costs the mission nothing — the record stands and
attributes. Baseline strictly worse on both axes → passes the improved gate.

Division of labor: [CORE-3](CORE-3-insider-collusion.md) measures likelihood-of-collusion
and cites signing as *deterrence*; CORE-4 owns the accountability property itself.
[HOST-2](HOST-2-database-write-compromise.md) owns the forgery direction (key substitution
at L5); [HOST-4](HOST-4-database-repudiation-attack.md) owns the deletion direction. Both
are exactly the caveats that cap this entry's bucket.

## Bucket

Bucket ② (argued by design). The core mechanism is ①-grade — offline verification is
executably demonstrated — but the *end-to-end* non-repudiation guarantee is argued, not
demonstrated: it holds only against an adversary below L5, because a database writer can
substitute the public key ([HOST-2](HOST-2-database-write-compromise.md)'s gap) and a
deleted record proves nothing ([HOST-4](HOST-4-database-repudiation-attack.md)). With the
operator row's independent key record and external trail, the argument closes; without
them, it degrades gracefully to tamper-evidence.

## ATT&CK mapping

`attack: []` — no Enterprise technique maps to passive repudiation: ATT&CK models
adversary *operations*, and disowning a past authorization is a claim, not a technique
(the same no-slot position as [DOS-4](DOS-4-approver-withholding.md)'s withholding and
[CRYPTO-1](CRYPTO-1-cryptographic-implementation-failure.md)'s implementation limits). The
active techniques adjacent to it — indicator removal, data manipulation — belong to
[HOST-4](HOST-4-database-repudiation-attack.md) and [HOST-2](HOST-2-database-write-compromise.md).
