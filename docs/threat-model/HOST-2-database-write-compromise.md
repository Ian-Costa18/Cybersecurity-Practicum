---
id: HOST-2
title: "Database Write Compromise"
stride: ["Tampering", "Elevation of Privilege"]
attack: [T1565.001]
capability: [L5]
delta: introduced
likelihood_baseline: N/A
likelihood_residual: medium
severity_baseline: N/A
severity_residual: critical
bucket: 2
related: [HOST-1, HOST-3, PUB-1, IDENT-1, HOST-4, CODE-1, DOS-2, CORE-4]
tests:
  - tests/approvals/test_votes.py::test_vote_is_ed25519_signed_and_verifies_offline
  - tests/core/test_crypto.py::test_verify_detects_a_tampered_record
  - tests/approvals/test_votes.py::test_a_reenrolled_users_old_votes_still_verify
  - tests/accounts/test_admin_portal.py::test_delete_drops_private_key_but_keeps_public_key
---

# HOST-2 — Database Write Compromise

| | |
|---|---|
| **Category** | Tampering; Elevation of Privilege |
| **Capability** | L5 — write access to the database. The read-only sibling is [HOST-3](HOST-3-database-read-compromise.md); host access that reaches the database is [HOST-1](HOST-1-proxy-host-compromise.md); the deletion counterpart (erasing the trail rather than rewriting it) is [HOST-4](HOST-4-database-repudiation-attack.md). |
| **What the attacker gains** | Write access to every table. Flip a stored Vote's decision (`deny` → `approve`) or fabricate one; alter account fields — `is_active`, `is_admin`, or a request's snapshotted `quorum`; overwrite a User's `public_key` or `encrypted_private_key` with attacker-controlled values. With full write the attacker can set a request's `quorum` to 1, insert a single approving Vote, and drive the request to `approved` — an unauthorized publish assembled entirely at the storage layer. |
| **What they cannot do** | Modify a signed Vote's *content* and still have it verify against an **unchanged** public key — Ed25519 verification fails for any altered record checked with the original key (`test_verify_detects_a_tampered_record`). Swap the held *artifact* for a different payload and have it publish — the Executor re-computes `SHA-256(held artifact)` against the approved `action_hash` immediately before publishing and refuses on mismatch (see [PUB-1](PUB-1-package-swap-between-upload-and-publication.md)), a re-check that does not trust the request's stored state. |
| **Current defenses** | Ed25519 approval signatures: every Vote is individually signed, so any modification to a record's *content* is detectable offline against the signing key, no password required (`test_vote_is_ed25519_signed_and_verifies_offline`, `test_verify_detects_a_tampered_record`). Public keys are retained permanently, even after account deletion, so historical verifiability is not destroyed by deleting an account (`tests/accounts/test_admin_portal.py::test_delete_drops_private_key_but_keeps_public_key` — deletion drops the private half, keeps the public key; `tests/approvals/test_votes.py::test_a_reenrolled_users_old_votes_still_verify` — a re-enrolled user's pre-existing votes still verify against the retained key). Execution-time hash re-check: the Executor re-verifies the artifact hash against the approved `action_hash` before publishing (PUB-1), independent of the database's stored request state. |
| **Operator configuration** | Apply least privilege to the proxy's DB role — INSERT on the approval-records table, but not UPDATE or DELETE. Separate the write connection (proxy) from read-only connections (audit tooling). Enable Postgres row-level integrity (triggers rejecting UPDATE on approval records) and pgaudit. Keep an independent record of enrollment-time public keys outside the database, so offline audit can detect key substitution until #121's signed snapshot lands. Back up regularly and verify backup integrity. |

## The gap — public-key substitution & unsigned fields

The signature defense assumes the *public key* is trustworthy, and at L5 it is not.
Verification rebuilds each record from the live `User.public_key` column, and the request
snapshot (`approvals/snapshot.py`, ADR 0008) freezes only the eligible `user_id`s — **not**
their keys. So the forging path is: generate a fresh keypair, overwrite the victim's
`public_key`, fabricate an approval record, and sign it with the new private key —
`Ed25519Verify` then passes, because it checks the attacker's record against the attacker's
key. Separately, `is_active` / `is_admin` / `quorum` carry **no** signature at all and flip
with zero cryptographic trace. Offline audit catches these only for a verifier holding an
*independent* record of the true public keys — which the MVP does not retain outside the
same database. This is why HOST-2 sits at ② and not ①: the offline-verify oracle fires for
content tampering but not for a key substitution, and it is the same gap
[CORE-4](CORE-4-authorization-repudiation.md)'s non-repudiation guarantee depends on the
operator closing.

## ATT&CK mapping

The mapping is one technique. **T1565.001 (Data Manipulation: Stored Data Manipulation):** the attacker manipulates data at rest — approval records and account/config fields in the database — to influence the system's decisions, here manufacturing an approval that never happened.

## Rating rationale

`delta: introduced` — approval records, the signing scheme, and the whole integrity story are proxy machinery; a maintainer publishing directly to PyPI has no approval database to tamper, so both baselines are N/A. Residual likelihood **medium** (the L5 default stands — a database foothold is exactly what the L3–L5 band prices in; no deviation is claimed). Residual severity **critical**: an L5 write can flip a request to `approved` or forge a verifying quorum and put an unauthorized artifact on PyPI, with post-hoc detection — the only barrier — holed by the key-substitution gap above.

## Bucket

Bucket ② (detection argued by design), **demoted from an earlier ① rating during the #107 deep-dive**. Content-level tamper-evidence is real and executably demonstrated — `test_verify_detects_a_tampered_record` fires when a record is altered under a fixed key. But the *complete* guarantee this threat needs — *a database-write attacker cannot rewrite approval history undetectably* — is **not** demonstrated: the public-key-substitution path produces a record that verifies, and the unsigned config fields leave no trace at all. This is the same evasion that holds [IDENT-1](IDENT-1-admin-account-compromise.md) at ②: the forgery is *validly signed*, so no oracle fires. It promotes to ① once #121 lands a signed creation snapshot (freezing keys + quorum), an execution-time re-check against that anchor, and a tamper-evident `AuditLog` — at which point a test can execute the key-swap forge and assert detection.

## Planned defenses

- **Tamper-evident DB records (signed quorum/key snapshot at creation, execution re-check against it, tamper-evident `AuditLog`)** — #121 — anchors the public keys and quorum the signature check depends on, closing the substitution and config-field gaps (**② → ①**).
