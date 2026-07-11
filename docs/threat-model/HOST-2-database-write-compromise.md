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
bucket: 1
related: [HOST-1, HOST-3, PUB-1, IDENT-1, HOST-4, CODE-1, DOS-2, CORE-4]
tests:
  - tests/approvals/test_votes.py::test_vote_is_ed25519_signed_and_verifies_offline
  - tests/core/test_crypto.py::test_verify_detects_a_tampered_record
  - tests/approvals/test_votes.py::test_a_reenrolled_users_old_votes_still_verify
  - tests/accounts/test_admin_portal.py::test_delete_drops_private_key_but_keeps_public_key
  - tests/approvals/test_integrity.py::test_execution_refuses_a_substituted_signing_key
  - tests/approvals/test_integrity.py::test_execution_freezes_on_a_weakened_quorum
  - tests/approvals/test_integrity.py::test_null_frozen_anchor_forged_quorum_is_frozen_not_published
  - tests/approvals/test_integrity.py::test_post_vote_quorum_tamper_breaks_the_vote_signature
  - tests/audit/test_audit.py::test_chain_detects_a_modified_row
  - tests/audit/test_audit.py::test_chain_detects_a_deleted_row
---

# HOST-2 — Database Write Compromise

| | |
|---|---|
| **Category** | Tampering; Elevation of Privilege |
| **Capability** | L5 — write access to the database. The read-only sibling is [HOST-3](HOST-3-database-read-compromise.md); host access that reaches the database is [HOST-1](HOST-1-proxy-host-compromise.md); the deletion counterpart (erasing the trail rather than rewriting it) is [HOST-4](HOST-4-database-repudiation-attack.md). |
| **What the attacker gains** | Write access to every table. Flip a stored Vote's decision (`deny` → `approve`) or fabricate one; alter account fields — `is_active`, `is_admin`, or a request's snapshotted `quorum`; overwrite a User's `public_key` or `encrypted_private_key` with attacker-controlled values. With full write the attacker can set a request's `quorum` to 1, insert a single approving Vote, and drive the request to `approved` — an unauthorized publish assembled entirely at the storage layer. |
| **What they cannot do** | Modify a signed Vote's *content* and still have it verify against an **unchanged** public key — Ed25519 verification fails for any altered record checked with the original key (`test_verify_detects_a_tampered_record`). Swap the held *artifact* for a different payload and have it publish — the Executor re-computes `SHA-256(held artifact)` against the approved `action_hash` immediately before publishing and refuses on mismatch (see [PUB-1](PUB-1-package-swap-between-upload-and-publication.md)), a re-check that does not trust the request's stored state. |
| **Current defenses** | Ed25519 approval signatures: every Vote is individually signed, so any modification to a record's *content* is detectable offline against the signing key, no password required (`test_vote_is_ed25519_signed_and_verifies_offline`, `test_verify_detects_a_tampered_record`). Public keys are retained permanently, even after account deletion, so historical verifiability is not destroyed by deleting an account (`tests/accounts/test_admin_portal.py::test_delete_drops_private_key_but_keeps_public_key` — deletion drops the private half, keeps the public key; `tests/approvals/test_votes.py::test_a_reenrolled_users_old_votes_still_verify` — a re-enrolled user's pre-existing votes still verify against the retained key). Execution-time hash re-check: the Executor re-verifies the artifact hash against the approved `action_hash` before publishing (PUB-1), independent of the database's stored request state. **Tamper-evident DB records (#121, [ADR 0015](../adr/0015-tamper-evident-db-records-two-trust-roots.md)):** the creation snapshot now **freezes each approver's signing key** and the vote payload **binds the snapshotted `quorum`**, and an **execution-time integrity re-check** verifies every Vote against the frozen key and compares the quorum to the live config before acting — a substituted public key, a forged Vote, or a weakened quorum freezes the request instead of publishing (`test_execution_refuses_a_substituted_signing_key`, `test_execution_freezes_on_a_weakened_quorum`, `test_post_vote_quorum_tamper_breaks_the_vote_signature`). The `AuditLog` is an **HMAC-SHA-256 hash chain** keyed by an HKDF-derived audit key off `server.secret_key`, so whole-row deletion/reordering — not just modification — is detectable at L5 (`test_chain_detects_a_modified_row`, `test_chain_detects_a_deleted_row`). |
| **Operator configuration** | Apply least privilege to the proxy's DB role — INSERT on the approval-records table, but not UPDATE or DELETE. Separate the write connection (proxy) from read-only connections (audit tooling). Enable Postgres row-level integrity (triggers rejecting UPDATE on approval records) and pgaudit. Since #121 the proxy detects key substitution in-band (the frozen creation snapshot), so an external key record is now defense-in-depth rather than the only recourse; for audit-trail integrity beyond a host compromise, mirror the hash-chained `AuditLog` to an external append-only sink (S3 Object Lock). Back up regularly and verify backup integrity. |

## The gap — public-key substitution & unsigned fields (closed by #121)

The signature defense *assumed* the public key was trustworthy, and at L5 it was not.
Verification rebuilt each record from the live `User.public_key` column, and the request
snapshot (`approvals/snapshot.py`, ADR 0008) froze only the eligible `user_id`s — **not**
their keys. So the forging path was: generate a fresh keypair, overwrite the victim's
`public_key`, fabricate an approval record, and sign it with the new private key —
`Ed25519Verify` then passed, because it checked the attacker's record against the attacker's
key. Separately, `quorum` carried **no** signature at all and flipped with zero
cryptographic trace.

**#121 ([ADR 0015](../adr/0015-tamper-evident-db-records-two-trust-roots.md)) closes this.**
The creation snapshot now freezes each eligible approver's `key_id` **and** `public_key`
(`approval_request_approvers.public_key`), and the signed vote payload binds the
snapshotted `quorum`. The **execution-time integrity re-check** (`approvals/integrity.py`,
run before any handoff in `service_types/dispatch.finalize`) verifies every Vote against
the *frozen* key — not the live column — so a substituted public key no longer makes a
forged Vote verify, and compares the snapshotted `quorum` against the config file (the
policy root of trust an L5 attacker cannot reach), so a pre-vote weakening is caught even
though each Vote signs the reduced value. On any failure the request freezes (`FROZEN`)
for manual review rather than publishing on tampered state. This is the same gap
[CORE-4](CORE-4-authorization-repudiation.md)'s non-repudiation guarantee depended on the
operator closing; the proxy now closes it in-band.

**The null-anchor corner (closed).** An approver eligible by user id but **unenrolled at
creation** — reachable via a wildcard or late-enrolling approver pool — snapshots a *null*
frozen `key_id`/`public_key`. A verify path that fell back to the live `user_keys` column
for such a Vote would reopen the very substitution gap the freeze closes: an L5 attacker
could plant a key for that approver (or ride a genuine later enrollment), forge a Vote
under it, and satisfy quorum with a Vote no honest approver cast. So a null frozen anchor
is treated as **non-votable** — `cast_vote` refuses it at the eligibility gate, and the
execution-time re-check hard-freezes any Vote carrying one, never consulting the live key
(`test_null_frozen_anchor_forged_quorum_is_frozen_not_published`; ADR 0015).

## ATT&CK mapping

The mapping is one technique. **T1565.001 (Data Manipulation: Stored Data Manipulation):** the attacker manipulates data at rest — approval records and account/config fields in the database — to influence the system's decisions, here manufacturing an approval that never happened.

## Rating rationale

`delta: introduced` — approval records, the signing scheme, and the whole integrity story are proxy machinery; a maintainer publishing directly to PyPI has no approval database to tamper, so both baselines are N/A. Residual likelihood **medium** (the L5 default stands — a database foothold is exactly what the L3–L5 band prices in; no deviation is claimed). Residual severity **critical**: an L5 write that reaches the executor could otherwise flip a request to `approved` or forge a verifying quorum and put an unauthorized artifact on PyPI — the impact if undetected is unchanged. What changed with #121 is the *detection*: the execution-time re-check now freezes rather than publishes on a substituted key or weakened quorum, and the audit chain makes row deletion detectable, so the previously-holed post-hoc detection is now demonstrated end to end.

## Bucket

Bucket ① (executably demonstrated), **promoted from ② by #121** (it had been demoted from an earlier ① during the #107 deep-dive, when the complete guarantee was not yet demonstrated). The guarantee this threat needs — *a database-write attacker cannot rewrite approval history or drive an unauthorized publish undetectably* — is now demonstrated end to end at the crypto/DB layer:

- The **key-substitution forge** is executed and detected: `test_execution_refuses_a_substituted_signing_key` overwrites the live public key and forges a Vote that verifies against it, and asserts the execution-time re-check still fails against the frozen snapshot key.
- The **quorum weakening** is executed and detected on both windows: `test_execution_freezes_on_a_weakened_quorum` (pre-vote, caught by the config re-check → `FROZEN`, no publish) and `test_post_vote_quorum_tamper_breaks_the_vote_signature` (post-vote, breaks the bound signature).
- The **audit-trail suppression** is executed and detected: `test_chain_detects_a_modified_row` and `test_chain_detects_a_deleted_row` show the HMAC chain flags both modification and whole-row deletion — the gap per-record signing could not.

The residual is the accepted host-secret limitation: an attacker holding `server.secret_key` (**HOST-1**, bucket ④) can re-derive the audit key and recompute the chain, and an external append-only sink is the only thing that beats them ([ADR 0015](../adr/0015-tamper-evident-db-records-two-trust-roots.md) threat boundary; optional operator-③ hardening, out of scope).

## Current defenses (planned defenses — now shipped)

- **Tamper-evident DB records (frozen quorum/key snapshot at creation, execution-time re-check against it, HMAC-SHA-256 hash-chained `AuditLog`)** — #121, [ADR 0015](../adr/0015-tamper-evident-db-records-two-trust-roots.md) — **shipped**, anchoring the public keys and quorum the signature check depends on and chaining the audit trail, closing the substitution and config-field gaps (**② → ①**).
