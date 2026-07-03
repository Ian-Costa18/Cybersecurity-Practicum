---
id: T28
title: "Database Repudiation Attack"
stride: ["Repudiation"]
attack: [T1070]
capability: [L5]
delta: introduced
likelihood_baseline: N/A
likelihood_residual: medium
severity_baseline: N/A
severity_residual: medium
bucket: 3
related: [T6, T13, T30]
---

<!-- Provisional ID (X6): T28–T30 are subject to the Phase D renumbering pass. -->

# T28 — Database Repudiation Attack

| | |
|---|---|
| **Category** | Repudiation |
| **Capability** | L5 — write/delete access to the database. The content-tampering sibling at the same rung is [T6](T06-database-write-compromise.md) (rewrite a record); the availability twin is [T30](T30-destructive-availability-attack.md) (destroy the machinery). |
| **What the attacker gains** | The ability to **delete or truncate whole approval and audit records**, erasing the evidence that an action occurred. The audit trail is per-record Ed25519-signed but **not hash-chained** ([cryptography.md §Audit Trail Integrity](../cryptography.md)), so signatures detect *modification* of a record but not *removal or reordering* of whole records — a deletion leaves no gap that verification can see. An attacker who forced or colluded in an unauthorized publish can then remove the Votes and `AuditLog` rows, and the event becomes deniable: no trustworthy record survives to attribute it. |
| **What they cannot do** | Alter a *retained* record's content undetectably — that is [T6](T06-database-write-compromise.md)'s territory (Ed25519 catches content edits). Publish, approve, or forge through this threat — it erases the past, it does not manufacture a future action. Break the system's ability to operate — deleting operational data to *halt* publishing is availability loss ([T30](T30-destructive-availability-attack.md)), not repudiation. |
| **Current defenses** | None in-proxy detects whole-record deletion today: per-record signatures protect content, not existence, and the MVP trail has no hash chain linking records. The only barriers are operator-enforced — a least-privilege database role and an external append-only sink (below). |
| **Operator configuration** | Give the proxy's DB role INSERT on the approval/audit tables but **not** DELETE or UPDATE. Mirror the audit trail to an external append-only store (WORM object storage, an append-only log service) out of reach of the database capability rungs — the defense family shared with [T30](T30-destructive-availability-attack.md). Keep offsite backups so a deletion can at least be *reconstructed* after the fact. Alert on any DELETE against the records tables. |

**Boundaries.** vs. [T6](T06-database-write-compromise.md): T6 owns *you cannot rewrite a Vote's content undetectably* (Ed25519 catches content edits); T28 owns *you can delete the whole Vote and nothing notices* (per-record signatures do not detect removal — the trail has no hash chain). Same capability rung, opposite operations. vs. [T30](T30-destructive-availability-attack.md): deleting records to *break the system's ability to function* is availability loss (T30); deleting records to *hide that an action happened* is repudiation (here). If one wipe does both, the availability consequence is rated under T30 and the accountability consequence here. vs. [T13](T13-admin-account-compromise.md): the quiet enroll-forward takeover leaves only unsigned `AuditLog` rows as its trace — T28 is the act of erasing exactly those rows to complete the cover-up.

The mapping is one technique. **T1070 (Indicator Removal):** the adversary deletes or manipulates artifacts — here approval and audit records — to remove evidence of their activity, which is the whole of what this threat narrates. T1562.001 (*Impair Defenses: Disable or Modify Tools*) was considered and dropped: disabling the audit-*writing* path means modifying proxy code, which is beyond a database-write capability (L5) — that position is [T4](T04-proxy-host-compromise.md)'s, not this threat's.

## Rating rationale

`delta: introduced` — the audit trail is a proxy construct; a maintainer publishing directly to PyPI has no approval history to suppress, so both baselines are N/A. Residual likelihood **medium** (the L5 default stands — deletion needs write access to the backing database, which is exactly what the L3–L5 band prices in; no deviation is claimed). Residual severity **medium**: the consequence is **evidence loss** — no unauthorized publish, no credential disclosure, only the destruction of accountability for actions that may have already happened — which is the "evidence loss" rung of the mission ladder, below the integrity/authorization tiers.

## Bucket

Bucket ③ (operator-enforced). The only thing standing between an L5 attacker and a clean deletion today is operator configuration: a least-privilege DB role (INSERT, no DELETE) and an external append-only store. Nothing in the proxy detects whole-record removal, because the trail is signed per-record but not chained. It promotes to **② (detection argued by design)** once #121 lands the tamper-evident `AuditLog` — a hash chain (each record committing to its predecessor) or an external append-only sink with actor identity makes deletion and reordering detectable, an argued property backed by the chaining construction though without a single end-to-end break-detection oracle.

## Planned defenses

- **Tamper-evident `AuditLog` (hash chain or external append-only sink, plus acting-actor identity on each row)** — #121 — makes whole-record deletion and reordering detectable rather than silent (**③ → ②**). The same issue's signed-snapshot leg serves [T6](T06-database-write-compromise.md).
