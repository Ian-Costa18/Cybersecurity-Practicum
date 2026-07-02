---
id: T30
title: "Destructive Availability Attack"
stride: ["Denial of Service"]
attack: [T1485, T1531, T1490]
capability: [L5, L6, L8]
delta: introduced
likelihood_baseline: N/A
likelihood_residual: medium
severity_baseline: N/A
severity_residual: low
bucket: 3
related: [T2, T3, T4, T5, T6, T27, T28]
---

<!-- Provisional ID (X6): T28–T30 are subject to the Phase D renumbering pass. -->

# T30 — Destructive Availability Attack

| | |
|---|---|
| **Category** | Denial of Service |
| **Capability** | L5, L6, or L8 — named per leg: L5 (database write) reaches all three legs directly and is the cheapest rung that can — wipe the tables, flip every approver's `is_active`. L6 (proxy host) adds destruction of co-located backups. L8 (admin) performs the lockout leg through the legitimate portal. |
| **What the attacker gains** | The proxy's capability is *lost*, never *subverted*: no publishes happen at all until the operator rebuilds. Three legs with one shape: (1) **State destruction** — drop or wipe the database: requests, votes, key material, approver roster. (2) **Backup destruction** — destroy recovery material so the loss sticks. (3) **Mass approver lockout** — deactivate or corrupt every approver account at once, making quorum *unreachable*: [T3](T03-approver-withholding.md)'s withholding forced on the entire roster simultaneously. |
| **What they cannot do** | Publish, approve, or forge. **This threat fails safe**: no variant of destruction can put an unauthorized artifact on PyPI — the worst case is an outage plus re-enrollment toil. Destroying *records to hide a publish that already happened* is not this threat either — that is audit-trail suppression (T28), the integrity twin. |
| **Current defenses** | Nothing in the system defends against this, and nothing could: backups, restore, and re-enrollment are deployment concerns no in-proxy mechanism can replace. This is ③ by *nature*, not by deferral. |
| **Operator configuration** | Regular database backups with at least one copy offsite and write-once (WORM) or otherwise out of reach of the capability rungs above — the defense family shared with audit-trail suppression (T28). A tested restore runbook. Database ACLs restricting write/DDL access to the proxy's own role. An approver re-enrollment procedure for the lockout leg. |

**Boundaries.** vs. [T2](T02-compromised-approver-as-denial-of-service.md)/[T3](T03-approver-withholding.md):
those are *vote-level* denial — one identity exercising (or withholding) its veto inside the
workflow; T30 removes the machinery itself. vs.
[T27](T27-request-resource-flooding.md): exhaustion by flooding is reversible — throttle or
revoke and the system recovers; destruction is not. vs.
[T4](T04-proxy-host-compromise.md)/[T5](T05-database-read-compromise.md)/[T6](T06-database-write-compromise.md):
those catalog what the same capability rungs can do to confidentiality and integrity; T30 is
the availability consequence of those rungs. vs. **T28** (audit-trail suppression): T30 owns
"capability lost," T28 owns "history erased" — if a wipe also destroys the record of past
actions, that consequence is rated under T28, not here.

**Delta.** Introduced: the proxy's database, key material, and approver roster are surface
that exists only because the proxy does — the baseline has no quorum to exhaust and no proxy
state to destroy. (Destroying the *package* itself is PyPI's availability problem in both
worlds and net-cancels out of scope.)

**Ratings.** Likelihood residual `medium` — the cheapest listed rung is L5 and the default
applies; no deviation claimed. Severity residual `low`: the mission (prevent unauthorized
publishes) is never compromised, only paused — pure availability, fails safe, with the
audit-history caveat carved out to T28 above.

**Why bucket ③.** Operator-enforced by nature: backups, offsite/WORM copies, restore
runbooks, ACLs, and re-enrollment are the entire defense, and all of them live outside the
proxy. No promotion path is claimed — there is no in-proxy oracle for "the operator kept
good backups."

**ATT&CK mapping.** One technique per leg, each a real mechanism. T1485 — *Data
Destruction*: the adversary destroys data and systems to interrupt operations (the
state-destruction leg). T1531 — *Account Access Removal*: the adversary deletes,
deactivates, or locks legitimate accounts to deny access (the mass-lockout leg). T1490 —
*Inhibit System Recovery*: the adversary destroys backups and recovery material so the
victim cannot restore (the backup leg).
