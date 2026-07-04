# Tamper-Evident DB Records: Two Trust Roots (No Server Signing Key on Approvals)

## Status
Accepted

## Context

The proxy's security story rests on records stored in a single database, and its
strongest adversary is [HOST-2](../threat-model/HOST-2-database-write-compromise.md):
an attacker with **write** access to that database but **not** the host. Two distinct
bodies of evidence live there, and both had integrity gaps (#121, found during the
#107 threat-model hardening pass):

1. **Approval records (Votes) and the policy they satisfy.** Each Vote is
   Ed25519-signed by its approver ([ADR 0002](0002-asymmetric-key-approval-signing.md)),
   but verification rebuilt the record from the **live** `user_keys.public_key` column
   and the **live** `approval_requests.quorum` — both writable at L5. So an attacker
   could overwrite a victim's public key and forge a Vote that verifies against the
   planted key, or lower a request's stored `quorum` and drive it to `approved` with
   fewer genuine approvals than policy demanded. Every signature verified; nothing
   detected the tamper (HOST-2 §"The gap"; ATT&CK T1556.009 / T1565.001).

2. **The audit trail (`AuditLog`).** The non-vote half of the trail — `request.*`,
   `action.*`, `grant.*`, `account.*` — carried **no** per-row signature and **no**
   chain. Independent per-record evidence (had it existed) detects *modification* but
   never *deletion or reordering* of whole rows, so an L5 attacker could scrub the
   `account.enrollment_issued` traces that [IDENT-1](../threat-model/IDENT-1-admin-account-compromise.md)'s
   "roster takeover cannot be silent" argument depends on, and disable the trail that
   HOST-4 (audit-trail suppression) is about.

A tempting single fix — give the server its own signing key and sign everything with
it — was rejected at the approval layer: it would make the **host** a signing
authority over approvals, so a host compromise ([HOST-1](../threat-model/HOST-1-proxy-host-compromise.md))
could manufacture approvals wholesale. Approval integrity must **not** rest on a
server-held key ([ADR 0010](0010-requesters-authenticated-not-signing.md): the proxy
authenticates requesters, it does not sign for them). But the audit trail has *no
approver in the loop* to sign its system-emitted rows, so it *needs* a server-side
mechanism. The two surfaces therefore resolve to **two different trust roots**, and
this ADR records both and why they differ.

## Decision

**Bind policy integrity into the approver signatures (no server key), and give the
audit trail a host-keyed hash chain — two trust roots for two surfaces.**

### Trust root 1 — approval/policy integrity: the approver signatures (no server key)

- **Freeze the signing keys at creation.** The creation snapshot (ADR 0008) now
  records, per eligible approver, the `key_id` and `public_key` active at creation
  (`approval_request_approvers.public_key`). The execution-time re-check verifies each
  Vote against this **frozen** key, not the live column. Keys are append-only and
  immutable, so an existing `key_id` whose live public half no longer matches the
  frozen one is an unambiguous **substitution** (a *legitimate* reset mints a **new**
  key row and leaves the frozen one intact, so it is not flagged).
- **Bind the quorum into every Vote.** The signed vote payload
  ([approver-authentication.md](../approver-authentication.md) §Signing the Approval
  Record) now includes the snapshotted `quorum`. Tampering the stored quorum after any
  Vote is cast breaks that Vote's signature — the same `Ed25519Verify` oracle.
- **Re-check against the policy root of trust at execution.** Before the Executor acts
  on an `approved` request, it compares the snapshotted `quorum` against the live
  service config, whose YAML file an L5 attacker cannot reach (that is HOST-1). This
  closes the *pre-vote* window, where a weakened quorum is set before any Vote exists
  so every Vote consistently signs the reduced value. On any failure — substituted
  key, non-verifying Vote, or divergent quorum — the request is **frozen** (`FROZEN`)
  for manual review rather than published on tampered state.

None of this introduces a server signing key over approvals: the authority remains the
approvers' keys plus the config file.

### Trust root 2 — audit-trail integrity: a host-keyed HMAC hash chain

- **Chain the `AuditLog`.** Each row commits to its predecessor with an HMAC-SHA-256
  link (`entry_hash` over the row's content and the previous row's `entry_hash`;
  `prev_hash` stores that predecessor digest). The chain makes whole-row
  deletion/reordering detectable, not just per-record modification, and is verified
  offline by `audit.integrity.verify_audit_chain`.
- **Key it off the host secret, domain-separated.** The chain key is HKDF-SHA-256
  derived from the existing `server.secret_key` with a dedicated `info` label, so it is
  **not** the same key the session cookie MAC already uses on the raw secret. One
  operator secret, two non-interchangeable keys.
- **Attribute the actor.** Admin-action rows record the acting admin's `actor_id`, the
  attribution IDENT-1's detection argument wants.

## Rationale

- **Why the asymmetry is correct, not an oversight.** The two surfaces have different
  adversary models. Approvals must survive a *host* compromise as far as possible, so
  their root of trust is the approvers' offline keys plus the operator's config file —
  never a host-held key. The audit trail has no approver to sign for it, so the best
  available root against a *database-write* attacker is a key the host holds; that is
  strictly weaker (it does not survive HOST-1) but strictly better than the nothing it
  replaces.
- **Reuse over novelty.** HMAC-SHA-256, HKDF, and Ed25519 are all already in
  `core/crypto.py` under [ADR 0003](0003-cryptographic-primitive-selection.md); this
  adds no new primitive and keeps the operator managing exactly one secret.
- **Freeze-for-review over refuse.** A divergent snapshot may be a genuine mid-flight
  config change (ADR 0008 has operators drain pending requests across a policy change),
  not an attack. Freezing for manual review is the conservative response that neither
  publishes on tampered state nor silently drops a legitimate request.

## Threat boundary (the accepted limitation)

The hash chain defends **HOST-2** (database write, no host secret): such an attacker
cannot recompute a valid `entry_hash`, so any modification or deletion is detected. It
does **not** defend **HOST-1** (host compromise): an attacker holding `server.secret_key`
can re-derive the audit key and rewrite the whole chain. HOST-1 is an accepted
limitation, bucket ④. The only mechanism that beats a host attacker is an **external
append-only sink** (e.g. S3 Object Lock) that even a full host compromise cannot
retroactively alter; that is noted as **optional operator-③ hardening and is out of
scope** here.

## Implications

- Schema (migration `0015`): `audit_log` gains `prev_hash`, `entry_hash`, `actor_id`;
  `approval_request_approvers` gains `key_id`, `public_key`. All nullable — the writer
  populates them and no backfill is done (the trail starts empty; in-flight requests
  drain under the old rule).
- The audit subscriber must be wired with the derived audit key (app factory and the
  provisioning CLI both do so); the offline verifier re-derives it from the same secret.
- The signed vote payload format changed (quorum added). The MVP versions no payloads
  and starts each trail/vote log empty, so no format-version migration is required.
- Docs updated in lockstep: [cryptography.md](../cryptography.md) §Audit Trail
  Integrity, [request-lifecycle.md](../request-lifecycle.md) §Execution-time integrity
  re-check, [source-layout.md](../source-layout.md) (the two `integrity` modules), and
  HOST-2's threat file (promoted ② → ①).

## Trade-offs Accepted

- **Audit integrity does not survive HOST-1.** Accepted and stated above; the external
  sink is the out-of-scope answer.
- **A legitimate mid-flight config change freezes the request.** Rare, and the safe
  failure mode; operators drain pending requests across a policy change anyway (ADR 0008).
- **One more secret-derived key to reason about.** Mitigated by HKDF domain separation
  from the session MAC and by deriving from the *same* `server.secret_key` the operator
  already manages.
