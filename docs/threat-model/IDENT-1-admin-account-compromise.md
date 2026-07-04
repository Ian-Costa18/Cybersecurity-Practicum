---
id: IDENT-1
title: "Admin Account Compromise"
stride: ["Elevation of Privilege"]
attack: [T1078, T1098, T1136.001]
capability: [L3]
delta: introduced
likelihood_baseline: N/A
likelihood_residual: medium
severity_baseline: N/A
severity_residual: critical
bucket: 2
related: [HOST-2, IDENT-2, VOTE-1, CORE-3, HOST-4, IDENT-6]
tests:
  - tests/approvals/test_votes.py::test_a_non_eligible_user_cannot_vote
  - tests/audit/test_audit.py::test_admin_action_lands_an_audit_row
  - tests/accounts/test_admin_portal.py::test_deactivate_emits_event_and_notifies_user
  - tests/accounts/test_admin_portal.py::test_reset_emits_credentials_reset_not_enrollment_issued
---

# IDENT-1 — Admin Account Compromise

| | |
|---|---|
| **Category** | Elevation of Privilege |
| **Capability** | L3 — the admin's password + TOTP together. The credential-free route to the same position, a stolen admin *session* cookie, is [VOTE-1](VOTE-1-proxy-session-hijacking.md). |
| **What the attacker gains** | Full control of the approver roster: create and deactivate accounts, reset credentials, regenerate enrollment links. The efficient attack is quiet: enroll *m* new attacker-controlled approvers, self-submit a malicious artifact (the new request snapshots the now-poisoned roster as its eligible set), then cast *m* genuine votes and publish. Every signature verifies — the takeover rides on legitimately-issued credentials, forging nothing. |
| **What they cannot do** | Retroactively modify a signed approval record — Ed25519 verification fails for any altered Vote. Cast, change, or withdraw a Vote *from the admin panel* — admin actions are scoped to account management, and voting requires a fresh password + TOTP re-authentication ([VOTE-1](VOTE-1-proxy-session-hijacking.md)). **Inject a voter into an in-flight request** — the eligible-approver set is snapshotted at request creation (ADR 0008; `approvals/snapshot.py`), and votes are checked against that frozen set (`test_a_non_eligible_user_cannot_vote`), so an account enrolled *after* a request exists can never vote on it. The takeover only bites *forward*, on requests the attacker creates after poisoning the roster; every request already pending when the compromise begins is frozen against the new accounts. |
| **Current defenses** | Admin authentication requires the same password + TOTP two-factor flow as approvers; admin is a flag on a regular account, not a separate privileged system. **Every admin action is journaled atomically:** the critical audit subscriber writes one `AuditLog` row per emitted event (`account.enrollment_issued`, `account.credentials_reset`, `account.deactivated`, `account.deleted`) in the same transaction as the transition (`test_admin_action_lands_an_audit_row`, `tests/audit/`). **The noisy takeover path self-announces:** credential reset and deactivation email the affected user in real time (`test_deactivate_emits_event_and_notifies_user`, `test_reset_emits_credentials_reset_not_enrollment_issued`), so resetting existing approvers alarms every victim at once. Honest limit: Votes are Ed25519-signed, but `AuditLog` rows are the **unsigned** half of the trail — no per-row signature or hash chain (see [HOST-2](HOST-2-database-write-compromise.md)) — so a database-write attacker could scrub the enrollment trail, and the rows do not record *which* admin acted. |
| **Operator configuration** | Keep admin accounts to the minimum. Treat admin credentials as Tier-1 secrets (hardware MFA, unique password, password manager). Deactivate admin accounts the moment an administrator leaves. **Review the admin action log regularly** — on the quiet enroll-forward path, that review is the detection. Do not reuse admin passwords across systems. |

## Related — privileged config input

The declarative-provisioning `users.yaml` ([config.md §`users.yaml`](../config.md#usersyaml-declarative-provisioning))
and `config.yaml` are the config-file analog of this threat: **trusted operator input**
equivalent to admin authority ([constraints.md §10](../constraints.md)). `users.yaml` can
mint admins (`is_admin: true`) and, in pre-credentialed mode, holds offline-guessable
credential material, so write access to it *is* an admin compromise reached through the
filesystem rather than the login. That surface is cataloged in its own right as
[IDENT-6](IDENT-6-declarative-provisioning-rogue-admin-injection.md) (the write-poison and
offline-crack legs); IDENT-1 links it here because the position it grants is identical to a
compromised admin account.

## ATT&CK mapping

The mapping is three techniques. **T1078 (Valid Accounts):** the attacker logs in with legitimately-issued stolen admin credentials, indistinguishable from the real admin. **T1098 (Account Manipulation):** they abuse admin authority to alter existing accounts — credential resets, deactivations — to gain or retain access. **T1136.001 (Create Account: Local Account):** they mint brand-new approver accounts under their control to meet quorum.

## Rating rationale

`delta: introduced` — the Admin Portal and the approver roster are proxy machinery with no baseline analog; a maintainer publishing directly to PyPI has no admin surface to compromise. Both baseline ratings are N/A. Residual likelihood is **medium** (the L3 default): the attack needs one specific admin's two authentication factors together, with no mechanical deviation up or down. Residual severity is **critical**: roster control manufactures a genuine quorum, and the result is an unauthorized artifact on PyPI, repeatable until someone notices — the top of the mission ladder.

## Bucket

Bucket ② (detection argued by design). *A roster takeover cannot be silent* is a designed-in property with tested components: the reset path alarms every victim in real time, and every path leaves a mandatory, timestamped causal chain in the `AuditLog`. It is **②, not ①**, because the quiet enroll-forward path fires no notification — no victim exists — so its only trace is journal rows that reach a human on log or roster review, and those rows are today unsigned and do not name the acting admin. It promotes to ① once admin-action notifications land (#125): a test can then execute the enroll-forward takeover and assert the alarm fires.

## Planned defenses

- **Admin-action notifications** — #125 — convert the quiet enroll-forward path from journal-only to alarmed (**② → ①**): the promotion test executes the takeover and asserts the alarm fires. (Split in the 2026-07-04 grill: **step-up re-auth** moved to #135 — it closes [VOTE-1](VOTE-1-proxy-session-hijacking.md)'s hijacked-admin-session escalation; **peer-approved admin actions** are future work.)
- **Tamper-evident `AuditLog` (per-row signature / hash chain or external append-only sink, plus acting-admin identity on each row)** — #121 — protects the evidence trail the bucket-② argument rests on; no bucket change on its own.
