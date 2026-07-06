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
bucket: 1
related: [HOST-2, IDENT-2, VOTE-1, CORE-3, HOST-4, IDENT-6]
tests:
  - tests/approvals/test_votes.py::test_a_non_eligible_user_cannot_vote
  - tests/audit/test_audit.py::test_admin_action_lands_an_audit_row
  - tests/accounts/test_admin_portal.py::test_deactivate_emits_event_and_notifies_user
  - tests/accounts/test_admin_portal.py::test_reset_emits_credentials_reset_not_enrollment_issued
  - tests/accounts/test_admin_portal.py::test_quiet_enroll_forward_takeover_alarms_other_admins
---

# IDENT-1 — Admin Account Compromise

| | |
|---|---|
| **Category** | Elevation of Privilege |
| **Capability** | L3 — the admin's password + TOTP together. The credential-free route to the same position, a stolen admin *session* cookie, is [VOTE-1](VOTE-1-proxy-session-hijacking.md). |
| **What the attacker gains** | Full control of the approver roster: create and deactivate accounts, reset credentials, regenerate enrollment links. The efficient attack is quiet: enroll *m* new attacker-controlled approvers, self-submit a malicious artifact (the new request snapshots the now-poisoned roster as its eligible set), then cast *m* genuine votes and publish. Every signature verifies — the takeover rides on legitimately-issued credentials, forging nothing. |
| **What they cannot do** | Retroactively modify a signed approval record — Ed25519 verification fails for any altered Vote. Cast, change, or withdraw a Vote *from the admin panel* — admin actions are scoped to account management, and voting requires a fresh password + TOTP re-authentication ([VOTE-1](VOTE-1-proxy-session-hijacking.md)). **Inject a voter into an in-flight request** — the eligible-approver set is snapshotted at request creation (ADR 0008; `approvals/snapshot.py`), and votes are checked against that frozen set (`test_a_non_eligible_user_cannot_vote`), so an account enrolled *after* a request exists can never vote on it. The takeover only bites *forward*, on requests the attacker creates after poisoning the roster; every request already pending when the compromise begins is frozen against the new accounts. |
| **Current defenses** | Admin authentication requires the same password + TOTP two-factor flow as approvers; admin is a flag on a regular account, not a separate privileged system. **Every admin action is journaled atomically:** the critical audit subscriber writes one `AuditLog` row per emitted event (`account.enrollment_issued`, `account.credentials_reset`, `account.groups_changed`, `account.deactivated`, `account.deleted`) in the same transaction as the transition (`test_admin_action_lands_an_audit_row`, `tests/audit/`), each row now naming the acting admin (`actor_id`, #121). **The quiet enroll-forward path is now alarmed (#125):** every enrollment-affecting roster mutation — issue/regenerate an enrollment link, reset credentials, edit an approver's groups/contact — fans an admin-action alarm to **all active admins**, so enrolling attacker-controlled approvers reaches an admin who did not perform it (or, on a hijacked admin session, the session's real owner — [VOTE-1](VOTE-1-proxy-session-hijacking.md)). The takeover can no longer proceed with no notification: an adversarial test executes the enroll-forward takeover and asserts the alarm fires (`test_quiet_enroll_forward_takeover_alarms_other_admins`). **The noisy path also self-announces:** credential reset and deactivation additionally email the affected user in real time (`test_deactivate_emits_event_and_notifies_user`, `test_reset_emits_credentials_reset_not_enrollment_issued`). Honest limits: the alarm is a best-effort notification over the same email channel the roster governs ([IDENT-3](IDENT-3-notification-channel-interception.md)), and where an admin is the *sole* administrator a rogue holder receives their own alarm — detection then rests on the audit trail. `AuditLog` rows are chained but remain the **unsigned** half of the trail (per-Vote Ed25519 is the signed half; see [HOST-2](HOST-2-database-write-compromise.md)). |
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

Bucket ① (detection demonstrated). *A roster takeover cannot be silent* is now a tested property on the takeover's own path: the quiet enroll-forward move — the one that has no victim to notify — fires an admin-action alarm to every active admin, and an adversarial test executes the enroll-forward takeover and asserts an admin who did not act is alarmed via the real notification channel (`test_quiet_enroll_forward_takeover_alarms_other_admins`, #125). This closes the gap that held it at ②: previously the quiet path fired no notification and its only trace was journal rows read on review. Alongside the alarm, every path still leaves a mandatory, timestamped, admin-attributed causal chain in the `AuditLog` (`test_admin_action_lands_an_audit_row`), and the noisy reset/deactivate paths additionally alarm the victim. The bucket rests on a best-effort email channel (the residual limits noted under Current defenses), but detection is now demonstrated, not merely argued.

## Planned defenses

- **Step-up re-authentication on admin actions** — #135, **landed** — the six sensitive admin actions (create · edit · reset · regenerate-link · deactivate · delete) now require a fresh password + single-use TOTP on top of the admin session, closing [VOTE-1](VOTE-1-proxy-session-hijacking.md)'s hijacked-admin-session escalation (carried the VOTE-1 `critical → high` residual-severity edit). Split from #125 in the 2026-07-04 grill.
- **Peer-approved admin actions** — future work — a second admin confirms sensitive roster operations (quorum-for-the-roster), the end-state tier.
- **Tamper-evident `AuditLog`** — #121, landed — per-row HMAC hash chain plus acting-admin identity on each row; protects the evidence trail the detection argument rests on. No bucket change on its own.
