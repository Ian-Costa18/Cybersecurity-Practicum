---
id: T13
title: "Admin Account Compromise"
stride: ["Elevation of Privilege"]
capability: [L3]
bucket: TODO  # four-bucket evaluation classification — owned by issue #107
related: [T6]
---

# T13 — Admin Account Compromise

| | |
|---|---|
| **Category** | Elevation of Privilege |
| **Capability** | L3 |
| **What the attacker gains** | Full control over the approver roster: create new accounts, deactivate existing ones, reset credentials, regenerate enrollment links. An attacker with admin access can install themselves or a colluding party as a new approver, meet quorum, and approve arbitrary requests. |
| **What they cannot do** | Retroactively modify approval records (tamper-evident via Ed25519). Approve requests without going through the authentication flow — admin panel actions are scoped to account management, not approval decisions. |
| **Related — privileged config input** | The declarative-provisioning `users.yaml` ([config.md §`users.yaml`](../config.md#usersyaml-declarative-provisioning)) and `config.yaml` are **trusted operator input** equivalent to admin authority: `users.yaml` can mint admins (`is_admin: true`) and, in pre-credentialed mode, holds offline-guessable credential material. Write access to these files *is* a compromise — this is the config-file analogue of admin-account compromise, accepted as out of scope the same way ([constraints.md §10](../constraints.md)). |
| **Current defenses** | Admin authentication requires the same password + TOTP two-factor flow as approvers. Admin is a flag on a regular user account, not a separate privileged system. **Admin actions are recorded in a dedicated audit trail:** the critical audit subscriber (the `audit/` slice; see [architecture.md](../architecture.md)) writes one `AuditLog` row for every emitted event — `account.enrollment_issued`, `account.credentials_reset`, `account.deactivated`, `account.deleted` — atomically with the transition it records. |
| **Planned defenses** | **Tamper-evident admin audit:** today's `AuditLog` rows are the *unsigned* half of the trail (no per-row signature, no hash chain — see T6), so a database-write attacker (L5) could alter or delete an admin-action record undetectably; an append-only / signed admin log closes this (shares T6's external write-once-log defense). Record the acting admin's identity explicitly on each row. Admin-action notifications: alert all admins when a new approver is enrolled or when credentials are reset. Peer-approved admin actions (future): require a second admin to confirm sensitive operations. |
| **Operator configuration** | Limit the number of admin accounts to the minimum necessary. Treat admin credentials as Tier-1 secrets (hardware MFA, unique password, stored in a password manager). Immediately deactivate admin accounts when an administrator leaves the organization. Review admin action logs regularly. Do not reuse admin passwords across systems. |
