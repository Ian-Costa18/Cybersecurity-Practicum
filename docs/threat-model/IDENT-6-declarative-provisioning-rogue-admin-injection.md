---
id: IDENT-6
title: "Declarative-Provisioning Rogue-Admin Injection"
stride: ["Tampering", "Information Disclosure", "Elevation of Privilege"]
attack: [T1552.001, T1136.001, T1110.002]
capability: [L6, external]
delta: introduced
likelihood_baseline: N/A
likelihood_residual: low
severity_baseline: N/A
severity_residual: critical
bucket: 3
related: [IDENT-1, HOST-1, HOST-3, CODE-2, HOST-5]
---

# IDENT-6 — Declarative-Provisioning Rogue-Admin Injection

| | |
|---|---|
| **Category** | Tampering (poison the file), Information Disclosure (leak the bundle), Elevation of Privilege (hold the minted admin) |
| **Capability** | L6 for the write leg — write access to `/config` on the host or control of the deploy pipeline that assembles it; `external` for the read leg — an off-boundary copy of the file (a git commit, a config backup, a world-readable mount) with no live foothold at all. |
| **What the attacker gains** | [`users.yaml`](../config.md#usersyaml-declarative-provisioning) is a credential-bearing file the proxy reconciles **create-if-absent on every boot** (`msig-provision`, [account-management.md](../account-management.md) §Declarative provisioning), able to mint admins (`is_admin: true`) and, in pre-credentialed Mode B, create a user **born enrolled** from an offline `hash-credentials` bundle. Two legs: **(a) write/poison** — add a Mode-B admin entry under a new username with attacker-controlled credentials, and the next boot mints a legitimate admin, forging nothing; from that seat the takeover is [IDENT-1](IDENT-1-admin-account-compromise.md)'s quiet path (enroll *m* attacker approvers → publish-at-will). The poison is **durable in the file**: create-if-absent means DB-side cleanup alone is not remediation — any fresh database (rebuild, restore from a clean backup, a second deployment sharing the config) re-mints the rogue admin until the file itself is cleaned. **(b) read/offline-crack** — the file's own documented trust posture ([config.md](../config.md) §Trust posture) is offline-guessable credential material: a Mode-B bundle carries the bcrypt hash *and* the password-wrapped signing key together, so a leaked copy is attackable offline like `/etc/shadow`, and a cracked bundle yields a complete working login (password, TOTP secret, signing key). |
| **What they cannot do** | Touch existing accounts through the file — reconciliation is create-if-absent by `username`, with no field mutation, no resurrection, and no deletion ([config.md](../config.md) §Reconciliation), so a poisoned entry cannot flip an existing user to admin or re-issue anyone's enrollment link. Escape the audit surface entirely — the minted account and everything it does thereafter are ordinary recorded account activity, so [IDENT-1](IDENT-1-admin-account-compromise.md)'s detection story (admin-action log review) applies from the first action. |
| **Current defenses** | In-app: none, by design — [constraints.md §10](../constraints.md) declares the config and users files **trusted, privileged operator input**: anyone who can write them already controls the proxy. This entry exists so that acceptance is a cataloged, rated surface rather than an unexamined one (considered ≠ forgotten). The all-or-none Mode-B validation (a partial credential bundle fails at boot) is the one mechanical guard, and it is integrity validation, not an authentication of the file's author. |
| **Operator configuration** | Restrict filesystem access to `/config` to the proxy and the deploy role. Keep the real `users.yaml` out of version control (commit only `users.example.yaml` with dummies) and out of world-readable mounts and backups. Use `$ENV{}` substitution for `totp_secret` so the one plaintext field never sits in the file. Use strong Mode-B passwords — the bundle is offline-attackable by design. Treat the deploy pipeline that writes `/config` as privileged infrastructure on par with the host itself. |

## Rating rationale

`delta: introduced` — by failure to cancel: the baseline has no boot-time provisioning file
able to mint identities that govern a publish. The nearest baseline analogs are
credential-in-file leaks (a `.pypirc`, a CI secret), but those leak a *token* — the
at-rest-credential story measured at [HOST-5](HOST-5-configured-service-credential-exposure-at-rest.md)
and [CORE-2](CORE-2-api-token-theft.md) — not the ability to *create a privileged identity*
inside the authorization system. No equivalent, no cancellation; both baselines N/A.

Residual likelihood **low**: the write leg is L6 (the L6–L9 default is low — an attacker
with `/config` write access is already at the host-compromise rung), and the read leg,
`external`, is justified low per the contract's no-default rule: it requires an
off-boundary leak of a file the operator row explicitly git-ignores and access-restricts.
Residual severity **critical**: a rogue admin enrolls *m* attacker-controlled approvers and
publishes at will with no independent barrier remaining — parity with
[IDENT-1](IDENT-1-admin-account-compromise.md), whose position this attack buys.

## Bucket

Bucket ③ (operator-enforced). Every mitigation is deployment hygiene the proxy cannot
compel — file ACLs, git-ignoring, `$ENV{}` substitution, password strength, pipeline trust.
That is the honest consequence of constraint #10: the proxy treats the file as trusted
input, so nothing in-app stands between a writable `/config` and a minted admin. No planned
in-app defense exists (a signed or attested users file would be one, but it is a deliberate
non-commitment — mentioned here, not planned).

## ATT&CK mapping

**T1552.001 (Unsecured Credentials: Credentials in Files):** the Mode-B bundle is
credential material at rest in a file — the read leg's exact fit. **T1136.001 (Create
Account: Local Account):** the write leg's outcome — the attacker causes the system to
create a local privileged account under their control. **T1110.002 (Brute Force: Password
Cracking):** offline cracking of a leaked bundle's bcrypt hash, which also unwraps the
signing key — the same offline half [HOST-3](HOST-3-database-read-compromise.md) owns for
the database copy of the same material.
