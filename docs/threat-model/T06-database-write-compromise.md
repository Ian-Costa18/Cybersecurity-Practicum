---
id: T6
title: "Database Write Compromise"
stride: ["Tampering", "Elevation of Privilege"]
attack: TODO  # MITRE ATT&CK Enterprise technique IDs — issue #107
capability: [L5]
delta: TODO  # net-delta class: improved | inherited | introduced — #107
likelihood_baseline: TODO  # high|medium|low; N/A iff delta: introduced — #107
likelihood_residual: TODO  # high|medium|low — #107
severity_baseline: TODO  # critical|high|medium|low; N/A iff delta: introduced — #107
severity_residual: TODO  # critical|high|medium|low — #107
bucket: TODO  # four-bucket evaluation classification — owned by issue #107
related: [T4, T11, T13]
---

# T6 — Database Write Compromise

| | |
|---|---|
| **Category** | Tampering, Elevation of Privilege |
| **Capability** | L5 |
| **What the attacker gains** | Ability to modify approval records (e.g., change a "deny" to "approve," or fabricate a record). Ability to alter `is_active`, `is_admin`, or `quorum` fields. Ability to swap `encrypted_private_key` or `public_key` for a controlled value. |
| **What they cannot do** | Forge a valid Ed25519 signature over a modified approval record — `Ed25519Verify(public_key, canonical_json(approval_record), approval_signature)` will fail for any modified record. Retroactively make a fabricated approval look valid without also controlling the public key (and the public key is stored separately). |
| **Current defenses** | Ed25519 audit signatures: every approval record is signed; any modification is detectable offline without any password. Public keys are retained permanently (even after account deletion): historical verifiability cannot be destroyed by deleting the account. |
| **Planned defenses** | Append-only audit log to an external write-once store (e.g., S3 with object lock, or a separate append-only database): even a DB write attacker cannot retroactively alter the log. Database row-level integrity checks (e.g., Postgres triggers that prevent UPDATE on the approval records table). |
| **Operator configuration** | Apply the principle of least privilege: the proxy's database user should have INSERT on the approval records table but not UPDATE or DELETE. Separate the write-enabled connection (used by the proxy) from read-only connections (used by audit tooling). Enable Postgres audit extension (pgaudit) or equivalent. Back up the database regularly; verify backup integrity. |
