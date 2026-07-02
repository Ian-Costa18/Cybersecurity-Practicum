---
id: T1
title: "Single Approver Account Compromise"
stride: ["Elevation of Privilege"]
attack: TODO  # MITRE ATT&CK Enterprise technique IDs — issue #107
capability: [L2, L3]
delta: TODO  # net-delta class: improved | inherited | introduced — #107
bucket: TODO  # four-bucket evaluation classification — owned by issue #107
related: [T25]
---

# T1 — Single Approver Account Compromise

| | |
|---|---|
| **Category** | Elevation of Privilege |
| **Capability** | L2 or L3 |
| **What the attacker gains** | The ability to submit one approval on behalf of the compromised approver. |
| **What they cannot do** | Unilaterally complete a request — quorum requires at least m approvals, so a single compromised identity is insufficient. |
| **Current defenses** | m-of-n quorum: any single compromised approver cannot unilaterally approve. Password + TOTP two-factor authentication: both factors must be compromised simultaneously (but see **T25** — absent rate limiting, the TOTP factor can be brute-forced online once the password is known, so this defense is weaker than it appears until anti-automation lands). Ed25519 signing: approvals are cryptographically tied to the authenticated identity and cannot be transferred or reused for a different request. |
| **Planned defenses** | SSO / external identity provider integration (lets organizations layer MFA from existing IdP on top of the proxy's quorum). Per-user credential wrapping (future threshold decryption would require compromising m approvers simultaneously, not just one). |
| **Operator configuration** | Set quorum thresholds with the expected breach rate in mind: 2-of-3 is weaker than 3-of-5. Keep approver rosters small (prefer a tight quorum over a large pool). Use unique, strong passwords and a hardware TOTP device where feasible. Immediately deactivate accounts at the first sign of compromise via the admin portal. |
