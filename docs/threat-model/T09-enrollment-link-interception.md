---
id: T9
title: "Enrollment Link Interception"
stride: ["Elevation of Privilege", "Spoofing"]
attack: TODO  # MITRE ATT&CK Enterprise technique IDs — issue #107
capability: [L1]
delta: TODO  # net-delta class: improved | inherited | introduced — #107
bucket: TODO  # four-bucket evaluation classification — owned by issue #107
related: []
---

# T9 — Enrollment Link Interception

| | |
|---|---|
| **Category** | Elevation of Privilege, Spoofing |
| **Capability** | L1 (with email access) |
| **What the attacker gains** | Enrollment links are single-use and expire in 24 hours, but if an attacker intercepts one before the legitimate approver uses it, the attacker can enroll as that approver — setting the password, TOTP secret, and effectively taking over the identity before it is established. |
| **What they cannot do** | Reuse a link that has already been consumed (single-use). Use the link after 24 hours (time-limited). |
| **Current defenses** | Single-use enrollment links: once consumed, the link is invalidated. 24-hour expiration: reduces the interception window. Admin must manually create the account — an out-of-band step that gives the real approver a chance to notice. |
| **Planned defenses** | Out-of-band enrollment confirmation: after enrollment, send a verification email to the approver or require them to confirm their identity to the admin before the account is activated. |
| **Operator configuration** | Distribute enrollment links using secure channels (end-to-end encrypted messaging where possible, not just plain email). Call the approver to confirm enrollment completion. Immediately regenerate enrollment links if an approver reports they never received one. Enable SMTP TLS to protect in-transit email. |
