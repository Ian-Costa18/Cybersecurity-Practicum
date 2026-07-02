---
id: T7
title: "TOTP Secret Exposure in Database"
stride: ["Information Disclosure"]
attack: TODO  # MITRE ATT&CK Enterprise technique IDs — issue #107
capability: [L4]
delta: TODO  # net-delta class: improved | inherited | introduced — #107
likelihood_baseline: TODO  # high|medium|low; N/A iff delta: introduced — #107
likelihood_residual: TODO  # high|medium|low — #107
severity_baseline: TODO  # critical|high|medium|low; N/A iff delta: introduced — #107
severity_residual: TODO  # critical|high|medium|low — #107
bucket: TODO  # four-bucket evaluation classification — owned by issue #107
related: [T5]
---

# T7 — TOTP Secret Exposure in Database

| | |
|---|---|
| **Category** | Information Disclosure |
| **Capability** | L4 |
| **What the attacker gains** | TOTP secrets are currently stored as plaintext in the database. An attacker who reads the database gets all TOTP secrets, allowing them to generate valid TOTP codes for any approver at any time. Combined with a cracked bcrypt hash (see T5), this yields complete account takeover of all accounts with a single database read — no network interaction required. |
| **What they cannot do** | This does not directly give them the private key (still needs password crack for PBKDF2 derivation), but the TOTP factor is completely eliminated as a defense. |
| **Current defenses** | None. This is an unaddressed gap in the current design. |
| **Planned defenses** | Encrypt TOTP secrets at rest using AES-256-GCM with a key derived from a system-level secret (not the user's password, since the proxy needs to verify TOTP without the user being present). The encryption key should be stored in environment variables or an external secrets manager, not in the database. |
| **Operator configuration** | Until TOTP encryption is implemented: treat database access controls as the only barrier. Restrict database access aggressively. Alert immediately on any unexpected database reads. Consider storing the database on an encrypted volume to raise the cost of offline extraction. |
