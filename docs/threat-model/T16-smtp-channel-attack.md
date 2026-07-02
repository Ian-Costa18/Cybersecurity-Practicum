---
id: T16
title: "SMTP Channel Attack"
stride: ["Information Disclosure", "Spoofing"]
attack: TODO  # MITRE ATT&CK Enterprise technique IDs — issue #107
capability: [L1]
delta: TODO  # net-delta class: improved | inherited | introduced — #107
likelihood_baseline: TODO  # high|medium|low; N/A iff delta: introduced — #107
likelihood_residual: TODO  # high|medium|low — #107
severity_baseline: TODO  # critical|high|medium|low; N/A iff delta: introduced — #107
severity_residual: TODO  # critical|high|medium|low — #107
bucket: TODO  # four-bucket evaluation classification — owned by issue #107
related: [T9]
---

# T16 — SMTP Channel Attack

| | |
|---|---|
| **Category** | Information Disclosure, Spoofing |
| **Capability** | L1 |
| **What the attacker gains** | Enrollment links and approval links are delivered via SMTP. An attacker who can intercept or inject into the SMTP channel can steal enrollment links (leading to account takeover — see T9) or approval links (which are not secret — security comes from authentication — but interception enables social engineering). |
| **What they cannot do** | Obtain credentials or approval authority from intercepting approval links alone (authentication is still required). |
| **Current defenses** | Approval links are not sensitive secrets (security comes from the authentication step). Enrollment links are single-use and time-limited. |
| **Planned defenses** | DMARC, DKIM, SPF enforcement on outbound email. Future multi-backend notification (Apprise) would allow supplementing email with more secure channels (e.g., push notifications to a trusted device). |
| **Operator configuration** | Configure SMTP with STARTTLS or SMTPS. Use a reputable email provider with SPF/DKIM/DMARC records. Never use unencrypted SMTP. Use `fallback_to_portal: true` as a hardening measure in high-security deployments — links are shown in the admin portal rather than emailed, requiring out-of-band distribution to approvers. |
