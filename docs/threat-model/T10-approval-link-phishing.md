---
id: T10
title: "Approval Link Phishing"
stride: ["Spoofing", "Information Disclosure"]
attack: TODO  # MITRE ATT&CK Enterprise technique IDs — issue #107
capability: [L1]
delta: TODO  # net-delta class: improved | inherited | introduced — #107
bucket: TODO  # four-bucket evaluation classification — owned by issue #107
related: []
---

# T10 — Approval Link Phishing

| | |
|---|---|
| **Category** | Spoofing, Information Disclosure |
| **Capability** | L1 |
| **What the attacker gains** | An attacker who can send email to approvers can craft a fake approval link pointing to a malicious proxy that captures the approver's password and TOTP code. |
| **What they cannot do** | Use captured credentials to forge Ed25519 approval signatures without also accessing the database (the private key is encrypted at rest with the approver's password; the database is not accessible to the phishing site). |
| **Current defenses** | Authentication happens on the proxy domain; approvers can verify the domain in the browser address bar. |
| **Planned defenses** | DMARC / DKIM / SPF on the notification email domain prevents email spoofing (attacker cannot send email appearing to come from the proxy domain). HTTPS with a known-good certificate for the proxy (approvers can verify). |
| **Operator configuration** | Configure DMARC, DKIM, and SPF on the proxy's email-sending domain. Use a consistent, recognizable sender address and proxy domain. Train approvers to verify the URL before entering credentials. Consider pinning the proxy domain in approver onboarding documentation. |
