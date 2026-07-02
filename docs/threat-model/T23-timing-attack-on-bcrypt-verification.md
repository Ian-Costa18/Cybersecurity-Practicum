---
id: T23
title: "Timing Attack on bcrypt Verification"
stride: ["Information Disclosure"]
attack: TODO  # MITRE ATT&CK Enterprise technique IDs — issue #107
capability: [L1]
delta: TODO  # net-delta class: improved | inherited | introduced — #107
likelihood_baseline: TODO  # high|medium|low; N/A iff delta: introduced — #107
likelihood_residual: TODO  # high|medium|low — #107
severity_baseline: TODO  # critical|high|medium|low; N/A iff delta: introduced — #107
severity_residual: TODO  # critical|high|medium|low — #107
bucket: TODO  # four-bucket evaluation classification — owned by issue #107
related: [T25]
---

# T23 — Timing Attack on bcrypt Verification

| | |
|---|---|
| **Category** | Information Disclosure |
| **Capability** | L1 |
| **What the attacker gains** | If the bcrypt comparison is not performed in constant time, an attacker who can make many authentication attempts and measure response times could gain partial information about the password hash. |
| **What they cannot do** | Immediately derive the password; this is a secondary oracle attack requiring many queries. |
| **Current defenses** | Standard bcrypt library implementations perform constant-time comparison of the output. Using a well-maintained library (e.g., `bcrypt` in Python) is sufficient. |
| **Planned defenses** | Explicitly use constant-time comparison (`hmac.compare_digest` in Python) when comparing any credentials. Confirm during code review. |
| **Operator configuration** | Add rate limiting on the login endpoint to prevent the volume of requests needed for a timing attack — the same in-proxy anti-automation control **T25** calls for against online credential guessing. |
