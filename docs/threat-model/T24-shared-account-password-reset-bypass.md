---
id: T24
title: "Shared Account Password Reset Bypass"
stride: ["Elevation of Privilege", "Information Disclosure"]
capability: [L7]
bucket: TODO  # four-bucket evaluation classification — owned by issue #107
related: []
---

# T24 — Shared Account Password Reset Bypass

| | |
|---|---|
| **Category** | Elevation of Privilege, Information Disclosure |
| **Capability** | L7 (insider approver or co-owner of the shared account) |
| **What the attacker gains** | External services (email providers, GitHub, etc.) send password reset emails to the shared account's registered email address. If one party controls or monitors that email address, they can initiate a password reset unilaterally — gaining sole control of the shared account without the knowledge or consent of the other co-owners. The proxy's quorum enforcement covers access to the shared account; it does not cover out-of-band credential recovery mechanisms on the external service. |
| **What they cannot do** | Use the proxy to approve their own unilateral action — the attack bypasses the proxy entirely by going through the external service's own recovery flow. |
| **Current defenses** | None. This is an out-of-scope architectural gap for the MVP. The proxy cannot intercept or gate external service recovery flows. |
| **Planned defenses** | Intermediary email account: route the shared account's recovery email to a dedicated inbox that is itself gated by a multi-party approval before forwarding. This would require an additional service layer outside the proxy. Deferred to future work. |
| **Operator configuration** | Until a formal mitigation is available: use a shared email account (e.g., a group inbox) for the external service's registration address, ensuring no single party has unilateral access. Document which party controls the recovery email and treat that as a trust boundary. Conduct periodic audits of the shared account's registered email and recovery methods. |
