---
id: T21
title: "CSRF on the Approve/Deny Form"
stride: ["Elevation of Privilege"]
attack: TODO  # MITRE ATT&CK Enterprise technique IDs — issue #107
capability: [L1]
delta: TODO  # net-delta class: improved | inherited | introduced — #107
likelihood_baseline: TODO  # high|medium|low; N/A iff delta: introduced — #107
likelihood_residual: TODO  # high|medium|low — #107
severity_baseline: TODO  # critical|high|medium|low; N/A iff delta: introduced — #107
severity_residual: TODO  # critical|high|medium|low — #107
bucket: TODO  # four-bucket evaluation classification — owned by issue #107
related: []
---

# T21 — CSRF on the Approve/Deny Form

| | |
|---|---|
| **Category** | Elevation of Privilege |
| **Capability** | L1 (web attacker who can get approver to visit a malicious page) |
| **What the attacker gains** | If the approve/deny form does not include a CSRF token, an attacker who can trick an authenticated approver (during their active approval window) into visiting a malicious page could submit a forged approval or denial. |
| **What they cannot do** | Trigger this attack outside the narrow window between the approver authenticating and the form being submitted. Stateless approver sessions limit the exposure to a single per-request authentication event. |
| **Current defenses** | Stateless per-approval sessions significantly reduce CSRF risk: the approver has no persistent session cookie that a CSRF attack could leverage across requests. |
| **Planned defenses** | CSRF tokens on the approve/deny form submission (standard practice; should be included in the web UI implementation). SameSite cookie attribute on any session cookies issued during the approval flow. |
| **Operator configuration** | Ensure the proxy is deployed on its own domain and not embedded in an iframe. Review the web framework's CSRF protection documentation and verify it is enabled. |
