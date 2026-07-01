---
id: T19
title: "Insider Collusion"
stride: ["Elevation of Privilege"]
capability: [L9]
bucket: TODO  # four-bucket evaluation classification — owned by issue #107
related: []
---

# T19 — Insider Collusion

| | |
|---|---|
| **Category** | Elevation of Privilege |
| **Capability** | L9 — at least m-of-n approvers coordinate maliciously |
| **What the attacker gains** | A quorum of colluding approvers can approve any request — the proxy cannot distinguish legitimate approval from coordinated malicious approval. |
| **What they cannot do** | Deny having approved — the Ed25519 audit trail proves each approver's participation and the proxy records non-repudiable signatures. |
| **Current defenses** | Audit trail: every approval is signed; post-incident forensics can prove who approved what and when. This does not prevent collusion but enables accountability after the fact. |
| **Planned defenses** | Approval content preview (in-browser package file browser) makes it harder to approve malicious content unknowingly. Screen-share auditing would record approvers' behavior during sensitive operations. Fine-grained authorization (per-user thresholds) can require approvals from disjoint groups, making full collusion harder. Formal verification (Tamarin/ProVerif) can verify the approval protocol's non-repudiation properties. |
| **Operator configuration** | Treat this as an HR and organizational security problem, not a technical one. Select approvers from independent organizational units where possible. Set quorum thresholds high enough that collusion requires meaningful organizational coordination (e.g., 4-of-7 across multiple teams). Conduct periodic audits of the approval log for anomalies. Review all approvals for high-value actions (major releases, infrastructure changes) after the fact. |
