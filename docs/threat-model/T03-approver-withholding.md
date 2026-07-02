---
id: T3
title: "Approver Withholding (Liveness Attack)"
stride: ["Denial of Service"]
attack: TODO  # MITRE ATT&CK Enterprise technique IDs — issue #107
capability: [L7]
delta: TODO  # net-delta class: improved | inherited | introduced — #107
bucket: TODO  # four-bucket evaluation classification — owned by issue #107
related: []
---

# T3 — Approver Withholding (Liveness Attack)

| | |
|---|---|
| **Category** | Denial of Service |
| **Capability** | L7 (or simply: approver is unresponsive) |
| **What the attacker gains** | By never acting (neither approving nor denying), the attacker prevents quorum from being reached indefinitely. Approval requests have no expiration in the MVP. |
| **What they cannot do** | Approve the action; passive inaction only stalls the request. |
| **Current defenses** | Admin can deactivate the inactive account and enroll a replacement approver. |
| **Planned defenses** | Approval timeouts: requests automatically denied after a configurable deadline. Reminder notifications sent to non-responding approvers at intervals. |
| **Operator configuration** | Set quorum accounting for realistic approver availability (e.g., if 1 of 5 approvers is routinely unreachable, require only 3-of-5). Establish SLAs with approvers (expected response time). Use the admin portal to deactivate accounts of approvers who have left the organization or become unreachable. |
