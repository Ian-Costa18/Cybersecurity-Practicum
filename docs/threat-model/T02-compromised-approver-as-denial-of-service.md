---
id: T2
title: "Compromised Approver as Denial-of-Service (Deny Button)"
stride: ["Denial of Service"]
capability: [L3, L7]
bucket: TODO  # four-bucket evaluation classification — owned by issue #107
related: [T27]
---

# T2 — Compromised Approver as Denial-of-Service (Deny Button)

| | |
|---|---|
| **Category** | Denial of Service |
| **Capability** | L3 or L7 |
| **What the attacker gains** | The ability to halt any request by clicking Deny, regardless of how many other approvers have already approved. A single approver can block quorum indefinitely. Under the append-only vote model ([ADR 0009](../adr/0009-append-only-vote-model.md)) the same insider can also *flap* — repeatedly approve-then-withdraw while the request is `pending` — to spam endorser-outcome notifications (see T27) and game quorum timing; each flip, however, costs a fresh password + TOTP re-authentication and is individually signed and audited, so the tactic is self-limiting and non-repudiable. |
| **What they cannot do** | Approve the action unilaterally; the deny only blocks, it does not redirect the action. |
| **Current defenses** | Admin portal account deactivation: setting `is_active = false` immediately invalidates the compromised approver's ability to act on any in-flight or future requests. |
| **Planned defenses** | Approval timeouts with automatic denial of timed-out requests prevent an attacker from simply withholding action rather than clicking Deny. Rate limiting on denials and anomaly detection ("Alice is denying everything") for operator alerting. |
| **Operator configuration** | Maintain a responsive admin contact who can deactivate accounts quickly. Set quorum such that losing one approver to deactivation does not block legitimate requests (e.g., 2-of-4 still works with one account deactivated). Write an incident runbook for "approver account deactivation." Document who holds admin credentials and how to reach them 24/7. |
