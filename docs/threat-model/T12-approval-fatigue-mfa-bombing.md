---
id: T12
title: "Approval Fatigue / MFA Bombing"
stride: ["Social Engineering", "Elevation of Privilege"]
capability: [L2]
bucket: TODO  # four-bucket evaluation classification — owned by issue #107
related: [T25, T27]
---

# T12 — Approval Fatigue / MFA Bombing

| | |
|---|---|
| **Category** | Social Engineering, Elevation of Privilege |
| **Capability** | L2 (compromised requester account) or any authenticated requester |
| **What the attacker gains** | An attacker floods approvers with repeated approval requests — exploiting the MVP's immediate-retry-after-denial (the "Request again" button, [web-proxy.md](../web-proxy.md)) — so that approvers, worn down by the volume, eventually click "Approve" without careful review. This is the MFA push-bombing pattern applied to multi-party approval: the goal is a **wrongful approval**, not unavailability. (The *resource/notification-saturation* side of the same flood — buried requests, retry-traffic amplification, storage exhaustion — is its own threat, **T27**.) |
| **What they cannot do** | Force approvers to approve; approvers must still authenticate (password + TOTP) and explicitly click Approve on each request — the flood pressures judgment, it does not bypass the vote. |
| **Current defenses** | None. This is a documented MVP limitation. The shared rate-limit control (**T25**) is the technical half of the fix; the human half is approver discipline. |
| **Planned defenses** | Cooldown period after denial before the same requester can reopen a request for the same service. Rate limiting per requester per service per time window on the request-creation endpoint (the same in-proxy limiter as T25/T27). Approval-fatigue detection: alert approvers or admins when a burst of requests arrives from a single source. |
| **Operator configuration** | Ensure approvers understand they should **never approve a request they did not initiate themselves** — include this in approver onboarding. Until rate limiting is implemented: monitor approval-request volume and investigate bursts; deactivate requester accounts showing anomalous behavior. |
