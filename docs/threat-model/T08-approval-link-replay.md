---
id: T8
title: "Approval Link Replay"
stride: ["Elevation of Privilege"]
attack: TODO  # MITRE ATT&CK Enterprise technique IDs — issue #107
capability: [L1, L2]
delta: TODO  # net-delta class: improved | inherited | introduced — #107
likelihood_baseline: TODO  # high|medium|low; N/A iff delta: introduced — #107
likelihood_residual: TODO  # high|medium|low — #107
severity_baseline: TODO  # critical|high|medium|low; N/A iff delta: introduced — #107
severity_residual: TODO  # critical|high|medium|low — #107
bucket: TODO  # four-bucket evaluation classification — owned by issue #107
related: []
---

# T8 — Approval Link Replay

| | |
|---|---|
| **Category** | Elevation of Privilege |
| **Capability** | L1, L2 |
| **What the attacker gains** | If an approval link can be reused, an attacker who obtains a previously used link could attempt to authenticate with a compromised approver account and cast or alter a Vote on a request. |
| **What they cannot do** | Replay a captured Vote as a stand-alone artifact — every Vote is independently signed and scoped to its `approval_request_id`, so it cannot be transplanted onto a different request or re-submitted without re-authenticating. Act on a closed request — Votes freeze at any terminal state (`approved`/`denied`/`cancelled`/`timed_out`), so a replayed link cannot change the outcome of a request that is no longer `pending`. Change a Vote without the approver — casting or superseding a Vote requires a fresh password + TOTP re-authentication every time. Note that under the append-only vote model (see [ADR 0009](../adr/0009-append-only-vote-model.md)) a Vote is no longer immutable: while a request is `pending`, the authenticated Approver may legitimately supersede their own prior Vote (flip the decision or withdraw). This is an intentional supersession by the real Approver, not a replay. |
| **Current defenses** | Append-only signed votes ([ADR 0009](../adr/0009-append-only-vote-model.md)): each Vote carries its `approval_request_id` and is independently signed, so a captured Vote cannot be replayed against another request. Fresh authentication on every link visit: casting or changing a Vote requires re-authenticating (password + TOTP) each time; obtaining the link alone is insufficient. **Single-use TOTP ([RFC 6238 §5.2](https://www.rfc-editor.org/rfc/rfc6238#section-5.2)):** an accepted TOTP code is recorded and burned per `(user, time-step)`, so a captured `password + TOTP` pair cannot be replayed once that code has been redeemed (see [approver-authentication.md](../approver-authentication.md)). Idempotent re-casts: an identical repeated decision is a no-op and does not alter the effective vote. Terminal-state freeze: once a request leaves `pending`, no further Vote (original or replayed) is accepted. |
| **Planned defenses** | Approval link expiration (currently absent; links do not expire): adds a time-based barrier for links that were captured but not used. **Residual exposure:** even with single-use TOTP, a captured-but-not-yet-redeemed code stays replayable within its ±1-step (~90 s) acceptance window (`auth.totp_window`) — this is why T8 is rated **partially**, not fully, mitigated below. Tightening `totp_window` toward `0` shrinks the window at the cost of clock-drift tolerance. |
| **Operator configuration** | Distribute approval links over TLS-protected channels only. If SMTP is used, ensure it is configured with STARTTLS or SMTPS. Treat any unexpected "already approved" or "link not found" responses as potential indicators of link interception. |
