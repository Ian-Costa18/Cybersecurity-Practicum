---
id: T3
title: "Approver Withholding (Liveness Attack)"
stride: ["Denial of Service"]
attack: []
capability: [L7]
delta: introduced
likelihood_baseline: N/A
likelihood_residual: medium
severity_baseline: N/A
severity_residual: low
bucket: 4
related: [T2, T30]
---

# T3 — Approver Withholding (Liveness Attack)

| | |
|---|---|
| **Category** | Denial of Service |
| **Capability** | L7 — an enrolled approver's silence. The honest caveat: no adversary is required at all — benign unavailability (vacation, departure, a dead phone) triggers exactly the same failure. |
| **What the attacker gains** | By never acting — neither approving nor denying — quorum is never reached, and since approval requests have no expiration in the MVP, the request stalls indefinitely. Crucially, this is the *stealthy* form of the veto: no vote means no signature, no audit entry, no attribution. |
| **What they cannot do** | Approve the action; passive inaction only stalls the request, which **fails safe** — nothing publishes. |
| **Current defenses** | Admin can deactivate the unresponsive account and enroll a replacement approver (`tests/accounts/test_admin_portal.py::test_deactivate_revokes_session_and_blocks_login` verifies the deactivation lever). Nothing bounds the stall itself — there is no timeout. |
| **Operator configuration** | Set quorum accounting for realistic approver availability (if 1 of 5 approvers is routinely unreachable, require 3-of-5). Establish response-time expectations with approvers. Deactivate and replace approvers who have left the organization or gone unreachable. |

**This is the passive twin of [T2](T02-compromised-approver-as-denial-of-service.md)** — both
are expressions of the same invariant, the single-approver availability veto (one enrolled
identity can block quorum liveness). The two files split on audit characteristics: T2's deny
is a signed, non-repudiable, immediately visible vote; withholding leaves no trace at all,
and is therefore the expression a careful attacker prefers.

**ATT&CK mapping.** None — `attack: []` is a considered verdict, not an omission: no
Enterprise technique maps to *passive inaction*. ATT&CK catalogs adversary behaviors, and
withholding consent is the absence of one; the nearest DoS techniques (flooding, service
stop, account removal, data destruction) all describe actions this threat never takes, and
forcing one would put a false row in the ATT&CK coverage table.

**Delta.** Introduced: the approval gate is what creates the liveness dependency — in the
baseline direct-publish world, nobody's silence can block a publish, because nobody's
consent is required.

**Ratings.** Likelihood residual `medium` — a justified deviation *upward* from the L7
default (`low`): the default prices compromising or suborning an approver, but this
precondition is also met by zero-capability benign unavailability. Not `high`, because
sensible quorum sizing absorbs single-approver loss and deactivate-and-replace recovers.
Severity residual `low`: pure availability; a stalled request fails safe.

**Why bucket ④.** Same discriminator as T2: the operator cannot prevent silence, only absorb
it (quorum slack) and respond to it (deactivate + replace). With no timeout in the MVP, the
unbounded stall is an accepted limitation until
[#30](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/30) lands.

## Planned defenses

- **Approval request timeouts (auto-deny on deadline)** — [#30](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/30) — promotes ④ → ① when it lands: it fills the request lifecycle's reserved `timed_out` terminal state, and the oracle is black-box testable (drive a request past its deadline, assert the terminal state).
- **Reminders to pending approvers** — [#31](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/31) — likelihood reducer (nudges the benignly-unresponsive), no bucket change.
- **Requester-triggered nudge of silent approvers** — [#99](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/99) — likelihood reducer, no bucket change.
