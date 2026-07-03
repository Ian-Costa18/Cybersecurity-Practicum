---
id: VOTE-2
title: "Captured-Credential Replay"
stride: ["Elevation of Privilege"]
attack: [T1111]
capability: [L1, L2]
delta: introduced
likelihood_baseline: N/A
likelihood_residual: low
severity_baseline: N/A
severity_residual: high
bucket: 1
related: [IDENT-2, IDENT-4, IDENT-3, INFO-1, IDENT-5]
tests:
  - tests/approvals/test_votes.py::test_a_reused_totp_code_is_burned_and_rejected
  - tests/approvals/test_votes.py::test_a_burned_code_cannot_vote_a_different_request
  - tests/auth/test_login.py::test_a_reused_totp_code_cannot_log_in_twice
  - tests/approvals/test_votes.py::test_voting_is_frozen_after_a_terminal_state
  - tests/approvals/test_approve.py::test_voting_on_a_closed_request_shows_the_frozen_page
  - tests/approvals/test_votes.py::test_identical_repeat_is_an_idempotent_noop
---

# VOTE-2 — Captured-Credential Replay

| | |
|---|---|
| **Category** | Elevation of Privilege |
| **Capability** | L1 — a network attacker capturing authentication material in transit; L2 — a credential attacker who already holds an Approver's password and needs only a one-shot TOTP. The replay window is precisely the L2 → vote gap. |
| **What the attacker gains** | One genuine signed Vote cast as the Approver, on one pending request — by redeeming a captured `password + TOTP` pair before the Approver does, within the TOTP acceptance window (±1 time-step, ~90 s at the default `auth.totp_window`). |
| **What they cannot do** | Reuse a redeemed TOTP to vote again — an accepted code is recorded and burned per `(user, time-step)` ([RFC 6238 §5.2](https://www.rfc-editor.org/rfc/rfc6238#section-5.2); see [approver-authentication.md](../approver-authentication.md)): `tests/approvals/test_votes.py::test_a_reused_totp_code_is_burned_and_rejected`. Spend a burned code on a different request: `tests/approvals/test_votes.py::test_a_burned_code_cannot_vote_a_different_request`. Reuse a redeemed code at login: `tests/auth/test_login.py::test_a_reused_totp_code_cannot_log_in_twice`. Vote after the request reaches any terminal state: `tests/approvals/test_votes.py::test_voting_is_frozen_after_a_terminal_state` (page-level: `tests/approvals/test_approve.py::test_voting_on_a_closed_request_shows_the_frozen_page`). Change the effective vote by repeating it: `tests/approvals/test_votes.py::test_identical_repeat_is_an_idempotent_noop`. Transplant a captured Vote onto another request — every Vote is independently signed and scoped to its `approval_request_id` ([ADR 0009](../adr/0009-append-only-vote-model.md)). |
| **Current defenses** | Single-use TOTP burn per `(user, time-step)`; fresh password + TOTP re-authentication on every vote (no session to steal on the approval flow — see [VOTE-3](VOTE-3-browser-borne-approval-coercion.md)); per-request signed, append-only Votes; terminal-state freeze; idempotent re-casts. All black-box tested (names above). |
| **Operator configuration** | Tighten `auth.totp_window` toward `0` to shrink the ±1-step replay window, at the cost of clock-drift tolerance. Serve all approval traffic over TLS so L1 capture in transit is foreclosed. Treat unexpected "already voted" or frozen-page responses reported by Approvers as potential replay indicators. |

**Delta.** Introduced: approval links and per-vote TOTP ceremonies exist only because the
proxy exists — the baseline direct-publish world has neither. Both baseline ratings N/A.

**Scope.** Retitled from "Approval Link Replay" (2026-07-02): the link was never the asset.
Approval links are deliberately not secrets — the request id is guessable by design and
security rests on per-vote authentication ([web-proxy.md](../web-proxy.md)) — so replaying
a *link* yields only the public approve page. The invariant is **captured authentication
material replayed within its validity window**: the one replayable asset is a
`password + TOTP` pair, and its window is the TOTP acceptance window. A request-level
nonce would add nothing: the approve page renders unauthenticated, so any party can fetch
a fresh nonce with the form — and the single-use TOTP burn already *is* a server-enforced
nonce per `(user, time-step)`, one generated on the Approver's device rather than handed
out by the server. Where the material comes from is [IDENT-4](IDENT-4-phishable-approver-authentication.md)
(capture) and [IDENT-3](IDENT-3-notification-channel-interception.md) (channel); VOTE-2 owns what a
captured pair is still worth.

**Why bucket ①.** Every "cannot do" claim above is a named, passing black-box test — the
burn, the cross-request burn, the login burn, the terminal freeze, and idempotent re-casts
are all executably demonstrated. The residual (a captured-but-unredeemed code inside its
~90 s window) is stated, bounded, and operator-tunable.

**Ratings.** Likelihood residual `low` is a justified downward deviation from the L1–L2
default (high): success requires the password *and* a real-time capture of a fresh TOTP
*and* winning a ~90-second race against the legitimate Approver — the tested single-use
burn forecloses everything slower. Severity residual `high`: a successful replay is one
genuine signed vote by a real Approver — an authorization-integrity hit — but it is
one-shot, one seat of m, and auditable; it is not durable publish-at-will.

**ATT&CK mapping.** T1111 — *Multi-Factor Authentication Interception*: the attacker
captures MFA codes (here, TOTP) in transit or at the point of entry and redeems them
before or instead of the legitimate user. The capture channels themselves are tagged on
[IDENT-4](IDENT-4-phishable-approver-authentication.md) (T1566.002, T1557) and
[IDENT-3](IDENT-3-notification-channel-interception.md) (T1114); VOTE-2 carries the replay itself.

## Planned defenses

- **Approval request timeouts (auto-deny on deadline)** — [#30](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/30) — bounds how long *any* captured material stays usable against a given request: once the request auto-denies, the terminal-state freeze is all a replayer reaches. No bucket change (① already); it shrinks the exposure window.
