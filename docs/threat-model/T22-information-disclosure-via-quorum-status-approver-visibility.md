---
id: T22
title: "Information Disclosure via Quorum Status & Approver Visibility"
stride: ["Information Disclosure"]
attack: [T1589]
capability: [L1]
delta: introduced
likelihood_baseline: N/A
likelihood_residual: high
severity_baseline: N/A
severity_residual: medium
bucket: 2
related: [T8, T12, T16]
---

# T22 — Information Disclosure via Quorum Status & Approver Visibility

| | |
|---|---|
| **Category** | Information Disclosure |
| **Capability** | L1 — any holder of a request's approval link views without authenticating. The two *reliable* holders sit higher: the Requester (L2 — the same request id is in their own waiting-room URL, and the approve page deliberately has no ownership guard) and the eligible Approvers (L7). Pure-L1 acquisition of a link is [T16](T16-smtp-channel-attack.md)/[T8](T08-approval-link-replay.md) territory — a UUIDv4 is not enumerable, even though the design does not treat it as secret. |
| **What the attacker gains** | The approve/deny page and its SSE stream show live quorum status and, per #22, the **named Endorsing Approvers** — Users whose effective vote is approve (e.g. "Approved by Alice & Bob — 2 of 3, waiting on 1 more"). The leak's value is targeting data: knowing who has endorsed and how many remain tells an adversary *whom to pressure* ("Alice and Bob are in; I'll lean on whoever's left"). Notably, this feed reaches the leak's most motivated consumer — the Requester of the request, who in [T12](T12-approval-request-fatigue.md)'s scenario is the attacker running the fatigue campaign. |
| **What they cannot do** | Forge or influence any vote — names cannot cast ballots. Nor learn the **silent roster**: Approvers who denied, withdrew, or have not acted are never named on the page or in any stream frame (a withdrawal drops off the endorser list, indistinguishable from never having acted), and an unknown or malformed request id yields 404. |
| **Current defenses** | The **disclosure boundary**, not the link: the spec disclaims link obscurity as a defense (`docs/web-proxy.md` §Approve/Deny Page Content: "security rests on the per-vote re-authentication, not on hiding the page") — what is defended is *what* the page reveals. Only opt-in endorsers are ever named; the boundary is executably demonstrated by `tests/approvals/test_approve.py::test_page_names_endorsers_and_counts_the_rest`, `test_withdrawn_approver_is_not_named`, `test_stream_is_link_scoped_and_names_endorsers`, and `test_unknown_request_returns_404`. |
| **Planned defenses** | None required — the disclosure is an accepted design decision (#22): endorser transparency helps Approvers coordinate, only the opt-in act of approving puts a name on the page, and the silent roster (the actual pressure targets) is structurally withheld. |
| **Operator configuration** | No action required. If endorser visibility is itself a concern for a deployment, set the expectation with Approvers at onboarding; the silent roster is never revealed regardless. |

**Delta.** Introduced: quorum status and an endorser roster exist only because the proxy
exists — the baseline direct-publish world has no vote to observe.

**Why bucket ②.** Accepted info-leak, argued by design — the method's ② definition covers
exactly this case. This is deliberately **not** bucket ④: ④'s discriminator ("the operator
cannot completely defend it, so we own it") fails here on both halves — the disclosure
*could* be removed trivially (we chose it, #22), and a real defense *is* claimed and holds
(the never-name-non-endorsers boundary). Per-leg: the boundary claims are ①-grade already —
the four tests above demonstrate them black-box; the ② names the argued judgment that the
residual inside that boundary is tolerable.

**Ratings.** Likelihood residual `high` is the L1 default, and honestly earned: the
disclosure is by design and available to every Requester on every request they create.
Severity residual `medium` on the mission ladder: a loss that does not itself move a
publish decision — endorser names cannot forge a vote; the harm is second-order targeting
data for social-engineering plays ([T12](T12-approval-request-fatigue.md),
[T10](T10-approval-link-phishing.md)). It is a real confidentiality loss, so above `low`.

**ATT&CK mapping.** T1589 — *Gather Victim Identity Information*: the adversary collects
names and roles of people worth targeting to support later operations. The endorser roster
is literally that list, kept live.
