# PRD: Multi-Party Authorization for Package Publishing

This is the **problem-space** document for the Multi-Signature Authentication Web Proxy: who it is for, what problem it solves, what success looks like, and how that success is measured. It deliberately does **not** redefine mechanisms. The state machine, HTTP surface, crypto, and component topology are owned by the documents linked throughout; where this PRD names a behavior, it links out rather than restating it. Scope (in/out of MVP) is owned by [mvp.md](mvp.md); this PRD owns *problem, personas, user stories, and success metrics*.

> **Provenance.** The framing below was sharpened against the project's [Project Proposal](../Practicum%20Work/Progress%20Reports/Project%20Proposal.tex), [Progress Report 1](../Practicum%20Work/Progress%20Reports/Progress%20Report%201.tex), and peer feedback recorded in [Video 1 Replies](../Practicum%20Work/Videos/Video%201%20Replies.json).

---

## Problem Statement

A maintainer on a software team can publish a package to a public registry (PyPI, npm) **on their own authority alone**. Nothing requires a second human to agree that *this exact artifact* should ship. That single point of authority is the root of a recurring class of supply-chain breach: when one maintainer account is compromised — by credential theft, a poisoned CI pipeline, or a trusted-but-subverted contributor — the attacker inherits the unilateral power to push backdoored code to everyone downstream. The breach notifications repeat the same shape: *one* account, *one* unilateral publish, thousands of victims.

The deeper problem is not that accounts get stolen. It is that **the package ecosystem has no concept of multi-party authorization for a publish.** Every defense the registries have added — mandatory 2FA, Trusted Publishing (OIDC) — hardens *authentication*: it makes it harder to *prove you are* the maintainer. None of them distribute the *decision*. The two are orthogonal. Authentication hardening does nothing once the actor is authenticated, and Trusted Publishing can even *widen* the blast radius by letting a compromised CI workflow publish with no human in the loop at all. XZ Utils is the proof: that was a *trusted* maintainer, and no amount of authentication would have stopped them.

What is missing is **authorization granularity** — the ability to require that *m of n* distinct humans consent to a specific artifact before it ships. There is also a governance cost to the status quo that has nothing to do with attacks: today, *adding* a maintainer means *handing out* unilateral publish rights. A lead maintainer who wants the force-multiplier of more contributors must accept that each new contributor becomes a new single point of failure. The open-source model's greatest strength — distributed contribution — is also, under the current authorization model, its greatest security liability.

See [CONTEXT.md](../CONTEXT.md) for the domain glossary and [threat-model.md](threat-model.md) for the full adversary model.

## Solution

A **general-purpose multi-signature authentication web proxy** that requires a configurable quorum of distinct, authenticated humans to approve an action before it proceeds. The proxy interposes on the request, holds it, solicits approvals, and only releases it once **quorum** is reached over **effective votes** — with no bypass, override, or emergency shortcut (see [constraints.md](constraints.md) §3).

The proxy is **general-purpose** by design — that is the research contribution, not an accident of breadth. It demonstrates the *same approval core* driving two structurally different post-approval outcomes (see [ADR 0007](adr/0007-two-aggregate-request-model.md)):

- **Package Publishing** (`one-time`, headline use case) — the Requester submits an artifact via normal tooling, the proxy binds it by hash, solicits approvals asynchronously, and on quorum executes a single publish to PyPI. The Requester does not wait at a browser. See [use-cases/01-package-publishing.md](use-cases/01-package-publishing.md).
- **Shared Account Management** (`forward-auth`, generality proof) — the Requester waits in a browser; on quorum the proxy issues a Service Grant and forwards them to the protected backend with injected identity headers, never revealing raw credentials. See [use-cases/02-shared-account-management.md](use-cases/02-shared-account-management.md).

The solution rests on three properties:

1. **Blast-radius containment + recovery.** A compromised account yields at most one vote — below quorum. A single Approver's **deny** both halts the request *and* surfaces the compromise ("I never requested this; two of my teammates' accounts just tried to push a package I've never seen").
2. **Force-multiplier without keys.** Adding a maintainer no longer means handing out the keys to the kingdom. Contributors can be added without granting any of them unilateral publish authority.
3. **Deliberate, proportionate friction.** A publish is a rare, high-stakes event. Trading minutes-to-hours of approval latency for "no single point of compromise" is a good deal *for this operation*. The friction is the point, not a defect.

Approvers carry **no additional key-management burden** — they authenticate with a password + TOTP they already manage; the proxy owns all Ed25519 key lifecycle internally ([constraints.md](constraints.md) §2, [ADR 0001](adr/0001-credential-backed-approval.md)).

## User Stories

Grouped by cluster via inline tags; numbering is continuous so each story has a stable identifier for later issue breakdown. **Actors use the canonical roles from [CONTEXT.md](../CONTEXT.md)** — *Requester*, *Approver*, *Admin*, or *User* (when a story spans both Requester and Approver capabilities) — not the persona labels (*maintainer*, *co-owner*) used in the prose above. The same person is a Requester in one moment and an Approver in another; the role names what they are doing in *this* story.

1. **[Publishing]** As a Requester, I want to submit a package through my normal tooling (Twine) using an API Token, so that no release ships on my say-so alone and I do not have to learn a new workflow.
2. **[Publishing]** As a Requester, I want the proxy to compute and bind the artifact's hash at upload time, so that the exact bytes I submitted are the exact bytes that can later be published (Hash Binding).
3. **[Publishing]** As a Requester, I want an immediate acknowledgment that my submission is held pending approval, so that I can walk away rather than wait at a browser (`one-time` flow).
4. **[Publishing]** As an Approver, I want to be notified automatically the moment a teammate requests a publish, so that I never have to be chased out-of-band on Slack (directly addresses the sudopair friction in peer feedback).
5. **[Publishing]** As an Approver, I want a pending approval's link to be recoverable by an Admin from the Admin Portal if email delivery fails, so that a flaky mail server never strands a pending request (operator-mediated portal fallback).
6. **[Publishing]** As an Approver, I want to download and inspect the *exact* artifact I am approving, so that I am consenting to what will actually ship — not a name and version number.
7. **[Publishing]** As an Approver, I want casting or changing my vote to require fresh password + TOTP re-authentication, so that a stolen Proxy Session cannot vote in my name.
8. **[Publishing]** As an Approver, I want my vote recorded as an Ed25519-signed record tied to my identity and the Approval Request, so that it cannot be forged retroactively even by a compromised proxy.
9. **[Publishing]** As an Approver, I want to change or withdraw my vote while the request is still `pending`, so that I can react to new information; the later vote supersedes the earlier one and the earlier one is retained for audit (append-only, [ADR 0009](adr/0009-append-only-vote-model.md)).
10. **[Publishing]** As an Approver, I want a single deny to halt the request immediately regardless of how many others approved, so that I can stop a suspicious publish in its tracks.
11. **[Publishing]** As a Requester, I want the package published automatically once quorum is reached, so that approval completes the release with no further manual step.
12. **[Publishing]** As an Approver, I want publication blocked if the held artifact no longer matches the hash I approved, so that a substituted payload can never ship under my approval.
13. **[Publishing]** As a Requester or Endorsing Approver, I want to be notified of the terminal outcome (published / denied / failed), so that I know where my request landed.
14. **[Publishing]** As a Requester, I want to cancel my own still-`pending` request, so that I can retract a mistaken or superseded submission.
15. **[Publishing]** As a User, I want to view the status of requests I created and requests I may approve from a self-service User Portal, so that I can track work without an admin (the portal is organized by capability precisely because one User is both Requester and Approver).
16. **[Shared Account]** As a Requester, I want to request access to a shared account and wait, so that I only gain access after my co-owners consent.
17. **[Shared Account]** As a Requester, I want to be forwarded into the backend with an injected identity once quorum approves, so that I get interactive access without ever seeing the raw shared credentials.
18. **[Shared Account]** As an Approver, I want to approve or deny another User's access request under the same re-authenticated, signed-vote flow as publishing, so that the security model is identical across use cases.
19. **[Admin]** As an Admin, I want to create a user and have the proxy email a single-use enrollment link, so that the new user sets their own password and TOTP without me ever seeing them.
20. **[Admin]** As an Admin, I want to deactivate a user immediately (revoking their sessions and in-flight approval links), so that I can contain a compromised account fast — the system's answer to a malicious Approver, in place of any override.
21. **[Admin]** As an Admin, I want to revoke a user's API Tokens without being able to create or view them, so that administration stays out of the credential path.
22. **[Admin]** As a User, I want to hold multiple individually-revocable API Tokens (one per machine), so that compromising one context does not force me to rotate all of them.

## Implementation Decisions

These are settled here; mechanism detail lives in the linked specs.

- **One approval core, two post-approval outcomes.** The Approval Request owns the vote; it hands off to a Post-Approval Object — an **Action** (`one-time`) or a **Service Grant** (`forward-auth`) — on `approved`. The two are bidirectionally linked for audit. ([ADR 0007](adr/0007-two-aggregate-request-model.md), [request-lifecycle.md](request-lifecycle.md)).
- **Quorum is configurable per service and mandatory.** `m-of-n` is the recommended default (preserves availability while still requiring collusion to defeat); `n-of-n` is the high-security extreme. No bypass exists ([constraints.md](constraints.md) §3).
- **Quorum and the single-denial rule are computed over effective votes**, never the full history ([CONTEXT.md](../CONTEXT.md), [ADR 0009](adr/0009-append-only-vote-model.md)).
- **Credential-backed, signed approvals.** Approvers hold no extra key material; the proxy decrypts each user's Ed25519 key transiently from their password at vote time and discards it immediately ([ADR 0001](adr/0001-credential-backed-approval.md), [ADR 0002](adr/0002-asymmetric-key-approval-signing.md), [cryptography.md](cryptography.md)).
- **Hash Binding via SHA-256** computed at upload; the Executor re-verifies before publishing ([constraints.md](constraints.md) §6, [ADR 0003](adr/0003-cryptographic-primitive-selection.md)).
- **Event-driven seam.** The Proxy emits events blind; Audit and Executor are critical consumers, the Notifier is best-effort ([ADR 0005](adr/0005-decoupled-notification-system.md), [architecture.md](architecture.md)).
- **Notification is best-effort for *delivery* but guaranteed for *solicitation and reachability*.** Every Approval Request emits a notification to every eligible Approver; if SMTP fails, the link is recoverable from the **Admin Portal** and hand-distributed by an operator (operator-mediated fallback; see [notification-system.md](notification-system.md), [ADR 0005](adr/0005-decoupled-notification-system.md)). Reachability derives from the critically-written Approval Request record, independent of best-effort notification delivery. MVP is **email-only**; multi-channel (Apprise) is future work.
- **The proxy is assumed to be the sole holder of publish credentials** ([constraints.md](constraints.md) §9). For PyPI this means a **machine/service account whose sole upload token is held by the proxy** — a human-accountable owner still exists (PyPI's Terms of Service require one) but holds no usable upload token. Enforcing the proxy as the sole network and credential path is an **operator-enforced operational precondition**, not something the proxy self-enforces ([constraints.md](constraints.md) §5, §9). The long-term fix is native registry support; this project advocates for it.

## Testing Decisions

A good test exercises **external behavior at the highest seam**, never implementation details. Tests survive refactoring because they push real inputs through real interfaces and observe real outputs. Per the existing posture ([mvp.md](mvp.md) Testing): real DB, real crypto, real HTTP, real in-process SMTP; the *only* mocked boundary is outbound third-party network (PyPI).

**Seams** (confirmed):

- **Proxy HTTP surface** (primary, highest) — tests drive package submission, `POST /approve/{id}`, and `GET /auth` as real HTTP. All user stories and both adversarial demos enter here.
- **PyPI publish boundary** (the one mocked seam) — the Executor's outbound publish is faked, and *that handoff is the assertion oracle.*
- **SMTP** (real in-process server, not mocked) — notification emission and portal-fallback reachability are observed here.
- **Forward-auth `/auth` boundary** — where forward-auth latency is measured.

**The evaluation triad** (all quantitative; security strict, performance report-only):

1. **Security ① — Quorum / threshold adversary.** Reproducible adversarial demonstration at the boundary case *t = m−1*: a `3-of-3` service, two fully-compromised accounts (the harness holds their password, TOTP seed, API tokens, and a live Proxy Session) acting as malicious Requester + malicious Approver, and one honest co-owner. **Pass/fail oracle: the PyPI mock is never invoked.** The honest co-owner's later **deny** (the "2am" narrative — request frozen at 2/3 until they wake, investigate, and deny) halts the request and exposes the compromise. *Pass = zero unauthorized publishes across all trials; any single bypass = fail.* Race-free because `n-of-n` cannot reach quorum without the honest seat.
2. **Security ② — Integrity / Hash Binding.** Upload artifact X, approve `hash(X)`, mutate one byte to produce X′, run the Executor. **Pass/fail oracle: the Executor refuses at the hash check and the PyPI mock is never reached with X′.** Scoped honestly: this defends the upload→publish window against substitution and makes record tampering detectable offline — it does *not* claim resistance to a fully compromised proxy holding the live token (an accepted MVP limitation, [mvp.md](mvp.md)).
3. **Performance — forward-auth overhead.** Measure p50/p95 latency the `/auth` subrequest adds per request. **Report-only, no target threshold** (optimization is out of scope per the proposal). Declared irrelevant for the publish flow, which is human-latency-dominated by design.
4. **Usability — functional completeness + automated solicitation.** Happy-path integration tests green end-to-end for *both* use cases (submit → notify → inspect → approve to quorum → publish/forward → outcome), **plus** a notification emitted per eligible Approver, **plus** the fallback link recoverable from the Admin Portal when SMTP is down (its reachability deriving from the Approval Request record, not from notification delivery). Friction (deliberate re-auth-per-vote, wait-for-quorum) is reported qualitatively, not faked as a satisfaction score.

## Out of Scope

- **Break-glass / emergency override.** Deliberately excluded: any override one person can pull is a backdoor around quorum and reintroduces exactly the single-point-of-failure the system exists to remove. Containment of a malicious Approver is handled by fast admin deactivation, not a system-level shortcut.
- **Production-hardened deployment.** This is a proof-of-concept whose goal is to demonstrate feasibility and **advocate for native multi-party authorization in package registries** — not to ship a production tool. It will be judged as a POC, not against production-readiness.
- **Insider collusion.** If *m* Approvers collude, they can approve anything; Approvers are assumed individually trusted ([constraints.md](constraints.md) §8).
- **Proxy bypass.** The proxy cannot enforce its own network placement; operators must make it the sole path ([constraints.md](constraints.md) §5).
- **Adversarial demo for shared-account.** Forward-auth carries the *generality proof* and the *performance metric*, evaluated to happy-path completion + `/auth` latency — not its own threshold/integrity demonstration.
- **Clock/scheduler and multi-channel notification** ([#30](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/30), [#31](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/31), [#20](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/20)); **approval-link expiry** (its current absence is documented in [mvp.md](mvp.md)); **threshold signatures (MuSig2/FROST)** ([docs/research/Multi-Sig Authentication/](research/Multi-Sig%20Authentication/)). All future work.

## Further Notes

- **Threshold signatures vs. collected signatures.** Peer feedback (Joanna, Robert) suggested MuSig2/FROST to produce a single backend-compatible signature. The MVP deliberately uses *collected, individually-signed* approvals — threshold schemes (FROST/GG20/DKLS) were weighed and rejected in favor of credential-backed approval to avoid the approver key-management burden ([ADR 0001](adr/0001-credential-backed-approval.md)), and the per-approver signing mechanism is Ed25519 key pairs ([ADR 0002](adr/0002-asymmetric-key-approval-signing.md)). Threshold schemes are noted as future work, with research already on file ([docs/research/Multi-Sig Authentication/](research/Multi-Sig%20Authentication/)).
- **Transparency log.** Peer feedback (Mikhail, Thea / CHAINIAC) suggested a Sigstore-style transparency log. The MVP's signed, offline-verifiable audit trail is the first step; an external write-once log is future hardening (a planned defense under [threat-model.md](threat-model.md) T6 — Database Write Compromise).
- **The shared-account story is the better *narrative* but the weaker *security* case.** It is retained for generality and relatability; the supply-chain case carries the rigorous motivation and both adversarial demos, per reviewer guidance.
- **Presentation.** The Security ① adversarial demo is designed to double as the spine of the 15-minute presentation — a runnable, narrated walk-through of the 2am compromise scenario.
