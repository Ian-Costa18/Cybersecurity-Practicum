---
id: T10
title: "Phishable Approver Authentication"
stride: ["Spoofing", "Elevation of Privilege"]
attack: [T1566.002, T1557]
capability: [L1]
delta: introduced
likelihood_baseline: N/A
likelihood_residual: high
severity_baseline: N/A
severity_residual: high
bucket: 2
related: [T8, T9, T16, T21]
---

# T10 — Phishable Approver Authentication

| | |
|---|---|
| **Category** | Spoofing, Elevation of Privilege |
| **Capability** | L1 — anyone who can put a page in front of an Approver (an email carrying a link, a lookalike domain, an AiTM relay). No proxy standing required. |
| **What the attacker gains** | Approver authentication rests on **phishable, replayable factors**: a password and a TOTP code typed into whatever page is in front of the Approver. Any capture channel harvests them — a spearphished fake approval link, a lookalike domain, or a real-time adversary-in-the-middle relay that forwards the victim's keystrokes to the real proxy. A relay is the worst case: it defeats TOTP freshness entirely *and* controls the POST — the victim believes they clicked deny while the relay submits approve, or targets a different pending request. Each capture buys one genuine signed Vote, of the attacker's choosing. The proxy's own ceremony aggravates the lure: it trains Approvers to receive emailed links and type credentials into the page that opens. |
| **What they cannot do** | Turn one capture into more than one vote — each accepted TOTP is burned per `(user, time-step)` ([T8](T08-captured-credential-replay.md), tested); the vote dies with the request's terminal state. Escape notice structurally: the phished vote is signed, attributed to the victim, and visible — [T22](T22-information-disclosure-via-quorum-status-approver-visibility.md)'s endorser visibility is what lets the real Approver spot a vote they never cast, and under the append-only vote model ([ADR 0009](../adr/0009-append-only-vote-model.md)) they can **supersede** it while the request is still pending. Publish alone — one phished Approver is one seat of m; a publish requires phishing m Approvers inside one pending window. |
| **Current defenses** | In-app capture prevention: none — that is this threat's point. What the design does instead is bound the blast radius (single-use TOTP, terminal freeze, quorum) and keep the recovery path open (supersession while pending). Authentication happens on the proxy's domain over HTTPS, so a vigilant Approver *can* verify the address bar — a human control, not an architectural one. |
| **Planned defenses** | **Phishing-resistant per-vote authentication (WebAuthn/FIDO2 passkeys)** — [#129](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/129) — the only mechanism that *closes* the invariant rather than shrinking it: an origin-bound credential will not produce an assertion for the wrong origin, no matter how convincing the page, defeating both credential capture and live AiTM relays. Non-trivial: the Ed25519 signing key is wrapped under the password today; the issue records three shapes (passkey as second factor with the password retained; PRF-extension key wrapping; layered). Promotes the capture-prevention leg toward ① when it lands. |
| **Operator configuration** | Configure DMARC, DKIM, and SPF on the notification sender domain so attacker mail cannot impersonate the proxy. Use one consistent, recognizable proxy domain and sender address; pin the proxy URL in Approver onboarding (bookmark, not link-clicking). Train Approvers to treat decision mismatches ("I clicked deny") and unexpected already-voted pages as incident indicators. |

**Delta.** Introduced, resolving the strawman's ⚑ ("② vs *inherited* — phishing existed
against PyPI accounts in the baseline"): the phished ceremony — emailed links plus
password + TOTP typed into a proxy page — exists only because the proxy does; the Approver
population itself is new; and baseline PyPI actually *offers* phishing-resistant WebAuthn
while the proxy's MVP does not. This surface is ours. Both baseline ratings N/A.

**Scope.** Retitled from "Approval Link Phishing" (2026-07-02): the fake approval-link
email is one instance, not the threat. The invariant is that the authentication factors
themselves are phishable and replayable, so every capture channel — phishing page,
lookalike domain, AiTM relay — converges on the same asset. A correction from the old
body: it claimed the attacker "cannot forge Ed25519 approval signatures without database
access" — true but irrelevant. Nobody needs to forge anything: the vote POST
authenticates, derives the key, decrypts, and signs **server-side**
([approver-authentication.md](../approver-authentication.md)), so a phisher submitting
captured credentials to the real proxy receives a *genuine* signed vote. The signature
scheme authenticates the password-holder, not the human. Division of labor within the
family: [T16](T16-notification-channel-interception.md) owns the channel the lure rides,
T10 owns the capture, [T8](T08-captured-credential-replay.md) owns what captured material
is worth, and [T21](T21-browser-borne-approval-coercion.md) owns the sibling coercion that
rides the Approver's own browser instead of stealing factors.

**Why bucket ②.** Argued by design, per-leg: capture cannot be prevented in-app today, but
its impact is bounded by ①-grade tested mechanics (one vote per capture, terminal freeze —
tests enumerated in [T8](T08-captured-credential-replay.md)), an open recovery path
(supersession while pending, surfaced by [T22](T22-information-disclosure-via-quorum-status-approver-visibility.md)'s
visibility), and the quorum backstop (m captures needed for a publish). The residual — an
attacker spends one phish for one bounded, attributable, reversible-while-pending vote —
is the accepted design position until
[#129](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/129) closes the
capture leg itself.

**Ratings.** Likelihood residual `high` — the L1 default stands, with no downward
justification available: phishing is the commonest real-world initial access vector, the
proxy's notification habit builds the exact reflex the lure needs, and unlike
[T21](T21-browser-borne-approval-coercion.md) nothing architecturally forecloses the
capture. Severity residual `high`: one genuine vote per capture, the attacker's choice of
decision, is an authorization-integrity hit — but one seat of m, superseding remains
possible while pending, and it is not durable; critical stays reserved for
publish-at-will.

**ATT&CK mapping.** T1566.002 — *Phishing: Spearphishing Link*: a targeted email carries a
link to an attacker-controlled page that harvests what the victim types. T1557 —
*Adversary-in-the-Middle*: the attacker relays traffic between the victim and the real
service, reading and altering it live — the decision-swapping relay above. T1111
(*Multi-Factor Authentication Interception*) is deliberately tagged on
[T8](T08-captured-credential-replay.md), which owns the replay of what T10 captures.
