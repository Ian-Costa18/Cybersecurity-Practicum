# Evaluation Plan

How the Multi-Party Authorization proxy is evaluated: what "success" means, how each claim is measured, and which artifacts the evaluation produces. This document is the source of truth for evaluation; the Progress Report 3 *Evaluation* section is a distillation that links here, and this plan becomes the backbone of the final report's Evaluation chapter.

> **Scope.** The evaluation covers the **package-publishing** use case only. "General-purpose multi-party authorization" remains the project's design property and future direction, but is **not evaluated** this term (see [#109](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/109)). Problem/solution framing and the [mvp-prd.md](mvp-prd.md) generality claims will be reconciled with this scope under that issue.

---

## What "evaluation" means here

A practicum solution must answer three questions. They are ordered here **by importance to the reader** — what someone who hears "I built a solution to a security problem" most wants to know, in order:

1. **It solves a problem.** No existing control enforces m-of-n human authorization of a registry publish bound to the exact artifact; the proxy fills that gap, and closing it buys a concrete security improvement. Shown by a **comparative positioning matrix**, **real-incident case studies**, and the industry-adoption trend that reinforces the gap.
2. **It works.** The system performs the package-publishing workflow end-to-end and holds up at the adversarial boundary case. Shown by a **two-act runnable demo** (the spine of the 15-minute video), with the integration test suite as backing evidence.
3. **It adds only a bounded set of new threats.** Relative to publishing without the proxy, the proxy introduces only an enumerated, mostly-defended set of new threats. Shown by the **net-delta threat classification** and the **executable adversarial test suite**.

**On the ordering.** The sort key is *importance to the reader*, not — as an earlier draft had it — how much of each is the author's own work. That deliberately fronts the most citation-heavy section (the gap analysis). For a proof-of-concept whose thesis is *"industry should adopt m-of-n publish authorization as a native capability,"* the load-bearing contribution is not the code but the identification of a gap no existing control fills and the conceptualization of a solution to it. Each section below names its own contribution, so the engineering that backs "it works" keeps full credit despite sitting second.

**The security claim is a net delta, not an absolute.** Rather than claim the proxy "resists everything in its threat model" — a hardening claim a proof-of-concept cannot fully back — the evaluation measures the *change* the proxy makes relative to the **direct-publish baseline**: an author publishing to PyPI with an API token plus account 2FA, no proxy. Every threat in the [threat model](threat-model/00-overview.md) is classified by its relationship to that baseline:

- **Improved** — a pre-existing threat the proxy measurably reduces (a single stolen credential can no longer publish unilaterally). *This is the value proposition; it is evidence for §1.*
- **Inherited** — a pre-existing threat the proxy leaves unchanged because it operates on a different layer (phishing an individual approver, brute-forcing one account's TOTP). The proxy is an **authorization** layer, not an **authentication** one; these remain the job of the controls that sit beside it. *Reported once as a scope statement in §3; never counted as a proxy weakness.*
- **Introduced** — attack surface that exists **only because the proxy exists** (the proxy host, its session and credential store, its approval links and notification channel). *This is the net-delta cost; it is the subject of §3.*

The honest headline: **the proxy closes a large pre-existing gap (Improved) at the price of a bounded, enumerated new attack surface (Introduced), while explicitly not addressing an orthogonal authentication layer (Inherited).** The attacks in the threat model are additionally aligned to **MITRE ATT&CK** techniques so that "pre-existing" is grounded in a recognized taxonomy rather than asserted; the per-threat ATT&CK and `delta` assignments are owned by [#107](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/107). Each threat additionally carries **anchored likelihood and severity ratings** in baseline/residual pairs; the rating method is defined in §3 (*Risk rating — likelihood and severity*).

Two axes are deliberately **excluded** — performance and human-subjects usability studies — each with a stated justification (see *Excluded axes*). Excluding them honestly, with reasons, is itself part of the evaluation, not an omission.

This plan does **not** depend on any other person using the system. Every result is either an automated test outcome or a cited analytical argument. No survey, interview, or satisfaction score is fabricated to stand in for real users.

---

## 1. It solves a problem — the gap, and what closing it buys

**Claim:** existing controls either harden *authentication/origin* or gate an *internal pipeline*; **none** enforces m-of-n human authorization of the *public registry publish*, bound to the exact artifact. The proxy fills that gap — and closing it yields a concrete, demonstrable security improvement.

**Contribution.** This section is the project's primary original contribution: not the implementation, but the identification and articulation of a gap no existing control fills, and a working conceptualization of how to fill it.

The argument runs in three moves: the gap is **real**, it is **costly to leave open**, and it is **live industry territory that remains unfilled** at the registry-publish point.

### Move 1 — the gap is real (comparative positioning matrix)

**Method — argued and cited, not empirically tested.** Each cell is a claim backed by a **citation to the control's own documented behavior**; no cell is an uncited assertion. Standing up live instances of each competing control is out of scope for the timeline, and several scenarios (trusted-insider) cannot be "tested" anyway. The discipline rule — *every cell cites a source* — is what converts this section from opinion into evidence.

**Attack scenarios (columns).**
- **A — Stolen single credential** — one account's password/token is compromised (e.g. the 2025 Shai-Hulud npm worm, which harvested maintainer tokens and automatically republished poisoned versions).
- **B — Trusted insider (XZ)** — a legitimate, authenticated maintainer acts maliciously (the XZ Utils backdoor, CVE-2024-3094).
- **C — Compromised CI pipeline** — a subverted build/publish pipeline ships a poisoned artifact that is nonetheless *authentically built and attested* (provenance proves origin, not behavior).
- **D — Direct publish to registry** — a maintainer publishes straight to PyPI/npm, bypassing the repo and CI.

**Controls (rows) and verdicts** (`✓` stops it · `~` partially / conditionally · `✗` does not):

| Control | A | B | C | D | Axis it operates on |
|---|:--:|:--:|:--:|:--:|---|
| Mandatory 2FA / MFA | ~ | ✗ | ✗ | ✗ | Authentication |
| Trusted Publishing (OIDC) | ✓ | ✗ | ✗ | ~ | Authentication (scoped, short-lived credential) |
| Build provenance (Sigstore / SLSA / PEP 740) | ✗ | ✗ | ✗ | ✗ | Origin/integrity attestation (detective, not preventive) |
| GitHub required reviews + branch protection / commit signing | ✓ | ~ | ✗ | ✗ | Code-repo **merge** decision |
| CI/CD deployment-approval gates (GH environments / GitLab) | ✓ | ~ | ~ | ✗ | Pipeline deploy gate (platform-bound) |
| Artifact-repo staging/promotion (Artifactory / Nexus) | ✓ | ~ | ~ | ✗ | Internal promotion gate (product-bound) |
| **The proxy** | **✓** | **✓** | **✓** | **✓\*** | **Authorization of the registry publish, artifact-bound** |

**Reading the matrix.** Rows 1–3 live on the authentication/origin axes and never touch *authorization* — provenance is the sharpest proof: an attestation certifies *where* a package was built and *from which commit*, **not what its code does**, so a poisoned-but-authentically-built artifact still verifies (column C, `✗`). Rows 4–6 *do* distribute the decision (hence `~` on B), but they gate the **repo merge** or an **internal pipeline**, are bound to that platform, and are **bypassed entirely by a direct registry publish** (column D, all `✗`). Only the proxy covers all four, because it holds the sole publish credential and binds the exact artifact by hash.

**\*Honest caveats on the proxy's column D and beyond.** Column D holds **only under the operator-enforced precondition** that the proxy is the sole holder of the publish token and the sole network path ([constraints.md](constraints.md) §5, §9) — the proxy cannot self-enforce its own placement (threat **PUB-2**, bucket ③). And a colluding quorum of ≥ *m* approvers (threat **CORE-3**, bucket ④) defeats any of these controls by definition. The matrix claims authorization coverage, not omnipotence.

**Complementary, not competing.** Automated **malware/dependency scanning** (Socket/Snyk-style) is *detection*, not authorization — it catches *known*-bad signatures, but the XZ backdoor evaded automated detection entirely and was found only by chance (a maintainer investigating an SSH latency anomaly), which is exactly why a human quorum is needed; feeding scan verdicts to approvers is captured as future work ([#108](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/108)).

### Move 2 — the gap is costly to leave open, and closing it pays off (case studies)

Two real incidents, chosen for their **different** honest outcomes, show what the gap costs and exactly how far the proxy's authorization layer goes — no further. Each follows a fixed structure: **what happened → which controls were in place and why they failed → what the proxy actually does (*resists* / *raises the bar* / *does not help*) → threat-model mapping.**

**Case study A — Shai-Hulud npm worm (2025): the proxy *resists* it. [flagship]**
- *What happened.* A self-replicating worm harvested maintainer tokens and automatically republished poisoned versions of the packages those maintainers owned.
- *Why existing controls failed.* Publisher-side 2FA, trusted publishing, and provenance did not stop a token-holding attacker from republishing under a legitimate identity.
- *What the proxy does.* **Resists.** A single stolen credential cannot reach quorum; honest co-owners see an unexpected, artifact-bound publish request and deny it. This is threat **CORE-1** (single-credential compromise) in the **Improved** class — the baseline publishes on one stolen token; the proxy does not.
- This is the proxy's flagship result, dramatized live by the 2 a.m.-deny demo (§2, Act 2).

**Case study B — XZ Utils backdoor, CVE-2024-3094 (2024): the proxy *raises the bar*; it does not guarantee prevention.**
- *What happened.* A legitimate maintainer spent years building trust, then shipped an obfuscated backdoor engineered to survive human review (hidden in build scripts and test fixtures).
- *Why existing controls failed.* The maintainer was authenticated and authorized; provenance would have attested the malicious build as authentic.
- *What the proxy does.* **Raises the bar — honestly, not immunity.** Quorum converts a unilateral insider action into one that must either deceive the m−1 other humans inspecting this exact high-stakes publish, or collude with them. If the reviewers cannot spot the backdoor, quorum still approves it. This straddles **Improved** (a lone insider can no longer act unilaterally) and the **accepted limitation** of colluding quorum (**CORE-3**, bucket ④). Presenting it as a partial result — not a win — is the point.

**Scope boundary (not a case study).** The proxy is producer-side. Consumer-side attacks such as **dependency confusion** (Birsan, 2021) — where the attacker publishes *their own* package and the victim's build resolves it over the intended internal one — fall **entirely outside** its boundary: there is no victim publish event to authorize, so the proxy has nothing to gate. Such attacks map to *none* of the proxy's threats (Improved / Inherited / Introduced) because they occur outside the system boundary. Naming this preempts the "what about dependency confusion?" question and fixes the edge of the proxy's remit; it does not warrant a full case study, because the proxy does nothing there.

### Move 3 — the gap is live industry territory, still unfilled at the registry-publish point

**AWS added a "multi-party approval" capability in 2025** — but scoped to *AWS's own resource operations* (currently AWS Backup logically air-gapped vaults, gated through IAM / Organizations), **not** a general-purpose proxy. It is evidence that m-of-n human approval *as a primitive* is being adopted by major platforms — and that every such adoption is **siloed inside one platform's control plane** (AWS for AWS operations, GitHub for its deploys, Artifactory for its repos). None gates an arbitrary registry publish. That pattern *reinforces* the gap this project targets rather than filling it: the primitive is proven and being adopted, but a general-purpose, registry-agnostic enforcement point does not exist. (How the proxy generalizes past package-publishing is future work, discussed in the report, not evaluated here — see Scope.)

---

## 2. It works — functional correctness

**Claim:** the proxy implements the complete package-publishing workflow end-to-end, it can be carried out by a real operator, and it holds up at the adversarial boundary case.

**Contribution.** This section is where the engineering is evidenced: a working system, exercised end-to-end by an automated suite. It sits second by reader-importance, but it is the largest build effort in the project.

**Primary artifact — a two-act runnable demo.** Correctness is demonstrated by a **guided, runnable walk-through** in two acts that map directly onto the video:

- **Act 1 — the normal publish workflow:** *submit via normal tooling → proxy binds by hash → approvers notified → approver inspects the exact artifact → re-authenticated signed votes → quorum reached → publish → audit record + terminal notification*, plus the **deny path** (a single deny halts the request).
- **Act 2 — the 2 a.m. compromise (flagship):** a reproducible adversarial demo at the boundary case **t = m−1** — a **3-of-3** publishing service, **two fully-compromised accounts** (the harness holds their passwords, TOTP seeds, API tokens, and a live Proxy Session) acting as malicious Requester + malicious Approver, and **one honest co-owner**. The request freezes at 2/3 until the honest co-owner wakes, investigates, and **denies** — halting the publish and surfacing the compromise. **Pass = zero unauthorized publishes across all trials; any single bypass = fail.** The scenario is race-free because `n-of-n` cannot reach quorum without the honest seat. Act 2 is the live proof of §1's *Improved* benefit and is designed to double as the spine of the final presentation.

**Backing rigor — the integration test suite.** The demo is not a one-off screen recording: every step is also exercised by an **end-to-end integration test** driven through the real Proxy HTTP surface (real DB, real crypto, real HTTP, real in-process SMTP; only the outbound PyPI publish is mocked). The tests make "it works" **reproducible and regression-proof**; the demo makes it **legible**.

**Metric — the workflow completes, itemized.** The headline is binary: *the complete package-publishing workflow executes end-to-end successfully*, **itemized as a capability checklist** — each capability the demo exercises, backed by a passing test:

| Capability exercised by the demo | Backing test |
|---|---|
| Submit via real tooling (Twine + API token) | ✓ |
| Hash-bind the artifact at upload | ✓ |
| Notify every eligible approver (+ Admin-Portal fallback when SMTP is down) | ✓ |
| Approver downloads and inspects the exact artifact | ✓ |
| Vote requires fresh password + TOTP; vote is Ed25519-signed | ✓ |
| Quorum reached over effective votes → automatic publish | ✓ |
| Single deny halts the request immediately | ✓ |
| Requester cancels own pending request | ✓ |
| Terminal outcome notified; signed audit record written | ✓ |

The [mvp-prd.md](mvp-prd.md) user stories define *what the workflow must do*; the demo and its backing tests show that it does.

**Demo format is an open sub-decision** between a **marimo notebook** (runnable and reactive, continuous with the project's video-deck tooling) or a **markdown how-to guide** (a written walk-through, with the integration suite carrying the "it actually runs" rigor).

**Friction is reported, not scored.** The system's deliberate friction — fresh password + TOTP re-authentication on every vote, and wait-for-quorum latency — is described **qualitatively as an intended design property**, not converted into a satisfaction number. A publish is a rare, high-stakes event; trading minutes-to-hours of approval latency for "no single point of compromise" is the point, not a defect (see [mvp-prd.md](mvp-prd.md) §Solution).

---

## 3. It adds only a bounded set of new threats — the net-delta cost

**Claim:** relative to the direct-publish baseline, the proxy introduces only a bounded, enumerated set of new threats, and it is honest about which it defends, which it delegates to operators, and which it accepts.

**Contribution.** The honest accounting of a proof-of-concept's own attack surface — what building this thing *costs* in new threats — rather than a hardening scorecard it cannot back.

The net-delta **cost** is the **Introduced** threats: surface that exists only because the proxy exists (the proxy host, its session and credential store, its approval links and notification channel). Each threat the proxy **owns** — Improved and Introduced — is classified into **exactly one** of four mitigation buckets:

| Bucket | Meaning | Evidence form |
|---|---|---|
| **① Executably demonstrated** | An automated test drives the attack and asserts it fails. | Named adversarial test + pass/fail oracle |
| **② Argued by design** | Reasoned mitigation that cannot be driven by an attack script (crypto invariants, accepted info-leaks). | Prose argument with reference |
| **③ Operator-enforced** | The system *cannot* defend it; mitigation is deployment/config/topology. | Operator checklist item |
| **④ Accepted limitation** | A documented, deliberate out-of-scope failure. | Stated limitation + rationale |

**The security result is a four-bucket distribution over the threats the proxy owns.** It reports how the Improved + Introduced threats distribute across the four buckets. **Inherited** threats carry `bucket: N/A` and do **not** appear in this distribution — applying a mitigation posture to a threat the proxy does not own would be a category error; they are handled in the scope statement below. The four buckets are **co-equal dimensions**: the system's security standing is its position across all four, each reported on its own terms.

> The **full, audited per-threat classification** — the `delta` (Improved / Inherited / Introduced) and `bucket` value for every threat, plus MITRE ATT&CK technique mappings — is performed in [#107](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/107) (threat-model hardening). This plan owns the *method*; that issue owns the finished table.

### Risk rating — likelihood and severity (anchored, not scored)

Beyond classification, every threat carries two **rated axes** — **likelihood** and **severity** — each recorded as a **baseline/residual pair**. The frontmatter contract, in order (the four new fields slot between `delta` and `bucket`):

```yaml
delta: improved|inherited|introduced
likelihood_baseline: high|medium|low|N/A   # N/A iff delta: introduced
likelihood_residual: high|medium|low
severity_baseline: critical|high|medium|low|N/A   # N/A iff delta: introduced
severity_residual: critical|high|medium|low
bucket: 1|2|3|4|N/A
```

**Semantics.**

- **Baseline** rates the equivalent attack scenario in the **direct-publish baseline** world (an author publishing to PyPI with an API token plus account 2FA, no proxy) — the *same* baseline the `delta` axis already measures against. **Residual** rates the threat under the proxy's **current design** — the same honest-audit stance the defense audit takes: what is built, not what is planned or aspirational.
- **Gating rule:** `delta: introduced` ⇒ both `_baseline` fields are `N/A` — the surface does not exist in the baseline world, so there is nothing to rate. This mirrors the existing `inherited ⇒ bucket: N/A` gate.
- `capability` is **not** a rated axis and is unchanged: it is *definitional* — what position the attacker must be in, described in proxy-world terms — which is exactly why it cannot carry a baseline value: the L-ladder names proxy components (proxy DB, proxy host, quorum) that do not exist in the baseline world. Likelihood is its *rated* counterpart.

**No computed risk score.** The (likelihood, severity) pair — a cell in a qualitative matrix — *is* the risk statement. Arithmetic over ordinal scales (DREAD-style multiplication or averaging) has no defensible semantics and is explicitly rejected.

**Anchor 1 — likelihood anchors to the attack's required precondition,** not to intuition. In the proxy world, the threat's `capability` tag sets the **default** residual likelihood via this published mapping; deviations from the default are allowed but must be justified in the threat body:

| Capability | Default residual likelihood | Precondition class |
|---|---|---|
| **L1–L2** | high | remote network position, or a single commodity credential theft |
| **L3–L5** | medium | full single-account compromise, or a database foothold |
| **L6–L9** | low | host code execution, insider, admin, or multi-party collusion |

In the baseline world the *same question* is asked — what position does the equivalent attack require *there* — just without L-labels, since the ladder does not apply outside the proxy.

**Anchor 2 — severity anchors to the mission outcome ladder,** read off the threat's own "what the attacker gains" row. The mission: **prevent an unauthorized package from reaching PyPI.** The ladder works identically in both worlds because it never mentions the proxy — that is what makes baseline and residual comparable:

| Severity | Meaning |
|---|---|
| **critical** | **Mission failure.** An unauthorized artifact reaches PyPI, or the attacker gains the durable ability to publish at will (e.g. quorum control, approver-roster takeover). |
| **high** | **Authorization integrity compromised.** The attacker corrupts an input to the publish decision (casts a genuine but unauthorized vote via a compromised approver, forges or miscounts a vote, weakens quorum policy, compromises a class of credentials or signing keys) — but at least one independent barrier still stands between them and a publish. |
| **medium** | **Security-relevant loss that does not move a publish decision.** Evidence loss (audit-trail suppression / repudiation), or disclosure of sensitive-but-not-credential information. |
| **low** | **Availability or minor disclosure; fails safe.** Capability is lost but no unauthorized publish can result; operator-recoverable. |

**Delta cross-check invariants.** The ratings are not decoration: they *verify* the `delta` classification.

- `improved` ⇒ the baseline is **strictly worse than the residual on at least one of the two axes** — and the improvement can land on either. **CORE-1** (single approver compromise) improves *severity*: baseline critical (one stolen PyPI credential = unilateral publish) → residual high (one compromised approver casts one genuine but unauthorized vote — an authorization-integrity hit — but m-of-n quorum is the ≥1 independent barrier still standing), while likelihood is roughly unchanged (phishing one approver ≈ phishing one maintainer). Still strictly improved on severity (critical → high), which is what the `improved` gate requires. **CORE-3** (insider collusion) improves *likelihood*: baseline, one insider publishes alone → residual, *m* coordinating colluders each leaving a signed vote — while severity stays critical → critical (if the collusion succeeds, an unauthorized publish still happens).
- `inherited` ⇒ the likelihoods must be **equal** — that is precisely what the method's net-cancellation rule means: the mechanism is standard-practice-equivalent in both worlds. **CRYPTO-2** (cryptographic side-channel leakage, the catalog's sole inherited entry) is the worked example: both worlds verify passwords with a standard constant-time library at standard practice, so the timing exposure is identical on each side of the ledger and cancels — likelihood low = low, severity low = low. Severity, however, **may legitimately differ** on an inherited threat: where the proxy contains an outcome the baseline didn't (one approver account instead of a whole publisher account), that containment is **CORE-1**'s improvement, counted **once** under CORE-1 and cross-referenced — it does not flip the inherited threat's delta, because delta classifies **mechanism ownership, not outcome size**. Severity comparison *illustrates* delta; it does not *define* it. A verifier treats baseline ≠ residual severity on an inherited threat as flag-for-review, not auto-fail.
- `introduced` ⇒ both baselines `N/A` (the gating rule above).

**What the axes feed.** (a) A **residual-likelihood × residual-severity qualitative risk matrix** in the threat-model overview — the conventional risk-matrix presentation; and (b) an **improved-threats table** showing baseline → residual per axis — essentially the §1 value proposition rendered as a table. One honesty condition keeps the ratings worth citing: the ladder must be allowed to produce **non-flattering answers** — a threat whose current-design residual is critical until a planned defense lands is rated critical *today* — or the rating is worthless as evidence.

> As with `delta` and `bucket`, this plan owns the *method*; the audited per-threat likelihood/severity values are owned by [#107](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/107) alongside the rest of the per-threat table.

### Bucket ① has two tiers (the seam is labelled)

- **Black-box adversarial** — the attack is driven through the **real HTTP boundary** and asserted at the mocked PyPI publish boundary. Strongest evidence. Oracle: *the PyPI mock is never invoked.*
- **Integrity / detection** — the attack tampers at the **crypto/database layer** and the test asserts detection. Oracle: *`Ed25519Verify(public_key, canonical_json(record), signature)` fails.*

Both are genuinely executable and both count as executably demonstrated (bucket ①); the tier is shown so the rigor is transparent.

### Seed set of executable threats (Introduced surface the proxy defends)

| Threat | Tier | Adversarial test | Pass/fail oracle |
|---|---|---|---|
| **PUB-1** — payload substitution | Black-box | Upload X, approve `hash(X)`, mutate one byte → X′, run Executor | Executor refuses at hash check; mock never reached with X′ |
| **VOTE-2** — approval-link replay | Black-box | Replay a used link / captured vote against another request; re-cast after terminal state | Re-auth required; vote rejected; terminal state frozen |
| **HOST-2 / IDENT-1** — record tampering / admin forgery | Integrity | Mutate a stored approval record; fabricate an "approve" | `Ed25519Verify` fails on the modified/forged record |

The flagship **CORE-1** demonstration (compromised quorum-minus-one cannot publish) is an *Improved* result and lives with the two-act demo in §2; it is the strongest black-box case but its subject is a pre-existing threat the proxy improves, not new surface.

### Security ② — integrity / hash binding

Upload artifact X, approve `hash(X)`, mutate one byte to produce X′, run the Executor. **Oracle: the Executor refuses at the hash check and the PyPI mock is never reached with X′.** Scoped honestly: this defends the **upload→publish window** (an Introduced window — the proxy holds the artifact between upload and approval) against substitution and makes record tampering detectable offline. It does **not** claim resistance to a fully compromised proxy holding the live upload token (an accepted limitation, bucket ④; see [constraints.md](constraints.md) §9, [mvp.md](mvp.md)).

### Provisional first-pass classification (to be finalized in [#107])

*Indicative only — the audited `delta`/`bucket` values live in [#107].* Demonstrated ①: CORE-1 (Improved), HOST-2, VOTE-2, PUB-1, IDENT-1 (and candidate crypto-invariant unit tests for CRYPTO-1, CSRF for VOTE-3). Argued ②: IDENT-4, VOTE-1, CRYPTO-1, INFO-1, CORE-2. Operator-enforced ③: HOST-3, IDENT-2, PUB-2, IDENT-3. Accepted ④: DOS-3, DOS-4, HOST-1, CORE-3. Several threats an earlier draft parked in "accepted limitation" — online TOTP brute force and individual-account attacks (parts of VOTE-4, PUB-3, IDENT-5, DOS-1) — are more honestly **Inherited** (authentication-layer, pre-existing, `bucket: N/A`) than accepted limitations; that reclassification is part of the [#107] audit. (IDENT-5/DOS-1 move to ① for their *Introduced* portion once the in-proxy rate limiter lands.)

### Inherited threats — out of scope by design (scope statement)

The proxy is an **authorization** layer; it does not address **authentication**-layer threats that pre-exist it and are unchanged by it — phishing an individual approver's password, brute-forcing one account's TOTP online. These remain the responsibility of the existing controls (2FA, approver training) that sit beside any publishing setup, exactly as in the baseline. They carry `bucket: N/A`, are catalogued in the threat model with `delta: inherited`, and are listed here **once** rather than defended threat-by-threat, because they were never the proxy's job. Stating the boundary explicitly is what keeps the reader evaluating the proxy on authorization, not on an axis it never claimed.

---

## Excluded axes

Two axes a reader might expect are deliberately excluded. Each exclusion is a stated act of judgment, not an omission.

**Performance.** Performance is not an evaluation axis:
- The only post-quorum action is a **single, human-gated publish**. End-to-end latency is dominated by **how quickly approvers decide**, which is a property of the humans, not the system — measuring it would report on the approvers, not the proxy.
- With the shared-account / forward-auth use case out of evaluation scope (§Scope), there is **no synchronous proxy-overhead path left to measure** — the forward-auth `/auth` subrequest was the only genuine system-latency metric, and it lives entirely in that use case.
- Optimization is **explicitly out of scope** per the project proposal; this is a proof-of-concept whose goal is feasibility and advocacy, not a production-tuned tool.

This exclusion was raised with the instructor, who concurred that performance is not a meaningful axis for this project and invited the decision to be documented here.

**Human-subjects usability study.** The system is a **proof-of-concept built to advocate** for m-of-n publish authorization as a capability industry platforms should adopt natively — not a product whose case rests on a measured satisfaction score. Formal human-subjects usability testing is therefore out of scope: the contribution is the demonstrated mechanism and the argument for it, not a usability rating. (Recruiting external users for a security proxy they have no package to publish through would also not be feasible in the practicum timeline, and would raise IRB questions for marginal value.) Informal expert feedback already gathered in peer video reviews is cited where relevant, but no formal study is claimed.

---

## Execution & artifacts

**Seams** (from [mvp-prd.md](mvp-prd.md) §Testing Decisions; real DB, real crypto, real HTTP, real in-process SMTP — only the outbound PyPI publish is mocked):

- **Proxy HTTP surface** — primary, highest seam; all user-story tests and both adversarial demos enter here.
- **PyPI publish boundary** — the one mocked seam, and the assertion oracle for the security demos.
- **SMTP** — real in-process server; notification emission and Admin-Portal fallback reachability are observed here.

**Runner.** `uv run pytest`. Adversarial demos are pytest cases with explicit oracles; the flagship 2 a.m.-deny demo is additionally scripted as a narrated walk-through for the presentation.

**Artifacts submitted.** (1) the test suite (functional + adversarial), (2) the two-act runnable demo (normal flow + 2 a.m. compromise) and its capability checklist, (3) the net-delta threat classification (the `delta` Improved/Inherited/Introduced axis composed with the four mitigation buckets, plus the anchored likelihood/severity baseline → residual ratings and the residual-likelihood × residual-severity risk matrix), (4) the cited comparative matrix and the case studies, (5) this plan and the [threat model](threat-model/00-overview.md).

---

## References

Citations follow **IEEE** style, managed in a shared `references.bib` so this plan and the progress reports cite from one source list. Seed sources:

- PyPI Trusted Publishing (OIDC); npm Trusted Publishing & provenance.
- OpenSSF `wg-securing-software-repos` — Build Provenance for All Package Registries; SLSA framework; Sigstore; PEP 740 (Index support for digital attestations).
- MITRE ATT&CK — Enterprise techniques (attack taxonomy for the threat model).
- XZ Utils backdoor — CVE-2024-3094 (NVD).
- Shai-Hulud npm worm (2025) — credential-theft, self-replicating supply-chain attack (CISA alert; Unit 42).
- Dependency confusion — A. Birsan (2021); CISA supply-chain guidance (scope-boundary case study).
- AWS Multi-party approval (2025) — scoped to AWS resource operations.
- Supply-chain references already in the project [literature review](research/index.md) (event-stream, ctx).
