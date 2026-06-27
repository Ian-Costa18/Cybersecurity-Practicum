# Evaluation Plan

How the Multi-Party Authorization proxy is evaluated: what "success" means, how each claim is measured, and which artifacts the evaluation produces. This document is the source of truth for evaluation; the Progress Report 3 *Evaluation* section is a distillation that links here, and this plan becomes the backbone of the final report's Evaluation chapter.

> **Scope.** The evaluation covers the **package-publishing** use case only. "General-purpose multi-party authorization" remains the project's design property and future direction, but is **not evaluated** this term (see [#109](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/109)). Problem/solution framing and the [mvp-prd.md](mvp-prd.md) generality claims will be reconciled with this scope under that issue.

---

## What "evaluation" means here

A practicum solution must show three things, in descending order of how much of each is the author's own work and research contribution:

1. **It works.** The system performs the package-publishing workflow end-to-end. Demonstrated by a **runnable workflow demo** (the spine of the 15-minute video), with the integration test suite as the backing evidence that each step works and keeps working.
2. **It resists the attacks it claims to resist.** The **subset of [threat-model](threat-model.md) threats that can be driven by an attack script** is turned into an executable adversarial test suite; the remaining threats are argued by design, delegated to operators, or accepted as limitations. The result is *how the enumerated threats distribute across those four buckets*, reported as four co-equal dimensions.
3. **It fills a gap existing tools leave open.** A **comparative positioning matrix** shows, with citations, that no existing control enforces *m-of-n human authorization of a registry publish bound to the exact artifact*.

Two axes are deliberately **excluded**, each with a stated justification: **performance** (§4) and **human-subjects usability studies** (§1). Excluding them honestly, with reasons, is itself part of the evaluation — not an omission.

This plan does **not** depend on any other person using the system. Every result is either an automated test outcome or a cited analytical argument. No survey, interview, or satisfaction score is fabricated to stand in for real users.

---

## 1. Functional correctness & usability

**Claim:** the proxy implements the complete package-publishing workflow, and it can be carried out end-to-end by a real operator.

**Primary artifact — a runnable workflow demo.** Correctness and usability are demonstrated by a **guided, runnable walk-through** of the full package-publishing flow: *submit via normal tooling → proxy binds by hash → approvers notified → approver inspects the exact artifact → re-authenticated signed votes → quorum reached → publish → audit record + terminal notification*, plus the **deny path** (a single deny halts the request). This demo is the spine of the 15-minute video — it is the thing a viewer watches to see that the system works and how a human uses it.

**Backing rigor — the integration test suite.** The demo is not a one-off screen recording: every step it walks through is also exercised by an **end-to-end integration test** driven through the real Proxy HTTP surface (real DB, real crypto, real HTTP, real in-process SMTP; only the outbound PyPI publish is mocked). The tests are what make "it works" **reproducible and regression-proof**; the demo is what makes it **legible**.

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

**Demo format is an open sub-decision** between two options: a **marimo notebook** (runnable and reactive, continuous with the project's video-deck tooling — executes the workflow live) or a **markdown how-to guide** (a written walk-through a reader follows step by step, with the integration suite carrying the "it actually runs" rigor). Either way the structure is one demo, **two acts**, mapping directly onto the video: *Act 1 — the normal publish workflow (this section); Act 2 — the "2 a.m." compromise (the Security ① flagship, §2).*

**Friction is reported, not scored.** The system's deliberate friction — fresh password + TOTP re-authentication on every vote, and wait-for-quorum latency — is described **qualitatively as an intended design property**, not converted into a satisfaction number. A publish is a rare, high-stakes event; trading minutes-to-hours of approval latency for "no single point of compromise" is the point, not a defect (see [mvp-prd.md](mvp-prd.md) §Solution).

**Why no human-subjects study.** The system is a **proof-of-concept built to advocate** for m-of-n publish authorization as a capability industry platforms should adopt natively — not a product whose case rests on a measured satisfaction score. Formal human-subjects usability testing is therefore out of scope: the contribution is the demonstrated mechanism and the argument for it, not a usability rating. (Recruiting external users for a security proxy they have no package to publish through would also not be feasible in the practicum timeline, and would raise IRB questions for marginal value.) The informal expert feedback already gathered in peer video reviews is cited where relevant, but no formal study is claimed.

---

## 2. Security evaluation — the executable threat suite

**Claim:** the proxy defeats the attacks its [threat model](threat-model.md) says it defeats, and is honest about the ones it does not.

The threat model is the **spine** of the security evaluation. Each of its enumerated threats is classified into **exactly one** of four buckets:

| Bucket | Meaning | Evidence form |
|---|---|---|
| **① Executably demonstrated** | An automated test drives the attack and asserts it fails. | Named adversarial test + pass/fail oracle |
| **② Argued by design** | Reasoned mitigation that cannot be driven by an attack script (e.g. crypto invariants, accepted info-leaks). | Prose argument with reference |
| **③ Operator-enforced** | The system *cannot* defend it; mitigation is deployment/config/topology. | Operator checklist item |
| **④ Accepted limitation** | A documented, deliberate out-of-scope failure. | Stated limitation + rationale |

**The security result is a four-bucket distribution.** The security result is *how the N enumerated threats distribute across the four buckets* — how many are executably demonstrated, how many argued by design, how many operator-enforced, and how many accepted as out-of-scope limitations. That per-bucket distribution is the "clarify the threat model and evaluation plan" deliverable. The four buckets are **co-equal dimensions**: the system's security standing is its position across all four, each reported on its own terms. The distribution counts only what each bucket genuinely holds — operator-config and accepted-limitation threats are reported as such, not as "passed."

> The **full, audited per-threat classification** is performed in [#107](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/107) (threat-model hardening). This plan owns the *method*; that issue owns the finished table.

### Bucket ① has two tiers (the seam is labelled)

- **Black-box adversarial** — the attack is driven through the **real HTTP boundary** and asserted at the mocked PyPI publish boundary. Strongest evidence. Oracle: *the PyPI mock is never invoked.*
- **Integrity / detection** — the attack tampers at the **crypto/database layer** and the test asserts detection. Oracle: *`Ed25519Verify(public_key, canonical_json(record), signature)` fails.*

Both are genuinely executable and both count as executably demonstrated (bucket ①); the tier is shown so the rigor is transparent rather than mixing a database-level assertion in with a full end-to-end attack.

### Seed set of executable threats

| Threat | Tier | Adversarial test | Pass/fail oracle |
|---|---|---|---|
| **T1** — single-approver compromise | Black-box | `n-of-n` service, one compromised account submits + approves; honest seats withhold | PyPI mock never invoked |
| **T11** — payload substitution | Black-box | Upload X, approve `hash(X)`, mutate one byte → X′, run Executor | Executor refuses at hash check; mock never reached with X′ |
| **T8** — approval-link replay | Black-box | Replay a used link / captured vote against another request; re-cast after terminal state | Re-auth required; vote rejected; terminal state frozen |
| **T6 / T13** — record tampering / admin forgery | Integrity | Mutate a stored approval record; fabricate an "approve" | `Ed25519Verify` fails on the modified/forged record |

### Flagship demonstration — Security ① ("the 2 a.m. deny")

A reproducible adversarial demo at the boundary case **t = m−1**: a **`3-of-3`** publishing service, **two fully-compromised accounts** (the harness holds their passwords, TOTP seeds, API tokens, and a live Proxy Session) acting as malicious Requester + malicious Approver, and **one honest co-owner**. The request freezes at 2/3 until the honest co-owner wakes, investigates, and **denies** — halting the publish and surfacing the compromise. **Pass = zero unauthorized publishes across all trials; any single bypass = fail.** The scenario is race-free because `n-of-n` cannot reach quorum without the honest seat, and it is designed to **double as the spine of the final presentation**.

### Security ② — integrity / hash binding

Upload artifact X, approve `hash(X)`, mutate one byte to produce X′, run the Executor. **Oracle: the Executor refuses at the hash check and the PyPI mock is never reached with X′.** Scoped honestly: this defends the **upload→publish window** against substitution and makes record tampering detectable offline — it does **not** claim resistance to a fully compromised proxy holding the live upload token (an accepted limitation, bucket ④; see [constraints.md](constraints.md) §9, [mvp.md](mvp.md)).

### Provisional first-pass classification (to be finalized in [#107])

*Indicative only — the audited version lives in [#107].* Demonstrated ①: T1, T6, T8, T11, T13 (and candidate crypto-invariant unit tests for T17, CSRF for T21). Argued ②: T10, T15, T17, T22. Operator-enforced ③: T5, T9, T14, T16. Accepted ④: T2, T3, T4, T7, T12, T19, T24.

---

## 3. Comparative positioning matrix

**Claim:** existing controls either harden *authentication/origin* or gate an *internal pipeline*; **none** enforces m-of-n human authorization of the *public registry publish*, bound to the exact artifact. The proxy fills that gap.

**Method — argued and cited, not empirically tested.** Each cell is a claim backed by a **citation to the control's own documented behavior**; no cell is an uncited assertion. Standing up live instances of each competing control is out of scope for the timeline and several scenarios (trusted-insider) cannot be "tested" anyway. The discipline rule — *every cell cites a source* — is what converts this section from opinion into evidence.

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

**Reading the matrix.** Rows 1–3 live on the authentication/origin axes and never touch *authorization* — provenance is the sharpest proof: an attestation certifies *where* a package was built and *from which commit*, **not what its code does**, so a poisoned-but-authentically-built artifact still verifies (column C, `✗`). The 2025 Shai-Hulud worm makes the authentication point concretely: it spread by stealing maintainer tokens and republishing, and npm's publisher-side controls (2FA, trusted publishing, provenance) did not stop it. Rows 4–6 *do* distribute the decision (hence `~` on B), but they gate the **repo merge** or an **internal pipeline**, are bound to that platform, and are **bypassed entirely by a direct registry publish** (column D, all `✗`). Only the proxy covers all four, because it holds the sole publish credential and binds the exact artifact by hash.

**\*Honest caveats on the proxy's column D and beyond.** Column D holds **only under the operator-enforced precondition** that the proxy is the sole holder of the publish token and the sole network path ([constraints.md](constraints.md) §5, §9) — the proxy cannot self-enforce its own placement (threat **T14**, bucket ③). And a colluding quorum of ≥ *m* approvers (threat **T19**, bucket ④) defeats any of these controls by definition. The matrix claims authorization coverage, not omnipotence.

**Complementary, not competing.** Two tools sit on a different axis and are noted in prose rather than scored: automated **malware/dependency scanning** (Socket/Snyk-style) is *detection*, not authorization — it catches *known*-bad signatures, but the XZ backdoor evaded automated detection entirely and was found only by chance (a maintainer investigating an SSH latency anomaly), which is exactly why a human quorum is needed; feeding scan verdicts to approvers is captured as future work ([#108](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/108)). Separately, **AWS added a "multi-party approval" capability in 2025** — but scoped to *AWS's own resource operations* (currently AWS Backup logically air-gapped vaults, gated through IAM / Organizations), **not** a general-purpose proxy. It is evidence that m-of-n human approval *as a primitive* is being adopted by major platforms — and that every such adoption is **siloed inside one platform's control plane** (AWS for AWS operations, GitHub for its deploys, Artifactory for its repos). None gates an arbitrary registry publish. That pattern *reinforces* the gap this project targets rather than filling it: the primitive is proven, but a general-purpose, registry-agnostic enforcement point does not exist.

---

## 4. Performance — excluded, with justification

Performance is **not** an evaluation axis, and the exclusion is deliberate:

- The only post-quorum action is a **single, human-gated publish**. End-to-end latency is dominated by **how quickly approvers decide**, which is a property of the humans, not the system — measuring it would report on the approvers, not the proxy.
- With the shared-account / forward-auth use case out of evaluation scope (§Scope), there is **no synchronous proxy-overhead path left to measure** — the forward-auth `/auth` subrequest was the only genuine system-latency metric, and it lives entirely in that use case.
- Optimization is **explicitly out of scope** per the project proposal; this is a proof-of-concept whose goal is feasibility and advocacy, not a production-tuned tool.

This exclusion was raised with the instructor, who concurred that performance is not a meaningful axis for this project and invited the decision to be documented here.

---

## Execution & artifacts

**Seams** (from [mvp-prd.md](mvp-prd.md) §Testing Decisions; real DB, real crypto, real HTTP, real in-process SMTP — only the outbound PyPI publish is mocked):

- **Proxy HTTP surface** — primary, highest seam; all user-story tests and both adversarial demos enter here.
- **PyPI publish boundary** — the one mocked seam, and the assertion oracle for the security demos.
- **SMTP** — real in-process server; notification emission and Admin-Portal fallback reachability are observed here.

**Runner.** `uv run pytest`. Adversarial demos are pytest cases with explicit oracles; the flagship Security ① demo is additionally scripted as a narrated walk-through for the presentation.

**Artifacts submitted.** (1) the test suite (functional + adversarial), (2) the runnable workflow demo (two acts: normal flow + Security ① compromise) and its capability checklist, (3) the four-bucket threat classification (executably demonstrated / argued by design / operator-enforced / accepted limitation), (4) the cited comparative matrix, (5) this plan and the [threat model](threat-model.md).

---

## References

Citations follow **IEEE** style, managed in a shared `references.bib` so this plan and the progress reports cite from one source list. Seed sources:

- PyPI Trusted Publishing (OIDC); npm Trusted Publishing & provenance.
- OpenSSF `wg-securing-software-repos` — Build Provenance for All Package Registries; SLSA framework; Sigstore; PEP 740 (Index support for digital attestations).
- XZ Utils backdoor — CVE-2024-3094 (NVD).
- Shai-Hulud npm worm (2025) — credential-theft, self-replicating supply-chain attack (CISA alert; Unit 42).
- AWS Multi-party approval (2025) — scoped to AWS resource operations.
- Supply-chain references already in the project [literature review](research/index.md) (event-stream, ctx).
