<!-- LTeX: enabled=false -->
# Controls-matrix research notes

Source-of-evidence backing for the **comparative positioning matrix** in
[evaluation-plan.md §1, Move 1](../../../../docs/evaluation-plan.md) — the artifact that proves the
project's primary claim: *no existing control enforces m-of-n human authorization of a registry
publish bound to the exact artifact; the proxy fills that gap.* Each note takes one matrix **row**
(a control) and defends its four cell verdicts against the four attack scenarios with cited,
documented behavior. Parent issue: [#113](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/113).

## If you are reviewing this work, read in this order

1. **[research-process.md](research-process.md)** — the method. Four phases per row
   (**ground → grill → preview → write**), the note template, the conventions, and the **row
   queue** (all 7 rows checked off). Read this first: it defines what a valid note is and what
   "the verdicts are fixed" means.
2. **[evaluation-plan.md §1, Move 1](../../../../docs/evaluation-plan.md)** — the matrix itself and
   its fixed verdicts. **The notes source and defend these verdicts; they do not invent them.** If a
   note's evidence contradicts a verdict, that is surfaced against the spec (and the spec edited in
   the same change) — never quietly reconciled.
3. **The seven control notes** (below), each self-contained.

## The four attack scenarios (matrix columns)

Always named, never by letter: **Stolen credential** (Shai-Hulud, 2025) · **Trusted insider** (XZ,
CVE-2024-3094) · **Compromised CI** (authentically-built poisoned artifact) · **Direct publish**
(straight to the registry, bypassing repo and CI).

## Artifact map — the seven rows

| Row | Control | Note | Verdicts (Stolen · Insider · CI · Direct) | Axis it operates on |
|:--:|---|---|:--:|---|
| 1 | Mandatory 2FA / MFA | [ctrl-mandatory-2fa.md](ctrl-mandatory-2fa.md) | `~ · ✗ · ✗ · ✗` | Authentication |
| 2 | Trusted Publishing (OIDC) | [ctrl-trusted-publishing.md](ctrl-trusted-publishing.md) | `✓ · ✗ · ✗ · ~` | Authentication (scoped, short-lived credential) |
| 3 | Build provenance (Sigstore / SLSA / PEP 740) | [ctrl-build-provenance.md](ctrl-build-provenance.md) | `✗ · ✗ · ✗ · ✗` | Origin/integrity attestation (detective) |
| 4 | GitHub required reviews + branch protection | [ctrl-github-branch-protection.md](ctrl-github-branch-protection.md) | `✓ · ~ · ✗ · ✗` | Code-repo **merge** decision |
| 5 | CI/CD deployment-approval gates | [ctrl-cicd-deployment-gates.md](ctrl-cicd-deployment-gates.md) | `✓ · ~ · ~ · ✗` | Pipeline deploy gate (platform-bound) |
| 6 | Artifact-repo staging/promotion (Artifactory / Nexus) | [ctrl-artifact-repo-promotion.md](ctrl-artifact-repo-promotion.md) | `✓ · ~ · ~ · ✗` | Internal promotion gate (product-bound) |
| 7 | **The proxy** | [ctrl-the-proxy.md](ctrl-the-proxy.md) | `✓ · ✓ · ✓ · ✓*` | **Authorization of the registry publish, artifact-bound** |

`✓` stops it · `~` partial/conditional (a ⚠ caveat box names the case caught and the case missed) ·
`✗` does not · `✓*` holds under a stated operator precondition.

## How to read a note

Every note follows the same template (see [research-process.md](research-process.md) §Note
template): **axis → primary sources → what it actually gates → anchored documented behavior →
per-column table with catches/misses → ⚠ caveat box(es) → how the proxy beats this row → bib keys
to defer.** The discipline rule that makes this *evidence* rather than opinion: **every cell cites a
source**, and where a control was deployed and still failed, a **named, primary-sourced incident**
anchors the `✗`/`~` (e.g. Shai-Hulud, Ultralytics, SolarWinds, XZ).

## Row 7 is special — the proxy scores its own matrix

[ctrl-the-proxy.md](ctrl-the-proxy.md) is the proxy grading itself, so it has **no "how the proxy
beats this row" section**. That section is replaced by the two **honest caveats** that bound the
proxy's own `✓`s — the note ends on its limits, not a victory lap:

- **Caveat 1 — sole-credential precondition ([PUB-2](../../../../docs/threat-model/PUB-2-proxy-bypass.md)).**
  Column D's `✓*` holds only if the proxy is genuinely the sole publish credential and network path
  ([constraints.md](../../../../docs/constraints.md) §5, §9) — a precondition the proxy **cannot
  self-verify**. Out-of-band reconciliation ([#124](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/124))
  now **detects** a bypass (bucket ① detection tier) but **prevention stays operator credential-topology
  hygiene** (bucket ③).
- **Caveat 2 — colluding / review-surviving quorum ([CORE-3](../../../../docs/threat-model/CORE-3-insider-collusion.md), bucket ④).**
  The `✓` on Trusted insider and Compromised CI buys *no unilateral action + a human gate on the
  exact artifact*, **not immunity**: a colluding quorum of ≥ *m*, or a payload engineered to survive
  honest review (the XZ shape), still publishes. The honest answer is deterrence (signed,
  non-repudiable votes) plus quorum topology, not prevention.

## References (bib keys)

Every source a note cites is landed in [`../../references.bib`](../../references.bib) — each note's
**Primary sources** list is the authoritative pointer from cell to bib key. Keys are reused across
rows where the same source recurs (e.g. `shai-hulud-unit42`, `openwall-xz-backdoor`,
`mitre-c0024-solarwinds`).

## Provenance / limits of this evidence

Each cell is **argued and cited, not empirically tested** — no live instance of a competing control
was stood up, and several scenarios (trusted-insider) cannot be tested anyway. The evidence is the
control's *own documented behavior* plus real incidents where it was in place and failed. This is a
deliberate, stated scope choice (evaluation-plan.md §1, Move 1), not a gap.
