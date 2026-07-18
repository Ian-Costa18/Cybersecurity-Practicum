---
bucket: M2
title: Comparative-evaluation and formal-methods frameworks
report_home:
  - "§4 — Positioning & Gap Analysis: comparative positioning matrix"
  - "§7 — Discussion: formal-methods future work"
proxy_grounding:
  - docs/evaluation-plan.md
  - docs/cryptography.md
  - docs/account-management.md
related_notes:
  - ../../../../docs/evaluation-plan.md
  - ../../../../docs/cryptography.md
  - ../../../../docs/use-cases/02-shared-account-management.md
bib_keys: [bonneau-quest-passwords, tamarin-prover]
status: vetted
---

## Why the report needs this

**Synthesis.** Section 4 uses a comparative matrix to make the project’s gap claim
inspectable: it compares controls against four attack scenarios, and each verdict is backed by
the control’s own documentation. The matrix is informed by Bonneau et al.’s comparative
framework, but is deliberately adapted: Bonneau et al. compare web-authentication schemes over
usability, deployability, and security benefits; this report compares publishing controls over
attack scenarios. The source supports the discipline of explicit, shared comparison criteria. It
does not validate this project’s individual ✓ / ~ / ✗ verdicts.

Section 7 names formal verification as future work, not completed evidence. A future model could
state scoped properties of the artifact-bound quorum protocol, such as requiring distinct valid
approvals before publication or preventing a vote from being replayed for another request. It
would not prove that people review artifacts well, that a quorum cannot collude, or that the full
Python/web deployment is flaw-free.

## Sources (vetted this session)

- Bonneau et al., *The Quest to Replace Passwords: A Framework for Comparative Evaluation of Web
  Authentication Schemes* — https://doi.org/10.1109/SP.2012.44 (accessed 2026-07-18) →
  `bonneau-quest-passwords` · the precedent for an explicit comparative-evaluation framework ·
  [formal]
- Meier et al., *The TAMARIN Prover for the Symbolic Analysis of Security Protocols* —
  https://doi.org/10.1007/978-3-642-39799-8_48 (accessed 2026-07-18) → `tamarin-prover` · a
  concrete formal-methods future-work path for the abstract approval protocol · [formal]
- Reese et al. and De Cristofaro et al. — retained as context only. They study human use of 2FA,
  not artifact review, asynchronous multi-person authorization, or this proxy’s workflow.

## Comparative evaluation: make the criteria explicit

Bonneau et al. evaluated password-replacement proposals using a shared set of stated benefits;
their subject and criteria differ from this report’s. The transferable lesson is methodological:
compare alternatives against visible criteria rather than implicitly changing the criterion from
row to row.

> "We evaluate two decades of proposals to replace text passwords for general-purpose user
authentication on the web using a broad set of twenty-five usability, deployability and security
benefits that an ideal scheme might provide."
> — Bonneau et al., Abstract

This anchors the narrow §4 statement that the report’s matrix is informed by a comparative
approach using explicit criteria. It does **not** make the project’s four scenarios equivalent to
Bonneau et al.’s 25 benefits.

> "We propose a standard benchmark and framework allowing schemes to be rated across a common,
broad spectrum of criteria chosen objectively for relevance in wide-ranging scenarios, without
hidden agenda."
> — Bonneau et al., §I, "Introduction"

The report adapts this principle by applying the same four attacker scenarios to every control.
The cited official documentation for each control remains the evidence for its matrix cells.

## Formal methods: a bounded future-work path

Tamarin analyzes an abstract protocol and attacker model, not a running FastAPI application. A
future effort could model request creation, artifact-hash binding, signed votes, and the quorum
rule, then ask whether a publication trace can occur without the required valid approvals. That
is complementary to this project’s executable tests: the model reasons over its stated
abstraction; the tests exercise the implemented HTTP and persistence boundaries.

> "The Tamarin prover supports the automated, unbounded, symbolic analysis of security protocols.
It features expressive languages for specifying protocols, adversary models, and properties, and
support for efficient deduction and equational reasoning."
> — Meier et al., Abstract

This supports the §7 proposal to formally model the **protocol-level** properties. It does not
support a claim that this project was formally verified, that Tamarin verifies implementation
code, or that it evaluates human judgment.

## How the proxy relates

The proxy’s comparative matrix is an argued evaluation of controls at the registry-publish
boundary, not a user study and not a numerical score. Its test suite demonstrates the implemented
workflow and selected adversarial cases; the net-delta threat catalog accounts for the new attack
surface. A future Tamarin model would add a third, narrower kind of evidence: protocol-level
reasoning about explicit attacker and approval rules.

The project deliberately excludes human-subjects usability evaluation. Existing 2FA studies do
not transfer: the proxy asks participants to inspect a high-consequence artifact, coordinate with
other approvers, and make an asynchronous authorization decision, rather than repeatedly log in.

## Open threads / to verify

- **Future generality, not M2:** `trustee-social-auth` is relevant to a possible future
  credential-recovery use case: a reset could become an auditable, quorum-gated action. The current
  proxy does not implement this; `docs/account-management.md` specifies admin-mediated,
  out-of-band recovery. If §7 includes this example, retrieve and deepen that source in the
  generality/future-work research pass rather than treating it as comparative-method evidence.

## Source decisions

- **Keep Bonneau et al., adapted and narrowly framed.** The final report can say that its matrix
  is *informed by* Bonneau et al.’s use of explicit shared criteria, then state exactly how this
  report changes the subject and criteria. It must not claim to apply the UDS framework wholesale
  or borrow the paper’s results.
- **Keep Tamarin as future work only.** It identifies a credible way to examine scoped protocol
  properties, but neither the model nor its proofs are part of this project’s evidence.
- **Do not cite the 2FA usability studies as proxy-usability evidence.** They establish the shape
  of studies the project did not perform, but their tasks do not model artifact review or quorum
  authorization. Keep Reese et al. only as optional future-work background.
- **Drop MFKDF from M2.** The proxy uses PBKDF2, bcrypt, TOTP, AES-GCM, and Ed25519 in separate
  documented roles; it does not derive a key from multiple factors. MFKDF would be a different
  mechanism, not evidence for the evaluation or approval model.
- **Move trustee-based social authentication out of M2.** It can support an unevaluated §7
  future-use-case discussion of quorum-gated credential recovery, not the current proxy or the
  comparative-evaluation method.
