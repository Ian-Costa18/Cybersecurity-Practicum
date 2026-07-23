<!-- LTeX: enabled=false -->
# Final Report — Outline

Working outline for the CS 6727 final report. Bare-bones and iterative — we build on it.
Constraint: **12-page body max (CS), excluding references.** See [Assignment.md](Assignment.md).
Template: **IEEE two-column (`IEEEtran`)** — chosen to maximize content under the page cap; wide
tables (e.g. the comparative matrix) use full-width `table*` floats. `references.bib` is already IEEE-styled.

**Cross-link convention:** conventional paper headings, with a one-line *claim tag* under
each evaluated section that names the [evaluation-plan.md](../../../docs/evaluation-plan.md)
claim it carries, so the report and the eval plan stay easy to cross-reference.

---

1. **Title & Abstract**

2. **Introduction**
   - Motivation, contribution
   - **Thesis (general → concrete):** multi-party approval is a *general* primitive; this paper
     instantiates and evaluates it for package publishing as the strong, concrete use case.
     The **motivating argument** — the reason the project exists — is that m-of-n *human*
     authorization is badly under-used: it belongs anywhere a single compromised credential can
     trigger a high-consequence action, not just package publishing. Package publishing is where
     we *prove it works*; the advocacy is that the primitive should be everywhere.
     (Opens the generality bookend that Discussion §7 closes; keeps generality as framing, never
     an evaluated claim — see [#109].)
   - *The Solution in Brief* (short subheading — what the proxy is, before we use it below)

3. **Background — Motivating Incidents**
   - Case studies: Shai-Hulud (2025) — the clean **stolen-credential** win; XZ Utils /
     CVE-2024-3094 (2024) — the **trusted-insider honesty anchor**. The two are a deliberate pair:
     Shai-Hulud is where the proxy wins outright, XZ is where it **does not** — a years-cultivated
     insider whose payload was engineered to survive review. The report pauses here to say plainly
     that **the proxy is not a silver bullet**; that honesty is what makes the evaluation credible.
   - What happened + why existing controls failed (the cost of the gap) — and, for XZ, why the proxy
     honestly does not close it either (carried into §4 and §7).
   - **The two cases are not co-equal in airtime.** Shai-Hulud gets the narrated case study
     (~1.0 pg): dated cold open, the auto-republish propagation mechanic, the 500-package /
     2M-weekly-downloads scale, the npm+GitHub response list, and the recurrence timeline
     through AsyncAPI (Jul 2026, "bypassed all human review") and TanStack (validly-attested
     SLSA L3 malware). That timeline is what makes the problem present-tense, and it feeds §4
     directly. XZ is a **short second movement** (~0.4 pg) doing exactly two jobs: the
     "every control was satisfied and the outcome was still CVSS 10.0" sentence, and the
     tarball-vs-git fact (the payload lived in binary test fixtures and the release tarball's
     build machinery, absent from the public git source; caught only because Andres Freund
     investigated a ~500 ms SSH login delay). The Jia Tan timeline compresses to a clause.
     Rationale: Shai-Hulud has to *establish* a problem, XZ only has to *bound* a claim, and
     bounding is cheaper. XZ is load-bearing again in §4 (Trusted-insider column) and §7
     (CORE-3), so §3 states the ceiling once and cross-references rather than re-arguing it.
   - *Research:* [incident-shai-hulud.md](research/sources/incident-shai-hulud.md),
     [incident-xz-backdoor.md](research/sources/incident-xz-backdoor.md).

4. **Positioning & Gap Analysis**
   > *Evaluation Claim 1 — "It solves a problem." Source: [evaluation-plan.md §1](../../../docs/evaluation-plan.md).*
   The section closes **three objections** to Claim 1, in order. (These are the three "moves" of
   [evaluation-plan.md §1](../../../docs/evaluation-plan.md); the numbering is kept because every
   `research/` note's `report_home` field indexes against it.)

   - **Framing first:** authorization layer vs. authentication layer — the distinction the whole
     section turns on, stated before any evidence.
   - **① The gap is real** *(plan Move 1)* — objection answered: *"2FA / Trusted Publishing / SLSA
     already covers this."* Comparative positioning matrix, controls × attack scenarios.
     **Verdicts are fixed by [evaluation-plan.md §1](../../../docs/evaluation-plan.md)** and
     source-defended per row in [research/controls-matrix/](research/controls-matrix/); do not
     re-derive them here.
     **Two-pass structure** (adopted from the final presentation, 2026-07-23): walk all six
     competitor rows first and land the reading — *not one covers more than one or two columns* —
     and only **then** introduce the proxy row. The reader should reach it already convinced one is
     needed. Method caveat stated where the matrix is introduced, not in a footnote: each cell is
     *argued and cited, not empirically tested*.
   - **② The gap is costly to leave open** *(plan Move 2)* — objection answered: *"fine, but who
     cares."* How the proxy addresses each Background case study — **honestly, including where it
     does not win**: Shai-Hulud's auto-republish leg breaks cleanly (one stolen token casts one vote
     of *m*); XZ only *raises the bar* (the lone insider is reduced to one vote of *m*), but a
     payload built to survive honest review still passes a genuine quorum — the proxy is an
     authorization gate, **not a malice detector**. This is the "not a silver bullet" boundary,
     stated where the matrix scores it ([ctrl-the-proxy.md](research/controls-matrix/ctrl-the-proxy.md)
     Caveat 2; [incident-xz-backdoor.md](research/sources/incident-xz-backdoor.md)).
   - **③ The gap is live industry territory, still unfilled** *(plan Move 3)* — objection answered:
     *"isn't this just AWS multi-party approval?"* Multi-party approval is shipping at AWS, Google,
     and Azure, but every adoption is welded to that platform's own control plane; Azure PIM — the
     one *general-purpose* privileged-access product — resolves on the first approver, so it is
     1-of-n, not a quorum. NIST SP 800-53 codifies the primitive only as a fixed *two*, confined to
     privileged commands. The primitive is therefore **recognized, not novel**: the contribution is
     *generalizing the count* and *placing it* at the registry-publish point.
     Sourced from [primitive-multiparty-approval.md](research/sources/primitive-multiparty-approval.md)
     and [primitive-sod-multiparty.md](research/sources/primitive-sod-multiparty.md).
   - **Doubles as Related Work** — no standalone Related Work section; ① and ③ carry it, engaging
     the literature *as evidence for the gap*, not as a deferential survey. **Related work stays
     here, not in the Intro** — leading with other systems reads as derivative
     ([How to write a technical paper](How%20to%20write%20a%20technical%20paper%20or%20a%20research%20paper.htm)).
     §1 makes the "underused" *claim* and signals "existing controls analyzed in §4" in one line;
     §4 carries the *evidence*.

5. **System Design**
   > *Evaluation Claim 2 — "It works." Source: [evaluation-plan.md §2](../../../docs/evaluation-plan.md).*
   - Architecture + end-to-end request/approval flow
   - Three-act demo + integration-suite evidence

6. **Security Analysis**
   > *Evaluation Claim 3 — "It adds only a bounded set of new threats." Source: [evaluation-plan.md §3](../../../docs/evaluation-plan.md).*
   - **Open on the concession, not the taxonomy** (adopted from the final presentation, 2026-07-23):
     voice the reader's objection and concede it flatly — *does this add new risks? Yes* — before
     any classification. Conceding first is what makes the net-delta model read as an audit rather
     than a defense. Lead the Introduced class with **concentration of risk**, the worst residual:
     risk that was spread across every maintainer's laptop now sits behind one gate.
   - Net-delta model: Improved / Inherited / Introduced. Tool-verified counts —
     24 introduced · 5 improved · 4 inherited = **33**; the proxy **owns** improved + introduced
     (**29 of 33**) and reports buckets over exactly those. The 4 inherited carry `bucket: N/A`
     and are a scope statement, not defended threat-by-threat.
   - Four mitigation buckets over threats the proxy owns
   - Methodology beats worth the space: the claim is a **net delta, not an absolute**; ordinal
     arithmetic (DREAD-style) is explicitly rejected, cited to DREAD's own co-author; ATT&CK anchors
     "pre-existing" so it is not a label self-assigned by the author.

7. **Discussion**
   - **Deployment preconditions — their own beat, ahead of limitations** (adopted from the final
     presentation, 2026-07-23). These are guarantees the proxy *cannot enforce for itself*, which is
     a different category from what it does not claim, and merging the two blurs both. Two carry the
     weight: **revoke every pre-existing publish token** (PUB-2 — otherwise an attacker does not
     have to beat the quorum, they publish *around* it; this is also the precondition behind Table I's
     `✓*` on Direct-publish, so state the link rather than letting it read as two caveats), and
     **choose the quorum and co-owners deliberately** (DOS-3, DOS-4 — high enough to mean something,
     low enough that losing one approver cannot freeze a release). The co-owner half is the CORE-3
     knob, which hands directly to the limitation below. Remainder: the ~40-box operator checklist.
   - Limitations (colluding quorum CORE-3 — **XZ Utils is the worked example: a review-surviving,
     years-cultivated insider is the case the proxy does not beat, so it is not a silver bullet**;
     operator-precondition PUB-2; PoC-not-hardened; excluded axes: performance, human-subjects
     usability). Traces to [incident-xz-backdoor.md](research/sources/incident-xz-backdoor.md).
   - **Future Work & Generalizability** — *closes the Intro's generality bookend*, and it is the
     **thesis payoff, not a footnote**. The project exists to argue that m-of-n *human*
     authorization is a general primitive that belongs far beyond package publishing — shared-account
     access, forward-auth-gated resources, and in principle *any* high-consequence action a single
     compromised credential can trigger. A further, unevaluated scenario is **quorum-gated
     credential recovery**: instead of one administrator resetting a user's password or second
     factor, independent recovery approvers would review and authorize the reset. The current proxy
     uses admin-mediated, out-of-band credential recovery. This is the largest, most-developed part
     of the section. Cites shared-account + forward-auth as designed-for evidence. Also develops **native registry
     integration** as the productization path that dissolves the proxy's single biggest introduced
     risk (concentration-of-risk — "one more juicy target" is moot once the registry, already the
     juiciest target in the ecosystem, offers this natively; Trusted Publishing is precedent that
     registries add auth features). Labeled unevaluated; the generality argument is *framing /
     advocacy*, never one of the three evaluated claims (#109).

8. **Conclusion**

9. **References**

10. **Appendix** — *generally follows the progress-report appendix structure* (they'll be similar):
    - AI Usage Disclosure (carried from the progress reports)
    - Work Product pointers (codebase, docs/ADRs, PRD, threat model, evaluation plan)
    - Full threat-model classification table (net-delta + buckets)
    - Capability checklist (overflow from System Design §5)
    - *(Tentative)* **Cryptographic-choice rationale** — why credential-backed approval over
      threshold signatures. The deciding factor is **usability, not a security gap**: threshold
      signatures are stronger on exactly one axis (approvers never trust the proxy to record their
      approval), but against the proxy's actual adversary — a *single compromised identity* — both
      models collapse to "compromise one identity," and threshold merely shifts that from *one
      password* to *one key* while forcing key management onto non-technical approvers (see
      [ADR 0001](../../docs/adr/0001-credential-backed-approval.md) §4). The security give-up is
      bounded and named: the proxy must be trusted to record honestly, but a proxy compromised
      *after* approval cannot forge approvals retroactively. Threshold m-of-n is not exotic — it is
      the shipped default of a mainstream secrets manager (HashiCorp Vault, 3-of-5) — which is
      precisely why the credential-backed variant of the same m-of-n idea was chosen for approver
      usability. Plus a one-line note on the primitives actually used, each standard and
      FIPS-forward in exactly one role: **Ed25519-IETF** (SUF-CMA approval signing), **AES-256-GCM**
      (private-key + TOTP-secret encryption at rest), **PBKDF2-HMAC-SHA-256** (key derivation),
      **bcrypt** (password verification), **SHA-256** (artifact hash binding), **HMAC-SHA-256**
      (session-cookie + audit-chain integrity), **TOTP** (second factor). Deranked from the body —
      this is a PoC, and the same design is realizable with threshold cryptography. Fed by research
      bucket **C1** ([research/sources/primitive-crypto-choices.md](research/sources/primitive-crypto-choices.md));
      keep only if the page budget allows.

---

## Page budget (soft maximums, IEEE two-column, 12-pg cap)

Priority principle: depth into the **contribution** (gap analysis + security net-delta); the
**engineering** (System Design) stays lean and figure-driven — detail overflows to the Appendix.

| Section | Max pages |
| --- | :---: |
| Title + Abstract | 0.3 |
| Introduction (+ Solution in Brief) | 1.5 |
| Background — Incidents | 1.5 |
| Positioning & Gap Analysis | 2.5 |
| System Design | 1.5 |
| Security Analysis | 2.0 |
| Discussion (Limitations + Future Work) | 1.5 |
| Conclusion | 0.3 |
| **Body total** | **~11.1** |
| References | *excluded from count* |
| Appendix | *overflow* |

---

## Figures & tables (load-bearing visuals)

Keep the set small — each costs real space in two-column. Confirmed set + one tentative:

- **Table I — Comparative positioning matrix** (controls × attack scenarios). Positioning §4; full-width `table*`. *This is the claim-1 evidence, so it earns full width.* ✅
- **Fig 1 — Architecture & request/approval data flow.** System Design §5. *Carries the load so the prose can stay lean.* ✅
- **Table II — Net-delta classification** (Improved / Inherited / Introduced × four mitigation buckets). Security Analysis §6. ✅
- **Fig 2 — *(TENTATIVE)* Illustrative "2 a.m." attack timeline.** 3-developer team; two log off; one pushes a malicious release at 2 a.m.; the proxy *holds* it instead of publishing; the two co-owners review it clear-headed in the morning and **deny**. Keep only if it narrates cleanly. Placement TBD (System Design §5 or Positioning §4). Illustrative, not the rigorous t = m−1 test.

Overflow to Appendix: capability checklist, full per-threat classification table.
