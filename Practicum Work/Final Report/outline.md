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
     (Opens the generality bookend that Discussion §7 closes; keeps generality as framing, never
     an evaluated claim — see [#109].)
   - *The Solution in Brief* (short subheading — what the proxy is, before we use it below)

3. **Background — Motivating Incidents**
   - Case studies: Shai-Hulud (2025), XZ Utils / CVE-2024-3094 (2024)
   - What happened + why existing controls failed (the cost of the gap)

4. **Positioning & Gap Analysis**
   > *Evaluation Claim 1 — "It solves a problem." Source: [evaluation-plan.md §1](../../../docs/evaluation-plan.md).*
   - Authorization layer vs. authentication layer
   - Comparative positioning matrix (controls × attack scenarios)
   - How the proxy addresses each Background case study
   - **Doubles as Related Work** — no standalone Related Work section. This section engages the
     literature (2FA, Trusted Publishing, provenance/SLSA, CI gates, Artifactory, AWS m-of-n)
     *as evidence for the gap*, not as a deferential survey. Intro signals "existing controls
     analyzed in §4" in one line.

5. **System Design**
   > *Evaluation Claim 2 — "It works." Source: [evaluation-plan.md §2](../../../docs/evaluation-plan.md).*
   - Architecture + end-to-end request/approval flow
   - Three-act demo + integration-suite evidence

6. **Security Analysis**
   > *Evaluation Claim 3 — "It adds only a bounded set of new threats." Source: [evaluation-plan.md §3](../../../docs/evaluation-plan.md).*
   - Net-delta model: Improved / Inherited / Introduced
   - Four mitigation buckets over threats the proxy owns

7. **Discussion**
   - Limitations (colluding quorum CORE-3, operator-precondition PUB-2, PoC-not-hardened; excluded
     axes: performance, human-subjects usability; **friction/adoption cost** — requiring a second
     approver on every publish is a real behavioral tax on a team, the classic objection to m-of-n
     human gates. Rebutted, not dismissed, in Future Work below — [TODO: cite AI-coding /
     review-time-share data, e.g. GitHub Octoverse or DORA, via `add-reference`].)
   - **Future Work & Generalizability** — *closes the Intro's generality bookend*, and it is the
     **thesis payoff, not a footnote**. The project exists to argue that m-of-n *human*
     authorization is a general primitive that belongs far beyond package publishing — shared-account
     access, forward-auth-gated resources, and in principle *any* high-consequence action a single
     compromised credential can trigger. This is the largest, most-developed part of the section.
     Cites shared-account + forward-auth as designed-for evidence. Also develops **native registry
     integration** as the productization path that dissolves the proxy's single biggest introduced
     risk (concentration-of-risk — "one more juicy target" is moot once the registry, already the
     juiciest target in the ecosystem, offers this natively; Trusted Publishing is precedent that
     registries add auth features). Labeled unevaluated; the generality argument is *framing /
     advocacy*, never one of the three evaluated claims (#109).
   - **[IDEA — revisit]** *Rebuttal to the friction/adoption-cost limitation above:* AI-assisted
     coding has shifted developer time from writing toward reviewing — review is no longer
     incremental overhead layered on top of primarily-writing work, it's closer to the primary
     work itself. That lowers the marginal cost of one more required review on the highest-stakes
     action a repo takes (publish), relative to a pre-AI baseline. Secondary benefit: it forces at
     least one human to seriously look at exactly the artifact about to ship — a partial counter to
     "nobody reviews the AI's code." Same treatment as the generality argument: unevaluated framing,
     not a measured claim — grounded with citations on AI-coding review-time-share, not a metric
     this project instruments itself.

8. **Conclusion**

9. **References**

10. **Appendix** — *generally follows the progress-report appendix structure* (they'll be similar):
    - AI Usage Disclosure (carried from the progress reports)
    - Work Product pointers (codebase, docs/ADRs, PRD, threat model, evaluation plan)
    - Full threat-model classification table (net-delta + buckets)
    - Capability checklist (overflow from System Design §5)

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
