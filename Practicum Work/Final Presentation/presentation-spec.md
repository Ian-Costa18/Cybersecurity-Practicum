<!-- LTeX: enabled=false -->
# Final Presentation — Spec

The design spec for the CS 6727 final presentation video. Synthesized from a grill-with-docs
session, 2026-07-14. Source assignment: [Assignment.md](Assignment.md). Companion artifacts this
spec must stay consistent with: the final-report outline
([../Final Report/outline.md](../Final%20Report/outline.md)) and the evaluation-demo PRD
([../../docs/evaluation-demo.md](../../docs/evaluation-demo.md)).

## Problem Statement

I have to deliver a graded **≤15-minute video presentation** (talking-head required) that a
conference-style audience — assumed to have basic familiarity with the topic but *none* with my
project — can follow. The assignment names six required components (problem, solution + methodology,
evaluation, real-world deployment, limitations, future work) and weights the **solution discussion
most heavily**.

I have a polished three-act marimo demo I want to use, but three tensions pull against each other:

- The demo is framed in its PRD as *evaluation* evidence, so if it eats 6–7 minutes it starves the
  higher-weighted *solution* discussion and blows the time budget.
- I don't want to follow the six-component list so literally that the talk becomes a worse, more
  mechanical thing than it could be.
- The presentation and the final report must not contradict each other — neither should assert
  something the other never says, or frame the same fact incompatibly.

## Solution

A **slide-led** talk whose backbone is the report's **three-claim evaluation arc**, with the marimo
demo embedded as the evidence for Claim 2. Building the talk on the same three claims as the report
makes contradiction structurally impossible — both make the same three arguments from the same
evidence. The six required components all appear as beats inside the arc, so nothing is missing, but
the arc (not the six-bullet list) is the organizing spine.

The demo is compressed to **~5 minutes** and does double duty: it is both the *solution walkthrough*
("here's how it works," the highest-weighted component) and the *evaluation* ("here's proof it
works"). The mechanism is taught on slides *before* the demo, so the demo shows the mechanism come
true rather than spending its runtime explaining it.

The dramatic build is **gap-as-setup**: hook the audience with a real incident, show that every
control they already deploy fails against it, *then* reveal the thesis as the answer to the question
they now feel. The project's motivating argument — that m-of-n **human** authorization is a general
primitive that belongs far beyond package publishing — bookends the talk: stated in the thesis up
front, paid off in future work at the end.

### Structure & time budget (15-min hard cap; ~14.9 planned)

| # | Beat | Claim | ~min |
|---|---|---|---|
| 1 | **Hook** — Shai-Hulud (2025): one maintainer credential → self-propagating malware to thousands | (hook) | 1.0 |
| 2 | **Gap** — every deployed control (2FA, Trusted Publishing, SLSA/provenance, CI gates, scanning) waves the compromised-maintainer attack through; build the comparative matrix with competitor columns only | Claim 1 | 2.0 |
| 3 | **Thesis** — *so how do you stop it?* → m-of-n human authorization; drop in the proxy's winning matrix column (the payoff); plant the advocacy (belongs everywhere); XZ (2024) named in one sentence as proof it's a pattern | Claim 1 | 0.75 |
| 4 | **Mechanism** — the request → hash-bind → per-vote reauth + Ed25519 sign → quorum → publish flow; architecture figure | Claim 2 (setup) | 1.5 |
| 5 | **Demo** — Act 0 single-button reveal → Act 1 legit → publish → Act 2 malicious → deny | Claim 2 (evidence) | 5.0 |
| 6 | **Threat delta** — lead with "you built one juicy target"; concede concentration-of-risk / PoC-not-hardened; bound to three themes; plant the native-registry cure | Claim 3 | 2.0 |
| 7 | **Discussion** — deployment prerequisites (operator checklist; PUB-2 + CORE-3 highlighted) · limitations as scope boundaries · future work (advocacy payoff + native registry) | (close) | 2.5 |
| 8 | **Close** — single line | — | 0.1 |

Solution discussion = mechanism (1.5) + demo (5.0) = **6.5 min**, the fattest block by design.

### Six required components → arc mapping

| Required component | Where it lives |
|---|---|
| Problem (what/why) | Hook + gap (beats 1–2) |
| Solution + methodology (how) | Thesis + mechanism + demo (beats 3–5) |
| Evaluation | The three-claim spine itself; demo is Claim 2's evidence |
| Real-world deployment | Discussion, beat 7 (operator checklist) |
| Limitations | Discussion, beat 7 |
| Future work | Discussion, beat 7 (advocacy + native registry) |

## User Stories

1. As the presenter, I want a slide-led talk (not demo-led), so that I have a grounded spine to
   explain motivation, the solution, limitations, and future work — things the demo cannot narrate.
2. As the presenter, I want the talk's backbone to be the report's three evaluation claims (solves a
   problem / works / bounded new threats), so that the talk and the report cannot contradict each
   other.
3. As the presenter, I want all six assignment-required components to appear as beats inside the
   arc, so that I satisfy the rubric without letting a literal six-bullet march make the talk worse.
4. As the presenter, I want the solution discussion (mechanism + demo) to be the largest time block,
   so that the highest-weighted grading component gets the most runtime.
5. As the presenter, I want to open on the Shai-Hulud incident told vividly, so that a topic-familiar
   audience immediately feels the stakes.
6. As the presenter, I want XZ Utils named in a single sentence, so that the attack reads as a
   pattern rather than a one-off without spending a second case-study's worth of time.
7. As the presenter, I want the gap analysis placed *before* the thesis, so that the solution lands
   as the answer to a question the audience already feels rather than a claim I then defend.
8. As the presenter, I want the comparative matrix to be one slide that builds — competitor columns
   during the gap, the proxy's winning column dropped in at the thesis — so that a single artifact
   serves both the gap and the payoff and saves a slide's runtime.
9. As the presenter, I want the request → hash-bind → reauth-sign → quorum → publish flow taught on
   slides before the demo, so that the demo shows the mechanism come true instead of explaining it.
10. As the presenter, I want to reuse the report's architecture figure for the mechanism slide, so
    that the two artifacts stay visually and conceptually consistent.
11. As the presenter, I want the demo held to ~5 minutes, so that it is the centerpiece without
    starving the framing or overrunning the 15-minute cap.
12. As the presenter, I want Act 0 to collapse to a single button press that reveals all three
    co-owners already set up with keys encrypted at rest, so that setup is shown as real in seconds
    rather than as a step-by-step ceremony.
13. As the presenter, I want Act 1 and Act 2 weighted roughly equally, so that the parallel structure
    (same setup, one variable flipped) points a spotlight at exactly what the proxy contributes.
14. As the presenter, I want Act 1's time spent on the *mechanism* (teaching pace, it's new) and
    Act 2's equal time spent on the *divergence* (the freeze at 2/3, the morning catch, the
    out-of-band verify, the deny), so that equal weight never becomes boring repetition.
15. As the presenter, I want Act 1 to close on `pip install ==1.0.0` succeeding and Act 2 to close on
    `pip install ==1.0.1` failing, so that the good-vs-blocked outcome is shown against a real index.
16. As the presenter, I want to speed up real processing waits (email delivery, publish) in post, so
    that I keep fidelity without spending runtime, per the assignment's explicit permission.
17. As the presenter, I want the threat-delta beat to open with the skeptic's gut objection ("you
    built one juicy target"), so that I address the doubt a security audience is already forming.
18. As the presenter, I want to concede concentration-of-risk / PoC-not-hardened as the single
    biggest introduced threat plainly, so that the concession buys credibility for the rest.
19. As the presenter, I want my *spoken* pass over the introduced threats organized into three
    human-legible themes (concentration of risk · human-factor: fatigue/coercion/replay ·
    availability: the gate as a jam point), so that Claim 3 lands as "I didn't just move the problem"
    without me reading rows aloud. The three themes are the headline, not an exhaustive partition —
    the introduced set spans 8 STRIDE families and a few (e.g. information disclosure, payload
    substitution) sit outside the three; the spoken line says the threats "worth your attention
    cluster into three themes," never that the delta *is* three themes.
20. As the presenter, I want the **full threat model on screen** as the threat-delta beat's artifact —
    all 33 catalogued threats (24 introduced · 5 improved · 4 inherited), grouped, as a backdrop, with
    the three themes (US19) **highlighting in sequence** over the *introduced* subset as I name them —
    so that the completeness is *shown* (I did the entire accounting) rather than asserted or deferred
    to the report. The improved/inherited threats sit in a quieter register (the proxy also fixes and
    inherits some — shown, not narrated); the wall reads "comprehensive"; the highlights carry the
    three points; the unlit introduced remainder (disclosure, payload substitution) is visible but not
    dwelt on. This deliberately puts the whole model up rather than a report-only distillation: showing
    everything and reading three clusters over it is more credible than a clean three-box slide, and it
    avoids a "trust me, the rest is in the report" hand-wave. The report still holds the full net-delta
    *classification* (delta × bucket per threat) for study at the reader's pace; the slide shows the
    model, not that analysis.
21. As the presenter, I want to plant native-registry integration as the *structural cure* for
    concentration-of-risk during the threat-delta beat, so that I can pay it off in future work.
22. As the presenter, I want Discussion to open on deployment prerequisites drawn from the operator
    checklist — highlighting revoke-all-pre-existing-tokens (PUB-2) and set-quorum-for-availability /
    pick-non-colluding-co-owners (CORE-3, DOS-3/4) — and link the checklist for the rest, so that
    "it only works if deployed right" is stated honestly.
23. As the presenter, I want Discussion's limitations framed as two *scope boundaries* — (1) a fully
    colluding quorum (CORE-3) out of scope by design, *bridged* from the deployment beat's "pick
    non-colluding owners" so it reads as an elevation (knob → non-goal), not a restatement; and (2) the
    inherited-surface limit (the proxy is a bolt-on in front of a registry it doesn't own, so it
    inherits that registry's threats — exemplar PUB-3 external account-recovery bypass; the catalogued
    `inherited` set are scope statements, not proxy weaknesses) — both pivoting to native integration,
    so that I say plainly what I did not claim and it hands to future work. Performance and
    human-subjects usability are deliberately **not** named: no measured data to report, and naming
    unmeasured dimensions with nothing to say is filler in a ≤15-min talk.
24. As the presenter, I want the deployment prerequisites and the threat-delta beat to divide labor
    cleanly (threat-delta = new attack surface I own; Discussion = what an operator must do + what I
    didn't evaluate + where it goes next), so that the two beats do not repeat each other.
25. As the presenter, I want future work to be the *thesis payoff*: the argument that m-of-n human
    authorization belongs anywhere a single compromised credential can trigger a high-consequence
    action (shared-account, forward-auth, and beyond), so that the project's motivating conviction
    frames the whole talk.
26. As the presenter, I want the advocacy stated as one sentence in the thesis and one in future work
    (a bookend), so that it frames the talk without consuming runtime — its full development lives in
    the report.
27. As the presenter, I want native-registry integration paid off in future work as the productization
    path, so that the audience sees the biggest introduced risk dissolves once the registry (already
    the juiciest target) offers this natively — Trusted Publishing is the precedent.
28. As the presenter, I want no standalone conclusion section — just a single closing line, so that
    the talk ends on the advocacy payoff rather than a recap the audience just heard.
29. As the presenter, I want a talking-head camera present per the assignment, dressed professionally,
    with no AI-generated voice or face, so that the submission meets the stated production rules.
30. As a grader, I want each of the six required components clearly present, so that the rubric is
    satisfied.
31. As a grader, I want the solution discussion presented at an appropriate level (screens and
    functionality walked through, not a code-level review or a CLI shown merely to prove it runs), so
    that the solution reads as professionally presented.
32. As a topic-familiar-but-project-unfamiliar audience member, I want the problem, the gap, and the
    mechanism explained before the demo, so that I can follow what I'm watching.
33. As a consistency maintainer, I want the talk to cite the same matrix, architecture figure,
    limitations, operator checklist, and advocacy bookend as the report, so that the two artifacts
    reinforce rather than contradict each other.

## Implementation Decisions

- **Medium & spine.** Slide-led video. The deck is a **Marp markdown deck** (built via the
  `video-deck` skill), surrounding the screen-recorded marimo demo. Backbone = the three evaluation
  claims from [evaluation-plan.md](../../docs/evaluation-plan.md), mirroring the report.
- **Front-half order (gap-as-setup):** hook → gap (build matrix, competitor columns only) → thesis
  (drop the proxy's winning column; plant advocacy) → mechanism → demo. This reorders the naive
  "thesis then defend" into "problem → everything fails → the answer → proof."
- **Comparative matrix is one building slide.** Competitor columns shown during the gap; the proxy
  column added at the thesis. Same artifact as the report's Table I (Claim 1 evidence).
- **Mechanism taught before the demo.** The request/approval/publish flow and architecture figure
  (report Fig 1) are on slides, so the demo is evidence, not instruction.
- **Demo compressed to ~5 min, embedded, does double duty** (solution walkthrough + evaluation).
  - **Act 0** → a single button reveals all three co-owners already provisioned (Mode-B, born
    enrolled) with keypairs whose private keys are encrypted at rest, read from real DB rows. No
    step-by-step ceremony. **The TOTP secret is no longer displayed.** (evaluation-demo.md updated to
    match this session.)
  - **Act 1 and Act 2 are a parallel structure** — same request→approval→publish flow, one variable
    flipped (legit + reaches quorum → publish, vs. malicious + does not → deny). Roughly equal
    weight; Act 1's time on the mechanism, Act 2's equal time on the divergence.
  - Real processing waits are sped up in post (assignment-sanctioned); the presentation itself is
    never sped up.
- **Threat-delta reframe (talk only, not the catalog).** The report keeps the rigorous
  Improved/Inherited/Introduced × four-bucket classification. The *talk* presents the same catalog
  through a human lens: open on the "one juicy target" objection, concede concentration-of-risk /
  PoC-not-hardened as the worst residual, bound the introduced set to three themes (concentration ·
  human-factor · availability), plant native-registry as the structural cure. No re-bucketing of the
  threat model.
- **Discussion (2.5 min) divides into three:** deployment prerequisites (operator checklist;
  PUB-2 + CORE-3/DOS highlighted) · limitations as scope boundaries (CORE-3 out of scope; performance
  and human-subjects usability unevaluated) · future work (advocacy payoff + native-registry
  productization path). No standalone conclusion — one closing line.
- **Advocacy is a bookend**, one sentence each in thesis and future work; full development is the
  report's job.
- **Docs edited to keep specs consistent this session:**
  - `docs/evaluation-demo.md` — Act 0 reframed to a single-button reveal; TOTP secret dropped from
    the displayed credential state; stale "show-one/automate-rest as Act 0" cross-references removed.
  - `Practicum Work/Final Report/outline.md` — advocacy/generality elevated to the thesis-payoff and
    made the largest part of future work; native-registry integration added as the productization
    path that dissolves concentration-of-risk; Intro thesis strengthened to state the motivating
    argument.

## Consistency check

The only verification this spec needs: every claim the talk makes must trace to the report and the
evaluation catalogs, beat by beat, so the two artifacts cannot contradict each other.

- Gap/matrix ↔ report §4 (Claim 1); mechanism + demo ↔ report §5 (Claim 2) and the evaluation-demo
  PRD; threat-delta ↔ report §6 (Claim 3) and the threat catalog; deployment ↔
  `docs/threat-model/operator-checklist.md`; limitations/future ↔ report §7.
- Every capability shown on camera already traces to a passing integration test via the
  evaluation-demo PRD's capability checklist — the talk inherits that guarantee.

## Out of Scope

- **Recording, editing, and post-processing the video** (future video-postprocess work) — this spec
  covers design and content, not production, beyond noting the talking-head + no-AI-voice/face rules.
- **General-purpose (non-package-publishing) demonstration** — generality stays framing/advocacy
  ([#109](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/109)), never an evaluated
  claim, in both talk and report.

## Further Notes

- **Consistency is a hard requirement, not a nicety.** The talk and report share: the three claims,
  the comparative matrix, the architecture figure, the limitations set, the operator checklist, and
  the advocacy bookend. A change to one that affects a shared element must be mirrored in the other.
