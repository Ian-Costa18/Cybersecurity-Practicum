<!-- LTeX: enabled=false -->
---
marp: true
theme: midnight
paginate: true
footer: "Multi-Party Authorization Proxy · CS 6727 Final Presentation"
---

<!-- ============================================================
     FINAL PRESENTATION DECK — SKELETON (structure only)
     Source of truth: presentation-spec.md (8-beat gap-as-setup arc).
     Backbone = the report's three-claim evaluation arc.
     ≤15 min hard cap; ~14.9 planned. Beat budgets in each slide's SCRIPT tag.
     This file is STUBS ONLY — no narrative content or design decisions yet;
     the content tickets (#165–#169) fill each movement.
     Keep every slide's UPPER-RIGHT corner clear for the talking-head overlay.
     ============================================================ -->

<!-- _class: title -->
<!-- _paginate: false -->
<!-- _footer: "" -->

# Multi-Party Authorization Proxy

### Final Presentation — CS 6727 Practicum

<div class="meta">Ian Barish</div>
<div class="ai">AI use: deck drafted &amp; copy-edited with Claude; research, design, and all project decisions are my own.</div>

<!-- SCRIPT (~10s): title card. Not one of the 8 beats — holds while the
     talking-head intro lands, then straight into the hook. -->

---

## Beat 1 · Hook

<!-- STUB — Shai-Hulud (2025): one maintainer credential → self-propagating
     malware to thousands. Told vividly (US5). One artifact TBD. -->

<!-- SCRIPT (~1.0 min | Claim: hook):
     • placeholder — vivid incident narration goes here (#166 front-half). -->

---

## Beat 2 · Gap

<!-- STUB — every deployed control (2FA, Trusted Publishing, SLSA/provenance,
     CI gates, scanning) waves the compromised-maintainer attack through.
     ARTIFACT: comparative matrix, COMPETITOR COLUMNS ONLY (builds; the proxy
     column is added at Beat 3). Same as report Table I. (US8, #113) -->

<!-- SCRIPT (~2.0 min | Claim 1):
     • placeholder — walk the matrix; every control fails the same way (#166). -->

---

## Beat 3 · Thesis

<!-- STUB — "so how do you stop it?" → m-of-n human authorization. Drop the
     proxy's WINNING column into the matrix (the payoff). Plant the advocacy in
     ONE sentence (belongs everywhere). XZ (2024) named in one sentence as proof
     it's a pattern — REVISITED at Beat 7 as the honesty anchor (US6). (US7, US8, US26) -->

<!-- SCRIPT (~0.75 min | Claim 1):
     • placeholder — the answer to the question the audience now feels (#166). -->

---

## Beat 4 · Mechanism

<!-- STUB — request → hash-bind → per-vote reauth + Ed25519 sign → quorum →
     publish. Taught on slides BEFORE the demo so the demo is evidence, not
     instruction (US9). ARTIFACT: reuse the report's architecture figure /
     Fig 1 (US10). (#167 mechanism movement) -->

<!-- SCRIPT (~1.5 min | Claim 2 setup):
     • placeholder — walk the flow + architecture figure (#167). -->

---

<!-- _class: demo -->

## Beat 5 · Demo  ▶ [ SCREEN RECORDING ]

<!-- ============================================================
     RECORDING PLACEHOLDER — ~5 min screen-recorded marimo cut spliced in post.
     NOT a live slide. Act 0 single-button reveal (3 co-owners provisioned,
     keys encrypted at rest, TOTP secret NOT shown) → Act 1 legit → reaches
     quorum → publish → pip install ==1.0.0 succeeds → Act 2 malicious →
     freeze at 2/3 → morning catch → out-of-band verify → deny → pip install
     ==1.0.1 fails. Act 1 (mechanism pace) ≈ Act 2 (divergence pace).
     Demo rework is #163 (Work Product A); this slide is just its anchor.
     Real processing waits sped up in post; the presentation is never sped up.
     ============================================================ -->

<!-- SCRIPT (~5.0 min | Claim 2 evidence):
     • placeholder — the recorded demo carries this beat. -->

---

## Beat 6 · Threat Delta

<!-- STUB — lead with the skeptic's objection: "you built one juicy target"
     (US17). Concede concentration-of-risk / PoC-not-hardened as the worst
     residual (US18). Bound the introduced set to THREE themes — concentration ·
     human-factor (fatigue/coercion/replay) · availability (the gate as a jam
     point) (US19). Plant native-registry as the structural cure (US21).
     ARTIFACT: three-theme distillation only — full net-delta table stays OFF
     the slides, it lives in the report (US20). (#168 threat-delta movement) -->

<!-- SCRIPT (~2.0 min | Claim 3):
     • placeholder — one juicy target → concede → three themes → cure (#168). -->

---

## Beat 7 · Discussion

<!-- STUB — three parts, dividing labor cleanly with Beat 6 (US24):
     1. Deployment prerequisites from the operator checklist; highlight
        revoke-all-pre-existing-tokens (PUB-2) + set-quorum / pick-non-colluding
        co-owners (CORE-3, DOS-3/4); link the checklist for the rest (US22).
     2. Limitations as SCOPE BOUNDARIES — colluding quorum (CORE-3) out of scope
        by design, with XZ (2024) as its concrete face: a review-surviving,
        years-cultivated insider is the attack the proxy does NOT beat — NOT a
        silver bullet; performance + human-subjects usability unevaluated (US23).
        Research anchor: Final Report/research/sources/incident-xz-backdoor.md.
     3. Future work — advocacy payoff (m-of-n belongs anywhere one credential
        triggers a high-consequence action, US25) + native-registry
        productization path (US27). No standalone conclusion. (#168) -->

<!-- SCRIPT (~2.5 min | close):
     • placeholder — deployment → limitations → future work (#168). -->

---

<!-- _class: ask -->

## Beat 8 · Close

<!-- STUB — a SINGLE closing line, landing on the advocacy payoff. No recap,
     no standalone conclusion section (US28). -->

<!-- SCRIPT (~0.1 min):
     • placeholder — one line, then end. -->
