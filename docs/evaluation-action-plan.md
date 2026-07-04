# Evaluation Plan of Action

Living tracker for executing [evaluation-plan.md](evaluation-plan.md) — the plan owns the *method*; this file owns the *work remaining*. Companion to the bucket-① promotion roll-up ([#131](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/131)), which stays the authoritative per-row checklist for promotions; this file adds the non-promotion work, ordering, dependencies, and admin steps around it. Update both as work lands.

**How to read this file.** Phases order by *importance × ease* — the most critical, cheapest work first, so anything that slips off the end of the timeline is the hard-and-less-critical tail. Phases are not strictly sequential: the **Build track** (code) and **Author track** (research/writing/demo) run in parallel; within a phase, tasks with no listed dependency are parallel with each other. The next action is always: *the topmost unchecked task whose dependencies are all checked.*

---

## Status snapshot

_Update this block whenever a promotion lands._

- Bucket ① today: **5** threats (CORE-1, CORE-2, PUB-1, VOTE-2, VOTE-3) — tests verified passing.
- Pending promotions: **8 rows / 8 issues** per #131 (#129/IDENT-4 descoped 2026-07-04; IDENT-4 stays ② argued-by-design).
- All promotion issues triaged out of `needs-triage` (2026-07-04): eight `ready-for-agent`, #129 → `future-enhancement`.
- Closed foundations: threat model audit (#107), suite mapping (#111), query/validate tooling (#130).

---

## Deliverables → required work

The five submitted artifacts from [evaluation-plan.md](evaluation-plan.md) §Execution & artifacts, and what each still needs:

| # | Deliverable | Required work | Status |
|---|---|---|---|
| 1 | **Test suite** (functional + adversarial) | Functional suite exists and passes. Adversarial coverage grows with each #131 promotion (Phases 1, 3, 4). | 5/14 rows demonstrated |
| 2 | **Two-act runnable demo** + capability checklist | Medium decision (grill), then #112 (Act 1), then #114 (Act 2). Capability checklist rows each traced to a passing test. | Not started |
| 3 | **Net-delta threat classification** (delta × bucket, likelihood/severity pairs, risk matrix) | Catalog data is complete and CI-validated. Remaining: render the results artifacts for the report (Phase 5) and keep frontmatter current as promotions land. | Data done; rendering pending |
| 4 | **Cited comparative matrix + case studies** | #119 (source citations) feeding #113 (matrix cells); case-study prose per evaluation-plan §1 Move 2. | Matrix drafted uncited |
| 5 | **Evaluation plan + threat model** (the docs themselves) | Done; keep fresh via the spec-freshness checks below. | Done, maintain |

---

## Phase 0 — Administrative unblock

Small, do immediately; everything else reads cleaner after.

- [x] **Fix #131 stale references** — the body cited retired `docs/threat-model/test-mapping.md`; repointed to threat-file `tests:` frontmatter + dashboard. *(Done 2026-07-04: zero occurrences remain, all 9 rows intact.)*
- [x] **Triage the promotion issues out of `needs-triage`** — *(2026-07-04)* eight `ready-for-agent`: #122, #123, #124, #126, #127, #32 (relabelled as-is), plus #121, #125, #128 after the grill below. #129 → `future-enhancement` (descoped). #135 filed (step-up re-auth, split from #125). No promotion issue carries `needs-triage`.
- [x] **Grill the four design-forked issues to `ready-for-agent`** — *(2026-07-04, decisions captured as issue comments + threat-file edits)*:
  - **#121 (HOST-2 audit trust root):** HMAC-SHA-256 hash chain keyed by an HKDF-derived dedicated audit key (from `server.secret_key`); detects modification + deletion/reorder; defends HOST-2, not HOST-1 (accepted ④); S3 sink = optional operator-③. Snapshot-into-vote + execution re-check unchanged (July 1). One ADR, two trust roots.
  - **#125 (IDENT-1):** scoped to the admin-action **notification** leg (② → ① promotion). Step-up re-auth → **#135**; peer-approved actions → future.
  - **#128 (IDENT-2):** build **both** — admin-gated activation (`pending-confirmation`; ① oracle = unactivated seat cannot vote) **and** completion notification.
  - **#129 (IDENT-4):** **descoped** to future work; IDENT-4 stays ② argued-by-design (likelihood high accepted). Struck from #131.
- [ ] **Hold the grilling session on Open Decisions** (bottom of this file) — several tasks below are blocked on those answers; grilling them once up front unblocks two phases.
  - Done when: each open decision has an answer recorded (here and/or in the owning issue), or is explicitly deferred with a date.

---

## Phase 1 — Quick-win promotions (Build track)

Cheapest bucket-① moves, highest count-impact per hour. No dependencies between the first three; #32 depends on #123.

Every promotion task in Phases 1, 3, 4 shares the same **end state** (from #131's definition of done):

> PR merged into the integration branch · the named adversarial test exists and passes under `uv run pytest` · the threat file's `bucket:` (or leg) raised to ① and the test added to its `tests:` frontmatter · `uv run tools/threat_model.py validate` green · issue closed with `merged via #<pr>` · the row checked in #131.

- [ ] **#127 → VOTE-3 (UI-redress leg)** — anti-framing headers (`X-Frame-Options` / CSP `frame-ancestors`). *Effort: trivial.* Oracle: headers present on the approval-page response.
- [ ] **#126 → DOS-1 (storage leg)** — upload-size + artifact-count caps. *Effort: small.* Oracle: oversized upload rejected, PyPI mock never called.
- [ ] **#123 → IDENT-5** — in-proxy rate limiting on auth endpoints (labelled *bucket-1 blocker*). *Effort: medium.* Oracle: credential-stuffing burst rejected. ⚠️ Limiter design shape is Open Decision 4.
- [ ] **#32 → DOS-1 (flooding legs)** — request-creation rate limits / per-requester quotas. *Effort: small.* **Depends on: #123** (reuse the limiter infrastructure — do back-to-back).

---

## Phase 2 — Author track (runs in parallel with Phases 1 & 3)

Writing and research; no code dependency on the Build track. Start as soon as Phase 0's grill answers land.

- [ ] **#119 — research deep-dive / citations** — source the background + comparative-matrix citations into `references.bib` (via the add-reference workflow). *No dependencies; feeds #113.*
  - Done when: every seed source in evaluation-plan §References has a verified `references.bib` entry, and #113's cell-citation needs are covered.
- [ ] **#112 — Demo Act 1 (happy path)** — full publish walk-through + deny-halt + self-cancel. **Depends on: Open Decision 1 (medium).**
  - Done when: #112's acceptance boxes checked; every capability shown traces to a passing integration test (the §2 capability checklist).
- [ ] **#113 — comparative positioning matrix** — 7×4 verdict cells, every cell cited. Structure can start immediately; **citations depend on #119**.
  - Done when: #113's acceptance boxes checked; matrix matches evaluation-plan §1 Move 1 or the plan is amended to match (spec-freshness rule).

---

## Phase 3 — The heavy promotion + flagship demo

- [ ] **#121 → HOST-2** — signed quorum/key snapshot, execution re-check, tamper-evident AuditLog. *Effort: large.* **Highest-value single promotion**: it is the only row that fills the integrity/detection ① tier, which currently has *zero* owned occupants — without it, evaluation-plan §3's two-tier story has an empty tier. Do before any Phase 4 item.
  - Oracle: binding check fails on key substitution / config-field tamper (`Ed25519Verify` detection tier).
- [ ] **#114 — Demo Act 2 (the 2 a.m. deny, flagship)** — 3-of-3, two compromised seats, honest co-owner denies. **Depends on: #112** (extends its scaffold/medium).
  - Done when: #114's acceptance boxes checked; oracle asserts zero publishes; narration continuous with Act 1.

---

## Phase 4 — Detection-tier promotions (independent; time-permitting tail)

No dependencies between these; order below is by value-per-effort. Each follows the shared promotion end state. These are the deliberate slip-candidates — dropping one costs a single row, not a deliverable.

- [ ] **#125 → IDENT-1** — admin-action notifications. *Effort: medium.* ⚠️ Scope is Open Decision 3 (notification leg only vs. the issue's full step-up/peer-approval hardening). Oracle: reset/deactivate emits a victim notification.
- [ ] **#124 → PUB-2** — reconcile PyPI releases against the proxy's publish log. *Effort: medium.* Oracle: out-of-band publish raises an alert.
- [ ] **#128 → IDENT-2** — out-of-band enrollment confirmation. *Effort: medium.* Oracle: real approver's "I never enrolled" fires before the stolen seat votes.
- [ ] **#129 → IDENT-4** — WebAuthn/FIDO2 per-vote auth. *Effort: large.* ⚠️ Build-vs-descope is Open Decision 2 — resolve it in the Phase 0 grill, not by default drift. If descoped: edit IDENT-4's `## Planned defenses` to withdraw the ① promise, update #131's row, state the withdrawal in the report.

---

## Phase 5 — Results assembly & closeout

Blocked by: all promotion rows either checked or explicitly re-scoped (threat file edited to match — a withdrawn promise is recorded, not silently dropped).

- [ ] **Run the full suite and gather results** — `uv run pytest` green, `validate` green, every checked row's tests named in frontmatter.
- [ ] **Render the results artifacts for the report** — four-bucket distribution over owned threats, residual-likelihood × residual-severity risk matrix, improved-threats (baseline → residual) table. Per #132, these ship as report content; the CI-checked static repo artifact is the deliberately-deferred alternative (Open Decision 5).
- [ ] **Close #131** with a summary comment (rows demonstrated vs. re-scoped).
- [ ] **Integration-branch milestone merge** — `progress-report-N` → `main` at the progress-report milestone, per the branch workflow.

---

## Recurring admin checklist (every promotion PR)

1. `git checkout <integration-branch>` → `git checkout -b <issue#>-<slug>`.
2. TDD the defense + named adversarial test (black-box through the real HTTP surface, or detection-tier at the crypto/DB layer — state the tier).
3. Update the threat file: `bucket:`, `tests:`, and the `## Current defenses` / `## Planned defenses` prose to match shipped reality.
4. `uv run pytest` · `uv run ruff check` · `uv run ruff format` · `uv run ty check` · `uv run tools/threat_model.py validate`.
5. PR with `--base <integration-branch>`; after merge, `gh issue close <#> -c "merged via #<pr>"` (closing keywords don't fire on integration-branch merges).
6. Check the row in #131. Update this file's Status snapshot.

---

## Opportunistic spec-freshness checks

Do these *while the relevant files are already in memory* for a task above — they cost minutes in context, hours cold. Found drift → fix in the same PR (overrides update the spec) or file an issue if out of scope.

- [ ] **evaluation-plan.md §"Provisional first-pass classification"** is now superseded by the audited catalog (#107 closed) — e.g. it lists IDENT-1 as a demonstrated-① candidate; the audited value is ②. Replace the paragraph with a pointer to the catalog/dashboard, or reword as history. *Do alongside any Phase 1 PR.*
- [ ] **Per promotion:** confirm the threat body's prose (attack story, defenses, oracle wording) matches what actually shipped — the frontmatter is CI-checked, the prose is not.
- [ ] **Per src/ change:** if a module is added/moved or a slice's responsibility changes, update [source-layout.md](source-layout.md) in the same change (CLAUDE.md rule).
- [ ] **Per citation:** entries land in `references.bib` source-verified (add-reference workflow), so evaluation-plan, PR4, and the final report cite one list.
- [ ] **#131 row wording vs. threat file:** when checking a row, confirm the row's oracle text still matches the threat file's `## Planned defenses` → shipped defense.
- [ ] **evaluation-plan.md §2 capability checklist vs. #112:** when the demo lands, verify each checklist row names a real passing test (no aspirational ✓).
- [ ] **#109 scope reconciliation:** mvp-prd.md generality framing vs. the package-publishing-only evaluation scope — owned by #109; check whether demo/matrix prose forces the edit sooner (Open Decision 6).

---

## Open decisions — grill these, do not decide inline

Deliberately left open; resolve in a grilling session (Phase 0) and record the answer here and in the owning issue.

1. **Demo medium** — marimo notebook vs. markdown how-to guide (evaluation-plan §2 names it an open sub-decision). Blocks #112, therefore #114. Considerations: continuity with video-deck tooling, grader-viewability on GitHub, who runs it.
2. ~~**#129 WebAuthn: build vs. descope**~~ — **RESOLVED 2026-07-04: descoped** to `future-enhancement`. IDENT-4 stays ② argued-by-design (likelihood high accepted); struck from #131.
3. ~~**#125 scope**~~ — **RESOLVED 2026-07-04: notification leg only** (② → ① promotion). Step-up re-auth → #135; peer-approved actions → future.
4. **Rate-limiter shape** (#123/#32) — one shared limiter mechanism serving both auth endpoints and request creation, or two local ones? Affects where it lives in the slice layout ([source-layout.md](source-layout.md)).
5. **#132 static results table** — stays deliberately deferred (report carries the table) or ship the CI-checked `report --check` artifact this cycle? Depends on whether the grader needs an in-repo view.
6. **#109 timing** — when to reconcile mvp-prd.md's generality claims with the package-publishing-only scope: before the demo/report prose cites them, or as a report-writing-time pass?
7. ~~**#122 (TOTP secrets encrypted at rest)**~~ — **RESOLVED 2026-07-04: in-cycle.** Not a #131 ① row — it hardens HOST-3 to uniformly ② (no plaintext credential at rest), a cleaner net-delta claim for §3. Handed off with the promotions, priority just below the eight; group it with the isolated tasks (#121/#124/#126/#127), *not* the same parallel wave as #123/#135 (shared auth slice). Testable artifact: a unit test asserting the stored TOTP column is ciphertext.
