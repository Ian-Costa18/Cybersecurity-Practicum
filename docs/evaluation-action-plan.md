# Evaluation Plan of Action

Living tracker for executing [evaluation-plan.md](evaluation-plan.md) — the plan owns the *method*; this file owns the *work remaining*. Companion to the bucket-① promotion roll-up ([#131](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/131)), which stays the authoritative per-row checklist for promotions; this file adds the non-promotion work, ordering, dependencies, and admin steps around it. Update both as work lands.

**How to read this file.** Phases order by *importance × ease* — the most critical, cheapest work first, so anything that slips off the end of the timeline is the hard-and-less-critical tail. Phases are not strictly sequential: the **Build track** (code) and **Author track** (research/writing/demo) run in parallel; within a phase, tasks with no listed dependency are parallel with each other. The next action is always: *the topmost unchecked task whose dependencies are all checked.*

---

## Status snapshot

_Update this block whenever a promotion lands._

- Bucket ① today: **11** threats (CORE-1, CORE-2, PUB-1, PUB-2, VOTE-2, VOTE-3, HOST-2, IDENT-2, IDENT-5, DOS-1, IDENT-1) — tests verified passing (frontmatter is CI-validated ground truth). Two tiers: **black-box** (CORE-1, CORE-2, IDENT-2, IDENT-5, DOS-1, PUB-1, VOTE-2, VOTE-3) and **integrity/detection** (HOST-2 audit chain #121, PUB-2 reconcile #124, IDENT-1 admin-action alarm #125). DOS-1 headline ① from storage #126 + flooding #32; its *connection-starvation* leg (d) stays operator-③. HOST-3 uniformly ② (#122). IDENT-2 detection leg ① (#128). VOTE-1 stays ② but `severity_residual` critical→high (#135 step-up re-auth). *(00-overview.md was materially behind — never absorbed wave-1's HOST-2/PUB-2 moves; full reconciliation in flight on `docs-overview-reconcile`.)*
- **All 8 #131 checklist rows are ticked** (#121, #124, #126, #127, #128, #123, #32, #125). **#135** (VOTE-1 step-up re-auth) landed via #149 (`severity_residual` critical→high applied; bucket stays ②). All batch **code** is merged; remaining = the overview/doc reconciliation pass (in flight), the review pass, and the single PR → `progress-report-4`. #129/IDENT-4 stays descoped.
- All promotion issues triaged out of `needs-triage` (2026-07-04): eight `ready-for-agent`, #129 → `future-enhancement`.
- Closed foundations: threat model audit (#107), suite mapping (#111), query/validate tooling (#130).
- **Batch execution state: see [Bucket-1 batch checkpoint](#bucket-1-batch-checkpoint-2026-07-04) below** — #128 landed (#145); demo Act 0 #143 landed (#144); #123 in flight; #32/#125/#135 queued.

---

## Deliverables → required work

The five submitted artifacts from [evaluation-plan.md](evaluation-plan.md) §Execution & artifacts, and what each still needs:

| # | Deliverable | Required work | Status |
|---|---|---|---|
| 1 | **Test suite** (functional + adversarial) | Functional suite exists and passes. Adversarial coverage grows with each #131 promotion (Phases 1, 3, 4). | 5/14 rows demonstrated |
| 2 | **Runnable demo** + capability checklist | Medium decided (marimo on the live compose stack — PRD [evaluation-demo.md](evaluation-demo.md), epic #142). Build: ~~#143 (Act 0)~~ **landed (#144)**, #112 (Act 1), #114 (Act 2). Capability checklist rows each traced to a passing test. | Act 0 landed; Acts 1–2 pending |
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

- [x] **#127 → VOTE-3 (UI-redress leg)** — anti-framing headers (`X-Frame-Options` / CSP `frame-ancestors`). *(Done 2026-07-04: merged via #136; oracle `tests/approvals/test_approve.py::test_approve_page_forbids_framing`; issue closed, #131 row ticked.)*
- [x] **#126 → DOS-1 (storage leg)** — upload-size + artifact-count caps. *(Done 2026-07-04: merged via #140; oracles in `tests/service_types/one_time/test_storage_caps.py`; 413/507 at the upload edge, size measured off the multipart spool; issue closed, #131 row ticked. Headline `bucket:` stays ③ until #32.)*
- [x] **#123 → IDENT-5** — in-proxy rate limiting on auth endpoints (labelled *bucket-1 blocker*). *(Done 2026-07-05: merged via #146. Shared `core/rate_limit.py` (framework-free) + `0017_rate_limit_counters` migration; throttle on login/approve/upload; deny-path deliberately unthrottled. Oracle `tests/auth/test_rate_limit.py::test_a_credential_stuffing_burst_against_login_is_rejected_with_429` (429 + Retry-After; correct creds from a throttled IP stay 429 → defeats online TOTP grinding). IDENT-5 ③→①. Issue closed, #131 row ticked.)* ⚠️ **00-overview.md not yet synced for IDENT-5's ① move — do in cleanup pass.**
- [ ] **#32 → DOS-1 (flooding legs)** — request-creation rate limits / per-requester quotas. *Effort: small.* **Depends on: #123** (reuse the limiter infrastructure — do back-to-back). Not started.

---

## Phase 2 — Author track (runs in parallel with Phases 1 & 3)

Writing and research; no code dependency on the Build track. Start as soon as Phase 0's grill answers land.

- [ ] **#119 — research deep-dive / citations** — source the background + comparative-matrix citations into `references.bib` (via the add-reference workflow). *No dependencies; feeds #113.*
  - Done when: every seed source in evaluation-plan §References has a verified `references.bib` entry, and #113's cell-citation needs are covered.
- [x] **#143 — Demo Act 0 (admin setup / introduce the team)** — provision a 3-of-3 service; one enrollment shown (`ada`, seeded live), two Mode-B (`bruno`/`carol` born-enrolled bundle); real encrypted rows. *(Done 2026-07-05: merged via #144 into `131-bucket-1-promotions`. `demo/notebooks/demo_lib.py` (tested flow + board scaffold) + `publish_demo.py` (marimo Act 0), `demo/seed/{users,config}.demo.yaml` throwaway seed, 16 backing tests in `tests/demo/`. All five gates green; `marimo export` runs Act 0 end-to-end against a real DB. Board node-set + degradation ladder established for Acts 1–2 to extend. Live-stack visual board render = presenter step, not CI-verified.)*
- [ ] **#112 — Demo Act 1 (happy path)** — full publish walk-through of `acme-widgets 1.0.0` + benign self-cancel/resubmit; ends on a successful `pip install`. Establishes the marimo notebook + Maltego board scaffold. *(Medium resolved — see Open Decision 1.)* **Deny-halt moved to Act 2.**
  - Done when: #112's acceptance boxes checked; every capability shown traces to a passing integration test (the §2 capability checklist).
- [ ] **#113 — comparative positioning matrix** — 7×4 verdict cells, every cell cited. Structure can start immediately; **citations depend on #119**.
  - Done when: #113's acceptance boxes checked; matrix matches evaluation-plan §1 Move 1 or the plan is amended to match (spec-freshness rule).

---

## Phase 3 — The heavy promotion + flagship demo

- [x] **#121 → HOST-2** — signed quorum/key snapshot, execution re-check, tamper-evident AuditLog. *(Done 2026-07-04: merged via #138. HMAC-SHA-256 audit hash chain under an HKDF-derived audit key off `server.secret_key`; snapshot-into-vote + execution re-check → new `FROZEN` state; ADR 0015 (one ADR, two trust roots); migration 0015. Detection-tier oracles in `tests/approvals/test_integrity.py`, `tests/audit/test_audit.py`, `tests/core/test_crypto.py`. Issue closed, #131 row ticked.)*
- [ ] **#114 — Demo Act 2 (the 2 a.m. deny, flagship)** — **single stolen credential** + careless rubber-stamp co-owner + diligent co-owner denies **live in the browser** on human context; request freezes at 2/3 then `DENIED`. Ends on a failing `pip install`. **Depends on: #112** (extends its scaffold). *Spec override: the t = m−1 worst case (two compromised seats) moves to the pytest suite; evaluation-plan §2 + #114 edited to match.*
  - Done when: #114's acceptance boxes checked; oracle asserts zero publishes (pypiserver index + `pip install` + audit); narration continuous with Act 1.

---

## Phase 4 — Detection-tier promotions (independent; time-permitting tail)

No dependencies between these; order below is by value-per-effort. Each follows the shared promotion end state. These are the deliberate slip-candidates — dropping one costs a single row, not a deliverable.

- [x] **#125 → IDENT-1** — admin-action notifications (notification leg only, per resolved Open Decision 3). *(Done 2026-07-05: merged via #148. New `AccountEdited`/`account.groups_changed` event; alarm on enrollment-issued / credentials-reset / groups-changed routed to **all** active admins via the typed-event → notification subscriber. Oracle `tests/accounts/test_admin_portal.py::test_quiet_enroll_forward_takeover_alarms_other_admins` (black-box + real SMTP). IDENT-1 ②→①. Issue closed, #131 row ticked.)* **IDENT-1's 00-overview.md ②→① flip deferred to the cleanup pass** (agent expressed the promotion in the threat file only, to avoid colliding with #147's overview rewrite). #135 (step-up re-auth) runs next; on its merge, VOTE-1 `severity_residual: critical → high`.
- [x] **#124 → PUB-2** — reconcile PyPI releases against the proxy's publish log. *(Done 2026-07-04: merged via #137. `service_types/one_time/reconcile.py` + `msig-reconcile` CLI, `publish.out_of_band_detected` typed event → audit + approver/admin email; detection-tier oracles in `tests/service_types/one_time/test_reconcile.py`. Issue closed, #131 row ticked.)*
- [x] **#128 → IDENT-2** — out-of-band enrollment confirmation, both legs (admin-gated `pending-confirmation` activation + completion notification). *(Done 2026-07-05: merged via #145. `accounts/admin.py` activation gate + `enroll.py`/`events.py`/`notifier.py`/`subscriber.py` completion notice; oracle `tests/accounts/test_activation.py::test_unactivated_seat_cannot_vote_until_admin_activates` (401 + zero Vote rows, black-box tier). IDENT-2 detection leg ③→①, prevention leg stays ③; 00-overview counts synced. Issue closed, #131 row ticked.)* Demo note: Act 0 (#143) uses Mode-B born-active provisioning, so #128 was never a demo blocker.
- [ ] **#129 → IDENT-4** — WebAuthn/FIDO2 per-vote auth. *Effort: large.* ⚠️ Build-vs-descope is Open Decision 2 — resolve it in the Phase 0 grill, not by default drift. If descoped: edit IDENT-4's `## Planned defenses` to withdraw the ① promise, update #131's row, state the withdrawal in the report.

---

## Phase 5 — Results assembly & closeout

Blocked by: all promotion rows either checked or explicitly re-scoped (threat file edited to match — a withdrawn promise is recorded, not silently dropped).

- [ ] **Run the full suite and gather results** — `uv run pytest` green, `validate` green, every checked row's tests named in frontmatter.
- [ ] **Render the results artifacts for the report** — four-bucket distribution over owned threats, residual-likelihood × residual-severity risk matrix, improved-threats (baseline → residual) table. Per #132, these ship as report content; the CI-checked static repo artifact is the deliberately-deferred alternative (Open Decision 5).
- [ ] **Close #131** with a summary comment (rows demonstrated vs. re-scoped).
- [ ] **Integration-branch milestone merge** — `progress-report-N` → `main` at the progress-report milestone, per the branch workflow.

---

## Bucket-1 batch checkpoint (2026-07-04)

Execution state of the bucket-① promotion batch, checkpointed mid-run (paused to conserve usage). An orchestrator session was driving one Opus programmer agent per issue, each in its own git worktree, PRs landing on a single promotion-integration branch.

### Branch topology (live)

`131-bucket-1-promotions` (cut off `progress-report-4`, pushed) collects every feature PR; when the batch is done it goes back to `progress-report-4` in **one** PR. Per-issue feature branches are cut off `131-bucket-1-promotions` and PR into it. All five landed PRs merged with all five gates green (`pytest` · `ruff check` · `ruff format --check` · `ty check` · `threat_model.py validate`); tip at checkpoint = `fe3887d`, 364 tests passing.

### Landed (5 of 10)

| Issue | PR | Result | Bookkeeping |
|---|---|---|---|
| #127 | #136 | VOTE-3 UI-redress leg ③→① (anti-framing middleware in `app.py`) | closed, #131 row ticked |
| #124 | #137 | PUB-2 ③→① detection (`reconcile.py` + `msig-reconcile`, out-of-band alert) | closed, #131 row ticked |
| #121 | #138 | HOST-2 ②→① (audit HMAC chain, snapshot re-check, `FROZEN`, ADR 0015, migration 0015) | closed, #131 row ticked |
| #122 | #139 | HOST-3 uniformly ② (TOTP AES-GCM wrap, migration 0016) | closed; not a #131 row |
| #126 | #140 | DOS-1 storage leg ③→① (upload 413 / artifact-count 507 caps) | closed, #131 row ticked |

Cross-PR integration fixes made on the integration branch itself: `2f3795a` threads #121's required `audit_key` into #124's reconcile wiring (same fix appeared in #122's branch; the duplicate resolved as a trivial merge conflict), and #122's migration was renumbered 0016 atop #121's 0015. Migration ledger: **0015 = #121, 0016 = #122, 0017 = reserved by #123's WIP.**

### Paused in flight (WIP preserved, uncommitted, in worktrees)

- **#123** — branch `123-auth-rate-limiting` @ base `4dbf681`, worktree `.claude/worktrees/agent-123-auth-rate-limiting`. New: `core/rate_limit.py`, `migrations/versions/0017_rate_limit_counters.py`, `tests/auth/test_rate_limit.py`, `tests/core/test_rate_limit.py`; modified: `auth/guards.py`, `auth/login.py`, `approvals/approve.py`, `one_time/upload.py`, `core/config.py`, `core/models.py`. Stopped at: red test for the 429 written; next step was wiring the deny-exempt guard onto the vote route.
- **#128** — branch `128-enrollment-activation` @ base `4dbf681`, worktree `.claude/worktrees/128-enrollment-activation`. New: `tests/accounts/test_activation.py`; modified: `accounts/admin.py`, `accounts/enroll.py`, `core/events.py`, `notifications/notifier.py`, `notifications/subscriber.py`, `tests/accounts/test_enrollment.py`. Stopped at: implementation largely in place; next step was cleaning stale comments in `tests/accounts/test_admin_portal.py`.

Both stopped mid-TDD **before** self-review; whoever resumes must finish the loop: gates → review skill (Standards + Spec) → merge `origin/131-bucket-1-promotions` in (it moved to `fe3887d` after they branched) → push → PR into `131-bucket-1-promotions`.

### Remaining sequence (collision groups still govern)

1. Finish + merge **#123** and **#128** (parallel OK with each other).
2. **#32** after #123 merges (reuses the shared limiter; DOS-1 flooding legs ③→①; raising DOS-1's headline `bucket:` to ① happens here, all legs then ①).
3. **#125 → #135 strictly sequential** (both rewrite `accounts/admin.py`). On #135's merge: VOTE-1 `severity_residual: critical → high`.
4. Batch-wide review-skill pass over `131-bucket-1-promotions` vs `progress-report-4`; fix findings.
5. Cleanup pass on the integration branch: IDENT-6's stale "`$ENV{}` the TOTP secret" operator-config prose (+ its echo in `00-overview.md`'s master table) — obsolete since #122; evaluation-plan §"Provisional first-pass classification" → replace with a pointer to the catalog (spec-freshness item); update this file's snapshot + record Open Decision 4's answer.
6. Final gates, then **one PR: `131-bucket-1-promotions` → `progress-report-4`**.

Also note: the user's `Practicum Work/Progress Reports/` files carry uncommitted local edits in the main checkout — leave them alone; they are excluded from all batch commits.

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

1. ~~**Demo medium**~~ — **RESOLVED 2026-07-04 (grill-with-docs):** a **marimo notebook driving the live `compose.publish.yaml` stack over real HTTP — nothing mocked**, shipped in both `edit` and `run` mode (run = default for the video), with a light-mode Maltego-style board and a degradation ladder (SVG → mermaid → checklist → markdown runbook). Oracle = pypiserver index + `DENIED`/audit + `pip install` bookend. Full design in the PRD ([evaluation-demo.md](evaluation-demo.md), epic #142). *Note: graders grade the video + reports, not the running system — no cold-grader path required.*
2. ~~**#129 WebAuthn: build vs. descope**~~ — **RESOLVED 2026-07-04: descoped** to `future-enhancement`. IDENT-4 stays ② argued-by-design (likelihood high accepted); struck from #131.
3. ~~**#125 scope**~~ — **RESOLVED 2026-07-04: notification leg only** (② → ① promotion). Step-up re-auth → #135; peer-approved actions → future.
4. ~~**Rate-limiter shape**~~ (#123/#32) — **RESOLVED 2026-07-05: one shared limiter.** #123 shipped a single framework-free `core/rate_limit.py` (+ `0017_rate_limit_counters` migration) serving the auth endpoints (merged #146); #32 reuses the same primitive for request-creation caps. Lives in `core/` per the slice layout ([source-layout.md](source-layout.md) updated in #146).
5. **#132 static results table** — stays deliberately deferred (report carries the table) or ship the CI-checked `report --check` artifact this cycle? Depends on whether the grader needs an in-repo view.
6. **#109 timing** — when to reconcile mvp-prd.md's generality claims with the package-publishing-only scope: before the demo/report prose cites them, or as a report-writing-time pass?
7. ~~**#122 (TOTP secrets encrypted at rest)**~~ — **RESOLVED 2026-07-04: in-cycle.** Not a #131 ① row — it hardens HOST-3 to uniformly ② (no plaintext credential at rest), a cleaner net-delta claim for §3. Handed off with the promotions, priority just below the eight; group it with the isolated tasks (#121/#124/#126/#127), *not* the same parallel wave as #123/#135 (shared auth slice). Testable artifact: a unit test asserting the stored TOTP column is ciphertext.
