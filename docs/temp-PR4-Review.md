# Progress Report 4 branch review

> Temporary review artifact. Reviewer: Claude (Opus 4.8), driven by the `review` skill
> plus parallel sub-agents. Date: 2026-07-08.

**Scope:** `git diff main...HEAD` plus uncommitted working-tree edits — 209 files,
~22k insertions. Reviewed across five parallel sub-agents (code Standards, code Spec,
docs consistency, demo-vs-PRD, practicum documents), with the full test suite run as
ground truth.

**Ground truth:** `uv run pytest` → **461 passed, 98% coverage, clean.**
`ruff check`, `ruff format`, `ty check`, and `threat_model.py validate` (33 threats)
all pass. Migration chain is linear (0014 → 0015 → 0016 → 0017).

The one finding that should block the HOST-2 → bucket ① claim is a confirmed
correctness hole in the audit re-check. Everything else is polish, doc drift, or
unfinished draft content.

---

## Spec axis (code vs. threat-model / eval-action-plan / ADRs)

### 🔴 CONFIRMED — HOST-2 execution re-check falls back to the live (attacker-rewritable) key

`src/msig_proxy/approvals/integrity.py:97-98` — for a vote whose frozen anchor is
null, the re-check verifies against `keys.public_key_for(session, vote.key_id)`, i.e.
the live `user_keys.public_key` column. ADR 0015
(`docs/adr/0015-tamper-evident-db-records-two-trust-roots.md`) states the opposite:
*"the execution-time re-check verifies each Vote against this **frozen** key, not the
live column."*

Reachability traced end to end and it holds:

- `src/msig_proxy/approvals/snapshot.py:92-93` freezes `(key_id=None, public_key=None)`
  for any eligible approver unenrolled at request creation.
- `src/msig_proxy/approvals/votes.py:304` gates eligibility on `user_id` membership in
  the snapshot, resolving the signing key **live** at cast time — so an approver
  unenrolled at creation who later enrolls can still vote on that request.
- `src/msig_proxy/approvals/integrity.py:85-86` skips those approvers in the
  substitution check (`key_id is None → continue`), and lines 97-98 then anchor their
  vote on the live key.

**Failure scenario:** a service with a wildcard / late-enrolling approver pool has
≥ quorum eligible approvers who were unenrolled at creation. An L5 DB-write attacker
inserts forged approve Votes for those `user_id`s and rewrites the matching live
`user_keys.public_key` rows to attacker keys. The re-check passes and the request
executes a publish it never earned — the exact guarantee HOST-2 ① promises. The ADR's
dismissal ("they cannot vote until they enroll anyway") addresses legitimate voting,
not forgery, which is the whole HOST-2 threat model.

**Fix:** treat a null frozen anchor in step 2 as a hard failure (freeze for manual
review) instead of falling back to the live key; equivalently, reject votes from
approvers with a null frozen key in `cast_vote` so the branch is dead. Either way,
delete the live-key fallback. Untested — no case exercises the unenrolled → enroll →
forge path.

### 🟡 Minor — quorum re-check silently no-ops on a removed service

`src/msig_proxy/approvals/integrity.py:111-112` skips the quorum-vs-config comparison
when the service is absent from config. Acceptable under the HOST-1 boundary (config
removal isn't L5), but worth a comment or a conservative freeze.

### Observation (matches written contract — confirm intent)

`src/msig_proxy/accounts/admin.py:227` `activate_user` is gated on `require_admin`,
not `require_admin_step_up`. VOTE-1's spec deliberately omits activate from the
step-up set, so the code matches the contract — but a hijacked admin session can flip
a pending-confirmation seat live, partially eroding the IDENT-2 out-of-band gate.
Confirm the omission is intentional.

**No missing requirements and no load-bearing scope creep.** All nine promotions ship
with their cited oracles; DOS-1's connection-starvation leg is correctly left
operator-③; every threat file, ADR, and config default was edited in lockstep with the
code (the CLAUDE.md "overrides update the spec" rule is honored).

---

## Standards axis (src / tests / migrations vs. source-layout, ADR 0012)

**No hard violations.** All four new modules (`core/rate_limit.py`,
`approvals/integrity.py`, `audit/integrity.py`, `one_time/reconcile.py`) are
framework-free, correctly placed, and `docs/source-layout.md` was updated in the same
change for each (the MUST-update rule is satisfied). No FastAPI leakage into logic
across the 12 web-edge files.

**One judgement call** (both code agents landed on the same file):
`src/msig_proxy/approvals/integrity.py:95` reaches into the private
`votes._votes_for`, which the vote-read seam (`docs/source-layout.md` and `votes.py`
docstrings) says callers should not reassemble. It's a genuine seam gap — no public
read returns raw `Vote` objects with signatures, which signature re-verification
needs — not gratuitous reaching. Same-slice, so not a dependency-rule break. Cleanest
fix: promote a public `votes.history_for(...)` and route integrity through it. Not
blocking.

---

## Docs consistency (specs vs. shipped code)

1. **Soft contradiction —** `docs/evaluation-plan.md:65` labels PUB-2 as "bucket ③",
   but the catalog promoted PUB-2 to ① via the #124 reconciler (`00-overview.md`,
   PUB-2 frontmatter `bucket: 1`). The sentence's *point* (prevention stays
   operator-enforced) is still true; only the flat tag is stale. Reword to note the
   detection leg is now ① while the preventive control remains ③.
2. **Nit —** `docs/evaluation-plan.md:210` pairs IDENT-1 with an `Ed25519Verify`-fails
   oracle that actually belongs to HOST-2; IDENT-1's ① rests on the #125 admin-action
   alarm. Reword the oracle.

Everything else verified clean: overview counts match frontmatter, ADR 0015 is in the
index, ADR 0005/0009/0011/0014 edits match shipped code, no dangling links to the
deleted `docs/threat-model.md`, and evaluation-plan vs action-plan agree on the 11
bucket-① set.

---

## Demo vs. PRD (`docs/evaluation-demo.md`, epic #142)

The demo runs and the personas/quorum/approvers are internally consistent, but several
PRD deliverables exist only as library helpers or prose, never rendered in the actual
notebook surface:

- **Honesty legend (US30) — absent.** No three-category legend in
  `demo/notebooks/publish_demo.py`, edit or run mode; it lives only in `demo_flow.py`
  comments.
- **Capability checklist (US29) — never rendered.** `demo_lib.render_capability_checklist`
  exists, is tested, and its test-ids all resolve, but no notebook cell calls it, and
  the `completed` tick-green argument is never passed.
- **Audit entry / always-visible index panel — partial.** Act 2 paints a `DENIED`
  overlay but never surfaces the audit chain in the notebook (only the test calls
  `verify_audit_chain`); there's no persistent index panel.
- **Dead Act 1 board beats.** Act 1 buttons jump beat −1 → 2 → 3 → 5 → 6, so
  `ACT1_STEPS[0/1/4]` never render as frames; board step list and notebook flow
  disagree. `app_title="MPA Proxy — Demo Act 0"` though the notebook holds all three
  acts.
- **Weakly-backed tests.** `test_published_version_appears_in_the_index` /
  `test_malicious_version_is_absent_from_the_index` assert only the index *parser*
  against hand-written HTML; they can't fail if the real publish/deny path breaks. The
  genuine oracles live in the quorum/deny tests, so coverage exists but not where the
  checklist traces it.

None of these block filming (single-operator demo), but the legend + checklist are the
PRD's honesty deliverables and are currently invisible on screen.

---

## Practicum documents

**Mechanics are healthy:** PR4 compiles clean (xelatex + bibtex), all 19 `\cite` keys
resolve with zero undefined citations/references, the moved `\bibliography{../references}`
path is correct in PR4 / PR3 / report.tex, the bucket table (11/8/5/5) and net-delta
line are byte-identical to `threat_model.py report` output, and authorship reads "Ian
Barish" everywhere (no "Ian Costa" in any deliverable).

**`Progress Report 4.tex` is still a working draft** — listed so nothing ships empty
(not edited here, per standing instruction):

- L121 literal `"roughly TODO"` placeholder for the effort metric.
- L123-135 Completed Tasks: one empty `\item` (six accomplishments sit commented-out).
- L161-180 Next Tasks: entire list `\iffalse`-disabled.
- L183-196 Questions: only a `%`-commented question, renders empty.
- L289-296 Report Outline: empty placeholder, though the section says it's due by PR4
  (point it at `Final Report/outline.md`).
- L241 broken timeline row `\tlrow{W9}{Begin final }{}` — truncated text, empty status,
  duplicates L242.
- L275-286 bucket table overflows the page (Overfull \hbox 229.8pt, matches the in-file
  TODO) — wrap the Threats column or shrink the font.

`report.tex` / `outline.md` are intentional early drafts (`\aidrafttrue`);
`video3_deck.md` is correctly the PR3-cycle deck.

---

## Summary per axis

- **Spec:** 1 confirmed correctness hole (HOST-2 live-key fallback,
  `integrity.py:98`) + 1 minor + 1 confirm-intent. Worst: the HOST-2 hole undercuts the
  branch's headline ① promotion.
- **Standards:** 0 hard, 1 judgement call (`integrity.py` reaching into a private vote
  helper). Worst: that seam gap.
- **Docs:** 1 soft contradiction (`evaluation-plan.md:65`) + 1 nit.
- **Demo:** honesty legend + capability checklist specified but never rendered on
  screen; worst is those two PRD deliverables being invisible.
- **Practicum:** mechanics clean; PR4.tex has ~7 unfinished/placeholder sections to
  fill before submission.

The HOST-2 fallback is the only item to treat as blocking.

### Suggested follow-ups

1. Failing test reproducing the forged-quorum path + `integrity.py` fix (fail-closed on
   null frozen anchor). — **blocking**
2. Render the honesty legend + capability checklist in `publish_demo.py`.
3. `docs/evaluation-plan.md:65` PUB-2 tag reword; `:210` IDENT-1 oracle reword.
4. Fill PR4.tex placeholder sections + fix the bucket-table overflow before submission.
