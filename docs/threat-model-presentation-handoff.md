# Handoff — Restructuring the Threat Model into a Presented Catalog

**Status:** design / grilling in progress, no implementation yet.
**Branch:** `threat-model-presentation` (cut from `progress-report-4`).
**Owning doc being reshaped:** [threat-model.md](threat-model.md).

This is a working handoff, not a spec. It captures a brainstorming + grilling session so a
fresh agent can resume. Content already living in other artifacts is referenced by path, not
duplicated.

---

## Goal

The threat model is one long, ~470-line Markdown file with a rigid per-threat template. The
user wants a **better presentation** of it — easier to edit/manage per-threat, plus a
**visual** at-a-glance layer (MITRE ATT&CK-style). The user liked all of the directions below
and wants this turned into a GitHub issue after the design is pinned down.

## Brainstormed directions (all liked by the user)

- **A. Per-threat catalog folder** — split into `docs/threat-model/` with one file per threat
  (`T01-…md` … `Tnn-…md`) + an `index.md` / `00-overview.md`. Each file carries identical YAML
  frontmatter (`id`, `title`, `stride`, `capability`, `bucket`/`status`, `related`) so the data
  is machine-readable.
- **B. Visual navigator matrix (ATT&CK feel)** — STRIDE category as columns, threat cards
  stacked, colored by mitigation status; a second cut is capability `L1–L9 × status`. Most
  reusable artifact for the video deck.
- **C. The threat-modeling diagrams the doc lacks** — a **data-flow diagram with trust
  boundaries** (Mermaid; ties threats to [architecture.md](architecture.md)) and one or two
  **attack trees** for crown-jewel goals ("publish malicious package", "approver identity
  takeover").
- **D. Structured-data → generated views** — generate the summary table, the matrix, and the
  operator checklist from per-threat frontmatter so they can't drift. Only option that adds a
  build step (script or CI) that must be remembered.
- **E. Low-effort in-place** — TOC + collapsible `<details>` + legends, stay single-file. A
  stepping stone.

**Recommendation on the table:** do **A + B + C as one move** (folder + frontmatter + index
dashboard carrying the matrix, a DFD, and the summary table), leaving D's build step for later
(frontmatter keeps that door open).

---

## Constraints already discovered (do not re-derive)

- **T-IDs are load-bearing.** Other docs reference threats by ID in prose (`T7`, `T12`, etc.).
  Inbound **links**, however, all point at the *file* `threat-model.md` — none use per-threat
  anchors. So splitting is cheap on links but **`T1…Tnn` must stay stable, addressable IDs**.
  Files that reference the threat model: `account-management.md`, `approver-authentication.md`,
  `architecture.md`, `config.md`, `cryptography.md`, `evaluation-plan.md`, `mvp-prd.md`,
  `notification-system.md`, `request-lifecycle.md`, `web-proxy.md`, `adr/0009-…md`,
  plus `docs/index.md` and `CONTEXT.md`'s own condensed "Threat Model" section.
- **Folder precedent exists** in this repo — mirror it: `use-cases/` (`00-overview.md` +
  numbered `01-…md`), `research/` (`index.md`), `adr/` (numbered + `index.md`).
- **The catalog is actively growing.** The working tree (uncommitted, see below) already adds
  **T25–T27**. Whatever structure we pick must make adding a threat cheap — this strengthens
  the per-file split.
- **Duplication to resolve (or own deliberately):** operator config appears both per-threat
  *and* re-collected in the Operator Checklist; the Summary Table re-states capability / STRIDE
  / status. These are the natural targets for option D.

## The classification-vocabulary conflict (important)

Three competing status vocabularies exist today and **must be canonicalized**:

1. `threat-model.md` Summary Table column **"Fully Mitigated (MVP)?"** — ad-hoc values
   (Yes / Partially / No / By design / Accepted).
2. [evaluation-plan.md](evaluation-plan.md) §2 — the **canonical four-bucket** scheme:
   **① executably demonstrated · ② argued by design · ③ operator-enforced · ④ accepted
   limitation**. This is the source of truth for evaluation.
3. The frontmatter `status` field proposed in option A.

**Resolution to carry forward:** the frontmatter field should be the **four-bucket** value
(`bucket: 1|2|3|4`), not a new third vocabulary — so the per-threat files become the natural
home for the audited classification.

## Dependency on issue #107 — the spine question (OPEN)

[evaluation-plan.md](evaluation-plan.md) §2 says **issue #107 (threat-model hardening)** owns
"the **full, audited per-threat classification**" and "the **finished table**." That is a
*content* decision over the same 24+ threats this restructure reshapes the *form* of. They
collide if run as independent issues touching all threats.

**Recommended sequencing (pending user confirmation of #107's state):** make this restructure
its **own issue, sequenced as a prerequisite to #107** — reshape into clean per-threat files
with a `bucket:` slot first, so #107 becomes "fill/correct one field per file + regenerate the
table" instead of rewriting a monolith we then re-split. **First question to resolve with the
user:** is #107 not-started / in-progress / already has draft work? `gh` is **not installed**
in this environment, so #107's live state could not be pulled — ask the user or use the
issue-tracker fallback ([agents/issue-tracker.md](agents/issue-tracker.md)).

---

## Grilling design tree — where we are

The `/grill-with-docs` (grilling + domain-modeling) session had reached **Q1** when the user
pivoted to "branch + handoff + push." Open branches of the tree, in dependency order:

1. **Relationship to #107** — *partially answered* (recommend separate issue, sequenced
   **before** #107). Needs user confirmation of #107's current state.
2. **Scope of this issue** — restructure-only (mechanical move + frontmatter + visuals) vs.
   also re-classifying content. Recommend restructure-only; classification stays #107's.
3. **Folder layout & naming** — follow `use-cases/` pattern: `00-overview.md` (or `index.md`) +
   `T01-<slug>.md`. Zero-pad IDs for sort order.
4. **Status vocabulary** — canonicalize to the four-bucket (see above).
5. **Frontmatter schema** — exact fields + whether `stride` / `capability` / `bucket` become
   canonical domain terms (candidate for `CONTEXT.md` glossary or an ADR).
6. **Generated vs. hand-maintained views** — option D's build step: yes/no, and if yes,
   script-only or wired into CI.
7. **Which visuals & where** — STRIDE×status matrix, capability×status matrix, DFD with trust
   boundaries, attack tree(s); which live in `index.md` vs. the video deck.
8. **Inbound-link + ID stability** — update the ~13 referencing docs; keep T-IDs stable.
9. **Source-of-truth upkeep** — `CONTEXT.md`'s own Threat Model section, the Operator Checklist
   duplication, and the CLAUDE.md "specs are source of truth / update the doc in the same
   change" rule.
10. **Presentation target** — docs-in-repo only, or also feed the **Marp video deck** (the
    Security ① "2 a.m. deny" demo is already the presentation spine per evaluation-plan §2).
11. **Acceptance criteria** — definition of done for the issue.

---

## Parallel uncommitted work — NOT part of this branch's commit

The working tree carried three unrelated in-progress edits when this branch was cut, left
**untouched and uncommitted** on purpose:

- `docs/threat-model.md` — expands the catalog (adds **T25 No Anti-Automation**, **T26 API
  Token Theft**, **T27 Request & Resource Flooding**, and edits to T1/T2).
- `docs/evaluation-plan.md`, `docs/web-proxy.md` — related in-progress edits.

This branch's commit contains **only this handoff doc**. Decide with the user whether the
T25–T27 expansion should land first (it changes the threat count the restructure operates on).

---

## Suggested skills for the next session

- **`/grill-with-docs`** (grilling + domain-modeling) — resume the tree at Q1; confirm #107
  state and the four-bucket canonicalization first.
- **`/request-refactor-plan`** or **`/qa`** — once the design is pinned, file the GitHub issue
  (mechanical move broken into safe steps suits `request-refactor-plan`). Note `gh` is not
  installed; fall back to [agents/issue-tracker.md](agents/issue-tracker.md).
- **`/review`** — after implementation, to check the restructure against the spec-as-source
  rule and that no inbound link or T-ID broke.

## First moves for the resuming agent

1. Read [threat-model.md](threat-model.md) (current working-tree version, incl. T25–T27),
   [evaluation-plan.md](evaluation-plan.md) §2, and this file.
2. Confirm #107's state and the sequencing decision with the user.
3. Resume grilling from Q2 with the four-bucket canonicalization assumed.
